//! AES-256-GCM AEAD floor benchmark (Phase-5 perf baseline).
//!
//! Measures the irreducible cost of `AesKey::encrypt` / `AesKey::decrypt`
//! (the cached-round-key cipher used on every data packet) at the four
//! representative plaintext sizes the data path actually emits. This
//! establishes the crypto floor that the Python plumbing overhead is
//! measured against, and reveals whether AES-NI is present on the host
//! (≈1 GB/s ⇒ no AES-NI; tens of GB/s ⇒ AES-NI).
//!
//! Run: `cargo bench --manifest-path rust/tuncore/Cargo.toml --bench aead`
//! Throughput is set to the plaintext size so criterion reports B/s directly.
//!
//! Wire v2: `seal` and `open` of 1400-byte packets, and `open` of junk with
//! and without a grace period (the per-session cost of a miss for
//! multi-client).

use criterion::{
    black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput,
};
use tuncore::aes_gcm::AesKey;
use tuncore::secure_memory::LockedKey32;
use tuncore::session_keys::{DirSecrets, SessionKeyManager};

/// Plaintext sizes (bytes) spanning the size-class range the shaper pads to:
/// 128 = smallest class, 1400 = largest (MTU-sized) class.
const SIZES: [usize; 4] = [128, 512, 1024, 1400];

fn make_key() -> AesKey {
    // Fixed all-ones key — value is irrelevant to AEAD timing; we only need a
    // valid 32-byte key so the round-key schedule (cached in `AesKey`) is built
    // once, exactly as on the real data path.
    let locked = LockedKey32::from_array([0x11u8; 32]).expect("32-byte key is infallible");
    AesKey::from_locked(locked)
}

fn bench_encrypt(c: &mut Criterion) {
    let key = make_key();
    let nonce = [0x42u8; 12];
    let aad = [0u8; 8]; // matches the 8-byte seq AAD used on the wire
    let mut group = c.benchmark_group("aead_encrypt");
    for &size in &SIZES {
        let plaintext = vec![0xABu8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                key.encrypt(black_box(&nonce), black_box(&plaintext), black_box(&aad))
                    .expect("encrypt")
            });
        });
    }
    group.finish();
}

fn bench_decrypt(c: &mut Criterion) {
    let key = make_key();
    let nonce = [0x42u8; 12];
    let aad = [0u8; 8];
    let mut group = c.benchmark_group("aead_decrypt");
    for &size in &SIZES {
        let plaintext = vec![0xABu8; size];
        // Pre-encrypt once; the benchmark times only the decrypt of a valid
        // ciphertext (the steady-state hot path — auth always succeeds).
        let ciphertext = key
            .encrypt(&nonce, &plaintext, &aad)
            .expect("setup encrypt");
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                key.decrypt(black_box(&nonce), black_box(&ciphertext), black_box(&aad))
                    .expect("decrypt")
            });
        });
    }
    group.finish();
}

fn dir(aead: u8, hp: u8) -> DirSecrets {
    DirSecrets {
        aead: LockedKey32::from_array([aead; 32]).expect("32-byte key is infallible"),
        hp: LockedKey32::from_array([hp; 32]).expect("32-byte key is infallible"),
    }
}

/// A sender and a receiver on fixed keys. With `grace`, one key change is
/// half done, so the receiver also tries its previous header key.
fn pair(grace: bool) -> (SessionKeyManager, SessionKeyManager) {
    let mut sender = SessionKeyManager::new(dir(1, 2), dir(3, 4), 7, None, None).expect("sender");
    let mut receiver =
        SessionKeyManager::new(dir(3, 4), dir(1, 2), 7, None, None).expect("receiver");
    if grace {
        let init = sender.initiate_rotation().expect("rotation");
        let pending = receiver
            .prepare_rotation_responder(&init.ephemeral_pub, init.new_epoch)
            .expect("prepare");
        let receiver_pub = pending.our_pub;
        receiver.apply_rotation_responder(pending).expect("apply");
        sender
            .complete_rotation_initiator(init, &receiver_pub)
            .expect("complete");
    }
    (sender, receiver)
}

fn bench_wire_v2(c: &mut Criterion) {
    let plaintext = vec![0xABu8; 1400 - 36];
    let mut group = c.benchmark_group("wire_v2");
    group.throughput(Throughput::Bytes(1400));

    let (mut sender, _) = pair(false);
    let mut seq = 0u64;
    group.bench_function("seal_1400", |b| {
        b.iter(|| {
            seq += 1;
            sender
                .seal(black_box(seq), black_box(&plaintext))
                .expect("seal")
        });
    });

    let (mut sender, mut receiver) = pair(false);
    let mut seq = 0u64;
    group.bench_function("open_valid_1400", |b| {
        b.iter_batched(
            || {
                seq += 1;
                sender.seal(seq, &plaintext).expect("seal")
            },
            |wire| receiver.open(black_box(&wire)).expect("open"),
            BatchSize::SmallInput,
        );
    });

    let junk = vec![0x5Au8; 1400];
    for (grace, name) in [(false, "open_junk_1400"), (true, "open_junk_1400_grace")] {
        let (_, mut receiver) = pair(grace);
        group.bench_function(name, |b| b.iter(|| receiver.open(black_box(&junk))));
    }
    group.finish();
}

criterion_group!(benches, bench_encrypt, bench_decrypt, bench_wire_v2);
criterion_main!(benches);
