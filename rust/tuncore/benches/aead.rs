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

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use tuncore::aes_gcm::AesKey;
use tuncore::secure_memory::LockedKey32;

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

criterion_group!(benches, bench_encrypt, bench_decrypt);
criterion_main!(benches);
