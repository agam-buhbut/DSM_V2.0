//! swtpm-backed integration tests for the TPM attest backend.
//!
//! Every test runs against a per-test swtpm instance over TCP (the swtpm
//! TCTI in tss-esapi 7.7.0 supports host + port only — there is no
//! unix-socket variant). The real host `/dev/tpm0` is NEVER touched, so these
//! tests are hermetic and CI-friendly.
//!
//! Harness shape (RAII):
//! - [`Swtpm::start`] authors fresh TPM state with `swtpm_setup`, picks a free
//!   consecutive TCP port pair (command + control), spawns `swtpm socket`, and
//!   poll-connects until the command port accepts (bounded ~5s, no fixed
//!   sleep).
//! - [`Swtpm::context`] returns a connected, started-up `tss_esapi::Context`
//!   pointed at that swtpm via the `swtpm:host=…,port=…` TCTI.
//! - [`Swtpm`]'s `Drop` kills the child and removes the temp state dir,
//!   best-effort and never panicking.
#![cfg(feature = "tpm-attest")]

use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use tss_esapi::constants::StartupType;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::tcti_ldr::TctiNameConf;
use tss_esapi::Context;

use tuncore::device_attest_tpm::TpmAttestKey;

/// Max time to wait for the swtpm command port to start accepting.
const READINESS_TIMEOUT: Duration = Duration::from_secs(5);
/// Poll interval while waiting for the command port.
const READINESS_POLL: Duration = Duration::from_millis(20);

/// RAII swtpm instance. Owns a per-test temp state dir and a spawned `swtpm
/// socket` child; kills the child and removes the state dir on `Drop`.
pub struct Swtpm {
    child: Child,
    state_dir: PathBuf,
    /// The TCTI string for tss-esapi, e.g. `swtpm:host=127.0.0.1,port=2321`.
    pub tcti: String,
    /// Command-channel port (control channel is `port + 1`).
    pub port: u16,
}

impl Swtpm {
    /// Author fresh TPM state, spawn swtpm on a free TCP port pair, and wait
    /// until the command port accepts connections.
    ///
    /// # Panics
    /// Panics (this is test code) if `swtpm`/`swtpm_setup` are missing, state
    /// authoring fails, or the server does not come up within
    /// [`READINESS_TIMEOUT`].
    #[must_use]
    pub fn start() -> Self {
        let state_dir = unique_state_dir();
        std::fs::create_dir_all(&state_dir).expect("create swtpm state dir");

        // Author TPM2 state (PCR banks etc.). We deliberately omit
        // --create-ek-cert: an EK certificate needs a localca with extra
        // filesystem rights and is irrelevant to a GetRandom plumbing proof.
        let setup = Command::new("swtpm_setup")
            .arg("--tpm2")
            .arg("--tpmstate")
            .arg(&state_dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("spawn swtpm_setup (is swtpm installed?)");
        assert!(setup.success(), "swtpm_setup failed to author TPM state");

        let port = free_port_pair();
        let ctrl = port + 1;
        let child = Command::new("swtpm")
            .arg("socket")
            .arg("--tpm2")
            // State is pre-authored, so the manufacturing init is not needed;
            // startup-clear self-runs TPM2_Startup(CLEAR) inside swtpm.
            .arg("--flags")
            .arg("not-need-init,startup-clear")
            .arg("--tpmstate")
            .arg(format!("dir={}", state_dir.display()))
            .arg("--server")
            .arg(format!("type=tcp,port={port},bindaddr=127.0.0.1"))
            .arg("--ctrl")
            .arg(format!("type=tcp,port={ctrl},bindaddr=127.0.0.1"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn swtpm (is it installed?)");

        let tcti = format!("swtpm:host=127.0.0.1,port={port}");
        let me = Self {
            child,
            state_dir,
            tcti,
            port,
        };
        me.wait_until_ready();
        me
    }

    /// Bounded poll-connect on the command port; never a fixed sleep. Drops
    /// `self` (running its cleanup) before panicking on timeout.
    fn wait_until_ready(&self) {
        let deadline = Instant::now() + READINESS_TIMEOUT;
        loop {
            if TcpStream::connect(("127.0.0.1", self.port)).is_ok() {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "swtpm did not start accepting on 127.0.0.1:{} within {:?}",
                self.port,
                READINESS_TIMEOUT
            );
            std::thread::sleep(READINESS_POLL);
        }
    }

    /// Open a fresh `Context` over this swtpm and bring the TPM up.
    ///
    /// swtpm was launched with `startup-clear`, so it has already run
    /// `TPM2_Startup(CLEAR)`; a second startup from the Esys layer returns
    /// `TPM2_RC_INITIALIZE`, which is benign and swallowed. Any other startup
    /// error is surfaced via `expect`.
    ///
    /// # Panics
    /// Panics (test code) if the Esys context cannot be created (e.g. the
    /// `libtss2-tcti-swtpm` TCTI module is missing) or startup fails for a
    /// reason other than "already initialised".
    #[must_use]
    pub fn context(&self) -> Context {
        let conf = TctiNameConf::from_str(&self.tcti).expect("parse swtpm TCTI");
        let mut ctx = Context::new(conf).expect("open Esys context over swtpm");
        if let Err(e) = ctx.startup(StartupType::Clear) {
            assert!(
                is_already_initialized(e),
                "unexpected TPM2_Startup failure: {e}"
            );
        }
        ctx
    }
}

impl Drop for Swtpm {
    fn drop(&mut self) {
        // Best-effort teardown; never panic in Drop. Kill the child, reap it
        // to avoid a zombie, then remove the temp state dir.
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.state_dir);
    }
}

/// Reserve a free TCP port pair (`p`, `p + 1`) on loopback. swtpm needs the
/// control channel at `port + 1`, so both must be free. Binds `:0` to learn a
/// free port, then confirms `p + 1` is also bindable; retries a bounded number
/// of times if the successor is taken or `p` is `u16::MAX`. A small TOCTOU
/// window remains after the listeners are dropped, which is acceptable for a
/// test harness.
fn free_port_pair() -> u16 {
    for _ in 0..50 {
        let Ok(primary) = TcpListener::bind("127.0.0.1:0") else {
            continue;
        };
        let p = primary
            .local_addr()
            .expect("local_addr of ephemeral listener")
            .port();
        if p == u16::MAX {
            continue;
        }
        // Hold `primary` bound while probing the successor so the OS will not
        // immediately hand `p` back out as another ephemeral port. Any bind
        // failure on the successor (AddrInUse or otherwise) just retries the
        // outer loop.
        if let Ok(successor) = TcpListener::bind(("127.0.0.1", p + 1)) {
            drop(successor);
            drop(primary);
            return p;
        }
    }
    panic!("could not reserve a free consecutive TCP port pair for swtpm");
}

/// A per-test temp state dir under the system temp dir, unique across
/// processes and rapid successive calls within one process.
fn unique_state_dir() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::env::temp_dir().join(format!("dsm-swtpm-{}-{}", std::process::id(), nanos))
}

/// True if a `tss_esapi::Error` is the benign "TPM already started"
/// (`TPM2_RC_INITIALIZE`) condition returned by a redundant `TPM2_Startup`.
/// `tss_esapi::Error` is `Copy` (a small RC enum), so it is taken by value.
fn is_already_initialized(e: tss_esapi::Error) -> bool {
    format!("{e}").contains("INITIALIZE")
}

#[test]
fn swtpm_harness_get_random_roundtrip() {
    let tpm = Swtpm::start();
    let mut ctx = tpm.context();

    let first = ctx.get_random(16).expect("get_random over swtpm");
    assert_eq!(first.value().len(), 16, "requested 16 random bytes");
    assert!(
        first.value().iter().any(|&b| b != 0),
        "16 zero bytes is not plausible RNG output"
    );

    // A second draw differs — the TPM RNG actually produces fresh entropy.
    let second = ctx.get_random(16).expect("second get_random over swtpm");
    assert_eq!(second.value().len(), 16);
    assert_ne!(
        first.value(),
        second.value(),
        "consecutive RNG draws must differ"
    );

    // Owner hierarchy resolves (empty-auth path is reachable) — cheap sanity
    // that the interface-type path used by later tasks compiles and links.
    let _ = Hierarchy::Owner;

    // Teardown happens on Drop here; the test asserts no panic by completing.
    drop(tpm);
}

#[test]
fn two_harnesses_use_distinct_ports_and_both_work() {
    // Proves per-test isolation: two concurrent swtpm instances get different
    // port pairs and independently serve GetRandom.
    let a = Swtpm::start();
    let b = Swtpm::start();
    assert_ne!(a.port, b.port, "harness instances must not share a port");
    // The pairs must not overlap either (a uses port+1 for ctrl).
    assert_ne!(a.port + 1, b.port, "control port of A collides with B");
    assert_ne!(b.port + 1, a.port, "control port of B collides with A");

    let mut ctx_a = a.context();
    let mut ctx_b = b.context();
    let ra = ctx_a.get_random(16).expect("get_random A");
    let rb = ctx_b.get_random(16).expect("get_random B");
    assert_eq!(ra.value().len(), 16);
    assert_eq!(rb.value().len(), 16);
}

// ---------------------------------------------------------------------------
// Task 3.4: `TpmAttestKey::generate` + `public_spki_der` + the SECURITY-CRITICAL
// child-template attribute lock.
// ---------------------------------------------------------------------------

#[test]
fn generate_produces_loadable_key() {
    // The key is created AND loaded inside the TPM; a successful return means
    // create_primary -> create -> load all succeeded and a usable child handle
    // exists. `public_spki_der` succeeding proves the loaded child has a public
    // area we could export, i.e. the handle is real.
    let tpm = Swtpm::start();
    let key = TpmAttestKey::generate_with_tcti(&tpm.tcti).expect("generate must succeed");
    assert!(
        key.public_spki_der().is_ok(),
        "a freshly generated, loaded key must expose its SPKI"
    );
}

#[test]
fn public_spki_der_parses_as_p256() {
    // The exported SPKI must be a valid P-256 SubjectPublicKeyInfo: an
    // independent crate (`p256`) parses it and the curve is implicitly NIST
    // P-256 (VerifyingKey is curve-fixed to P-256).
    let tpm = Swtpm::start();
    let key = TpmAttestKey::generate_with_tcti(&tpm.tcti).expect("generate");
    let spki = key.public_spki_der().expect("spki");

    // Independent parser proves the exported pubkey is valid P-256.
    VerifyingKey::from_public_key_der(spki).expect("SPKI must parse as a P-256 verifying key");
    // P-256 SubjectPublicKeyInfo over an uncompressed point is a fixed 91 bytes
    // — same shape the soft backend produces.
    assert_eq!(spki.len(), 91, "P-256 SPKI is a fixed 91 bytes");
}

/// SECURITY: the residency lock. The child key's `TPMA_OBJECT` bitmask IS the
/// non-extractability guarantee — a single wrong bit silently loses key
/// residency. Each load-bearing attribute is asserted explicitly against the
/// `Public` the TPM returned for the loaded child, so a flipped bit fails here.
#[test]
fn child_template_attributes_locked() {
    let tpm = Swtpm::start();
    let key = TpmAttestKey::generate_with_tcti(&tpm.tcti).expect("generate");
    let attrs = key.child_object_attributes();

    // SET: the attest key signs, lives only in this TPM, and is non-migratable.
    assert!(
        attrs.sign_encrypt(),
        "sign MUST be SET (this is a signing key)"
    );
    assert!(
        attrs.fixed_tpm(),
        "fixedTPM MUST be SET (key can never be duplicated off this TPM)"
    );
    assert!(
        attrs.fixed_parent(),
        "fixedParent MUST be SET (key can never be re-parented / migrated)"
    );
    assert!(
        attrs.sensitive_data_origin(),
        "sensitiveDataOrigin MUST be SET (the TPM generated the scalar)"
    );
    assert!(
        attrs.user_with_auth(),
        "userWithAuth MUST be SET (usable under the empty-auth HMAC session)"
    );

    // CLEAR: not a restricted key (signs externally supplied digests), not a
    // decryption key, and duplication-encryption is irrelevant/off.
    assert!(
        !attrs.restricted(),
        "restricted MUST be CLEAR (must sign external handshake digests)"
    );
    assert!(
        !attrs.decrypt(),
        "decrypt MUST be CLEAR (this is not a decryption key)"
    );
    assert!(
        !attrs.encrypted_duplication(),
        "encryptedDuplication MUST be CLEAR"
    );
}

#[test]
fn distinct_generations_produce_distinct_keys() {
    // Each generate() creates a fresh in-TPM scalar, so two keys (even on the
    // same swtpm) must have different public SPKIs.
    let tpm = Swtpm::start();
    let k1 = TpmAttestKey::generate_with_tcti(&tpm.tcti).expect("k1");
    let k2 = TpmAttestKey::generate_with_tcti(&tpm.tcti).expect("k2");
    assert_ne!(
        k1.public_spki_der().expect("k1 spki"),
        k2.public_spki_der().expect("k2 spki"),
        "two generate() calls must yield different fresh keys"
    );
}

// ---------------------------------------------------------------------------
// Task 3.5: in-TPM ECDSA `sign` + independent `p256` verification. These prove
// the TPM produces a valid P-256 ECDSA-SHA256 signature over the exported key,
// indistinguishable in DER shape from the soft backend's output, and that
// `sign` re-opens its own context (the persistence proof).
// ---------------------------------------------------------------------------

#[test]
fn sign_then_verify_with_p256() {
    // The core property: a TPM-produced signature verifies as P-256
    // ECDSA-SHA256 under the exported SPKI, using a fully independent verifier
    // (`p256`). This proves the in-TPM key signs correctly and the DER round-trips.
    let tpm = Swtpm::start();
    let key = TpmAttestKey::generate_with_tcti(&tpm.tcti).expect("generate");
    let msg = b"DSM-BIND-v1\x00 test handshake hash material";

    let sig_der = key.sign(msg).expect("sign in TPM");
    let vk =
        VerifyingKey::from_public_key_der(key.public_spki_der().expect("spki")).expect("parse vk");
    let sig = Signature::from_der(&sig_der).expect("parse DER ECDSA signature");
    vk.verify(msg, &sig)
        .expect("TPM signature must verify as P-256 ECDSA-SHA256 under the exported SPKI");
}

#[test]
fn sign_in_fresh_context_after_generate() {
    // Persistence proof, made explicit: `generate` opens a context, loads the
    // child, flushes its handles, and DROPS that context before returning. No
    // live handle survives. `sign` must therefore re-open its own context and
    // reload the child under a freshly RE-DERIVED deterministic primary. A
    // successful, verifying signature proves the primary re-derivation is
    // deterministic and the child genuinely persists in the TPM.
    let tpm = Swtpm::start();
    let key = TpmAttestKey::generate_with_tcti(&tpm.tcti).expect("generate");
    // No handle from generate is reused — sign always re-opens (see impl). A
    // second sign on the same key likewise re-opens, proving repeatability.
    let msg = b"persistence-proof: child reloads under re-derived primary";
    let vk =
        VerifyingKey::from_public_key_der(key.public_spki_der().expect("spki")).expect("parse vk");

    for round in 0..2 {
        let sig_der = key
            .sign(msg)
            .unwrap_or_else(|e| panic!("sign round {round}: {e}"));
        let sig = Signature::from_der(&sig_der).expect("parse sig");
        vk.verify(msg, &sig)
            .unwrap_or_else(|e| panic!("verify round {round}: {e}"));
    }
}

#[test]
fn tampered_message_fails_verify() {
    // Sanity that the signature is a real signature over the message, not a
    // constant: a signature over message A must NOT verify against message B.
    let tpm = Swtpm::start();
    let key = TpmAttestKey::generate_with_tcti(&tpm.tcti).expect("generate");
    let sig_der = key.sign(b"original message").expect("sign");
    let vk =
        VerifyingKey::from_public_key_der(key.public_spki_der().expect("spki")).expect("parse vk");
    let sig = Signature::from_der(&sig_der).expect("parse sig");
    assert!(
        vk.verify(b"tampered message", &sig).is_err(),
        "a signature over a different message must not verify"
    );
}

#[test]
fn wrong_key_fails_verify() {
    // A signature from key1 must NOT verify against key2's SPKI — the signature
    // is bound to the specific in-TPM key, not the message alone.
    let tpm = Swtpm::start();
    let key1 = TpmAttestKey::generate_with_tcti(&tpm.tcti).expect("k1");
    let key2 = TpmAttestKey::generate_with_tcti(&tpm.tcti).expect("k2");
    let msg = b"shared message signed by key1";
    let sig_der = key1.sign(msg).expect("sign with k1");
    let vk2 =
        VerifyingKey::from_public_key_der(key2.public_spki_der().expect("k2 spki")).expect("vk2");
    let sig = Signature::from_der(&sig_der).expect("parse sig");
    assert!(
        vk2.verify(msg, &sig).is_err(),
        "key1's signature must not verify under key2's SPKI"
    );
}

#[test]
fn sign_enforces_1mib_cap() {
    // Parity with the soft backend's L-CRYPT-3 cap: a message exactly at the
    // 1 MiB cap is accepted and verifies; one byte over is rejected.
    let tpm = Swtpm::start();
    let key = TpmAttestKey::generate_with_tcti(&tpm.tcti).expect("generate");

    // Exactly at the cap: accepted + verifies (matches soft, which accepts it).
    let at_cap = vec![0x5Au8; 1 << 20];
    let sig_der = key.sign(&at_cap).expect("sign at 1 MiB cap must succeed");
    let vk = VerifyingKey::from_public_key_der(key.public_spki_der().expect("spki")).expect("vk");
    let sig = Signature::from_der(&sig_der).expect("parse sig");
    vk.verify(&at_cap, &sig)
        .expect("at-cap signature must verify");

    // One byte over the cap: rejected with the same typed error as soft.
    let over_cap = vec![0x5Au8; (1 << 20) + 1];
    let err = key
        .sign(&over_cap)
        .expect_err("over-cap message must be rejected (1 MiB cap parity)");
    assert!(
        err.contains("sign msg too large"),
        "cap error must match the soft backend's wording, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// Task 3.6: `to_store_blob` / `from_store_blob` persistence roundtrip, tampered
// -blob rejection, and the SECURITY-CRITICAL cross-TPM residency proof — a blob
// provisioned on one TPM must NOT yield a working key on another.
// ---------------------------------------------------------------------------

#[test]
fn store_blob_roundtrip_same_tpm() {
    // Persist the key as a DSMT blob, restore it (on the SAME swtpm), and prove
    // the restored key is the original: identical SPKI, and it signs a message
    // that verifies under the original SPKI. The restored key drives a real
    // TPM2_Load on first sign, so a working signature proves the blob carries a
    // genuinely loadable private area.
    let tpm = Swtpm::start();
    let key = TpmAttestKey::generate_with_tcti(&tpm.tcti).expect("generate");
    let original_spki = key.public_spki_der().expect("spki").to_vec();

    let blob = key.to_store_blob().expect("to_store_blob");
    drop(key); // the original is gone; only the blob survives

    let restored =
        TpmAttestKey::from_store_blob_with_tcti(&blob, &tpm.tcti).expect("restore from blob");
    assert_eq!(
        restored.public_spki_der().expect("restored spki"),
        &original_spki[..],
        "restored key must expose the SAME public SPKI (same key)"
    );

    let msg = b"DSM-BIND-v1\x00 roundtrip-restored handshake material";
    let sig_der = restored
        .sign(msg)
        .expect("restored key must sign on the same TPM");
    let vk = VerifyingKey::from_public_key_der(&original_spki).expect("vk from original spki");
    let sig = Signature::from_der(&sig_der).expect("parse DER sig");
    vk.verify(msg, &sig)
        .expect("restored key's signature must verify under the original SPKI");
}

#[test]
fn store_blob_parse_rejects_tampered() {
    // A tampered DSMT header is rejected by `from_store_blob` (it delegates to
    // tpm_blob::parse, which fails closed with a typed error). No panic, and the
    // failure is surfaced as the crate's `String` error — and crucially happens
    // BEFORE any TPM interaction.
    let tpm = Swtpm::start();
    let key = TpmAttestKey::generate_with_tcti(&tpm.tcti).expect("generate");
    let mut blob = key.to_store_blob().expect("to_store_blob");
    drop(key);

    // Flip the version byte in the DSMT header (offset 4). `TpmAttestKey` is
    // intentionally NOT `Debug` (it holds private key material), so we destructure
    // the `Err` with a `let-else` instead of `expect_err`.
    blob[4] = 0xFE;
    let Err(err) = TpmAttestKey::from_store_blob_with_tcti(&blob, &tpm.tcti) else {
        panic!("tampered DSMT header must be rejected");
    };
    assert!(
        err.contains("unsupported version"),
        "tampered header must surface tpm_blob's typed rejection, got: {err}"
    );

    // Flipping the magic is likewise a typed rejection (not a panic).
    let mut bad_magic = key_blob_for(&tpm);
    bad_magic[0] = b'X';
    let Err(err2) = TpmAttestKey::from_store_blob_with_tcti(&bad_magic, &tpm.tcti) else {
        panic!("bad magic must be rejected");
    };
    assert!(
        err2.contains("bad magic"),
        "bad-magic blob must surface tpm_blob's typed rejection, got: {err2}"
    );
}

/// Helper: provision a throwaway key on `tpm` and return its store blob. Used by
/// `store_blob_parse_rejects_tampered` to get a second valid blob to corrupt.
fn key_blob_for(tpm: &Swtpm) -> Vec<u8> {
    let k = TpmAttestKey::generate_with_tcti(&tpm.tcti).expect("generate for blob");
    k.to_store_blob().expect("to_store_blob")
}

/// SECURITY — the headline residency proof. A DSMT blob provisioned on TPM A
/// carries a `TPM2B_PRIVATE` sensitive area wrapped to A's Owner primary. The
/// child is `fixedTPM | fixedParent`, so it is non-duplicable and non-portable:
/// a SEPARATE TPM B (fresh state, different seed) cannot re-derive A's primary,
/// so `TPM2_Load` of the child blob under B's (different) primary MUST fail.
///
/// In the stateless re-open model `from_store_blob` only parses + reconstructs
/// structs (no TPM call), so it SUCCEEDS on B with the same bytes. The failure
/// surfaces on the first `sign`, which re-opens B's context, re-derives B's
/// Owner primary, and tries to `TPM2_Load` the child — and that load fails.
/// This proves the key is bound to the TPM that created it: a stolen blob is
/// useless on any other device.
#[test]
fn cross_tpm_residency_fails() {
    // Provision on TPM A and capture the blob.
    let tpm_a = Swtpm::start();
    let key_a = TpmAttestKey::generate_with_tcti(&tpm_a.tcti).expect("generate on A");
    let blob = key_a.to_store_blob().expect("to_store_blob on A");
    // Sanity: the blob is valid ON A (would sign fine here). Drop A's handle.
    drop(key_a);

    // Spin up a genuinely SEPARATE TPM B: fresh state dir + different ports +
    // an independently authored TPM seed (Swtpm::start runs swtpm_setup).
    let tpm_b = Swtpm::start();
    assert_ne!(
        tpm_a.tcti, tpm_b.tcti,
        "B must be a different TPM instance than A (distinct TCTI/ports)"
    );

    // Parsing/reconstruction on B succeeds — it is the same bytes, no TPM call.
    let restored_on_b = TpmAttestKey::from_store_blob_with_tcti(&blob, &tpm_b.tcti)
        .expect("parse + reconstruct on B must succeed (no TPM interaction yet)");

    // The actual residency check: signing on B re-derives B's primary and tries
    // to TPM2_Load A's child blob under it — this MUST fail.
    let sign_res = restored_on_b.sign(b"attempt to use A's key on B");
    let err = sign_res.expect_err(
        "RESIDENCY VIOLATION: A's key blob signed on TPM B — the key is NOT TPM-bound!",
    );

    // The residency proof is SPECIFICALLY a `TPM2_Load` integrity rejection:
    // B re-derives a DIFFERENT Owner primary, so the child's private area
    // (wrapped to A's primary) fails its integrity check on load. tss-esapi
    // formats the format-1 RC `TPM2_RC_INTEGRITY` (0x9F) as
    // "integrity check failed (...)", wrapped by `sign` as
    // "TPM error: integrity check failed (...)". Asserting on that exact RC
    // text — not merely "any error containing tpm" — is what makes this test
    // genuinely prove residency rather than incidentally pass on some other
    // failure.
    let lower = err.to_ascii_lowercase();
    assert!(
        lower.contains("tpm error") && lower.contains("integrity check failed"),
        "residency failure must be the TPM2_Load integrity rejection \
         (TPM2_RC_INTEGRITY), got: {err}"
    );

    // And it must NOT be any of the pre-TPM input guards: the size cap, a
    // zeroized key, or a TCTI parse failure. Excluding these proves the
    // failure originated from the TPM load, not from `sign`'s own guards.
    assert!(
        !err.contains("sign msg too large"),
        "residency failure must be the load integrity error, not the size cap: {err}"
    );
    assert!(
        !err.contains("attest key has been zeroized"),
        "residency failure must be the load integrity error, not a zeroized key: {err}"
    );
    assert!(
        !err.contains("invalid TPM TCTI"),
        "residency failure must be the load integrity error, not a TCTI parse error: {err}"
    );
}

// ---------------------------------------------------------------------------
// Task 3.8: `zeroize` makes the key unusable (parity with the soft backend's
// "attest key has been zeroized" contract), is idempotent, and the stateless
// re-open model leaks NO transient TPM handle across repeated provisions/signs
// (every load is paired with a flush inside its own session).
// ---------------------------------------------------------------------------

/// After `zeroize`, every accessor must return the SAME typed error the soft
/// backend returns (`"attest key has been zeroized"`). This locks the
/// cross-backend FFI/Python contract: a verifier/store cannot distinguish a
/// zeroized TPM key from a zeroized soft key by its error.
#[test]
fn zeroize_makes_key_unusable() {
    // Post-zeroize, every accessor must return this exact soft-identical string.
    const ZEROIZED: &str = "attest key has been zeroized";

    let tpm = Swtpm::start();
    let mut key = TpmAttestKey::generate_with_tcti(&tpm.tcti).expect("generate");

    // Pre-zeroize: everything works.
    assert!(key.public_spki_der().is_ok(), "spki must work pre-zeroize");
    assert!(key.sign(b"x").is_ok(), "sign must work pre-zeroize");
    assert!(
        key.to_store_blob().is_ok(),
        "to_store_blob must work pre-zeroize"
    );

    key.zeroize();

    // Post-zeroize: every accessor fails with the soft-identical error string.
    let spki_err = key
        .public_spki_der()
        .expect_err("public_spki_der must fail post-zeroize");
    assert_eq!(
        spki_err, ZEROIZED,
        "public_spki_der must return the soft-identical zeroized error"
    );
    let sign_err = key.sign(b"x").expect_err("sign must fail post-zeroize");
    assert_eq!(
        sign_err, ZEROIZED,
        "sign must return the soft-identical zeroized error"
    );
    let store_err = key
        .to_store_blob()
        .expect_err("to_store_blob must fail post-zeroize");
    assert_eq!(
        store_err, ZEROIZED,
        "to_store_blob must return the soft-identical zeroized error"
    );
}

/// `zeroize` must be safe to call twice (parity with soft). The second call has
/// nothing to scrub and must not panic; the key stays unusable.
#[test]
fn zeroize_is_idempotent() {
    let tpm = Swtpm::start();
    let mut key = TpmAttestKey::generate_with_tcti(&tpm.tcti).expect("generate");

    key.zeroize();
    key.zeroize(); // second call: no panic, no double-free, no resurrection.

    assert!(
        key.public_spki_der().is_err(),
        "key must stay unusable after a second zeroize"
    );
    assert!(
        key.sign(b"x").is_err(),
        "sign must stay blocked after a second zeroize"
    );
}

/// LEAK GUARD — the headline hygiene proof for the stateless re-open model.
///
/// Each `generate`/`sign` opens its OWN context, `create_primary` + `load`s the
/// child, and flushes BOTH transient handles (child + primary) inside its own
/// session before the context drops; NO handle is held across calls. A TPM has
/// only ~3 transient-object slots, so if any path leaked a transient handle,
/// the second or third provision would fail with `TPM_RC_OBJECT_MEMORY`
/// (out-of-memory). Running `generate` (and `sign`) many times on ONE swtpm and
/// having every call succeed proves the flushing is correct and slot-leak-free.
#[test]
fn no_transient_handle_leak_across_provisions() {
    // Far more iterations than the ~3 transient slots: a single leaked handle
    // per provision would exhaust the TPM well before the loop completes.
    const PROVISIONS: usize = 10;

    let tpm = Swtpm::start();
    for i in 0..PROVISIONS {
        let mut key = TpmAttestKey::generate_with_tcti(&tpm.tcti)
            .unwrap_or_else(|e| panic!("provision {i} failed (transient-slot leak?): {e}"));
        // Each sign also opens+loads+flushes its own context; loop it a couple
        // of times per key to prove sign does not leak either.
        for r in 0..3 {
            key.sign(b"leak-guard probe")
                .unwrap_or_else(|e| panic!("sign {r} on provision {i} failed (leak?): {e}"));
        }
        key.zeroize();
    }

    // A FINAL provision after PROVISIONS rounds must still succeed — if any of
    // the prior rounds had leaked a slot, the TPM would be exhausted by now.
    let final_key = TpmAttestKey::generate_with_tcti(&tpm.tcti)
        .expect("final provision after the loop must succeed (no accumulated slot leak)");
    assert!(
        final_key.public_spki_der().is_ok(),
        "final key must be fully usable — proves no transient-slot exhaustion"
    );
}

// ---------------------------------------------------------------------------
// Task 3.12: bind the operator passphrase to the attest key's TPM auth value.
// `encrypt_to_store(pass)` runs TPM2_ObjectChangeAuth to set the child key's
// auth = HKDF(pass); `decrypt_from_store(blob, pass)` caches the derived auth
// and `sign` installs it via tr_set_auth. The headline property: the WRONG
// passphrase cannot sign (TPM authorization rejection). An empty passphrase
// keeps the empty-auth behaviour (back-compat), and the fresh `generate`d key
// signs with empty auth (the enroll CSR path).
// ---------------------------------------------------------------------------

/// SECURITY — the two-factor proof. After binding a passphrase as the key's TPM
/// auth, restoring with the CORRECT passphrase signs and verifies, but restoring
/// with a WRONG passphrase derives the wrong auth and the TPM REJECTS the sign
/// with an authorization-HMAC failure (DA counter incremented). This is the
/// defense: disk blob + TPM access are NOT enough without the passphrase.
#[test]
fn sign_requires_correct_passphrase_auth() {
    let tpm = Swtpm::start();
    let key = TpmAttestKey::generate_with_tcti(&tpm.tcti).expect("generate");
    let spki = key.public_spki_der().expect("spki").to_vec();

    // Bind the passphrase as the key's TPM auth at store time.
    let blob = key
        .encrypt_to_store(b"correct-horse-battery-staple")
        .expect("encrypt_to_store with passphrase (ObjectChangeAuth)");
    drop(key); // only the auth-bound blob survives

    // CORRECT passphrase: restore, sign, and verify under the original SPKI.
    let good = TpmAttestKey::decrypt_from_store_with_tcti(
        &blob,
        &tpm.tcti,
        b"correct-horse-battery-staple",
    )
    .expect("restore with correct passphrase");
    let msg = b"DSM-BIND-v1\x00 task-3.12 two-factor sign";
    let sig_der = good
        .sign(msg)
        .expect("correct passphrase must produce a valid signature");
    let vk = VerifyingKey::from_public_key_der(&spki).expect("vk from spki");
    let sig = Signature::from_der(&sig_der).expect("parse DER sig");
    vk.verify(msg, &sig)
        .expect("correctly-authed TPM signature must verify");

    // WRONG passphrase: the derived auth is wrong, so TPM2_Sign under the
    // nullauth session fails the authorization HMAC check. tss-esapi formats
    // TPM2_RC_AUTH_FAIL as "the authorization HMAC check failed and DA counter
    // incremented (...)"; `sign` wraps it as "TPM error: ...". Asserting on that
    // exact authorization wording — not "any error" — is what makes this prove
    // the passphrase is genuinely load-bearing rather than incidentally failing.
    let bad = TpmAttestKey::decrypt_from_store_with_tcti(&blob, &tpm.tcti, b"WRONG-passphrase")
        .expect("parse blob (wrong-pass still parses; auth is wrong, not the bytes)");
    let err = bad
        .sign(msg)
        .expect_err("a WRONG passphrase MUST fail to sign (TPM auth rejection)");
    let lower = err.to_ascii_lowercase();
    assert!(
        lower.contains("tpm error")
            && lower.contains("authorization")
            && (lower.contains("hmac check failed") || lower.contains("auth")),
        "wrong-passphrase failure must be the TPM authorization rejection \
         (TPM2_RC_AUTH_FAIL / BAD_AUTH), got: {err}"
    );
    // And it must NOT be any of `sign`'s pre-TPM input guards — excluding these
    // proves the failure originated from the TPM's auth check.
    assert!(
        !err.contains("sign msg too large"),
        "auth failure must not be the size cap: {err}"
    );
    assert!(
        !err.contains("attest key has been zeroized"),
        "auth failure must not be a zeroized key: {err}"
    );
    assert!(
        !lower.contains("integrity check failed"),
        "auth failure must be the auth-HMAC rejection, NOT a load-integrity \
         (cross-TPM) error — same TPM, same primary, only the auth differs: {err}"
    );
}

/// Back-compat: an EMPTY passphrase binds NO auth, so store→restore→sign works
/// exactly as the no-passphrase native path. Also exercises the enroll-shaped
/// flow: the freshly generated (empty-auth) key signs BEFORE store.
#[test]
fn empty_passphrase_keeps_empty_auth() {
    let tpm = Swtpm::start();
    let key = TpmAttestKey::generate_with_tcti(&tpm.tcti).expect("generate");
    let spki = key.public_spki_der().expect("spki").to_vec();

    // The enroll CSR path: the fresh empty-auth key signs before any store.
    let csr_msg = b"enroll: fresh empty-auth key signs the CSR before store";
    let csr_sig = key
        .sign(csr_msg)
        .expect("freshly generated empty-auth key must sign (enroll CSR path)");
    let vk = VerifyingKey::from_public_key_der(&spki).expect("vk");
    vk.verify(
        csr_msg,
        &Signature::from_der(&csr_sig).expect("parse csr sig"),
    )
    .expect("fresh-key signature must verify");

    // Empty passphrase: no auth bound; restore + sign works (back-compat).
    let blob = key
        .encrypt_to_store(b"")
        .expect("encrypt_to_store with empty passphrase == to_store_blob");
    drop(key);

    let restored = TpmAttestKey::decrypt_from_store_with_tcti(&blob, &tpm.tcti, b"")
        .expect("restore with empty passphrase");
    assert_eq!(
        restored.public_spki_der().expect("restored spki"),
        &spki[..],
        "empty-passphrase restore yields the same public key"
    );
    let msg = b"DSM-BIND-v1\x00 empty-auth roundtrip";
    let sig_der = restored.sign(msg).expect("empty-auth restored key signs");
    vk.verify(msg, &Signature::from_der(&sig_der).expect("parse sig"))
        .expect("empty-auth restored signature must verify");
}
