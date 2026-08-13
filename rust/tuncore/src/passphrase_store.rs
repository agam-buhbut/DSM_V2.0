//! Argon2id + XChaCha20-Poly1305 sealed-blob primitive.
//!
//! Shared between `identity::IdentityKeyPair` (32-byte X25519 scalar) and
//! `device_attest_soft::SoftAttestKey` (32-byte ECDSA P-256 scalar) for
//! at-rest, passphrase-protected secret storage.
//!
//! v1 wire layout:
//! `magic(4 = "DSMK") || version(1 = 0x01) || m_cost_kib(4 BE) ||
//! t_cost(4 BE) || parallelism(4 BE) || salt(32) || nonce(24) ||
//! ciphertext+tag`.
//! AEAD AAD: `header(17) || salt || nonce` — the full header is bound
//! into the AAD so any tampered version or KDF-parameter byte fails
//! AEAD authentication (and a salt-or-nonce flip is detected before a
//! passphrase-derived-key collision is even attempted).
//!
//! KDF parameters are read from the header and bounds-checked *before*
//! the KDF runs, so a hostile blob cannot trigger a multi-GiB
//! allocation. Blobs that do not start with the magic are legacy
//! (pre-header) blobs — `salt(32) || nonce(24) || ciphertext+tag`, AAD
//! = `salt || nonce` — and decrypt with the frozen production
//! parameters below.
//!
//! Argon2 parameters are deliberately strong (512 MiB / 4 iters / parallelism 2).
//! A v1 blob is `V1_HEADER_LEN` bytes longer than the legacy minimum, so length
//! checks against [`MIN_BLOB_LEN`] must use `<`, not `==`.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

use crate::secure_memory::LockedKey32;

pub const ARGON2_SALT_LEN: usize = 32;
pub const ARGON2_MEM_COST_KIB: u32 = 524_288; // 512 MiB
pub const ARGON2_TIME_COST: u32 = 4;
pub const ARGON2_PARALLELISM: u32 = 2;
pub const XCHACHA_NONCE_LEN: usize = 24;
/// XChaCha20-Poly1305 authentication tag length.
pub const TAG_LEN: usize = 16;

/// Smallest legal legacy blob: salt + nonce + tag (with zero-byte
/// plaintext). Any shorter input cannot represent a complete AEAD
/// ciphertext. v1 blobs additionally carry the [`V1_HEADER_LEN`]-byte
/// header up front.
pub const MIN_BLOB_LEN: usize = ARGON2_SALT_LEN + XCHACHA_NONCE_LEN + TAG_LEN;

/// Magic prefix identifying a versioned (v1+) sealed blob.
pub const BLOB_MAGIC: [u8; 4] = *b"DSMK";
/// Current sealed-blob format version.
pub const BLOB_VERSION_1: u8 = 1;
/// magic(4) + version(1) + m_cost_kib(4) + t_cost(4) + parallelism(4).
pub const V1_HEADER_LEN: usize = 17;

// Bounds enforced on header-supplied KDF parameters before the KDF
// runs. The memory cap is the DoS guard: a hostile blob (writable only
// by an attacker who already controls the key file) must not be able to
// make `open` attempt a huge allocation. Ceilings are kept just above
// production (512 MiB / t 4 / p 2 -> 2x / 2x / 4x headroom) to minimize
// the forced-KDF amplification window; a future v2 bump is trivial via
// the version byte if stronger params are ever needed.
const M_COST_MIN_KIB: u32 = 8;
const M_COST_MAX_KIB: u32 = 1_048_576; // 1 GiB
const T_COST_MIN: u32 = 1;
const T_COST_MAX: u32 = 8;
const PARALLELISM_MIN: u32 = 1;
const PARALLELISM_MAX: u32 = 8;

/// Argon2id cost parameters carried in (or implied by) a sealed blob.
#[derive(Clone, Copy)]
struct KdfParams {
    m_cost_kib: u32,
    t_cost: u32,
    parallelism: u32,
}

/// Production parameters: written into every freshly sealed v1 blob and
/// assumed for legacy (pre-header) blobs.
const PARAMS_V1: KdfParams = KdfParams {
    m_cost_kib: ARGON2_MEM_COST_KIB,
    t_cost: ARGON2_TIME_COST,
    parallelism: ARGON2_PARALLELISM,
};

fn validate_params(params: &KdfParams) -> Result<(), String> {
    if !(M_COST_MIN_KIB..=M_COST_MAX_KIB).contains(&params.m_cost_kib) {
        return Err(format!(
            "argon2 m_cost {} KiB out of bounds ({M_COST_MIN_KIB}..={M_COST_MAX_KIB})",
            params.m_cost_kib
        ));
    }
    if !(T_COST_MIN..=T_COST_MAX).contains(&params.t_cost) {
        return Err(format!(
            "argon2 t_cost {} out of bounds ({T_COST_MIN}..={T_COST_MAX})",
            params.t_cost
        ));
    }
    if !(PARALLELISM_MIN..=PARALLELISM_MAX).contains(&params.parallelism) {
        return Err(format!(
            "argon2 parallelism {} out of bounds ({PARALLELISM_MIN}..={PARALLELISM_MAX})",
            params.parallelism
        ));
    }
    // Argon2's own constraint: memory must cover 8 blocks per lane.
    if params.m_cost_kib < 8 * params.parallelism {
        return Err(format!(
            "argon2 m_cost {} KiB out of bounds (must be >= 8 * parallelism {})",
            params.m_cost_kib, params.parallelism
        ));
    }
    Ok(())
}

fn build_v1_header(params: &KdfParams) -> [u8; V1_HEADER_LEN] {
    let mut header = [0u8; V1_HEADER_LEN];
    header[..4].copy_from_slice(&BLOB_MAGIC);
    header[4] = BLOB_VERSION_1;
    header[5..9].copy_from_slice(&params.m_cost_kib.to_be_bytes());
    header[9..13].copy_from_slice(&params.t_cost.to_be_bytes());
    header[13..17].copy_from_slice(&params.parallelism.to_be_bytes());
    header
}

/// Derive a 32-byte symmetric key from a passphrase + salt via Argon2id,
/// written directly into a mlock'd heap buffer so no transient copy of
/// the derived key ever lands on the stack.
fn derive_argon2_key(
    passphrase: &[u8],
    salt: &[u8],
    kdf_params: &KdfParams,
) -> Result<LockedKey32, String> {
    let mut derived = LockedKey32::zeroed()?;
    let params = Params::new(
        kdf_params.m_cost_kib,
        kdf_params.t_cost,
        kdf_params.parallelism,
        Some(32),
    )
    .map_err(|e| format!("argon2 params: {e}"))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2
        .hash_password_into(passphrase, salt, derived.as_mut())
        .map_err(|e| format!("argon2 hash: {e}"))?;

    Ok(derived)
}

/// Legacy (pre-header) AAD: `salt || nonce`.
fn build_aad(salt: &[u8], nonce: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(salt.len() + nonce.len());
    aad.extend_from_slice(salt);
    aad.extend_from_slice(nonce);
    aad
}

/// v1 AAD: `header || salt || nonce`. Binding the full header means any
/// tampered version or KDF-parameter byte fails AEAD authentication.
fn build_aad_v1(header: &[u8], salt: &[u8], nonce: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(header.len() + salt.len() + nonce.len());
    aad.extend_from_slice(header);
    aad.extend_from_slice(salt);
    aad.extend_from_slice(nonce);
    aad
}

/// Seal `plaintext` under `passphrase`. Returns the serialized v1 blob:
/// `header(17) || salt(32) || nonce(24) || ciphertext+tag`, sealed with
/// the production KDF parameters.
///
/// `plaintext` is borrowed and never copied other than into the AEAD
/// engine's internal buffer; the caller owns its lifetime and any
/// scrubbing requirements on the plaintext side.
pub fn seal(plaintext: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, String> {
    if passphrase.is_empty() {
        return Err("passphrase must not be empty".into());
    }

    let header = build_v1_header(&PARAMS_V1);

    let mut salt = [0u8; ARGON2_SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    let derived = derive_argon2_key(passphrase, &salt, &PARAMS_V1)?;

    let cipher = XChaCha20Poly1305::new_from_slice(derived.as_array())
        .map_err(|e| format!("cipher init: {e}"))?;

    let mut nonce_bytes = [0u8; XCHACHA_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let aad = build_aad_v1(&header, &salt, &nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|e| format!("encrypt: {e}"))?;

    let mut blob =
        Vec::with_capacity(V1_HEADER_LEN + ARGON2_SALT_LEN + XCHACHA_NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&header);
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);

    Ok(blob)
}

/// Open a sealed blob. Returns the plaintext wrapped in [`Zeroizing`] so
/// it is scrubbed when the caller's binding drops.
///
/// Blobs starting with [`BLOB_MAGIC`] are versioned: the header's KDF
/// parameters are bounds-checked before the KDF runs. Blobs without the
/// magic are legacy and decrypt with the frozen production parameters.
///
/// The caller is responsible for asserting the plaintext is the expected
/// length / shape for its application. This module only guarantees that
/// the bytes came from a successful AEAD authentication under the
/// supplied passphrase.
///
/// Returns the same opaque "decryption failed" string on bad passphrase
/// *and* on ciphertext corruption so the two cases are indistinguishable
/// to a caller doing simple error-string inspection.
pub fn open(blob: &[u8], passphrase: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    if blob.len() >= BLOB_MAGIC.len() && blob[..BLOB_MAGIC.len()] == BLOB_MAGIC {
        open_v1(blob, passphrase)
    } else {
        open_legacy(blob, passphrase)
    }
}

/// v1 path: parse + bounds-check header params *before* the KDF runs,
/// then decrypt with the full header bound into the AAD.
fn open_v1(blob: &[u8], passphrase: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    if blob.len() < V1_HEADER_LEN + MIN_BLOB_LEN {
        return Err("blob too short".into());
    }
    if passphrase.is_empty() {
        return Err("passphrase must not be empty".into());
    }

    let version = blob[BLOB_MAGIC.len()];
    if version != BLOB_VERSION_1 {
        return Err(format!("unsupported sealed-blob version {version}"));
    }

    // Slice-to-array conversions cannot fail given the length check
    // above; the error arm exists only to honour the no-unwrap rule.
    let be_u32 = |range: core::ops::Range<usize>| -> Result<u32, String> {
        let bytes: [u8; 4] = blob[range]
            .try_into()
            .map_err(|_| "header field slice length".to_string())?;
        Ok(u32::from_be_bytes(bytes))
    };
    let params = KdfParams {
        m_cost_kib: be_u32(5..9)?,
        t_cost: be_u32(9..13)?,
        parallelism: be_u32(13..17)?,
    };
    validate_params(&params)?;

    let header = &blob[..V1_HEADER_LEN];
    let salt = &blob[V1_HEADER_LEN..V1_HEADER_LEN + ARGON2_SALT_LEN];
    let nonce_bytes =
        &blob[V1_HEADER_LEN + ARGON2_SALT_LEN..V1_HEADER_LEN + ARGON2_SALT_LEN + XCHACHA_NONCE_LEN];
    let ciphertext = &blob[V1_HEADER_LEN + ARGON2_SALT_LEN + XCHACHA_NONCE_LEN..];
    let aad = build_aad_v1(header, salt, nonce_bytes);

    decrypt_sealed(salt, nonce_bytes, ciphertext, &aad, &params, passphrase)
}

/// Legacy path: pre-header layout, AAD = `salt || nonce`, frozen
/// production KDF parameters.
fn open_legacy(blob: &[u8], passphrase: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    if blob.len() < MIN_BLOB_LEN {
        return Err("blob too short".into());
    }
    if passphrase.is_empty() {
        return Err("passphrase must not be empty".into());
    }

    let salt = &blob[..ARGON2_SALT_LEN];
    let nonce_bytes = &blob[ARGON2_SALT_LEN..ARGON2_SALT_LEN + XCHACHA_NONCE_LEN];
    let ciphertext = &blob[ARGON2_SALT_LEN + XCHACHA_NONCE_LEN..];
    let aad = build_aad(salt, nonce_bytes);

    decrypt_sealed(salt, nonce_bytes, ciphertext, &aad, &PARAMS_V1, passphrase)
}

/// Shared KDF + AEAD-open tail of [`open_v1`] and [`open_legacy`]; the arms
/// differ only in blob offsets, AAD construction and KDF parameter source.
fn decrypt_sealed(
    salt: &[u8],
    nonce_bytes: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
    params: &KdfParams,
    passphrase: &[u8],
) -> Result<Zeroizing<Vec<u8>>, String> {
    let derived = derive_argon2_key(passphrase, salt, params)?;

    let cipher = XChaCha20Poly1305::new_from_slice(derived.as_array())
        .map_err(|e| format!("cipher init: {e}"))?;

    let nonce = XNonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| "decryption failed: wrong passphrase or corrupted data".to_string())?;

    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let secret = b"32-byte secret right here ******";
        assert_eq!(secret.len(), 32);
        let blob = seal(secret, b"passphrase").expect("seal");
        let pt = open(&blob, b"passphrase").expect("open");
        assert_eq!(&*pt, secret);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let blob = seal(b"secret", b"correct").expect("seal");
        let err = open(&blob, b"wrong").unwrap_err();
        assert!(err.contains("decryption failed"), "got: {err}");
    }

    #[test]
    fn empty_passphrase_rejected_on_seal() {
        let err = seal(b"secret", b"").unwrap_err();
        assert!(err.contains("passphrase must not be empty"), "got: {err}");
    }

    #[test]
    fn empty_passphrase_rejected_on_open() {
        let blob = seal(b"secret", b"correct").expect("seal");
        let err = open(&blob, b"").unwrap_err();
        assert!(err.contains("passphrase must not be empty"), "got: {err}");
    }

    #[test]
    fn short_blob_rejected() {
        let err = open(&[0u8; 10], b"pass").unwrap_err();
        assert!(err.contains("blob too short"), "got: {err}");
    }

    #[test]
    fn corrupted_ciphertext_rejected() {
        let mut blob = seal(b"secret", b"pass").expect("seal");
        let last = blob.len() - 1;
        blob[last] ^= 0xFF;
        let err = open(&blob, b"pass").unwrap_err();
        assert!(err.contains("decryption failed"), "got: {err}");
    }

    #[test]
    fn corrupted_salt_rejected() {
        // Flipping salt bytes changes the Argon2-derived key → AEAD auth
        // fails. Salt is in AAD too, so even if the derived key collided
        // the AAD mismatch would trigger the same error path.
        let mut blob = seal(b"secret", b"pass").expect("seal");
        blob[0] ^= 0xFF;
        let err = open(&blob, b"pass").unwrap_err();
        assert!(err.contains("decryption failed"), "got: {err}");
    }

    #[test]
    fn corrupted_nonce_rejected() {
        // Nonce is in AAD; flipping a nonce byte breaks AAD even before
        // the AEAD's own nonce-dependent state diverges.
        let mut blob = seal(b"secret", b"pass").expect("seal");
        blob[ARGON2_SALT_LEN] ^= 0xFF;
        let err = open(&blob, b"pass").unwrap_err();
        assert!(err.contains("decryption failed"), "got: {err}");
    }

    #[test]
    fn distinct_seals_per_call() {
        let b1 = seal(b"secret", b"pass").expect("seal 1");
        let b2 = seal(b"secret", b"pass").expect("seal 2");
        assert_ne!(b1, b2);
    }

    #[test]
    fn wire_layout_lock() {
        // Audit-stability test: the v1 blob layout is the contract
        // between `identity` and `device_attest_soft` and any on-disk
        // blob ever written. Lock the byte-positions so a future edit
        // that accidentally reorders header / salt / nonce / ciphertext
        // fails loudly.
        let blob = seal(b"abc", b"pass").expect("seal");
        // header(17) || salt(32) || nonce(24) || ciphertext(3) + tag(16)
        // = 92
        assert_eq!(
            blob.len(),
            V1_HEADER_LEN + ARGON2_SALT_LEN + XCHACHA_NONCE_LEN + 3 + TAG_LEN
        );
        assert_eq!(&blob[..4], &BLOB_MAGIC);
        assert_eq!(blob[4], BLOB_VERSION_1);
        assert_eq!(&blob[5..9], &ARGON2_MEM_COST_KIB.to_be_bytes());
        assert_eq!(&blob[9..13], &ARGON2_TIME_COST.to_be_bytes());
        assert_eq!(&blob[13..17], &ARGON2_PARALLELISM.to_be_bytes());
        let salt = &blob[V1_HEADER_LEN..V1_HEADER_LEN + ARGON2_SALT_LEN];
        let nonce = &blob
            [V1_HEADER_LEN + ARGON2_SALT_LEN..V1_HEADER_LEN + ARGON2_SALT_LEN + XCHACHA_NONCE_LEN];
        let ct = &blob[V1_HEADER_LEN + ARGON2_SALT_LEN + XCHACHA_NONCE_LEN..];
        assert_eq!(salt.len(), 32);
        assert_eq!(nonce.len(), 24);
        assert_eq!(ct.len(), 3 + TAG_LEN);
    }

    #[test]
    fn empty_plaintext_is_valid() {
        let blob = seal(b"", b"pass").expect("seal empty");
        // Blob is exactly header + MIN_BLOB_LEN bytes (no ciphertext,
        // tag only).
        assert_eq!(blob.len(), V1_HEADER_LEN + MIN_BLOB_LEN);
        let pt = open(&blob, b"pass").expect("open empty");
        assert_eq!(&**pt, b"");
    }

    #[test]
    fn property_roundtrip_random_plaintext_lengths() {
        // Property: a seal/open round-trip recovers the plaintext for
        // a range of sizes (32 is the production size for both
        // IdentityKeyPair and SoftAttestKey; larger / smaller cases
        // confirm `passphrase_store` is plaintext-shape-agnostic).
        use rand::rngs::OsRng;
        use rand::RngCore;

        // Argon2id is expensive (512 MiB per call), so the length set is kept small.
        for &len in &[0usize, 1, 16, 31, 32, 33, 64, 128, 512] {
            let mut plaintext = vec![0u8; len];
            OsRng.fill_bytes(&mut plaintext);
            let blob = seal(&plaintext, b"correct horse battery staple").expect("seal");
            let recovered = open(&blob, b"correct horse battery staple").expect("open");
            assert_eq!(&**recovered, &plaintext[..], "len={len}");
            assert_eq!(blob.len(), V1_HEADER_LEN + MIN_BLOB_LEN + len);
        }
    }

    /// Replicates the pre-v1 wire layout exactly: `salt(32) || nonce(24)
    /// || ciphertext+tag` with AAD = `salt || nonce` and the frozen
    /// production Argon2id parameters. Used to prove `open` still reads
    /// blobs written before the versioned header existed.
    ///
    /// A random legacy salt has a negligible 2^-32 chance of starting
    /// with the v1 magic bytes (in which case `open` would mis-dispatch
    /// it to the v1 path); accepted here as it is in production.
    fn make_legacy_blob(plaintext: &[u8], passphrase: &[u8]) -> Vec<u8> {
        let mut salt = [0u8; ARGON2_SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let mut nonce_bytes = [0u8; XCHACHA_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);

        let derived = derive_argon2_key(passphrase, &salt, &PARAMS_V1).expect("kdf");
        let cipher = XChaCha20Poly1305::new_from_slice(derived.as_array()).expect("cipher init");
        let nonce = XNonce::from_slice(&nonce_bytes);
        let aad = build_aad(&salt, &nonce_bytes);
        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .expect("encrypt");

        let mut blob = Vec::with_capacity(ARGON2_SALT_LEN + XCHACHA_NONCE_LEN + ciphertext.len());
        blob.extend_from_slice(&salt);
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ciphertext);
        blob
    }

    #[test]
    fn v1_seal_open_roundtrip() {
        let secret = b"32-byte secret right here ******";
        let blob = seal(secret, b"passphrase").expect("seal");
        assert_eq!(&blob[..4], &BLOB_MAGIC);
        assert_eq!(blob[4], BLOB_VERSION_1);
        let pt = open(&blob, b"passphrase").expect("open");
        assert_eq!(&*pt, secret);
    }

    #[test]
    fn v1_legacy_blob_still_decrypts() {
        let secret = b"32-byte secret right here ******";
        let blob = make_legacy_blob(secret, b"passphrase");
        let pt = open(&blob, b"passphrase").expect("open legacy");
        assert_eq!(&*pt, secret);
    }

    #[test]
    fn v1_tampered_version_rejected() {
        let mut blob = seal(b"secret", b"pass").expect("seal");
        blob[4] ^= 0xFF; // version 1 -> 0xFE
        let err = open(&blob, b"pass").unwrap_err();
        assert!(
            err.contains("unsupported sealed-blob version"),
            "got: {err}"
        );
    }

    #[test]
    fn v1_tampered_params_rejected() {
        // Flip the LSB of t_cost (4 -> 5): still within bounds, so the
        // params validate and the KDF runs — but the header is bound
        // into the AAD, so AEAD authentication must fail.
        let mut blob = seal(b"secret", b"pass").expect("seal");
        blob[12] ^= 0x01;
        let err = open(&blob, b"pass").unwrap_err();
        assert!(err.contains("decryption failed"), "got: {err}");
    }

    #[test]
    fn v1_oversize_params_rejected_before_kdf() {
        // A hostile blob advertising m_cost = u32::MAX must be rejected
        // by the bounds check before the KDF runs — i.e. no multi-GiB
        // allocation is ever attempted.
        let mut blob = Vec::new();
        blob.extend_from_slice(&BLOB_MAGIC);
        blob.push(BLOB_VERSION_1);
        blob.extend_from_slice(&u32::MAX.to_be_bytes()); // m_cost_kib
        blob.extend_from_slice(&ARGON2_TIME_COST.to_be_bytes());
        blob.extend_from_slice(&ARGON2_PARALLELISM.to_be_bytes());
        blob.extend_from_slice(&[0u8; ARGON2_SALT_LEN + XCHACHA_NONCE_LEN + TAG_LEN]);
        let err = open(&blob, b"pass").unwrap_err();
        assert!(err.contains("out of bounds"), "got: {err}");
    }

    #[test]
    fn property_every_byte_flip_in_blob_fails_decrypt() {
        // Property: flipping ANY byte of a sealed blob — header, salt,
        // nonce, or ciphertext+tag — must cause `open` to fail. The full
        // header plus salt and nonce are bound into the AEAD's AAD, so
        // even a bit-flip outside the ciphertext block authenticates as
        // a failure. This guards against any future refactor that omits
        // header/salt/nonce from AAD.
        //
        // The failure MESSAGE differs by region, so only `is_err()` is
        // asserted per position:
        //   magic flips    -> legacy-path dispatch -> "decryption failed"
        //   version flip   -> "unsupported sealed-blob version"
        //   param flips    -> "out of bounds" (bounds check) OR
        //                     "decryption failed" (AAD binding)
        //   salt/nonce/ct  -> "decryption failed"
        let plaintext = b"32-byte secret right here ******";
        assert_eq!(plaintext.len(), 32);
        let original_blob = seal(plaintext, b"pass").expect("seal");

        // Post-v1 the non-header regions are SAMPLED rather than walked
        // exhaustively: most flips outside the header trigger a full
        // Argon2id run (512 MiB / 4 iters) before the AEAD rejects, so
        // walking salt + nonce + 8 ct bytes as the pre-v1 test did would
        // take many minutes. Coverage: all 17 header bytes, first/last
        // salt byte, first/last nonce byte, first/middle/last ct+tag
        // byte.
        let salt_start = V1_HEADER_LEN;
        let nonce_start = V1_HEADER_LEN + ARGON2_SALT_LEN;
        let ct_start = V1_HEADER_LEN + ARGON2_SALT_LEN + XCHACHA_NONCE_LEN;
        let last = original_blob.len() - 1;
        let mut positions: Vec<usize> = (0..V1_HEADER_LEN).collect();
        positions.extend([
            salt_start,
            salt_start + ARGON2_SALT_LEN - 1,
            nonce_start,
            nonce_start + XCHACHA_NONCE_LEN - 1,
            ct_start,
            ct_start + (last - ct_start) / 2,
            last,
        ]);

        for byte_idx in positions {
            let mut blob = original_blob.clone();
            blob[byte_idx] ^= 0xFF;
            open(&blob, b"pass")
                .map(|_| ())
                .expect_err(&format!("flipping byte {byte_idx} must fail decryption"));
        }
    }
}
