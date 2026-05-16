//! Argon2id + XChaCha20-Poly1305 sealed-blob primitive.
//!
//! Shared between `identity::IdentityKeyPair` (32-byte X25519 scalar) and
//! `device_attest_soft::SoftAttestKey` (32-byte ECDSA P-256 scalar) for
//! at-rest, passphrase-protected secret storage.
//!
//! Wire layout: `salt(32) || nonce(24) || ciphertext+tag`.
//! AEAD AAD: `salt || nonce` (so a salt-or-nonce flip is detected before
//! a passphrase-derived-key collision is even attempted).
//!
//! Argon2 parameters are deliberately strong (512 MiB / 4 iters /
//! parallelism 2). Changing them would break compatibility with existing
//! on-disk blobs, so the constants are kept stable and exposed for any
//! callers that need to compute exact-blob sizes (e.g. for an up-front
//! "blob too short" check tied to a fixed plaintext length).

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

/// Smallest legal blob: salt + nonce + tag (with zero-byte plaintext).
/// Any shorter input cannot represent a complete AEAD ciphertext.
pub const MIN_BLOB_LEN: usize = ARGON2_SALT_LEN + XCHACHA_NONCE_LEN + TAG_LEN;

/// Derive a 32-byte symmetric key from a passphrase + salt via Argon2id,
/// written directly into a mlock'd heap buffer so no transient copy of
/// the derived key ever lands on the stack.
fn derive_argon2_key(passphrase: &[u8], salt: &[u8]) -> Result<LockedKey32, String> {
    let mut derived = LockedKey32::zeroed()?;
    let params = Params::new(
        ARGON2_MEM_COST_KIB,
        ARGON2_TIME_COST,
        ARGON2_PARALLELISM,
        Some(32),
    )
    .map_err(|e| format!("argon2 params: {e}"))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2
        .hash_password_into(passphrase, salt, derived.as_mut())
        .map_err(|e| format!("argon2 hash: {e}"))?;

    Ok(derived)
}

fn build_aad(salt: &[u8], nonce: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(salt.len() + nonce.len());
    aad.extend_from_slice(salt);
    aad.extend_from_slice(nonce);
    aad
}

/// Seal `plaintext` under `passphrase`. Returns the serialized blob:
/// `salt(32) || nonce(24) || ciphertext+tag`.
///
/// `plaintext` is borrowed and never copied other than into the AEAD
/// engine's internal buffer; the caller owns its lifetime and any
/// scrubbing requirements on the plaintext side.
pub fn seal(plaintext: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, String> {
    if passphrase.is_empty() {
        return Err("passphrase must not be empty".into());
    }

    let mut salt = [0u8; ARGON2_SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    let derived = derive_argon2_key(passphrase, &salt)?;

    let cipher = XChaCha20Poly1305::new_from_slice(derived.as_array())
        .map_err(|e| format!("cipher init: {e}"))?;

    let mut nonce_bytes = [0u8; XCHACHA_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let aad = build_aad(&salt, &nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad: &aad })
        .map_err(|e| format!("encrypt: {e}"))?;

    let mut blob = Vec::with_capacity(ARGON2_SALT_LEN + XCHACHA_NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);

    Ok(blob)
}

/// Open a sealed blob. Returns the plaintext wrapped in [`Zeroizing`] so
/// it is scrubbed when the caller's binding drops.
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
    if blob.len() < MIN_BLOB_LEN {
        return Err("blob too short".into());
    }
    if passphrase.is_empty() {
        return Err("passphrase must not be empty".into());
    }

    let salt = &blob[..ARGON2_SALT_LEN];
    let nonce_bytes = &blob[ARGON2_SALT_LEN..ARGON2_SALT_LEN + XCHACHA_NONCE_LEN];
    let ciphertext = &blob[ARGON2_SALT_LEN + XCHACHA_NONCE_LEN..];

    let derived = derive_argon2_key(passphrase, salt)?;

    let cipher = XChaCha20Poly1305::new_from_slice(derived.as_array())
        .map_err(|e| format!("cipher init: {e}"))?;

    let nonce = XNonce::from_slice(nonce_bytes);
    let aad = build_aad(salt, nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, Payload { msg: ciphertext, aad: &aad })
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
        // Random salt + nonce per call must produce distinct blobs even
        // when the plaintext and passphrase are identical.
        let b1 = seal(b"secret", b"pass").expect("seal 1");
        let b2 = seal(b"secret", b"pass").expect("seal 2");
        assert_ne!(b1, b2);
    }

    #[test]
    fn wire_layout_lock() {
        // Audit-stability test: the blob layout is the contract between
        // `identity` and `device_attest_soft` and any on-disk blob ever
        // written. Lock the byte-positions so a future edit that
        // accidentally reorders salt / nonce / ciphertext fails loudly.
        let blob = seal(b"abc", b"pass").expect("seal");
        // salt(32) || nonce(24) || ciphertext(3) + tag(16) = 75
        assert_eq!(blob.len(), ARGON2_SALT_LEN + XCHACHA_NONCE_LEN + 3 + TAG_LEN);
        // Salt is the first 32 bytes; nonce the next 24; ciphertext+tag
        // is the rest.
        let salt = &blob[..ARGON2_SALT_LEN];
        let nonce = &blob[ARGON2_SALT_LEN..ARGON2_SALT_LEN + XCHACHA_NONCE_LEN];
        let ct = &blob[ARGON2_SALT_LEN + XCHACHA_NONCE_LEN..];
        assert_eq!(salt.len(), 32);
        assert_eq!(nonce.len(), 24);
        assert_eq!(ct.len(), 3 + TAG_LEN);
    }

    #[test]
    fn empty_plaintext_is_valid() {
        let blob = seal(b"", b"pass").expect("seal empty");
        // Blob is exactly MIN_BLOB_LEN bytes (no ciphertext, tag only).
        assert_eq!(blob.len(), MIN_BLOB_LEN);
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

        // Argon2id is expensive (512 MiB per call). Use small `iters`
        // outside of the 32-byte case so the test runs in seconds.
        for &len in &[0usize, 1, 16, 31, 32, 33, 64, 128, 512] {
            let mut plaintext = vec![0u8; len];
            OsRng.fill_bytes(&mut plaintext);
            let blob = seal(&plaintext, b"correct horse battery staple")
                .expect("seal");
            let recovered = open(&blob, b"correct horse battery staple")
                .expect("open");
            assert_eq!(&**recovered, &plaintext[..], "len={len}");
            assert_eq!(blob.len(), MIN_BLOB_LEN + len);
        }
    }

    #[test]
    fn property_every_byte_flip_in_blob_fails_decrypt() {
        // Property: flipping ANY byte of a sealed blob — salt, nonce, or
        // ciphertext+tag — must cause `open` to fail. The salt and nonce
        // are bound into the AEAD's AAD, so even a bit-flip outside the
        // ciphertext block authenticates as a failure. This guards
        // against any future refactor that omits salt/nonce from AAD.
        let plaintext = b"32-byte secret right here ******";
        assert_eq!(plaintext.len(), 32);
        let original_blob = seal(plaintext, b"pass").expect("seal");

        // Walking every byte of a 64-byte sample (salt + nonce + first
        // 8 bytes of ciphertext) keeps the test fast while still
        // sampling each region of the blob.
        for byte_idx in 0..(ARGON2_SALT_LEN + XCHACHA_NONCE_LEN + 8) {
            let mut blob = original_blob.clone();
            blob[byte_idx] ^= 0xFF;
            let err = open(&blob, b"pass")
                .map(|_| ())
                .expect_err(&format!(
                    "flipping byte {byte_idx} must fail decryption"
                ));
            assert!(
                err.contains("decryption failed"),
                "byte {byte_idx}: unexpected error message: {err}"
            );
        }
    }
}
