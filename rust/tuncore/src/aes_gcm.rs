use crate::secure_memory::LockedKey32;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};

/// Opaque AES-256-GCM key handle. Key bytes never cross FFI boundary.
///
/// Holds BOTH the raw key in mlock'd, zeroize-on-drop `LockedKey32` AND
/// the pre-expanded `Aes256Gcm` cipher (the AES-256 round-key schedule
/// + GHASH H precomputation). The expansion runs once in `from_locked`
///   rather than per-call — caching cut a measured 2-3x throughput hit on
///   the data path where every packet was paying the schedule cost.
///
/// Security note: the cached `Aes256Gcm` holds ~240 bytes of derived
/// round-key state on the regular (non-mlock'd) heap. The aes-gcm
/// `zeroize` feature is enabled in `Cargo.toml`, so `Aes256Gcm` runs
/// `ZeroizeOnDrop` and the round-key buffer is wiped when this struct
/// drops — preserving the wipe-on-drop guarantee for the lifetime of
/// the `AesKey`. The cache is still on regular heap (not mlock'd), so
/// it CAN be swapped to disk under memory pressure; this is mitigated
/// by the process-wide `disable_core_dumps` + `PR_SET_DUMPABLE=0` hardening
/// applied at startup.
pub struct AesKey {
    cipher: Aes256Gcm,
    // _key kept around so the LockedKey32's munlock + zeroize on Drop
    // runs after `cipher` is dropped (Rust drops fields in declaration
    // order: `cipher` first, then `_key`).
    _key: LockedKey32,
}

impl AesKey {
    /// Build an `AesKey` from a pre-allocated locked heap buffer. Preferred
    /// when the caller can write key material directly into the heap
    /// (e.g. via HKDF expand into `LockedKey32::zeroed().as_mut()`).
    /// Infallible — kept as a method so the cipher invariant lives on the
    /// type.
    pub fn from_locked(key: LockedKey32) -> Self {
        // new_from_slice on a 32-byte slice cannot fail — Aes256Gcm
        // accepts exactly KeySize=32. Documented invariant of the
        // aes-gcm crate; calling unwrap is the idiomatic form for an
        // infallible-by-key-length construction.
        let cipher = Aes256Gcm::new_from_slice(key.as_array())
            .expect("Aes256Gcm::new_from_slice on 32-byte LockedKey32 is infallible");
        Self { cipher, _key: key }
    }

    /// Convenience constructor: accepts a 32-byte array by value. Incurs
    /// a transient stack copy of the key before it reaches the heap — use
    /// `from_locked` to avoid that where possible.
    pub fn from_array(key_bytes: [u8; 32]) -> Result<Self, String> {
        Ok(Self::from_locked(LockedKey32::from_array(key_bytes)?))
    }

    /// Encrypt plaintext with the given 96-bit nonce and additional authenticated data.
    /// Returns ciphertext || 16-byte GCM tag.
    pub fn encrypt(
        &self,
        nonce: &[u8; 12],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, String> {
        self.cipher
            .encrypt(
                Nonce::from_slice(nonce),
                aes_gcm::aead::Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|e| format!("encrypt: {e}"))
    }

    /// Decrypt ciphertext (with appended GCM tag) using the given nonce and AAD.
    /// Returns plaintext, or error if authentication fails.
    pub fn decrypt(
        &self,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, String> {
        self.cipher
            .decrypt(
                Nonce::from_slice(nonce),
                aes_gcm::aead::Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| "decryption failed: authentication tag mismatch".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> AesKey {
        use rand::rngs::OsRng;
        use rand::RngCore;
        let mut locked = LockedKey32::zeroed().unwrap();
        OsRng.fill_bytes(locked.as_mut());
        AesKey::from_locked(locked)
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = test_key();
        let nonce = [1u8; 12];
        let plaintext = b"hello, world";
        let aad = b"header-data";

        let ct = key.encrypt(&nonce, plaintext, aad).unwrap();
        let pt = key.decrypt(&nonce, &ct, aad).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_ciphertext_has_tag() {
        let key = test_key();
        let nonce = [2u8; 12];
        let ct = key.encrypt(&nonce, b"data", b"").unwrap();
        // ciphertext len = plaintext len + 16 byte tag
        assert_eq!(ct.len(), 4 + 16);
    }

    #[test]
    fn test_wrong_aad_fails() {
        let key = test_key();
        let nonce = [3u8; 12];
        let ct = key.encrypt(&nonce, b"data", b"correct").unwrap();
        assert!(key.decrypt(&nonce, &ct, b"wrong").is_err());
    }

    #[test]
    fn test_wrong_nonce_fails() {
        let key = test_key();
        let ct = key.encrypt(&[4u8; 12], b"data", b"").unwrap();
        assert!(key.decrypt(&[5u8; 12], &ct, b"").is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = test_key();
        let nonce = [6u8; 12];
        let mut ct = key.encrypt(&nonce, b"data", b"").unwrap();
        ct[0] ^= 0xFF;
        assert!(key.decrypt(&nonce, &ct, b"").is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        let key = test_key();
        let nonce = [7u8; 12];
        let ct = key.encrypt(&nonce, b"", b"aad").unwrap();
        assert_eq!(ct.len(), 16); // tag only
        let pt = key.decrypt(&nonce, &ct, b"aad").unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn test_different_keys_incompatible() {
        let k1 = test_key();
        let k2 = test_key();
        let nonce = [8u8; 12];
        let ct = k1.encrypt(&nonce, b"secret", b"").unwrap();
        assert!(k2.decrypt(&nonce, &ct, b"").is_err());
    }
}
