use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use crate::secure_memory::LockedKey32;

/// Opaque AES-256-GCM key handle. Key bytes never cross FFI boundary.
/// The key lives at a stable heap address via `LockedKey32` — mlock'd and
/// zeroized on drop, resilient to ownership moves.
pub struct AesKey {
    key: LockedKey32,
}

impl AesKey {
    /// Build an `AesKey` from a pre-allocated locked heap buffer. Preferred
    /// when the caller can write key material directly into the heap
    /// (e.g. via HKDF expand into `LockedKey32::zeroed().as_mut()`).
    pub fn from_locked(key: LockedKey32) -> Result<Self, String> {
        Ok(Self { key })
    }

    /// Convenience constructor: accepts a 32-byte array by value. Incurs
    /// a transient stack copy of the key before it reaches the heap — use
    /// `from_locked` to avoid that where possible.
    pub fn from_array(key_bytes: [u8; 32]) -> Result<Self, String> {
        Ok(Self { key: LockedKey32::from_array(key_bytes)? })
    }

    /// Initialize cipher from the stored key.
    fn cipher(&self) -> Result<Aes256Gcm, String> {
        Aes256Gcm::new_from_slice(self.key.as_array()).map_err(|e| format!("cipher: {e}"))
    }

    /// Encrypt plaintext with the given 96-bit nonce and additional authenticated data.
    /// Returns ciphertext || 16-byte GCM tag.
    pub fn encrypt(&self, nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
        self.cipher()?
            .encrypt(
                Nonce::from_slice(nonce),
                aes_gcm::aead::Payload { msg: plaintext, aad },
            )
            .map_err(|e| format!("encrypt: {e}"))
    }

    /// Decrypt ciphertext (with appended GCM tag) using the given nonce and AAD.
    /// Returns plaintext, or error if authentication fails.
    pub fn decrypt(&self, nonce: &[u8; 12], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
        self.cipher()?
            .decrypt(
                Nonce::from_slice(nonce),
                aes_gcm::aead::Payload { msg: ciphertext, aad },
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
        AesKey::from_locked(locked).unwrap()
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
