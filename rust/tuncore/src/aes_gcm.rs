use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use crate::secure_memory::{mlock_slice, munlock_slice};
use zeroize::Zeroizing;

/// Opaque AES-256-GCM key handle. Key bytes never cross FFI boundary.
/// mlock'd in memory, zeroized on drop.
pub struct AesKey {
    key: Zeroizing<[u8; 32]>,
    locked: bool,
}

impl AesKey {
    /// Create a new AES key from raw bytes and lock it in memory.
    pub fn new(key_bytes: [u8; 32]) -> Result<Self, String> {
        let key = Zeroizing::new(key_bytes);
        mlock_slice(key.as_ref())?;
        Ok(Self { key, locked: true })
    }

    /// Initialize cipher from the stored key.
    fn cipher(&self) -> Result<Aes256Gcm, String> {
        Aes256Gcm::new_from_slice(self.key.as_ref()).map_err(|e| format!("cipher: {e}"))
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

    /// Raw key bytes for internal crypto operations (e.g. session key derivation).
    /// Must never cross the FFI boundary.
    /// Currently unused — will be needed when session key rotation is integrated.
    #[allow(dead_code)]
    pub(crate) fn raw(&self) -> &[u8; 32] {
        &self.key
    }
}

impl Drop for AesKey {
    fn drop(&mut self) {
        if self.locked {
            let _ = munlock_slice(self.key.as_ref());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> AesKey {
        let mut bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
        AesKey::new(bytes).unwrap()
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
