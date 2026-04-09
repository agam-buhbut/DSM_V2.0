use crate::secure_memory::{disable_core_dumps, mlock_slice, munlock_slice, secure_zero};
use argon2::{Argon2, Algorithm, Version, Params};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::rngs::OsRng;
use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

const ARGON2_SALT_LEN: usize = 32;
const ARGON2_MEM_COST_KIB: u32 = 524_288; // 512 MiB
const ARGON2_TIME_COST: u32 = 4;
const ARGON2_PARALLELISM: u32 = 2;
const XCHACHA_NONCE_LEN: usize = 24;

/// Derive an encryption key from a passphrase and salt using Argon2id.
fn derive_argon2_key(passphrase: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
    let mut derived = Zeroizing::new([0u8; 32]);
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

/// Build AAD for identity store encryption: salt || nonce.
fn build_store_aad(salt: &[u8], nonce: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(salt.len() + nonce.len());
    aad.extend_from_slice(salt);
    aad.extend_from_slice(nonce);
    aad
}

/// Static X25519 identity keypair for Noise XX handshake.
/// Private key is mlock'd and zeroized on drop.
pub struct IdentityKeyPair {
    secret: Zeroizing<[u8; 32]>,
    public: [u8; 32],
    locked: bool,
}

impl IdentityKeyPair {
    /// Generate a new random identity keypair.
    pub fn generate() -> Result<Self, String> {
        disable_core_dumps()?;

        let mut secret_bytes = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(secret_bytes.as_mut());

        mlock_slice(secret_bytes.as_ref())?;

        let secret = StaticSecret::from(*secret_bytes);
        let public = PublicKey::from(&secret);

        Ok(Self {
            secret: secret_bytes,
            public: *public.as_bytes(),
            locked: true,
        })
    }

    /// Reconstruct from raw secret bytes (e.g. after decryption from store).
    fn from_secret(secret_bytes: Zeroizing<[u8; 32]>) -> Result<Self, String> {
        disable_core_dumps()?;
        mlock_slice(secret_bytes.as_ref())?;

        let secret = StaticSecret::from(*secret_bytes);
        let public = PublicKey::from(&secret);
        let pub_bytes = *public.as_bytes();

        // Re-derive done; secret_bytes already holds the key
        Ok(Self {
            secret: secret_bytes,
            public: pub_bytes,
            locked: true,
        })
    }

    pub fn public_key(&self) -> &[u8; 32] {
        &self.public
    }

    /// Access the secret key bytes. Caller must not persist or copy.
    pub fn secret_key(&self) -> &[u8; 32] {
        &self.secret
    }

    /// Encrypt the keypair to a blob using a passphrase (Argon2id + XChaCha20-Poly1305).
    /// Format: salt(32) || nonce(24) || ciphertext+tag
    pub fn encrypt_to_store(&self, passphrase: &[u8]) -> Result<Vec<u8>, String> {
        if passphrase.is_empty() {
            return Err("passphrase must not be empty".into());
        }

        let mut salt = [0u8; ARGON2_SALT_LEN];
        OsRng.fill_bytes(&mut salt);

        let derived = derive_argon2_key(passphrase, &salt)?;

        let cipher = XChaCha20Poly1305::new_from_slice(derived.as_ref())
            .map_err(|e| format!("cipher init: {e}"))?;

        let mut nonce_bytes = [0u8; XCHACHA_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        let aad = build_store_aad(&salt, &nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, Payload { msg: self.secret.as_ref(), aad: &aad })
            .map_err(|e| format!("encrypt: {e}"))?;

        let mut blob = Vec::with_capacity(ARGON2_SALT_LEN + XCHACHA_NONCE_LEN + ciphertext.len());
        blob.extend_from_slice(&salt);
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ciphertext);

        Ok(blob)
    }

    /// Decrypt a keypair from a stored blob using a passphrase.
    pub fn decrypt_from_store(blob: &[u8], passphrase: &[u8]) -> Result<Self, String> {
        let min_len = ARGON2_SALT_LEN + XCHACHA_NONCE_LEN + 32 + 16; // key + tag
        if blob.len() < min_len {
            return Err("blob too short".into());
        }
        if passphrase.is_empty() {
            return Err("passphrase must not be empty".into());
        }

        let salt = &blob[..ARGON2_SALT_LEN];
        let nonce_bytes = &blob[ARGON2_SALT_LEN..ARGON2_SALT_LEN + XCHACHA_NONCE_LEN];
        let ciphertext = &blob[ARGON2_SALT_LEN + XCHACHA_NONCE_LEN..];

        let derived = derive_argon2_key(passphrase, salt)?;

        let cipher = XChaCha20Poly1305::new_from_slice(derived.as_ref())
            .map_err(|e| format!("cipher init: {e}"))?;

        let nonce = XNonce::from_slice(nonce_bytes);

        let aad = build_store_aad(salt, nonce_bytes);

        let plaintext = Zeroizing::new(
            cipher
                .decrypt(nonce, Payload { msg: ciphertext, aad: &aad })
                .map_err(|_| "decryption failed: wrong passphrase or corrupted data".to_string())?,
        );

        if plaintext.len() != 32 {
            return Err("decrypted key has wrong length".into());
        }

        let mut secret_bytes = Zeroizing::new([0u8; 32]);
        secret_bytes.copy_from_slice(&plaintext);

        Self::from_secret(secret_bytes)
    }
}

impl Drop for IdentityKeyPair {
    fn drop(&mut self) {
        if self.locked {
            let _ = munlock_slice(self.secret.as_ref());
        }
        // Zeroizing handles zeroing of self.secret
        secure_zero(&mut self.public);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let kp = IdentityKeyPair::generate().unwrap();
        assert_ne!(kp.public_key(), &[0u8; 32]);
        assert_ne!(kp.secret_key(), &[0u8; 32]);
    }

    #[test]
    fn test_public_key_derives_from_secret() {
        let kp = IdentityKeyPair::generate().unwrap();
        let secret = StaticSecret::from(*kp.secret_key());
        let expected_pub = PublicKey::from(&secret);
        assert_eq!(kp.public_key(), expected_pub.as_bytes());
    }

    #[test]
    fn test_encrypt_decrypt_store() {
        let kp = IdentityKeyPair::generate().unwrap();
        let passphrase = b"test-passphrase-123";

        let blob = kp.encrypt_to_store(passphrase).unwrap();
        let restored = IdentityKeyPair::decrypt_from_store(&blob, passphrase).unwrap();

        assert_eq!(kp.secret_key(), restored.secret_key());
        assert_eq!(kp.public_key(), restored.public_key());
    }

    #[test]
    fn test_wrong_passphrase_fails() {
        let kp = IdentityKeyPair::generate().unwrap();
        let blob = kp.encrypt_to_store(b"correct").unwrap();
        assert!(IdentityKeyPair::decrypt_from_store(&blob, b"wrong").is_err());
    }

    #[test]
    fn test_empty_passphrase_rejected() {
        let kp = IdentityKeyPair::generate().unwrap();
        assert!(kp.encrypt_to_store(b"").is_err());
    }

    #[test]
    fn test_truncated_blob_rejected() {
        assert!(IdentityKeyPair::decrypt_from_store(&[0u8; 10], b"pass").is_err());
    }

    #[test]
    fn test_corrupted_blob_rejected() {
        let kp = IdentityKeyPair::generate().unwrap();
        let mut blob = kp.encrypt_to_store(b"pass").unwrap();
        // Flip a byte in the ciphertext
        let last = blob.len() - 1;
        blob[last] ^= 0xFF;
        assert!(IdentityKeyPair::decrypt_from_store(&blob, b"pass").is_err());
    }
}
