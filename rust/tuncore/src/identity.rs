use crate::secure_memory::LockedKey32;
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

/// Derive a passphrase-encryption key via Argon2id into a locked 32-byte heap
/// buffer. Expansion writes directly into the heap, so no transient copy of
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

/// Build AAD for identity store encryption: salt || nonce.
fn build_store_aad(salt: &[u8], nonce: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(salt.len() + nonce.len());
    aad.extend_from_slice(salt);
    aad.extend_from_slice(nonce);
    aad
}

/// Static X25519 identity keypair for Noise XX handshake.
/// Secret is pinned on the mlock'd heap and zeroized on drop via `LockedKey32`.
pub struct IdentityKeyPair {
    secret: LockedKey32,
    public: [u8; 32],
}

impl IdentityKeyPair {
    /// Generate a new random identity keypair. The secret is written directly
    /// into a mlock'd heap buffer via `OsRng`.
    pub fn generate() -> Result<Self, String> {
        let mut secret = LockedKey32::zeroed()?;
        OsRng.fill_bytes(secret.as_mut());

        let static_secret = StaticSecret::from(*secret.as_array());
        let public = PublicKey::from(&static_secret);

        Ok(Self {
            secret,
            public: *public.as_bytes(),
        })
    }

    /// Build from a pre-populated `LockedKey32` (e.g. after decryption from
    /// disk). Derives the public key.
    fn from_locked(secret: LockedKey32) -> Result<Self, String> {
        let static_secret = StaticSecret::from(*secret.as_array());
        let public = PublicKey::from(&static_secret);

        Ok(Self {
            secret,
            public: *public.as_bytes(),
        })
    }

    pub fn public_key(&self) -> &[u8; 32] {
        &self.public
    }

    /// Access the secret key bytes. Caller must not persist or copy.
    pub fn secret_key(&self) -> &[u8; 32] {
        self.secret.as_array()
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

        let cipher = XChaCha20Poly1305::new_from_slice(derived.as_array())
            .map_err(|e| format!("cipher init: {e}"))?;

        let mut nonce_bytes = [0u8; XCHACHA_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        let aad = build_store_aad(&salt, &nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, Payload { msg: self.secret.as_array(), aad: &aad })
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

        let cipher = XChaCha20Poly1305::new_from_slice(derived.as_array())
            .map_err(|e| format!("cipher init: {e}"))?;

        let nonce = XNonce::from_slice(nonce_bytes);

        let aad = build_store_aad(salt, nonce_bytes);

        // AEAD decrypt returns a heap Vec<u8> — wrap in Zeroizing so the
        // plaintext copy is scrubbed after we move it into the locked buffer.
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(nonce, Payload { msg: ciphertext, aad: &aad })
                .map_err(|_| "decryption failed: wrong passphrase or corrupted data".to_string())?,
        );

        if plaintext.len() != 32 {
            return Err("decrypted key has wrong length".into());
        }

        let mut secret = LockedKey32::zeroed()?;
        secret.as_mut().copy_from_slice(&plaintext);

        Self::from_locked(secret)
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
