use crate::passphrase_store::{self, ARGON2_SALT_LEN, XCHACHA_NONCE_LEN};
use crate::secure_memory::{public_from_locked, random_locked_key32, LockedKey32};
use zeroize::Zeroize;

/// X25519 scalar length — used in `decrypt_from_store`'s up-front
/// blob-length check so a too-short blob fails with "blob too short"
/// rather than going through Argon2 + AEAD only to produce a length-
/// mismatch error at the end.
const SECRET_LEN: usize = 32;

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
        let secret = random_locked_key32()?;
        let public = public_from_locked(&secret);
        Ok(Self { secret, public })
    }

    /// Build from a pre-populated `LockedKey32` (e.g. after decryption from
    /// disk). Derives the public key. Infallible — kept on the type so the
    /// public-key derivation lives next to the field that owns it.
    fn from_locked(secret: LockedKey32) -> Self {
        let public = public_from_locked(&secret);
        Self { secret, public }
    }

    pub fn public_key(&self) -> &[u8; 32] {
        &self.public
    }

    /// Access the secret key bytes. Caller must not persist or copy.
    pub fn secret_key(&self) -> &[u8; 32] {
        self.secret.as_array()
    }

    /// Overwrite the secret key with zeros. Safe to call multiple times;
    /// the keypair is unusable afterwards. The public key is not sensitive
    /// (derivable from secret only, never secret itself) so it is left intact.
    ///
    /// Uses [`Zeroize::zeroize`] for the volatile, dead-store-elimination-
    /// proof write — a plain `.fill(0)` would be a regular store that an
    /// optimizing compiler is in principle free to elide if it could prove
    /// the buffer was never read again.
    pub fn zeroize(&mut self) {
        self.secret.as_mut().zeroize();
    }

    /// Encrypt the keypair to a blob using a passphrase
    /// (Argon2id + XChaCha20-Poly1305).
    ///
    /// Format: the versioned sealed-blob format owned by
    /// [`passphrase_store::seal`] (`DSMK` magic || version || Argon2id
    /// params || salt || nonce || ciphertext+tag), identical to the
    /// attest-store wire format.
    pub fn encrypt_to_store(&self, passphrase: &[u8]) -> Result<Vec<u8>, String> {
        passphrase_store::seal(self.secret.as_array(), passphrase)
    }

    /// Decrypt a keypair from a stored blob using a passphrase.
    pub fn decrypt_from_store(blob: &[u8], passphrase: &[u8]) -> Result<Self, String> {
        // Up-front blob length check tied to the *expected* plaintext
        // (32-byte scalar) so the failure message is the precise "blob
        // too short" rather than a generic AEAD failure for blobs whose
        // tag-shaped tail happens to authenticate to a too-short
        // plaintext. The shared helper also rejects shorter blobs but at
        // the looser `salt + nonce + tag` minimum.
        let min_len = ARGON2_SALT_LEN + XCHACHA_NONCE_LEN + SECRET_LEN + passphrase_store::TAG_LEN;
        if blob.len() < min_len {
            return Err("blob too short".into());
        }

        let plaintext = passphrase_store::open(blob, passphrase)?;
        if plaintext.len() != SECRET_LEN {
            return Err("decrypted key has wrong length".into());
        }

        let mut secret = LockedKey32::zeroed()?;
        secret.as_mut().copy_from_slice(&plaintext);

        Ok(Self::from_locked(secret))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::{PublicKey, StaticSecret};

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
    fn test_zeroize_clears_secret() {
        let mut kp = IdentityKeyPair::generate().unwrap();
        assert_ne!(kp.secret_key(), &[0u8; 32]);
        kp.zeroize();
        assert_eq!(kp.secret_key(), &[0u8; 32]);
        // Public key is not sensitive and is left intact
        // Idempotent
        kp.zeroize();
        assert_eq!(kp.secret_key(), &[0u8; 32]);
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
