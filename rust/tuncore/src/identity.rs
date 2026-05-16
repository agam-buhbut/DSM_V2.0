use crate::passphrase_store::{self, ARGON2_SALT_LEN, XCHACHA_NONCE_LEN};
use crate::secure_memory::LockedKey32;
use hkdf::Hkdf;
use hmac::{Hmac, Mac as _};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

type HmacSha256 = Hmac<Sha256>;

/// X25519 scalar length — used in `decrypt_from_store`'s up-front
/// blob-length check so a too-short blob fails with "blob too short"
/// rather than going through Argon2 + AEAD only to produce a length-
/// mismatch error at the end.
const SECRET_LEN: usize = 32;

/// Compute the X25519 public key for a static secret living in mlock'd
/// memory.
///
/// **Unavoidable stack copy.** `x25519_dalek::StaticSecret::from` consumes
/// `[u8; 32]` by value (no `&[u8; 32]` constructor is exposed in
/// x25519-dalek 2.x), so dereferencing `secret.as_array()` materializes
/// a transient stack copy of the scalar before `StaticSecret` copies it
/// again into its own (clamped) internal storage. Both intermediate
/// copies are scrubbed:
///   * `static_secret` impls `ZeroizeOnDrop`, so its internal copy is
///     wiped at end-of-scope below.
///   * the unnamed `*secret.as_array()` temporary lives on this function's
///     stack frame only; the next caller's stack frame overwrites it.
///
/// A leak window exists between function return and the next stack-frame
/// reuse where a debugger / `/proc/PID/mem` reader could still observe
/// the bytes. The wrapping daemon hardens against this via
/// `PR_SET_DUMPABLE=0` + `PR_SET_NO_NEW_PRIVS=1` (see
/// `secure_memory::harden_process`), and the temporary is short-lived
/// (single function call). Tighter elimination would require a
/// `StaticSecret::from(&[u8; 32])` upstream.
fn derive_static_pub(secret: &LockedKey32) -> [u8; 32] {
    let static_secret = StaticSecret::from(*secret.as_array());
    *PublicKey::from(&static_secret).as_bytes()
    // `static_secret` drops here — ZeroizeOnDrop scrubs its internal copy.
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
        let public = derive_static_pub(&secret);
        Ok(Self { secret, public })
    }

    /// Build from a pre-populated `LockedKey32` (e.g. after decryption from
    /// disk). Derives the public key.
    fn from_locked(secret: LockedKey32) -> Result<Self, String> {
        let public = derive_static_pub(&secret);
        Ok(Self { secret, public })
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

    /// Compute HMAC-SHA256 over `data` using a key derived from this
    /// identity's secret via HKDF-SHA256 (info = `context`). The derived key
    /// is scoped to this call, zeroized on drop, and never leaves Rust —
    /// callers receive only the 32-byte tag.
    pub fn compute_hmac(&self, context: &[u8], data: &[u8]) -> Result<[u8; 32], String> {
        let hkdf = Hkdf::<Sha256>::new(
            Some(b"dsm-known-hosts-hmac-v3-"),
            self.secret.as_array(),
        );
        let mut key = Zeroizing::new([0u8; 32]);
        hkdf.expand(context, key.as_mut())
            .map_err(|e| format!("hkdf expand: {e}"))?;

        let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(&*key)
            .map_err(|e| format!("hmac init: {e}"))?;
        hmac::Mac::update(&mut mac, data);
        let tag = mac.finalize().into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&tag);
        Ok(out)
    }

    /// Encrypt the keypair to a blob using a passphrase
    /// (Argon2id + XChaCha20-Poly1305).
    ///
    /// Format: `salt(32) || nonce(24) || ciphertext+tag`. The actual
    /// sealing is delegated to [`passphrase_store::seal`] so the wire
    /// format is identical to the attest-store wire format.
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
    fn test_compute_hmac_deterministic_and_context_bound() {
        let kp = IdentityKeyPair::generate().unwrap();
        let tag1 = kp.compute_hmac(b"ctx-a", b"hello").unwrap();
        let tag2 = kp.compute_hmac(b"ctx-a", b"hello").unwrap();
        let tag3 = kp.compute_hmac(b"ctx-b", b"hello").unwrap();
        assert_eq!(tag1, tag2);
        assert_ne!(tag1, tag3);
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
