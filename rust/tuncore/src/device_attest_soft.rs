//! Software ECDSA P-256 device attestation backend.
//!
//! Behind the `dev-soft-attest` Cargo feature. Provides a software-resident
//! ECDSA P-256 signing key for development, CI, and tests where TPM/Keystore
//! hardware is not available.
//!
//! NOT for production: the signing key lives in process memory with no
//! hardware binding and is extractable by anyone with code execution as the
//! user.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use p256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

use crate::secure_memory::LockedKey32;

// Argon2id + XChaCha20-Poly1305 parameters intentionally match
// `identity::IdentityKeyPair::encrypt_to_store` so the attest store has the
// same passphrase-cracking cost profile as the identity store.
const ARGON2_SALT_LEN: usize = 32;
const ARGON2_MEM_COST_KIB: u32 = 524_288; // 512 MiB
const ARGON2_TIME_COST: u32 = 4;
const ARGON2_PARALLELISM: u32 = 2;
const XCHACHA_NONCE_LEN: usize = 24;
const SCALAR_LEN: usize = 32;

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

fn build_store_aad(salt: &[u8], nonce: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(salt.len() + nonce.len());
    aad.extend_from_slice(salt);
    aad.extend_from_slice(nonce);
    aad
}

/// A software-resident ECDSA P-256 attestation key.
///
/// `SigningKey` from the `p256` crate impls `ZeroizeOnDrop` for its inner
/// scalar; we Box it so the secret bytes live at a stable heap address that
/// does not move when the wrapping struct moves.
pub struct SoftAttestKey {
    signing_key: Box<SigningKey>,
    verifying_key_spki_der: Vec<u8>,
}

impl SoftAttestKey {
    pub fn generate() -> Result<Self, String> {
        let signing_key = SigningKey::random(&mut OsRng);
        Self::from_signing_key(signing_key)
    }

    fn from_signing_key(signing_key: SigningKey) -> Result<Self, String> {
        let verifying_key = VerifyingKey::from(&signing_key);
        let spki_der = verifying_key
            .to_public_key_der()
            .map_err(|e| format!("encode SPKI DER: {e}"))?
            .as_bytes()
            .to_vec();
        Ok(Self {
            signing_key: Box::new(signing_key),
            verifying_key_spki_der: spki_der,
        })
    }

    pub fn public_spki_der(&self) -> &[u8] {
        &self.verifying_key_spki_der
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, String> {
        let signature: Signature = self.signing_key.sign(msg);
        Ok(signature.to_der().as_bytes().to_vec())
    }

    /// PKCS#8 DER encoding of the private key.
    ///
    /// Soft backend only: this is the export that lets the `enroll`
    /// subcommand hand the key to `cryptography.x509.CertificateSigningRequestBuilder`
    /// for CSR generation. TPM / Keystore backends MUST NOT expose this —
    /// they sign the CSR internally via platform APIs and never leak
    /// private key bytes.
    pub fn private_pkcs8_der(&self) -> Result<Vec<u8>, String> {
        let pkcs8 = self
            .signing_key
            .to_pkcs8_der()
            .map_err(|e| format!("encode PKCS#8 DER: {e}"))?;
        Ok(pkcs8.as_bytes().to_vec())
    }

    /// Encrypt the signing key to a passphrase-protected blob.
    /// Format: `salt(32) || nonce(24) || ciphertext+tag`
    /// Plaintext = the 32-byte ECDSA P-256 scalar.
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

        // Wrap the scalar copy so it is scrubbed before returning.
        let scalar_bytes = Zeroizing::new(self.signing_key.to_bytes());

        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: scalar_bytes.as_slice(),
                    aad: &aad,
                },
            )
            .map_err(|e| format!("encrypt: {e}"))?;

        let mut blob = Vec::with_capacity(ARGON2_SALT_LEN + XCHACHA_NONCE_LEN + ciphertext.len());
        blob.extend_from_slice(&salt);
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ciphertext);

        Ok(blob)
    }

    /// Decrypt a signing key from a stored blob using a passphrase.
    pub fn decrypt_from_store(blob: &[u8], passphrase: &[u8]) -> Result<Self, String> {
        let min_len = ARGON2_SALT_LEN + XCHACHA_NONCE_LEN + SCALAR_LEN + 16; // scalar + tag
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

        let plaintext = Zeroizing::new(
            cipher
                .decrypt(nonce, Payload { msg: ciphertext, aad: &aad })
                .map_err(|_| {
                    "decryption failed: wrong passphrase or corrupted data".to_string()
                })?,
        );

        if plaintext.len() != SCALAR_LEN {
            return Err("decrypted scalar has wrong length".into());
        }

        let signing_key = SigningKey::from_slice(&plaintext)
            .map_err(|e| format!("invalid ECDSA scalar: {e}"))?;

        Self::from_signing_key(signing_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    use p256::pkcs8::DecodePublicKey;

    #[test]
    fn generate_produces_parseable_spki() {
        let key = SoftAttestKey::generate().expect("generate");
        let spki = key.public_spki_der();
        assert!(!spki.is_empty());
        VerifyingKey::from_public_key_der(spki).expect("parseable SPKI");
    }

    #[test]
    fn sign_verify_roundtrip() {
        let key = SoftAttestKey::generate().expect("generate");
        let msg = b"DSM-BIND-v1\x00 test handshake hash material";
        let sig_der = key.sign(msg).expect("sign");

        let vk = VerifyingKey::from_public_key_der(key.public_spki_der()).expect("parse vk");
        let sig = Signature::from_der(&sig_der).expect("parse sig");
        vk.verify(msg, &sig).expect("verify must succeed");
    }

    #[test]
    fn tampered_message_fails_verify() {
        let key = SoftAttestKey::generate().expect("generate");
        let sig_der = key.sign(b"original message").expect("sign");
        let vk = VerifyingKey::from_public_key_der(key.public_spki_der()).expect("parse vk");
        let sig = Signature::from_der(&sig_der).expect("parse sig");
        assert!(vk.verify(b"tampered message", &sig).is_err());
    }

    #[test]
    fn signature_from_other_key_fails_verify() {
        let key1 = SoftAttestKey::generate().expect("k1");
        let key2 = SoftAttestKey::generate().expect("k2");
        let msg = b"shared message";
        let sig_der = key1.sign(msg).expect("sign with k1");
        let vk2 = VerifyingKey::from_public_key_der(key2.public_spki_der()).expect("parse vk2");
        let sig = Signature::from_der(&sig_der).expect("parse sig");
        assert!(vk2.verify(msg, &sig).is_err());
    }

    #[test]
    fn distinct_generations_produce_distinct_keys() {
        let k1 = SoftAttestKey::generate().expect("k1");
        let k2 = SoftAttestKey::generate().expect("k2");
        assert_ne!(k1.public_spki_der(), k2.public_spki_der());
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = SoftAttestKey::generate().expect("generate");
        let blob = key.encrypt_to_store(b"correct horse battery staple").expect("encrypt");
        let restored = SoftAttestKey::decrypt_from_store(&blob, b"correct horse battery staple")
            .expect("decrypt");
        assert_eq!(key.public_spki_der(), restored.public_spki_der());

        // Restored key signs verifiably under the original SPKI.
        let msg = b"roundtrip-test";
        let sig_der = restored.sign(msg).expect("sign");
        let vk = VerifyingKey::from_public_key_der(key.public_spki_der()).expect("parse vk");
        let sig = Signature::from_der(&sig_der).expect("parse sig");
        vk.verify(msg, &sig).expect("verify must succeed under original SPKI");
    }

    #[test]
    fn wrong_passphrase_fails() {
        let key = SoftAttestKey::generate().expect("generate");
        let blob = key.encrypt_to_store(b"correct").expect("encrypt");
        assert!(SoftAttestKey::decrypt_from_store(&blob, b"wrong").is_err());
    }

    #[test]
    fn empty_passphrase_rejected_on_encrypt() {
        let key = SoftAttestKey::generate().expect("generate");
        assert!(key.encrypt_to_store(b"").is_err());
    }

    #[test]
    fn empty_passphrase_rejected_on_decrypt() {
        let key = SoftAttestKey::generate().expect("generate");
        let blob = key.encrypt_to_store(b"correct").expect("encrypt");
        assert!(SoftAttestKey::decrypt_from_store(&blob, b"").is_err());
    }

    #[test]
    fn truncated_blob_rejected() {
        assert!(SoftAttestKey::decrypt_from_store(&[0u8; 10], b"pass").is_err());
    }

    #[test]
    fn corrupted_ciphertext_rejected() {
        let key = SoftAttestKey::generate().expect("generate");
        let mut blob = key.encrypt_to_store(b"pass").expect("encrypt");
        // Flip a byte inside the ciphertext+tag region.
        let last = blob.len() - 1;
        blob[last] ^= 0xFF;
        assert!(SoftAttestKey::decrypt_from_store(&blob, b"pass").is_err());
    }

    #[test]
    fn corrupted_salt_rejected() {
        let key = SoftAttestKey::generate().expect("generate");
        let mut blob = key.encrypt_to_store(b"pass").expect("encrypt");
        // Flipping a byte in the salt changes the derived key → AEAD fails.
        blob[0] ^= 0xFF;
        assert!(SoftAttestKey::decrypt_from_store(&blob, b"pass").is_err());
    }

    #[test]
    fn distinct_blobs_per_encryption() {
        // Same key, same passphrase, two encryptions must produce different
        // blobs (random salt + nonce).
        let key = SoftAttestKey::generate().expect("generate");
        let b1 = key.encrypt_to_store(b"pass").expect("encrypt 1");
        let b2 = key.encrypt_to_store(b"pass").expect("encrypt 2");
        assert_ne!(b1, b2);
    }
}
