//! Software ECDSA P-256 device attestation backend.
//!
//! Behind the `dev-soft-attest` Cargo feature. Provides a software-resident
//! ECDSA P-256 signing key for development, CI, and tests where TPM/Keystore
//! hardware is not available.
//!
//! NOT for production: the signing key lives in process memory with no
//! hardware binding and is extractable by anyone with code execution as the
//! user.

use p256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};
use rand::rngs::OsRng;
use zeroize::Zeroizing;

// Argon2id + XChaCha20-Poly1305 sealed-blob shape lives in
// `passphrase_store` and is shared with `identity::IdentityKeyPair` so
// both stores have an identical wire format and identical Argon2 cost.
use crate::passphrase_store::{self, ARGON2_SALT_LEN, XCHACHA_NONCE_LEN};

const SCALAR_LEN: usize = 32;

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

    /// SubjectPublicKeyInfo DER of the verifying key. Returns
    /// `Err("attest key has been zeroized")` once `zeroize()` has been
    /// called (M-CRYPT-8: the previous code left the SPKI cache in
    /// place after zeroize and would happily hand out a pubkey whose
    /// corresponding scalar was the freshly-generated replacement —
    /// signatures produced post-zeroize would not verify against the
    /// returned SPKI). Callers can detect "already zeroized" via the
    /// returned error rather than silently receiving stale bytes.
    pub fn public_spki_der(&self) -> Result<&[u8], String> {
        if self.verifying_key_spki_der.is_empty() {
            return Err("attest key has been zeroized".into());
        }
        Ok(&self.verifying_key_spki_der)
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, String> {
        if self.verifying_key_spki_der.is_empty() {
            return Err("attest key has been zeroized".into());
        }
        // L-CRYPT-3: cap msg size so a malicious Python caller (or
        // network-fed verifier challenge in a future code path) can't
        // force the SHA-256 update through an unbounded buffer. 1 MiB
        // is far above any legitimate use (DSM binding signatures
        // sign 92 bytes; ECDSA can sign arbitrary-length messages but
        // the implementation hashes them with SHA-256 first).
        const SIGN_MSG_MAX: usize = 1 << 20;
        if msg.len() > SIGN_MSG_MAX {
            return Err(format!(
                "sign msg too large: {} > {SIGN_MSG_MAX}",
                msg.len()
            ));
        }
        let signature: Signature = self.signing_key.sign(msg);
        Ok(signature.to_der().as_bytes().to_vec())
    }

    /// Wipe the signing scalar AND the cached SPKI so subsequent calls
    /// to `sign`/`public_spki_der`/`private_pkcs8_der`/`build_csr` fail
    /// loudly rather than producing a signature that doesn't match the
    /// cleared SPKI cache (M-CRYPT-8 fix). Safe to call multiple times.
    ///
    /// `SigningKey` impls `ZeroizeOnDrop` but not `Zeroize`, so the scalar
    /// cannot be wiped in place. Instead we move the original out of the
    /// `Box` (releasing it for `Drop` to run, which fires the ZeroizeOnDrop
    /// wipe on its inner NonZeroScalar) and replace it with a freshly
    /// generated key so the struct stays valid for the brief window
    /// before Drop. The SPKI cache is cleared, so even though the
    /// replacement key technically has a corresponding pubkey, callers
    /// cannot obtain it from this instance.
    pub fn zeroize(&mut self) {
        let replacement = SigningKey::random(&mut OsRng);
        let old = std::mem::replace(&mut self.signing_key, Box::new(replacement));
        drop(old); // ZeroizeOnDrop wipes the scalar here.
                   // M-CRYPT-8: clear the cached SPKI too so the post-zeroize
                   // state is unambiguously "consumed" — every accessor returns
                   // Err rather than silently handing out a public key that
                   // doesn't match any callable signing capacity.
        use zeroize::Zeroize;
        self.verifying_key_spki_der.zeroize();
    }

    /// PKCS#8 DER encoding of the private key, wrapped in [`Zeroizing`] so
    /// the encoded scalar is scrubbed when the caller drops it.
    ///
    /// Soft backend only. Internal use: consumed by ``build_csr`` to feed
    /// rcgen's key importer entirely within Rust. Not exposed to Python any
    /// more (was previously exported via PyAttestKey, audit M4). TPM /
    /// Keystore backends MUST NOT expose this — they sign the CSR internally
    /// via platform APIs and never leak private key bytes.
    ///
    /// The return type is `Zeroizing<Vec<u8>>` rather than plain `Vec<u8>`
    /// so a future caller cannot accidentally leave the encoded scalar in
    /// a long-lived heap allocation. The wrapper costs nothing at the
    /// borrow site (deref-to-slice still works) but makes the safety
    /// invariant load-bearing in the type system.
    pub fn private_pkcs8_der(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        let pkcs8 = self
            .signing_key
            .to_pkcs8_der()
            .map_err(|e| format!("encode PKCS#8 DER: {e}"))?;
        Ok(Zeroizing::new(pkcs8.as_bytes().to_vec()))
    }

    /// Build a DER-encoded CSR for this attest key with the given CN and
    /// noise-static binding extension.
    ///
    /// The PKCS#8 export of the signing scalar stays inside Rust (wrapped in
    /// `Zeroizing`) so the key bytes never reach a Python `bytes`/list. The
    /// produced CSR is signed by the attest key (proof-of-possession of the
    /// hardware-bound private key). The custom critical extension
    /// ``id-dsm-noiseStaticBinding`` (1.3.6.1.4.1.99999.1.1) carries the
    /// 32-byte X25519 Noise static pubkey wrapped per the conventional
    /// OCTET STRING form.
    pub fn build_csr(&self, cn: &str, noise_static_pub: &[u8]) -> Result<Vec<u8>, String> {
        use rcgen::{CertificateParams, CustomExtension, DnType, KeyPair};

        // RFC 5280 caps Subject CommonName at 64 UTF-8 bytes (ub-common-name).
        // Cap higher than the RFC limit but still bounded so a malicious
        // caller cannot force unbounded String/CSR allocation through this
        // FFI entry point.
        const CN_MAX_BYTES: usize = 255;
        if cn.is_empty() {
            return Err("cn must not be empty".into());
        }
        if cn.len() > CN_MAX_BYTES {
            return Err(format!("cn too long: {} > {CN_MAX_BYTES}", cn.len()));
        }

        if noise_static_pub.len() != 32 {
            return Err(format!(
                "noise_static_pub must be 32 bytes, got {}",
                noise_static_pub.len()
            ));
        }

        // `private_pkcs8_der` now returns the encoded scalar already wrapped
        // in `Zeroizing`, so we just bind the result directly.
        let pkcs8 = self.private_pkcs8_der()?;
        let key_pair =
            KeyPair::try_from(pkcs8.as_slice()).map_err(|e| format!("rcgen key import: {e}"))?;

        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, cn.to_string());

        // DER OCTET STRING (32) || raw pub — matches Python's
        // encode_noise_static_binding_value in dsm.crypto.cert.
        let mut ext_value = Vec::with_capacity(2 + noise_static_pub.len());
        ext_value.push(0x04); // OCTET STRING tag
                              // Length-byte cast: bounded above by the 32-byte length check
                              // at L135–140; the truncation cannot lose information.
        #[allow(clippy::cast_possible_truncation)]
        ext_value.push(noise_static_pub.len() as u8);
        ext_value.extend_from_slice(noise_static_pub);

        let mut ext =
            CustomExtension::from_oid_content(&[1, 3, 6, 1, 4, 1, 99999, 1, 1], ext_value);
        ext.set_criticality(true);
        params.custom_extensions.push(ext);

        let csr = params
            .serialize_request(&key_pair)
            .map_err(|e| format!("rcgen CSR serialize: {e}"))?;
        Ok(csr.der().to_vec())
    }

    /// Encrypt the signing key to a passphrase-protected blob.
    /// Format: `salt(32) || nonce(24) || ciphertext+tag`. Plaintext is
    /// the 32-byte ECDSA P-256 scalar.
    ///
    /// Sealing is delegated to [`passphrase_store::seal`] so this blob
    /// shape is byte-identical to the identity-store blob shape.
    pub fn encrypt_to_store(&self, passphrase: &[u8]) -> Result<Vec<u8>, String> {
        // `to_bytes()` materializes the scalar; wrap in `Zeroizing` so
        // the temporary copy is scrubbed once `seal` has copied it into
        // the AEAD engine.
        let scalar_bytes = Zeroizing::new(self.signing_key.to_bytes());
        passphrase_store::seal(scalar_bytes.as_slice(), passphrase)
    }

    /// Decrypt a signing key from a stored blob using a passphrase.
    pub fn decrypt_from_store(blob: &[u8], passphrase: &[u8]) -> Result<Self, String> {
        // Up-front "blob too short" check tied to the 32-byte scalar
        // we are expecting — the shared helper rejects shorter blobs
        // at the looser `salt + nonce + tag` minimum, so we tighten
        // here to preserve the precise error message.
        let min_len = ARGON2_SALT_LEN + XCHACHA_NONCE_LEN + SCALAR_LEN + passphrase_store::TAG_LEN;
        if blob.len() < min_len {
            return Err("blob too short".into());
        }

        let plaintext = passphrase_store::open(blob, passphrase)?;
        if plaintext.len() != SCALAR_LEN {
            return Err("decrypted scalar has wrong length".into());
        }

        let signing_key =
            SigningKey::from_slice(&plaintext).map_err(|e| format!("invalid ECDSA scalar: {e}"))?;

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
        let spki = key.public_spki_der().unwrap();
        assert!(!spki.is_empty());
        VerifyingKey::from_public_key_der(spki).expect("parseable SPKI");
    }

    #[test]
    fn sign_verify_roundtrip() {
        let key = SoftAttestKey::generate().expect("generate");
        let msg = b"DSM-BIND-v1\x00 test handshake hash material";
        let sig_der = key.sign(msg).expect("sign");

        let vk =
            VerifyingKey::from_public_key_der(key.public_spki_der().unwrap()).expect("parse vk");
        let sig = Signature::from_der(&sig_der).expect("parse sig");
        vk.verify(msg, &sig).expect("verify must succeed");
    }

    #[test]
    fn tampered_message_fails_verify() {
        let key = SoftAttestKey::generate().expect("generate");
        let sig_der = key.sign(b"original message").expect("sign");
        let vk =
            VerifyingKey::from_public_key_der(key.public_spki_der().unwrap()).expect("parse vk");
        let sig = Signature::from_der(&sig_der).expect("parse sig");
        assert!(vk.verify(b"tampered message", &sig).is_err());
    }

    #[test]
    fn signature_from_other_key_fails_verify() {
        let key1 = SoftAttestKey::generate().expect("k1");
        let key2 = SoftAttestKey::generate().expect("k2");
        let msg = b"shared message";
        let sig_der = key1.sign(msg).expect("sign with k1");
        let vk2 =
            VerifyingKey::from_public_key_der(key2.public_spki_der().unwrap()).expect("parse vk2");
        let sig = Signature::from_der(&sig_der).expect("parse sig");
        assert!(vk2.verify(msg, &sig).is_err());
    }

    #[test]
    fn distinct_generations_produce_distinct_keys() {
        let k1 = SoftAttestKey::generate().expect("k1");
        let k2 = SoftAttestKey::generate().expect("k2");
        assert_ne!(k1.public_spki_der().unwrap(), k2.public_spki_der().unwrap());
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = SoftAttestKey::generate().expect("generate");
        let blob = key
            .encrypt_to_store(b"correct horse battery staple")
            .expect("encrypt");
        let restored = SoftAttestKey::decrypt_from_store(&blob, b"correct horse battery staple")
            .expect("decrypt");
        assert_eq!(
            key.public_spki_der().unwrap(),
            restored.public_spki_der().unwrap()
        );

        // Restored key signs verifiably under the original SPKI.
        let msg = b"roundtrip-test";
        let sig_der = restored.sign(msg).expect("sign");
        let vk =
            VerifyingKey::from_public_key_der(key.public_spki_der().unwrap()).expect("parse vk");
        let sig = Signature::from_der(&sig_der).expect("parse sig");
        vk.verify(msg, &sig)
            .expect("verify must succeed under original SPKI");
    }

    /// Regression for M-CRYPT-8: after `zeroize()`, the SPKI cache MUST
    /// be cleared so subsequent accessors return Err rather than silently
    /// handing out bytes that don't match any callable signing capacity.
    #[test]
    fn zeroize_clears_spki_cache_and_blocks_subsequent_accessors() {
        let mut key = SoftAttestKey::generate().expect("generate");
        assert!(key.public_spki_der().is_ok());
        assert!(key.sign(b"x").is_ok());
        key.zeroize();
        assert!(
            key.public_spki_der().is_err(),
            "public_spki_der must fail post-zeroize"
        );
        assert!(key.sign(b"x").is_err(), "sign must fail post-zeroize");
        // Idempotent: second zeroize is safe.
        key.zeroize();
        assert!(key.public_spki_der().is_err());
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
