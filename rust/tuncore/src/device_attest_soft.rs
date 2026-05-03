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
use p256::pkcs8::EncodePublicKey;
use rand::rngs::OsRng;

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
}
