use rand::rngs::OsRng;
use rand::RngCore;
use snow::{Builder, HandshakeState, TransportState};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Protocol prologue authenticated by both sides.
/// Format: "DSM" || version(2 bytes) || initiator_role || responder_role
const PROLOGUE: &[u8] = b"DSM\x00\x01\x00\x01";

/// Noise XX cipher suite: X25519 DH, AES-256-GCM, SHA-256.
const NOISE_PATTERN: &str = "Noise_XX_25519_AESGCM_SHA256";

/// Maximum handshake message size (padded to hide message lengths).
pub const HANDSHAKE_PAD_SIZE: usize = 1400;

/// Fixed attestation-payload size carried in Noise XX msg2 (server cert + sig)
/// and msg3 (client cert + sig). The payload is always exactly this many
/// bytes, padded internally by the producer (cert/sig + length framing +
/// random pad). A fixed size keeps the snow message length protocol-constant
/// and avoids reintroducing the length prefix that audit finding H1 removed.
///
/// Sizing: a P-256 cert with custom binding extension is ~600 bytes; an
/// ASN.1-DER ECDSA signature is ~70-72 bytes; framing is 4 bytes (two u16
/// length tags). 1024 leaves ~340 bytes of random pad for forward-compat.
pub const HANDSHAKE_ATTEST_PAYLOAD_SIZE: usize = 1024;

/// Exact Snow message sizes for Noise_XX_25519_AESGCM_SHA256.
/// These are protocol-constant — binding them out of band eliminates the
/// previously-unauthenticated length prefix (audit finding H1).
///   msg1 = e(32)                                                      → 32
///   msg2 = e(32) + ENC(s)(48) + ENC(payload)(payload_size + 16 tag)   → 1120
///   msg3 = ENC(s)(48) + ENC(payload)(payload_size + 16 tag)           → 1088
const MSG1_SNOW_LEN: usize = 32;
const MSG2_SNOW_LEN: usize = 32 + 48 + HANDSHAKE_ATTEST_PAYLOAD_SIZE + 16;
const MSG3_SNOW_LEN: usize = 48 + HANDSHAKE_ATTEST_PAYLOAD_SIZE + 16;

const _: () = assert!(MSG2_SNOW_LEN <= HANDSHAKE_PAD_SIZE);
const _: () = assert!(MSG3_SNOW_LEN <= HANDSHAKE_PAD_SIZE);

/// Size of the X25519 ephemeral public key in Noise XX msg1.
const EPHEMERAL_SIZE: usize = 32;

/// Reject an ephemeral X25519 public key that lies in a small subgroup.
///
/// X25519 static-secret scalars are clamped to multiples of 8 by the
/// dalek library, so any point whose order divides 8 (the full set of
/// canonical low-order points) multiplied by a clamped scalar lands at
/// the identity — which `SharedSecret::was_contributory()` reports as
/// non-contributory. Probing with a fresh clamped scalar detects all
/// such points reliably and is ~100µs of overhead per handshake.
///
/// Snow (the Noise implementation) does not perform this check, and
/// accepting a low-order ephemeral would cause `ee` to produce a
/// known / zero shared secret, destroying the secrecy of the session.
///
/// The probe DH is run unconditionally and the contributory result is
/// evaluated in constant time (via `subtle::ConstantTimeEq`) so that
/// the accept/reject decision does not leak through branch timing.
fn validate_ephemeral_not_low_order(pub_bytes: &[u8]) -> Result<(), String> {
    if pub_bytes.len() != EPHEMERAL_SIZE {
        return Err("ephemeral public key wrong length".into());
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(pub_bytes);

    let mut probe = [0u8; 32];
    OsRng.fill_bytes(&mut probe);
    let probe_secret = StaticSecret::from(probe);
    let public = PublicKey::from(pk_arr);
    let shared = probe_secret.diffie_hellman(&public);

    // Constant-time comparison of the full shared secret against the
    // all-zero point. `was_contributory()` internally checks this, but we
    // re-implement via `subtle` to make the comparison observably uniform
    // regardless of where the first differing byte lies.
    let zero = [0u8; 32];
    let is_zero: u8 = shared.as_bytes().ct_eq(&zero).unwrap_u8();
    // is_zero == 1 → non-contributory → reject
    if is_zero == 1 {
        return Err("rejected low-order ephemeral public key".into());
    }
    Ok(())
}

/// Pack a handshake message: [snow_data || random_padding].
/// Snow data is always placed at offset 0 with a protocol-constant length;
/// the remainder is uniform random padding. No length field on the wire.
fn pack_handshake(snow_data: &[u8], expected_len: usize) -> Result<Vec<u8>, String> {
    if snow_data.len() < expected_len {
        return Err("snow produced shorter payload than expected".into());
    }
    let mut out = vec![0u8; HANDSHAKE_PAD_SIZE];
    out[..expected_len].copy_from_slice(&snow_data[..expected_len]);
    OsRng.fill_bytes(&mut out[expected_len..]);
    Ok(out)
}

/// Unpack a handshake message: extract the protocol-constant prefix.
fn unpack_handshake<'a>(buf: &'a [u8], expected_len: usize) -> Result<&'a [u8], String> {
    if buf.len() < expected_len {
        return Err("invalid handshake message".into());
    }
    Ok(&buf[..expected_len])
}

/// Initiator (client) side of the Noise XX handshake.
pub struct NoiseInitiator {
    state: HandshakeState,
}

/// Responder (server) side of the Noise XX handshake.
pub struct NoiseResponder {
    state: HandshakeState,
}

/// Completed handshake result: a transport-mode cipher pair.
pub struct NoiseTransport {
    inner: TransportState,
}

impl NoiseInitiator {
    /// Create a new initiator with the given static secret key.
    pub fn new(static_secret: &[u8; 32]) -> Result<Self, String> {
        let state = Builder::new(NOISE_PATTERN.parse().map_err(|e| format!("pattern: {e}"))?)
            .local_private_key(static_secret)
            .prologue(PROLOGUE)
            .build_initiator()
            .map_err(|e| format!("build initiator: {e}"))?;

        Ok(Self { state })
    }

    /// Get the handshake hash. Must be called after handshake completes,
    /// before `into_transport()`. Used to derive initial session keys.
    pub fn get_handshake_hash(&self) -> Vec<u8> {
        self.state.get_handshake_hash().to_vec()
    }

    /// Message 1: -> e
    pub fn write_message_1(&mut self) -> Result<Vec<u8>, String> {
        let mut buf = Zeroizing::new(vec![0u8; HANDSHAKE_PAD_SIZE]);
        let len = self
            .state
            .write_message(&[], &mut buf)
            .map_err(|e| format!("write msg1: {e}"))?;
        if len != MSG1_SNOW_LEN {
            return Err(format!("msg1 length mismatch: got {len}, expected {MSG1_SNOW_LEN}"));
        }
        pack_handshake(&buf, MSG1_SNOW_LEN)
    }

    /// Message 2: <- e, ee, s, es [+ attest_payload]
    ///
    /// Decrypts the responder's attestation payload and returns
    /// `(remote_static, attest_payload)` where `attest_payload` is exactly
    /// `HANDSHAKE_ATTEST_PAYLOAD_SIZE` bytes — the caller parses the
    /// internal cert/sig framing and ignores trailing pad.
    ///
    /// The binding signature inside `attest_payload` is over the handshake
    /// hash captured BEFORE this call (i.e. post-msg1). The caller must
    /// snapshot `get_handshake_hash()` before invoking `read_message_2`.
    pub fn read_message_2(&mut self, msg: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
        let snow_data = unpack_handshake(msg, MSG2_SNOW_LEN)?;

        // Noise XX msg2 starts with the responder's ephemeral public key (32
        // bytes). Reject low-order points before `ee` mixes them into the
        // handshake state.
        validate_ephemeral_not_low_order(&snow_data[..EPHEMERAL_SIZE])?;

        let mut payload = vec![0u8; HANDSHAKE_ATTEST_PAYLOAD_SIZE];
        let len = self
            .state
            .read_message(snow_data, &mut payload)
            .map_err(|e| format!("read msg2: {e}"))?;
        if len != HANDSHAKE_ATTEST_PAYLOAD_SIZE {
            return Err(format!(
                "msg2 attest payload length mismatch: got {len}, expected {HANDSHAKE_ATTEST_PAYLOAD_SIZE}"
            ));
        }

        let remote_static = self
            .state
            .get_remote_static()
            .ok_or("no remote static key after msg2")?
            .to_vec();

        Ok((remote_static, payload))
    }

    /// Message 3: -> s, se [+ attest_payload]
    ///
    /// `attest_payload` must be exactly `HANDSHAKE_ATTEST_PAYLOAD_SIZE`
    /// bytes. The caller produces it by serializing
    /// `cert_len(2) || cert || sig_len(2) || sig` then padding with random
    /// bytes; the binding signature is over the handshake hash captured
    /// before this call (i.e. post-msg2).
    pub fn write_message_3(&mut self, attest_payload: &[u8]) -> Result<Vec<u8>, String> {
        if attest_payload.len() != HANDSHAKE_ATTEST_PAYLOAD_SIZE {
            return Err(format!(
                "msg3 attest payload must be {HANDSHAKE_ATTEST_PAYLOAD_SIZE} bytes, got {}",
                attest_payload.len()
            ));
        }
        let mut buf = Zeroizing::new(vec![0u8; HANDSHAKE_PAD_SIZE]);
        let len = self
            .state
            .write_message(attest_payload, &mut buf)
            .map_err(|e| format!("write msg3: {e}"))?;
        if len != MSG3_SNOW_LEN {
            return Err(format!("msg3 length mismatch: got {len}, expected {MSG3_SNOW_LEN}"));
        }
        pack_handshake(&buf, MSG3_SNOW_LEN)
    }

    /// Transition to transport mode after handshake completion.
    pub fn into_transport(self) -> Result<NoiseTransport, String> {
        let transport = self
            .state
            .into_transport_mode()
            .map_err(|e| format!("transport mode: {e}"))?;
        Ok(NoiseTransport { inner: transport })
    }

    pub fn is_handshake_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }
}

impl NoiseResponder {
    /// Create a new responder with the given static secret key.
    pub fn new(static_secret: &[u8; 32]) -> Result<Self, String> {
        let state = Builder::new(NOISE_PATTERN.parse().map_err(|e| format!("pattern: {e}"))?)
            .local_private_key(static_secret)
            .prologue(PROLOGUE)
            .build_responder()
            .map_err(|e| format!("build responder: {e}"))?;

        Ok(Self { state })
    }

    /// Get the handshake hash. Must be called after handshake completes,
    /// before `into_transport()`. Used to derive initial session keys.
    pub fn get_handshake_hash(&self) -> Vec<u8> {
        self.state.get_handshake_hash().to_vec()
    }

    /// Message 1: -> e
    /// The ephemeral public key occupies the first 32 bytes of the message.
    pub fn read_message_1(&mut self, msg: &[u8]) -> Result<(), String> {
        let snow_data = unpack_handshake(msg, MSG1_SNOW_LEN)?;
        let ephemeral = &snow_data[..EPHEMERAL_SIZE];

        // Reject a small-subgroup ephemeral before snow mixes it via `ee`.
        validate_ephemeral_not_low_order(ephemeral)?;

        let mut payload = vec![0u8; HANDSHAKE_PAD_SIZE];
        self.state
            .read_message(snow_data, &mut payload)
            .map_err(|e| format!("read msg1: {e}"))?;
        Ok(())
    }

    /// Message 2: <- e, ee, s, es [+ attest_payload]
    ///
    /// `attest_payload` must be exactly `HANDSHAKE_ATTEST_PAYLOAD_SIZE`
    /// bytes (server's cert + binding signature, padded). The binding
    /// signature is over the handshake hash captured before this call
    /// (i.e. post-msg1).
    pub fn write_message_2(&mut self, attest_payload: &[u8]) -> Result<Vec<u8>, String> {
        if attest_payload.len() != HANDSHAKE_ATTEST_PAYLOAD_SIZE {
            return Err(format!(
                "msg2 attest payload must be {HANDSHAKE_ATTEST_PAYLOAD_SIZE} bytes, got {}",
                attest_payload.len()
            ));
        }
        let mut buf = Zeroizing::new(vec![0u8; HANDSHAKE_PAD_SIZE]);
        let len = self
            .state
            .write_message(attest_payload, &mut buf)
            .map_err(|e| format!("write msg2: {e}"))?;
        if len != MSG2_SNOW_LEN {
            return Err(format!("msg2 length mismatch: got {len}, expected {MSG2_SNOW_LEN}"));
        }
        pack_handshake(&buf, MSG2_SNOW_LEN)
    }

    /// Message 3: -> s, se [+ attest_payload]
    ///
    /// Decrypts the initiator's attestation payload and returns
    /// `(remote_static, attest_payload)`. The binding signature inside
    /// `attest_payload` is over the handshake hash captured before this
    /// call (i.e. post-msg2). The caller must snapshot
    /// `get_handshake_hash()` before invoking `read_message_3`.
    pub fn read_message_3(&mut self, msg: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
        let snow_data = unpack_handshake(msg, MSG3_SNOW_LEN)?;
        let mut payload = vec![0u8; HANDSHAKE_ATTEST_PAYLOAD_SIZE];
        let len = self
            .state
            .read_message(snow_data, &mut payload)
            .map_err(|e| format!("read msg3: {e}"))?;
        if len != HANDSHAKE_ATTEST_PAYLOAD_SIZE {
            return Err(format!(
                "msg3 attest payload length mismatch: got {len}, expected {HANDSHAKE_ATTEST_PAYLOAD_SIZE}"
            ));
        }

        let remote_static = self
            .state
            .get_remote_static()
            .ok_or("no remote static key after msg3")?
            .to_vec();

        Ok((remote_static, payload))
    }

    /// Transition to transport mode after handshake completion.
    pub fn into_transport(self) -> Result<NoiseTransport, String> {
        let transport = self
            .state
            .into_transport_mode()
            .map_err(|e| format!("transport mode: {e}"))?;
        Ok(NoiseTransport { inner: transport })
    }

    pub fn is_handshake_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }
}

impl NoiseTransport {
    /// Encrypt a message using the transport cipher.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; plaintext.len() + 16]; // 16-byte AEAD tag
        let len = self
            .inner
            .write_message(plaintext, &mut buf)
            .map_err(|e| format!("transport encrypt: {e}"))?;
        buf.truncate(len);
        Ok(buf)
    }

    /// Decrypt a message using the transport cipher.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; ciphertext.len()];
        let len = self
            .inner
            .read_message(ciphertext, &mut buf)
            .map_err(|e| format!("transport decrypt: {e}"))?;
        buf.truncate(len);
        Ok(buf)
    }

    // NOTE: Key extraction from snow TransportState is not supported.
    // Key rotation uses separate ephemeral DH (see session_keys.rs) instead.
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gen_keypair() -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }

    fn random_attest_payload() -> Vec<u8> {
        let mut buf = vec![0u8; HANDSHAKE_ATTEST_PAYLOAD_SIZE];
        OsRng.fill_bytes(&mut buf);
        buf
    }

    fn do_handshake(
        client_secret: &[u8; 32],
        server_secret: &[u8; 32],
    ) -> (NoiseInitiator, NoiseResponder) {
        let mut initiator = NoiseInitiator::new(client_secret).unwrap();
        let mut responder = NoiseResponder::new(server_secret).unwrap();

        let msg1 = initiator.write_message_1().unwrap();
        responder.read_message_1(&msg1).unwrap();

        let server_payload = random_attest_payload();
        let msg2 = responder.write_message_2(&server_payload).unwrap();
        initiator.read_message_2(&msg2).unwrap();

        let client_payload = random_attest_payload();
        let msg3 = initiator.write_message_3(&client_payload).unwrap();
        responder.read_message_3(&msg3).unwrap();

        (initiator, responder)
    }

    #[test]
    fn test_full_handshake() {
        let client_secret = gen_keypair();
        let server_secret = gen_keypair();

        let mut initiator = NoiseInitiator::new(&client_secret).unwrap();
        let mut responder = NoiseResponder::new(&server_secret).unwrap();

        let msg1 = initiator.write_message_1().unwrap();
        assert_eq!(msg1.len(), HANDSHAKE_PAD_SIZE);
        responder.read_message_1(&msg1).unwrap();

        let server_payload = random_attest_payload();
        let msg2 = responder.write_message_2(&server_payload).unwrap();
        assert_eq!(msg2.len(), HANDSHAKE_PAD_SIZE);
        let (server_static, recovered_server_payload) = initiator.read_message_2(&msg2).unwrap();
        assert_eq!(recovered_server_payload, server_payload);

        let expected_server_pub = PublicKey::from(&StaticSecret::from(server_secret));
        assert_eq!(server_static, expected_server_pub.as_bytes());

        let client_payload = random_attest_payload();
        let msg3 = initiator.write_message_3(&client_payload).unwrap();
        assert_eq!(msg3.len(), HANDSHAKE_PAD_SIZE);
        let (client_static, recovered_client_payload) = responder.read_message_3(&msg3).unwrap();
        assert_eq!(recovered_client_payload, client_payload);

        let expected_client_pub = PublicKey::from(&StaticSecret::from(client_secret));
        assert_eq!(client_static, expected_client_pub.as_bytes());

        assert!(initiator.is_handshake_finished());
        assert!(responder.is_handshake_finished());

        let mut client_transport = initiator.into_transport().unwrap();
        let mut server_transport = responder.into_transport().unwrap();

        let ct = client_transport.encrypt(b"hello server").unwrap();
        let pt = server_transport.decrypt(&ct).unwrap();
        assert_eq!(pt, b"hello server");

        let ct = server_transport.encrypt(b"hello client").unwrap();
        let pt = client_transport.decrypt(&ct).unwrap();
        assert_eq!(pt, b"hello client");
    }

    #[test]
    fn test_all_messages_same_size() {
        let k1 = gen_keypair();
        let k2 = gen_keypair();
        let mut initiator = NoiseInitiator::new(&k1).unwrap();
        let mut responder = NoiseResponder::new(&k2).unwrap();

        let msg1 = initiator.write_message_1().unwrap();
        assert_eq!(msg1.len(), HANDSHAKE_PAD_SIZE);
        responder.read_message_1(&msg1).unwrap();

        let msg2 = responder.write_message_2(&random_attest_payload()).unwrap();
        assert_eq!(msg2.len(), HANDSHAKE_PAD_SIZE);

        initiator.read_message_2(&msg2).unwrap();
        let msg3 = initiator.write_message_3(&random_attest_payload()).unwrap();
        assert_eq!(msg3.len(), HANDSHAKE_PAD_SIZE);
    }

    #[test]
    fn test_attest_payload_wrong_size_rejected() {
        let k1 = gen_keypair();
        let k2 = gen_keypair();
        let mut initiator = NoiseInitiator::new(&k1).unwrap();
        let mut responder = NoiseResponder::new(&k2).unwrap();

        let msg1 = initiator.write_message_1().unwrap();
        responder.read_message_1(&msg1).unwrap();

        // Too small.
        let too_small = vec![0u8; HANDSHAKE_ATTEST_PAYLOAD_SIZE - 1];
        let err = responder.write_message_2(&too_small).unwrap_err();
        assert!(err.contains("attest payload"), "got: {err}");

        // Too large.
        let too_large = vec![0u8; HANDSHAKE_ATTEST_PAYLOAD_SIZE + 1];
        let err = responder.write_message_2(&too_large).unwrap_err();
        assert!(err.contains("attest payload"), "got: {err}");
    }

    #[test]
    fn test_attest_payload_roundtrips_byte_for_byte() {
        let k1 = gen_keypair();
        let k2 = gen_keypair();
        let mut initiator = NoiseInitiator::new(&k1).unwrap();
        let mut responder = NoiseResponder::new(&k2).unwrap();

        let msg1 = initiator.write_message_1().unwrap();
        responder.read_message_1(&msg1).unwrap();

        // Use a recognisable pattern, not random — so we can pinpoint the
        // bytes that come back.
        let mut server_payload = vec![0u8; HANDSHAKE_ATTEST_PAYLOAD_SIZE];
        for (i, b) in server_payload.iter_mut().enumerate() {
            *b = (i & 0xFF) as u8;
        }
        let msg2 = responder.write_message_2(&server_payload).unwrap();
        let (_remote_static, got) = initiator.read_message_2(&msg2).unwrap();
        assert_eq!(got, server_payload);

        let mut client_payload = vec![0u8; HANDSHAKE_ATTEST_PAYLOAD_SIZE];
        for (i, b) in client_payload.iter_mut().enumerate() {
            *b = ((i.wrapping_mul(7)) & 0xFF) as u8;
        }
        let msg3 = initiator.write_message_3(&client_payload).unwrap();
        let (_remote_static, got) = responder.read_message_3(&msg3).unwrap();
        assert_eq!(got, client_payload);
    }

    #[test]
    fn test_transport_tampered_ciphertext_fails() {
        let k1 = gen_keypair();
        let k2 = gen_keypair();

        let (initiator, responder) = do_handshake(&k1, &k2);

        let mut ct = initiator.into_transport().unwrap();
        let mut st = responder.into_transport().unwrap();

        let mut ciphertext = ct.encrypt(b"secret").unwrap();
        ciphertext[0] ^= 0xFF;
        assert!(st.decrypt(&ciphertext).is_err());
    }

    #[test]
    fn test_multiple_transport_messages() {
        let k1 = gen_keypair();
        let k2 = gen_keypair();

        let (initiator, responder) = do_handshake(&k1, &k2);

        let mut ct = initiator.into_transport().unwrap();
        let mut st = responder.into_transport().unwrap();

        for i in 0..100u32 {
            let msg = format!("message {i}");
            let encrypted = ct.encrypt(msg.as_bytes()).unwrap();
            let decrypted = st.decrypt(&encrypted).unwrap();
            assert_eq!(decrypted, msg.as_bytes());
        }
    }

    #[test]
    fn test_handshake_rejects_low_order_ephemeral_in_msg1() {
        let server_secret = gen_keypair();
        let mut responder = NoiseResponder::new(&server_secret).unwrap();

        // Fake msg1: zero ephemeral + zero padding (all-zeros is a low-order point).
        let msg = vec![0u8; HANDSHAKE_PAD_SIZE];
        let err = responder.read_message_1(&msg).unwrap_err();
        assert!(
            err.contains("low-order"),
            "expected low-order rejection, got: {err}"
        );
    }

    #[test]
    fn test_handshake_tampered_msg2_fails() {
        // msg2 is AEAD-authenticated (ee, s, es) — tampering any byte in
        // the fixed snow-payload prefix must cause the initiator to fail.
        let client_secret = gen_keypair();
        let server_secret = gen_keypair();

        let mut initiator = NoiseInitiator::new(&client_secret).unwrap();
        let mut responder = NoiseResponder::new(&server_secret).unwrap();

        let msg1 = initiator.write_message_1().unwrap();
        responder.read_message_1(&msg1).unwrap();
        let mut msg2 = responder.write_message_2(&random_attest_payload()).unwrap();
        // Flip a byte inside the encrypted static block (past the ephemeral)
        msg2[40] ^= 0xFF;
        assert!(initiator.read_message_2(&msg2).is_err());
    }

    #[test]
    fn test_handshake_hash_to_session_keys() {
        use crate::session_keys::SessionKeyManager;

        let k1 = gen_keypair();
        let k2 = gen_keypair();

        let (initiator, responder) = do_handshake(&k1, &k2);

        let client_hash = initiator.get_handshake_hash();
        let server_hash = responder.get_handshake_hash();
        assert_eq!(client_hash, server_hash);

        let mut client_keys =
            SessionKeyManager::from_handshake_hash(&client_hash, true, None, None).unwrap();
        let mut server_keys =
            SessionKeyManager::from_handshake_hash(&server_hash, false, None, None).unwrap();

        let aad = b"e2e";
        let initial_epoch = client_keys.epoch();
        let (nonce, ct, _) = client_keys.encrypt(b"client msg", aad).unwrap();
        let pt = server_keys.decrypt(&nonce, &ct, aad, 1, false).unwrap();
        assert_eq!(pt, b"client msg");

        let (nonce, ct, _) = server_keys.encrypt(b"server msg", aad).unwrap();
        let pt = client_keys.decrypt(&nonce, &ct, aad, 1, false).unwrap();
        assert_eq!(pt, b"server msg");

        // Initial epoch derived from handshake hash is the same on both sides
        // but not deterministically "1".
        assert_eq!(initial_epoch, server_keys.epoch());
    }
}
