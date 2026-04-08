use sha2::{Sha256, Digest};
use snow::{Builder, HandshakeState, TransportState};

/// Protocol prologue authenticated by both sides.
/// Format: "DSM" || version(2 bytes) || initiator_role || responder_role
const PROLOGUE: &[u8] = b"DSM\x00\x01\x00\x01";

/// Noise XX cipher suite: X25519 DH, AES-256-GCM, SHA-256.
const NOISE_PATTERN: &str = "Noise_XX_25519_AESGCM_SHA256";

/// Maximum handshake message size (padded to hide message lengths).
pub const HANDSHAKE_PAD_SIZE: usize = 1400;

/// 2-byte length prefix for handshake framing (XOR-obfuscated).
const LEN_PREFIX: usize = 2;

/// Size of the X25519 ephemeral public key in Noise XX msg1.
const EPHEMERAL_SIZE: usize = 32;

/// Derive a 2-byte XOR mask from the ephemeral public key in msg1.
/// The ephemeral is random per session, so the mask varies per session.
/// Both sides can compute this from the wire data — no extra bytes on wire.
fn derive_mask(ephemeral: &[u8]) -> [u8; 2] {
    let hash = Sha256::digest(ephemeral);
    [hash[0], hash[1]]
}

/// Pack a handshake message: [len_be16^mask || snow_data || random_padding]
/// Total output is always HANDSHAKE_PAD_SIZE bytes.
fn pack_handshake(snow_data: &[u8], data_len: usize, mask: &[u8; 2]) -> Vec<u8> {
    use rand::RngCore;
    let mut out = vec![0u8; HANDSHAKE_PAD_SIZE];
    let len_u16 = data_len as u16;
    let len_bytes = len_u16.to_be_bytes();
    out[0] = len_bytes[0] ^ mask[0];
    out[1] = len_bytes[1] ^ mask[1];
    out[LEN_PREFIX..LEN_PREFIX + data_len].copy_from_slice(&snow_data[..data_len]);
    // Fill remainder with random padding
    rand::thread_rng().fill_bytes(&mut out[LEN_PREFIX + data_len..]);
    out
}

/// Unpack a handshake message: extract snow data from [len_be16^mask || data || padding].
fn unpack_handshake<'a>(buf: &'a [u8], mask: &[u8; 2]) -> Result<&'a [u8], String> {
    if buf.len() < LEN_PREFIX {
        return Err("handshake message too short".into());
    }
    let data_len = u16::from_be_bytes([buf[0] ^ mask[0], buf[1] ^ mask[1]]) as usize;
    if LEN_PREFIX + data_len > buf.len() {
        return Err("handshake length prefix exceeds message".into());
    }
    Ok(&buf[LEN_PREFIX..LEN_PREFIX + data_len])
}

/// Initiator (client) side of the Noise XX handshake.
pub struct NoiseInitiator {
    state: HandshakeState,
    /// Per-session mask derived from the ephemeral key in msg1.
    mask: Option<[u8; 2]>,
}

/// Responder (server) side of the Noise XX handshake.
pub struct NoiseResponder {
    state: HandshakeState,
    /// Per-session mask derived from the ephemeral key in msg1.
    mask: Option<[u8; 2]>,
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

        Ok(Self { state, mask: None })
    }

    /// Get the handshake hash. Must be called after handshake completes,
    /// before `into_transport()`. Used to derive initial session keys.
    pub fn get_handshake_hash(&self) -> Vec<u8> {
        self.state.get_handshake_hash().to_vec()
    }

    /// Message 1: -> e
    /// Returns 1400 bytes. No mask on wire — mask is derived from the ephemeral
    /// public key embedded in the Snow payload.
    pub fn write_message_1(&mut self) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; HANDSHAKE_PAD_SIZE];
        let len = self
            .state
            .write_message(&[], &mut buf)
            .map_err(|e| format!("write msg1: {e}"))?;

        // Derive mask from the ephemeral key (first 32 bytes of snow output)
        if len < EPHEMERAL_SIZE {
            return Err("msg1 snow data too short for ephemeral".into());
        }
        let mask = derive_mask(&buf[..EPHEMERAL_SIZE]);
        self.mask = Some(mask);

        Ok(pack_handshake(&buf, len, &mask))
    }

    /// Message 2: <- e, ee, s, es
    /// Returns the server's static public key.
    pub fn read_message_2(&mut self, msg: &[u8]) -> Result<Vec<u8>, String> {
        let mask = self.mask.ok_or("mask not set — call write_message_1 first")?;
        let snow_data = unpack_handshake(msg, &mask)?;
        let mut payload = vec![0u8; HANDSHAKE_PAD_SIZE];
        let _len = self
            .state
            .read_message(snow_data, &mut payload)
            .map_err(|e| format!("read msg2: {e}"))?;

        let remote_static = self
            .state
            .get_remote_static()
            .ok_or("no remote static key after msg2")?
            .to_vec();

        Ok(remote_static)
    }

    /// Message 3: -> s, se
    /// Returns a fixed-size padded message (1400 bytes).
    pub fn write_message_3(&mut self) -> Result<Vec<u8>, String> {
        let mask = self.mask.ok_or("mask not set — call write_message_1 first")?;
        let mut buf = vec![0u8; HANDSHAKE_PAD_SIZE];
        let len = self
            .state
            .write_message(&[], &mut buf)
            .map_err(|e| format!("write msg3: {e}"))?;
        Ok(pack_handshake(&buf, len, &mask))
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

        Ok(Self { state, mask: None })
    }

    /// Get the handshake hash. Must be called after handshake completes,
    /// before `into_transport()`. Used to derive initial session keys.
    pub fn get_handshake_hash(&self) -> Vec<u8> {
        self.state.get_handshake_hash().to_vec()
    }

    /// Message 1: -> e
    /// Input is 1400 bytes. Derives mask from the ephemeral key at fixed offset.
    /// In Noise XX msg1, the ephemeral public key is the first 32 bytes of Snow data,
    /// located at buf[LEN_PREFIX..LEN_PREFIX+32].
    pub fn read_message_1(&mut self, msg: &[u8]) -> Result<(), String> {
        if msg.len() < LEN_PREFIX + EPHEMERAL_SIZE {
            return Err("message 1 too short for ephemeral".into());
        }

        // The ephemeral key is at a fixed offset (after the 2-byte length prefix)
        let ephemeral = &msg[LEN_PREFIX..LEN_PREFIX + EPHEMERAL_SIZE];
        let mask = derive_mask(ephemeral);
        self.mask = Some(mask);

        let snow_data = unpack_handshake(msg, &mask)?;
        let mut payload = vec![0u8; HANDSHAKE_PAD_SIZE];
        self.state
            .read_message(snow_data, &mut payload)
            .map_err(|e| format!("read msg1: {e}"))?;
        Ok(())
    }

    /// Message 2: <- e, ee, s, es
    /// Returns a fixed-size padded message (1400 bytes).
    pub fn write_message_2(&mut self) -> Result<Vec<u8>, String> {
        let mask = self.mask.ok_or("mask not set — call read_message_1 first")?;
        let mut buf = vec![0u8; HANDSHAKE_PAD_SIZE];
        let len = self
            .state
            .write_message(&[], &mut buf)
            .map_err(|e| format!("write msg2: {e}"))?;
        Ok(pack_handshake(&buf, len, &mask))
    }

    /// Message 3: -> s, se
    /// Returns the initiator's static public key.
    pub fn read_message_3(&mut self, msg: &[u8]) -> Result<Vec<u8>, String> {
        let mask = self.mask.ok_or("mask not set — call read_message_1 first")?;
        let snow_data = unpack_handshake(msg, &mask)?;
        let mut payload = vec![0u8; HANDSHAKE_PAD_SIZE];
        let _len = self
            .state
            .read_message(snow_data, &mut payload)
            .map_err(|e| format!("read msg3: {e}"))?;

        let remote_static = self
            .state
            .get_remote_static()
            .ok_or("no remote static key after msg3")?
            .to_vec();

        Ok(remote_static)
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
    use x25519_dalek::{PublicKey, StaticSecret};

    fn gen_keypair() -> [u8; 32] {
        let mut key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut key);
        key
    }

    fn do_handshake(
        client_secret: &[u8; 32],
        server_secret: &[u8; 32],
    ) -> (NoiseInitiator, NoiseResponder) {
        let mut initiator = NoiseInitiator::new(client_secret).unwrap();
        let mut responder = NoiseResponder::new(server_secret).unwrap();

        let msg1 = initiator.write_message_1().unwrap();
        responder.read_message_1(&msg1).unwrap();

        let msg2 = responder.write_message_2().unwrap();
        initiator.read_message_2(&msg2).unwrap();

        let msg3 = initiator.write_message_3().unwrap();
        responder.read_message_3(&msg3).unwrap();

        (initiator, responder)
    }

    #[test]
    fn test_full_handshake() {
        let client_secret = gen_keypair();
        let server_secret = gen_keypair();

        let mut initiator = NoiseInitiator::new(&client_secret).unwrap();
        let mut responder = NoiseResponder::new(&server_secret).unwrap();

        // Message 1: -> e (1400 bytes, no mask prefix on wire)
        let msg1 = initiator.write_message_1().unwrap();
        assert_eq!(msg1.len(), HANDSHAKE_PAD_SIZE);
        responder.read_message_1(&msg1).unwrap();

        // Message 2: <- e, ee, s, es (1400 bytes)
        let msg2 = responder.write_message_2().unwrap();
        assert_eq!(msg2.len(), HANDSHAKE_PAD_SIZE);
        let server_static = initiator.read_message_2(&msg2).unwrap();

        let expected_server_pub = PublicKey::from(&StaticSecret::from(server_secret));
        assert_eq!(server_static, expected_server_pub.as_bytes());

        // Message 3: -> s, se (1400 bytes)
        let msg3 = initiator.write_message_3().unwrap();
        assert_eq!(msg3.len(), HANDSHAKE_PAD_SIZE);
        let client_static = responder.read_message_3(&msg3).unwrap();

        let expected_client_pub = PublicKey::from(&StaticSecret::from(client_secret));
        assert_eq!(client_static, expected_client_pub.as_bytes());

        assert!(initiator.is_handshake_finished());
        assert!(responder.is_handshake_finished());

        let mut client_transport = initiator.into_transport().unwrap();
        let mut server_transport = responder.into_transport().unwrap();

        // Bidirectional transport
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

        let msg2 = responder.write_message_2().unwrap();
        assert_eq!(msg2.len(), HANDSHAKE_PAD_SIZE);

        initiator.read_message_2(&msg2).unwrap();
        let msg3 = initiator.write_message_3().unwrap();
        assert_eq!(msg3.len(), HANDSHAKE_PAD_SIZE);
    }

    #[test]
    fn test_mask_derived_from_ephemeral() {
        // Verify that the mask is set after write_message_1
        let k1 = gen_keypair();
        let mut initiator = NoiseInitiator::new(&k1).unwrap();
        assert!(initiator.mask.is_none());
        initiator.write_message_1().unwrap();
        assert!(initiator.mask.is_some());
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
    fn test_handshake_hash_to_session_keys() {
        use crate::session_keys::SessionKeyManager;

        let k1 = gen_keypair();
        let k2 = gen_keypair();

        let (initiator, responder) = do_handshake(&k1, &k2);

        // Both sides derive session keys from the same handshake hash
        let client_hash = initiator.get_handshake_hash();
        let server_hash = responder.get_handshake_hash();
        assert_eq!(client_hash, server_hash);

        let mut client_keys =
            SessionKeyManager::from_handshake_hash(&client_hash, true, 1).unwrap();
        let mut server_keys =
            SessionKeyManager::from_handshake_hash(&server_hash, false, 1).unwrap();

        // Bidirectional communication works
        let aad = b"e2e";
        let (nonce, ct, _) = client_keys.encrypt(b"client msg", aad).unwrap();
        let pt = server_keys.decrypt(&nonce, &ct, aad, 1, false).unwrap();
        assert_eq!(pt, b"client msg");

        let (nonce, ct, _) = server_keys.encrypt(b"server msg", aad).unwrap();
        let pt = client_keys.decrypt(&nonce, &ct, aad, 1, false).unwrap();
        assert_eq!(pt, b"server msg");
    }
}
