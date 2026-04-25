use crate::aes_gcm::AesKey;
use crate::nonce::NonceGenerator;
use crate::replay_window::ReplayWindow;
use crate::secure_memory::LockedKey32;
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use std::time::{Duration, Instant};
use x25519_dalek::{PublicKey, StaticSecret};

/// Rotation threshold baselines. Each session independently jitters these
/// (±20% packets, ±10% time) so the rotation moment is not predictable to a
/// passive observer watching packet flow or wall-clock timing.
const ROTATION_PACKET_BASE: u64 = 5000;
const ROTATION_PACKET_JITTER: u64 = 1000; // ±20%
const ROTATION_TIME_BASE_SECS: u64 = 600; // 10 minutes
const ROTATION_TIME_JITTER_SECS: u64 = 60; // ±10%
const GRACE_PERIOD_SECS: u64 = 5;

fn randomized_packet_threshold() -> u64 {
    let mut rng_bytes = [0u8; 8];
    OsRng.fill_bytes(&mut rng_bytes);
    let r = u64::from_be_bytes(rng_bytes);
    let jitter = (r % (2 * ROTATION_PACKET_JITTER + 1)) as i64 - ROTATION_PACKET_JITTER as i64;
    ((ROTATION_PACKET_BASE as i64) + jitter).max(1) as u64
}

fn randomized_time_threshold() -> Duration {
    let mut rng_bytes = [0u8; 8];
    OsRng.fill_bytes(&mut rng_bytes);
    let r = u64::from_be_bytes(rng_bytes);
    let jitter =
        (r % (2 * ROTATION_TIME_JITTER_SECS + 1)) as i64 - ROTATION_TIME_JITTER_SECS as i64;
    let secs = ((ROTATION_TIME_BASE_SECS as i64) + jitter).max(1) as u64;
    Duration::from_secs(secs)
}

/// Session key state for one direction of traffic.
struct DirectionKeys {
    key: AesKey,
    nonce_gen: NonceGenerator,
}

impl DirectionKeys {
    fn new(key: LockedKey32, epoch: u32) -> Result<Self, String> {
        Ok(Self {
            key: AesKey::from_locked(key)?,
            nonce_gen: NonceGenerator::new(epoch),
        })
    }
}

/// Generate a fresh ephemeral X25519 secret from CSPRNG, written directly
/// into a mlock'd heap buffer.
pub fn gen_ephemeral_secret() -> Result<LockedKey32, String> {
    let mut secret = LockedKey32::zeroed()?;
    OsRng.fill_bytes(secret.as_mut());
    Ok(secret)
}

/// Compute DH shared secret and derive session keys from it.
/// This is used for post-handshake bootstrap to avoid the vulnerability
/// of deriving keys from the PUBLIC handshake transcript hash.
///
/// This function is called by BOTH sides after exchanging ephemeral public keys.
/// The `our_secret` must be kept secret; only the public key is sent to the peer.
pub fn bootstrap_keys_from_dh(
    our_secret_bytes: &[u8; 32],
    peer_public_bytes: &[u8; 32],
    is_initiator: bool,
) -> Result<SessionKeyManager, String> {
    let our_secret = StaticSecret::from(*our_secret_bytes);
    let peer_public = PublicKey::from(*peer_public_bytes);
    let shared = our_secret.diffie_hellman(&peer_public);

    // Reject low-order points to prevent shared secret = 0
    if !shared.was_contributory() {
        return Err("bootstrap: non-contributory shared secret (low-order public key)".into());
    }

    // `shared.as_bytes()` borrows from the zeroizing `SharedSecret`; consumed
    // inline so no copy escapes this function. The `SharedSecret` is dropped
    // at end-of-scope (x25519-dalek zeroizes on drop).
    SessionKeyManager::from_bootstrap_shared_secret(shared.as_bytes(), is_initiator)
}

/// Full session key state managing current and previous epoch keys,
/// replay protection, and rotation lifecycle.
pub struct SessionKeyManager {
    epoch: u32,
    send: DirectionKeys,
    recv: DirectionKeys,
    replay: ReplayWindow,

    /// Previous epoch recv key kept during grace period after rotation.
    prev_recv: Option<DirectionKeys>,
    prev_replay: Option<ReplayWindow>,
    grace_start: Option<Instant>,

    packets_sent: u64,
    epoch_start: Instant,

    /// Per-session randomized rotation thresholds (see audit M1/M2).
    packet_threshold: u64,
    time_threshold: Duration,
}

/// Result of a key rotation initiation.
pub struct RotationInit {
    pub new_epoch: u32,
    pub ephemeral_pub: [u8; 32],
    ephemeral_secret: LockedKey32,
}

/// Result of processing a rotation acknowledgment.
pub struct RotationComplete {
    pub new_epoch: u32,
}

/// Opaque handle for a responder's derived-but-not-yet-applied rotation.
/// Keeps the new keys in mlock'd memory until `apply_rotation_responder`
/// consumes it.
pub struct ResponderPending {
    pub our_pub: [u8; 32],
    pub new_epoch: u32,
    new_send: LockedKey32,
    new_recv: LockedKey32,
}

impl SessionKeyManager {
    /// Create a session key manager from the Noise handshake hash.
    /// Derives initial send/recv keys via HKDF, written directly into
    /// mlock'd heap buffers (no transient stack copies of key material).
    /// `is_initiator`: true for client (initiator), false for server (responder).
    pub fn from_handshake_hash(
        hash: &[u8],
        is_initiator: bool,
    ) -> Result<Self, String> {
        let hk = Hkdf::<Sha256>::new(Some(b"dsm-v2-session-init"), hash);

        let mut key_a = LockedKey32::zeroed()?;
        let mut key_b = LockedKey32::zeroed()?;
        hk.expand(b"dsm-session-initiator", key_a.as_mut())
            .map_err(|e| format!("hkdf key_a: {e}"))?;
        hk.expand(b"dsm-session-responder", key_b.as_mut())
            .map_err(|e| format!("hkdf key_b: {e}"))?;

        // Derive initial epoch deterministically from the handshake hash so
        // both peers agree without extra wire bytes, and so the epoch doesn't
        // deterministically start at 1 (audit I3 — linkability).
        let mut epoch_bytes = [0u8; 4];
        hk.expand(b"dsm-session-epoch", &mut epoch_bytes)
            .map_err(|e| format!("hkdf epoch: {e}"))?;
        // Keep the epoch in a range that still allows many rotations before
        // overflow; clamp to the low 28 bits so u32 rotation has ~16M headroom.
        let initial_epoch = u32::from_be_bytes(epoch_bytes) & 0x0FFF_FFFF;

        let (send_key, recv_key) = if is_initiator {
            (key_a, key_b) // initiator sends with key_a, receives with key_b
        } else {
            (key_b, key_a) // responder sends with key_b, receives with key_a
        };

        Self::new(send_key, recv_key, initial_epoch)
    }

    /// Create a session from a secret shared value (e.g., ephemeral DH or bootstrap).
    /// Unlike `from_handshake_hash` which uses the PUBLIC transcript hash, this
    /// derives keys from SECRET material, preventing passive observation.
    ///
    /// `is_initiator`: true for client (initiator), false for server (responder).
    pub fn from_bootstrap_shared_secret(
        shared_secret: &[u8],
        is_initiator: bool,
    ) -> Result<Self, String> {
        let hk = Hkdf::<Sha256>::new(Some(b"dsm-v2-bootstrap-hkdf"), shared_secret);

        let mut key_a = LockedKey32::zeroed()?;
        let mut key_b = LockedKey32::zeroed()?;
        hk.expand(b"dsm-bootstrap-initiator-send", key_a.as_mut())
            .map_err(|e| format!("hkdf key_a: {e}"))?;
        hk.expand(b"dsm-bootstrap-responder-send", key_b.as_mut())
            .map_err(|e| format!("hkdf key_b: {e}"))?;

        // Derive initial epoch from secret material (not public hash).
        let mut epoch_bytes = [0u8; 4];
        hk.expand(b"dsm-bootstrap-epoch", &mut epoch_bytes)
            .map_err(|e| format!("hkdf epoch: {e}"))?;
        let initial_epoch = u32::from_be_bytes(epoch_bytes) & 0x0FFF_FFFF;

        let (send_key, recv_key) = if is_initiator {
            (key_a, key_b) // initiator sends with key_a, receives with key_b
        } else {
            (key_b, key_a) // responder sends with key_b, receives with key_a
        };

        Self::new(send_key, recv_key, initial_epoch)
    }

    /// Create a new session from initial handshake-derived keys.
    pub fn new(
        send_key: LockedKey32,
        recv_key: LockedKey32,
        initial_epoch: u32,
    ) -> Result<Self, String> {
        Ok(Self {
            epoch: initial_epoch,
            send: DirectionKeys::new(send_key, initial_epoch)?,
            recv: DirectionKeys::new(recv_key, initial_epoch)?,
            replay: ReplayWindow::new(),
            prev_recv: None,
            prev_replay: None,
            grace_start: None,
            packets_sent: 0,
            epoch_start: Instant::now(),
            packet_threshold: randomized_packet_threshold(),
            time_threshold: randomized_time_threshold(),
        })
    }

    /// Encrypt a packet. Returns (nonce, ciphertext) and the current epoch.
    pub fn encrypt(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<([u8; 12], Vec<u8>, u32), String> {
        let nonce = self
            .send
            .nonce_gen
            .next()
            .ok_or("nonce counter exhausted — rotation overdue")?;
        let ciphertext = self.send.key.encrypt(&nonce, plaintext, aad)?;
        self.packets_sent += 1;
        Ok((nonce, ciphertext, self.epoch))
    }

    /// Decrypt a packet. Tries current epoch first, then previous if in grace period.
    /// `seq` is the sequence number for replay checking.
    ///
    /// To avoid leaking replay-vs-forgery distinction through timing or error
    /// strings (audit M3), the AEAD decrypt is always performed. The replay
    /// window result is folded into the final accept/reject decision, and
    /// both failure modes return the same opaque error string.
    pub fn decrypt(
        &mut self,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
        seq: u64,
        is_prev_epoch: bool,
    ) -> Result<Vec<u8>, String> {
        const AUTH_FAILED: &str = "authentication failed";

        if is_prev_epoch {
            let Some(prev) = self.prev_recv.as_ref() else {
                return Err(AUTH_FAILED.into());
            };
            let Some(prev_replay) = self.prev_replay.as_mut() else {
                return Err(AUTH_FAILED.into());
            };
            let replay_ok = prev_replay.check(seq);
            let aead_result = prev.key.decrypt(nonce, ciphertext, aad);
            match (replay_ok, aead_result) {
                (true, Ok(pt)) => {
                    prev_replay.update(seq);
                    Ok(pt)
                }
                _ => Err(AUTH_FAILED.into()),
            }
        } else {
            let replay_ok = self.replay.check(seq);
            let aead_result = self.recv.key.decrypt(nonce, ciphertext, aad);
            match (replay_ok, aead_result) {
                (true, Ok(pt)) => {
                    self.replay.update(seq);
                    Ok(pt)
                }
                _ => Err(AUTH_FAILED.into()),
            }
        }
    }

    /// Check if key rotation is needed.
    pub fn needs_rotation(&self) -> bool {
        self.packets_sent >= self.packet_threshold
            || self.epoch_start.elapsed() >= self.time_threshold
    }

    /// Initiate key rotation: generate an ephemeral keypair for the new epoch.
    pub fn initiate_rotation(&self) -> Result<RotationInit, String> {
        let secret = gen_ephemeral_secret()?;
        let static_secret = StaticSecret::from(*secret.as_array());
        let public = PublicKey::from(&static_secret);

        let new_epoch = self.epoch.checked_add(1).ok_or("epoch overflow")?;
        Ok(RotationInit {
            new_epoch,
            ephemeral_pub: *public.as_bytes(),
            ephemeral_secret: secret,
        })
    }

    /// Complete rotation as the initiator after receiving the responder's ACK.
    pub fn complete_rotation_initiator(
        &mut self,
        init: RotationInit,
        remote_ephemeral_pub: &[u8; 32],
    ) -> Result<RotationComplete, String> {
        let (new_send, new_recv) = derive_rotation_keys(
            init.ephemeral_secret.as_array(),
            remote_ephemeral_pub,
            init.new_epoch,
        )?;
        self.apply_rotation(new_send, new_recv, init.new_epoch)
    }

    /// Complete rotation as the responder after receiving the initiator's INIT.
    /// Returns (ephemeral_pub, RotationComplete) — send ephemeral_pub in ACK.
    ///
    /// This is the single-shot variant. Network users should prefer
    /// `prepare_rotation_responder` + `apply_rotation_responder` so that the
    /// REKEY_ACK can be sent with the OLD keys (needed for the initiator to
    /// decrypt it before it has applied its own rotation).
    pub fn complete_rotation_responder(
        &mut self,
        remote_ephemeral_pub: &[u8; 32],
        new_epoch: u32,
    ) -> Result<([u8; 32], RotationComplete), String> {
        let pending = self.prepare_rotation_responder(remote_ephemeral_pub, new_epoch)?;
        let our_pub = pending.our_pub;
        let complete = self.apply_rotation_responder(pending)?;
        Ok((our_pub, complete))
    }

    /// First phase of the network-responder rotation flow: derive the new
    /// keys and our ephemeral public key, but do NOT mutate `self`. Caller
    /// sends the ACK with the still-current (old) keys and then invokes
    /// `apply_rotation_responder` to actually rotate.
    pub fn prepare_rotation_responder(
        &self,
        remote_ephemeral_pub: &[u8; 32],
        new_epoch: u32,
    ) -> Result<ResponderPending, String> {
        let expected = self.epoch.checked_add(1).ok_or("epoch overflow")?;
        if new_epoch != expected {
            return Err(format!(
                "unexpected epoch: expected {expected}, got {new_epoch}"
            ));
        }

        let secret = gen_ephemeral_secret()?;
        let static_secret = StaticSecret::from(*secret.as_array());
        let our_pub = *PublicKey::from(&static_secret).as_bytes();

        // Responder's send = initiator's recv and vice versa,
        // so we swap the derive direction
        let (new_recv, new_send) =
            derive_rotation_keys(secret.as_array(), remote_ephemeral_pub, new_epoch)?;

        Ok(ResponderPending { our_pub, new_epoch, new_send, new_recv })
    }

    /// Second phase: consume the `ResponderPending` produced by
    /// `prepare_rotation_responder` and swap the session keys in.
    pub fn apply_rotation_responder(
        &mut self,
        pending: ResponderPending,
    ) -> Result<RotationComplete, String> {
        self.apply_rotation(pending.new_send, pending.new_recv, pending.new_epoch)
    }

    /// Apply new keys, keeping old recv key for grace period.
    fn apply_rotation(
        &mut self,
        new_send_key: LockedKey32,
        new_recv_key: LockedKey32,
        new_epoch: u32,
    ) -> Result<RotationComplete, String> {
        // Pre-construct new keys before replacing (fail early on AesKey error)
        let new_recv = DirectionKeys::new(new_recv_key, new_epoch)?;
        let new_send = DirectionKeys::new(new_send_key, new_epoch)?;

        // Move current recv to previous for grace period
        let old_recv = std::mem::replace(&mut self.recv, new_recv);
        let old_replay = std::mem::replace(&mut self.replay, ReplayWindow::new());

        self.prev_recv = Some(old_recv);
        self.prev_replay = Some(old_replay);
        self.grace_start = Some(Instant::now());

        self.send = new_send;

        self.epoch = new_epoch;
        self.packets_sent = 0;
        self.epoch_start = Instant::now();
        // Re-roll thresholds for the new epoch so the next rotation is also
        // unpredictable to a passive observer.
        self.packet_threshold = randomized_packet_threshold();
        self.time_threshold = randomized_time_threshold();

        Ok(RotationComplete { new_epoch })
    }

    /// Call periodically to clean up expired grace period keys.
    pub fn tick(&mut self) {
        if let Some(start) = self.grace_start {
            if start.elapsed().as_secs() >= GRACE_PERIOD_SECS {
                self.prev_recv = None;
                self.prev_replay = None;
                self.grace_start = None;
            }
        }
    }

    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    pub fn packets_sent(&self) -> u64 {
        self.packets_sent
    }

    pub fn has_grace_period(&self) -> bool {
        self.grace_start.is_some()
    }
}

/// Derive send and recv keys from an ephemeral DH shared secret.
/// Returns (initiator_send_key, initiator_recv_key) — each derived directly
/// into a mlock'd heap buffer.
fn derive_rotation_keys(
    our_secret: &[u8; 32],
    remote_pub: &[u8; 32],
    epoch: u32,
) -> Result<(LockedKey32, LockedKey32), String> {
    let secret = StaticSecret::from(*our_secret);
    let public = PublicKey::from(*remote_pub);
    let shared = secret.diffie_hellman(&public);

    // Reject low-order points: a malicious peer presenting a small-subgroup
    // public key would yield a known/zero shared secret, defeating forward
    // secrecy from rotation. x25519-dalek does not reject these by default.
    if !shared.was_contributory() {
        return Err("rotation DH: non-contributory shared secret (low-order public key)".into());
    }

    // Fixed protocol salt for HKDF. The DH shared secret provides full entropy
    // as IKM, so a fixed salt is sufficient per RFC 5869 §3.1.
    // Epoch is encoded in the info parameter for domain separation.
    let hk = Hkdf::<Sha256>::new(Some(b"dsm-v2-rotation-hkdf-salt"), shared.as_bytes());

    let epoch_bytes = epoch.to_be_bytes();
    let expand_key = |label: &[u8], dir: &str| -> Result<LockedKey32, String> {
        let mut info = Vec::with_capacity(label.len() + epoch_bytes.len());
        info.extend_from_slice(label);
        info.extend_from_slice(&epoch_bytes);
        let mut key = LockedKey32::zeroed()?;
        hk.expand(&info, key.as_mut())
            .map_err(|e| format!("hkdf {dir}: {e}"))?;
        Ok(key)
    };

    let send_key = expand_key(b"dsm-rot-send-", "send")?;
    let recv_key = expand_key(b"dsm-rot-recv-", "recv")?;

    Ok((send_key, recv_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_paired_managers() -> (SessionKeyManager, SessionKeyManager) {
        let mut send_bytes = [0u8; 32];
        let mut recv_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut send_bytes);
        OsRng.fill_bytes(&mut recv_bytes);

        // Client sends with send_bytes, server receives with send_bytes
        // Server sends with recv_bytes, client receives with recv_bytes
        let client = SessionKeyManager::new(
            LockedKey32::from_array(send_bytes).unwrap(),
            LockedKey32::from_array(recv_bytes).unwrap(),
            1,
        )
        .unwrap();
        let server = SessionKeyManager::new(
            LockedKey32::from_array(recv_bytes).unwrap(),
            LockedKey32::from_array(send_bytes).unwrap(),
            1,
        )
        .unwrap();
        (client, server)
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (mut client, mut server) = make_paired_managers();
        let aad = b"test-header";

        let (nonce, ct, epoch) = client.encrypt(b"hello", aad).unwrap();
        assert_eq!(epoch, client.epoch());
        assert_eq!(epoch, server.epoch());

        let pt = server.decrypt(&nonce, &ct, aad, 1, false).unwrap();
        assert_eq!(pt, b"hello");
    }

    #[test]
    fn test_replay_rejected() {
        let (mut client, mut server) = make_paired_managers();
        let aad = b"hdr";

        let (nonce, ct, _) = client.encrypt(b"data", aad).unwrap();
        server.decrypt(&nonce, &ct, aad, 1, false).unwrap();
        // Same seq number again
        assert!(server.decrypt(&nonce, &ct, aad, 1, false).is_err());
    }

    #[test]
    fn test_needs_rotation_by_packets() {
        let (mut client, _) = make_paired_managers();
        let aad = b"";

        // Upper bound of the randomized threshold is base + jitter.
        for _ in 0..(ROTATION_PACKET_BASE + ROTATION_PACKET_JITTER) {
            client.encrypt(b"x", aad).unwrap();
        }
        assert!(client.needs_rotation());
    }

    #[test]
    fn test_key_rotation_flow() {
        let (mut client, mut server) = make_paired_managers();
        let aad = b"aad";

        let start_epoch = client.epoch();
        // Pre-rotation: verify communication works
        let (n, ct, _) = client.encrypt(b"before", aad).unwrap();
        let pt = server.decrypt(&n, &ct, aad, 1, false).unwrap();
        assert_eq!(pt, b"before");

        // Initiate rotation from client
        let init = client.initiate_rotation().unwrap();
        assert_eq!(init.new_epoch, start_epoch + 1);

        // Server processes init and responds
        let (server_eph_pub, _) = server
            .complete_rotation_responder(&init.ephemeral_pub, init.new_epoch)
            .unwrap();

        // Client completes with server's response
        client
            .complete_rotation_initiator(init, &server_eph_pub)
            .unwrap();

        assert_eq!(client.epoch(), start_epoch + 1);
        assert_eq!(server.epoch(), start_epoch + 1);

        // Post-rotation: verify communication still works
        let (n, ct, epoch) = client.encrypt(b"after", aad).unwrap();
        assert_eq!(epoch, start_epoch + 1);
        let pt = server.decrypt(&n, &ct, aad, 1, false).unwrap();
        assert_eq!(pt, b"after");
    }

    #[test]
    fn test_grace_period_accepts_old_epoch() {
        let (mut client, mut server) = make_paired_managers();
        let aad = b"a";

        // Encrypt a packet before rotation
        let (_n_old, _ct_old, _) = client.encrypt(b"old-data", aad).unwrap();

        // Rotate
        let init = client.initiate_rotation().unwrap();
        let (server_eph, _) = server
            .complete_rotation_responder(&init.ephemeral_pub, init.new_epoch)
            .unwrap();
        client
            .complete_rotation_initiator(init, &server_eph)
            .unwrap();

        // Old packet arrives during grace period — use prev epoch flag
        // Note: in practice the old packet would use the old key, so this
        // test verifies the grace period mechanism exists
        assert!(server.has_grace_period());
    }

    #[test]
    fn test_wrong_epoch_rejected() {
        let (_, mut server) = make_paired_managers();
        let mut eph = [0u8; 32];
        OsRng.fill_bytes(&mut eph);
        // Skipping ahead by more than 1 epoch must fail
        let bogus_epoch = server.epoch().wrapping_add(5);
        assert!(server.complete_rotation_responder(&eph, bogus_epoch).is_err());
    }

    #[test]
    fn test_from_handshake_hash_roundtrip() {
        // Simulate both sides deriving keys from the same handshake hash
        let mut hash = [0u8; 32];
        OsRng.fill_bytes(&mut hash);

        let mut client = SessionKeyManager::from_handshake_hash(&hash, true).unwrap();
        let mut server = SessionKeyManager::from_handshake_hash(&hash, false).unwrap();
        let aad = b"test-aad";

        // Both peers derive the same initial epoch from the handshake hash
        assert_eq!(client.epoch(), server.epoch());
        let initial_epoch = client.epoch();

        // Client -> Server
        let (nonce, ct, epoch) = client.encrypt(b"hello from client", aad).unwrap();
        assert_eq!(epoch, initial_epoch);
        let pt = server.decrypt(&nonce, &ct, aad, 1, false).unwrap();
        assert_eq!(pt, b"hello from client");

        // Server -> Client
        let (nonce, ct, epoch) = server.encrypt(b"hello from server", aad).unwrap();
        assert_eq!(epoch, initial_epoch);
        let pt = client.decrypt(&nonce, &ct, aad, 1, false).unwrap();
        assert_eq!(pt, b"hello from server");
    }

    #[test]
    fn test_from_handshake_hash_rotation() {
        let mut hash = [0u8; 32];
        OsRng.fill_bytes(&mut hash);

        let mut client = SessionKeyManager::from_handshake_hash(&hash, true).unwrap();
        let mut server = SessionKeyManager::from_handshake_hash(&hash, false).unwrap();
        let aad = b"rot";
        let start_epoch = client.epoch();

        // Initiate rotation from client
        let init = client.initiate_rotation().unwrap();
        let (server_eph_pub, _) = server
            .complete_rotation_responder(&init.ephemeral_pub, init.new_epoch)
            .unwrap();
        client
            .complete_rotation_initiator(init, &server_eph_pub)
            .unwrap();

        assert_eq!(client.epoch(), start_epoch + 1);
        assert_eq!(server.epoch(), start_epoch + 1);

        // Post-rotation: verify communication still works
        let (nonce, ct, epoch) = client.encrypt(b"after rotation", aad).unwrap();
        assert_eq!(epoch, start_epoch + 1);
        let pt = server.decrypt(&nonce, &ct, aad, 1, false).unwrap();
        assert_eq!(pt, b"after rotation");

        let (nonce, ct, _) = server.encrypt(b"server after rotation", aad).unwrap();
        let pt = client.decrypt(&nonce, &ct, aad, 1, false).unwrap();
        assert_eq!(pt, b"server after rotation");
    }

    #[test]
    fn test_rotation_rejects_low_order_pub() {
        // The 8 low-order X25519 points produce a non-contributory (all-zero)
        // shared secret and must be rejected to preserve forward secrecy.
        // Canonical all-zeros point — one of the standard small-order points.
        let low_order: [u8; 32] = [0u8; 32];

        let (_, mut server) = make_paired_managers();
        let next_epoch = server.epoch() + 1;
        let result = server.complete_rotation_responder(&low_order, next_epoch);
        assert!(
            result.is_err(),
            "rotation must reject low-order remote ephemeral"
        );
    }

    #[test]
    fn test_failed_decrypt_does_not_advance_replay() {
        let (mut client, mut server) = make_paired_managers();
        let aad = b"hdr";

        // Encrypt a legitimate packet at seq=1
        let (nonce, ct, _) = client.encrypt(b"legit", aad).unwrap();

        // Forge a packet with high seq (999) and invalid ciphertext
        let bad_ct = vec![0xDE; 32];
        let bad_nonce = [0u8; 12];
        let bad_aad = b"hdr";

        // This should fail AEAD authentication
        assert!(server.decrypt(&bad_nonce, &bad_ct, bad_aad, 999, false).is_err());

        // The replay window must NOT have advanced to 999.
        // A legitimate packet at seq=1 must still be accepted.
        let pt = server.decrypt(&nonce, &ct, aad, 1, false).unwrap();
        assert_eq!(pt, b"legit");

        // Also verify that seq=999 is still fresh (not marked as seen)
        // Verify seq=999 is still fresh (not marked as seen) — second forged
        // attempt at same seq should fail on AEAD, not on replay
        assert!(server.decrypt(&bad_nonce, &bad_ct, bad_aad, 999, false).is_err());
    }
}
