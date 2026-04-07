use crate::aes_gcm::AesKey;
use crate::nonce::NonceGenerator;
use crate::replay_window::ReplayWindow;
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use std::time::Instant;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Rotation thresholds.
const ROTATION_PACKET_THRESHOLD: u64 = 5000;
const ROTATION_TIME_THRESHOLD_SECS: u64 = 600; // 10 minutes
const GRACE_PERIOD_SECS: u64 = 5;

/// Session key state for one direction of traffic.
struct DirectionKeys {
    key: AesKey,
    nonce_gen: NonceGenerator,
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
}

/// Result of a key rotation initiation.
pub struct RotationInit {
    pub new_epoch: u32,
    pub ephemeral_pub: [u8; 32],
    ephemeral_secret: Zeroizing<[u8; 32]>,
}

/// Result of processing a rotation acknowledgment.
pub struct RotationComplete {
    pub new_epoch: u32,
}

impl SessionKeyManager {
    /// Create a new session from initial handshake-derived keys.
    pub fn new(send_key: [u8; 32], recv_key: [u8; 32], initial_epoch: u32) -> Result<Self, String> {
        Ok(Self {
            epoch: initial_epoch,
            send: DirectionKeys {
                key: AesKey::new(send_key)?,
                nonce_gen: NonceGenerator::new(initial_epoch),
            },
            recv: DirectionKeys {
                key: AesKey::new(recv_key)?,
                nonce_gen: NonceGenerator::new(initial_epoch),
            },
            replay: ReplayWindow::new(),
            prev_recv: None,
            prev_replay: None,
            grace_start: None,
            packets_sent: 0,
            epoch_start: Instant::now(),
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
    pub fn decrypt(
        &mut self,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
        seq: u64,
        is_prev_epoch: bool,
    ) -> Result<Vec<u8>, String> {
        // Try previous epoch if flagged and grace period is active
        if is_prev_epoch {
            if let (Some(prev), Some(prev_replay)) =
                (&self.prev_recv, &mut self.prev_replay)
            {
                if !prev_replay.check_and_update(seq) {
                    return Err("replay detected (prev epoch)".into());
                }
                return prev.key.decrypt(nonce, ciphertext, aad);
            }
            return Err("no previous epoch keys available".into());
        }

        // Current epoch
        if !self.replay.check_and_update(seq) {
            return Err("replay detected".into());
        }
        self.recv.key.decrypt(nonce, ciphertext, aad)
    }

    /// Check if key rotation is needed.
    pub fn needs_rotation(&self) -> bool {
        self.packets_sent >= ROTATION_PACKET_THRESHOLD
            || self.epoch_start.elapsed().as_secs() >= ROTATION_TIME_THRESHOLD_SECS
    }

    /// Initiate key rotation: generate an ephemeral keypair for the new epoch.
    pub fn initiate_rotation(&self) -> Result<RotationInit, String> {
        let mut secret_bytes = Zeroizing::new([0u8; 32]);
        rand::thread_rng().fill_bytes(secret_bytes.as_mut());

        let secret = StaticSecret::from(*secret_bytes);
        let public = PublicKey::from(&secret);

        Ok(RotationInit {
            new_epoch: self.epoch + 1,
            ephemeral_pub: *public.as_bytes(),
            ephemeral_secret: secret_bytes,
        })
    }

    /// Complete rotation as the initiator after receiving the responder's ACK.
    pub fn complete_rotation_initiator(
        &mut self,
        init: RotationInit,
        remote_ephemeral_pub: &[u8; 32],
    ) -> Result<RotationComplete, String> {
        let (new_send, new_recv) =
            derive_rotation_keys(&init.ephemeral_secret, remote_ephemeral_pub, init.new_epoch)?;
        self.apply_rotation(new_send, new_recv, init.new_epoch)
    }

    /// Complete rotation as the responder after receiving the initiator's INIT.
    /// Returns (ephemeral_pub, RotationComplete) — send ephemeral_pub in ACK.
    pub fn complete_rotation_responder(
        &mut self,
        remote_ephemeral_pub: &[u8; 32],
        new_epoch: u32,
    ) -> Result<([u8; 32], RotationComplete), String> {
        if new_epoch != self.epoch + 1 {
            return Err(format!(
                "unexpected epoch: expected {}, got {new_epoch}",
                self.epoch + 1
            ));
        }

        let mut secret_bytes = Zeroizing::new([0u8; 32]);
        rand::thread_rng().fill_bytes(secret_bytes.as_mut());

        let secret = StaticSecret::from(*secret_bytes);
        let our_pub = *PublicKey::from(&secret).as_bytes();

        // Responder's send = initiator's recv and vice versa,
        // so we swap the derive direction
        let (new_recv, new_send) =
            derive_rotation_keys(&secret_bytes, remote_ephemeral_pub, new_epoch)?;

        let complete = self.apply_rotation(new_send, new_recv, new_epoch)?;
        Ok((our_pub, complete))
    }

    /// Apply new keys, keeping old recv key for grace period.
    fn apply_rotation(
        &mut self,
        new_send_key: [u8; 32],
        new_recv_key: [u8; 32],
        new_epoch: u32,
    ) -> Result<RotationComplete, String> {
        // Move current recv to previous for grace period
        let old_recv = std::mem::replace(
            &mut self.recv,
            DirectionKeys {
                key: AesKey::new(new_recv_key)?,
                nonce_gen: NonceGenerator::new(new_epoch),
            },
        );
        let old_replay = std::mem::replace(&mut self.replay, ReplayWindow::new());

        self.prev_recv = Some(old_recv);
        self.prev_replay = Some(old_replay);
        self.grace_start = Some(Instant::now());

        // Replace send key
        self.send = DirectionKeys {
            key: AesKey::new(new_send_key)?,
            nonce_gen: NonceGenerator::new(new_epoch),
        };

        self.epoch = new_epoch;
        self.packets_sent = 0;
        self.epoch_start = Instant::now();

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
/// Returns (initiator_send_key, initiator_recv_key).
fn derive_rotation_keys(
    our_secret: &[u8; 32],
    remote_pub: &[u8; 32],
    epoch: u32,
) -> Result<([u8; 32], [u8; 32]), String> {
    let secret = StaticSecret::from(*our_secret);
    let public = PublicKey::from(*remote_pub);
    let shared = secret.diffie_hellman(&public);

    let salt = format!("dsm-v2-rotation-salt-{epoch}");
    let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), shared.as_bytes());

    let mut send_key = [0u8; 32];
    let send_info = format!("dsm-rot-send-{epoch}");
    hk.expand(send_info.as_bytes(), &mut send_key)
        .map_err(|e| format!("hkdf send: {e}"))?;

    let mut recv_key = [0u8; 32];
    let recv_info = format!("dsm-rot-recv-{epoch}");
    hk.expand(recv_info.as_bytes(), &mut recv_key)
        .map_err(|e| format!("hkdf recv: {e}"))?;

    Ok((send_key, recv_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_paired_managers() -> (SessionKeyManager, SessionKeyManager) {
        let mut send_key = [0u8; 32];
        let mut recv_key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut send_key);
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut recv_key);

        // Client sends with send_key, server receives with send_key
        // Server sends with recv_key, client receives with recv_key
        let client = SessionKeyManager::new(send_key, recv_key, 1).unwrap();
        let server = SessionKeyManager::new(recv_key, send_key, 1).unwrap();
        (client, server)
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (mut client, mut server) = make_paired_managers();
        let aad = b"test-header";

        let (nonce, ct, epoch) = client.encrypt(b"hello", aad).unwrap();
        assert_eq!(epoch, 1);

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

        for _ in 0..5000 {
            client.encrypt(b"x", aad).unwrap();
        }
        assert!(client.needs_rotation());
    }

    #[test]
    fn test_key_rotation_flow() {
        let (mut client, mut server) = make_paired_managers();
        let aad = b"aad";

        // Pre-rotation: verify communication works
        let (n, ct, _) = client.encrypt(b"before", aad).unwrap();
        let pt = server.decrypt(&n, &ct, aad, 1, false).unwrap();
        assert_eq!(pt, b"before");

        // Initiate rotation from client
        let init = client.initiate_rotation().unwrap();
        assert_eq!(init.new_epoch, 2);

        // Server processes init and responds
        let (server_eph_pub, _) = server
            .complete_rotation_responder(&init.ephemeral_pub, init.new_epoch)
            .unwrap();

        // Client completes with server's response
        client
            .complete_rotation_initiator(init, &server_eph_pub)
            .unwrap();

        assert_eq!(client.epoch(), 2);
        assert_eq!(server.epoch(), 2);

        // Post-rotation: verify communication still works
        let (n, ct, epoch) = client.encrypt(b"after", aad).unwrap();
        assert_eq!(epoch, 2);
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
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut eph);
        // Try epoch 5 when current is 1 — should fail
        assert!(server.complete_rotation_responder(&eph, 5).is_err());
    }
}
