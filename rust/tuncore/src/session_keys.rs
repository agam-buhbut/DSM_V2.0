use crate::aes_gcm::AesKey;
use crate::nonce::NonceGenerator;
use crate::replay_window::ReplayWindow;
use crate::secure_memory::{public_from_locked, LockedKey32};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use std::time::{Duration, Instant};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Default rotation thresholds. Operators can override at session
/// construction; ±[`ROTATION_JITTER_PCT`]% jitter is applied to BOTH
/// packets and time so the rotation moment is not predictable to a
/// passive observer watching packet flow or wall-clock timing.
pub const ROTATION_PACKET_BASE: u64 = 5000;
pub const ROTATION_TIME_BASE_SECS: u64 = 600; // 10 minutes
/// Proportional jitter: ±20% of the operator-supplied base. Absolute
/// jitter (the previous design) produced [1, base+1000] when operators
/// set small bases — making them rotate every packet. Proportional
/// jitter keeps the operator's intent intact across the full range.
const ROTATION_JITTER_PCT: u64 = 20;
/// How long an old recv key stays usable for late packets once the new
/// keys are known to work on both sides.
const GRACE_PERIOD_SECS: u64 = 5;

/// Longest time the responder keeps the old keys while it waits for the
/// first packet sent under the new keys. That packet proves the initiator
/// got REKEY_ACK. If the ACK was lost, the initiator resends REKEY_INIT
/// under the old keys and the responder must still be able to read it and
/// answer with the cached ACK, so this limit must be longer than the
/// initiator's whole retry plan (`REKEY_RETRY_BUDGET` from
/// `REKEY_ACK_TIMEOUT`, `REKEY_EARLY_RETRY_DELAYS` and `MAX_REKEY_RETRIES`
/// in dsm/rekey.py, 68 s today). A Python test checks this. After the
/// limit the responder gives up waiting: it swaps to the new send key and
/// drops the old recv key.
pub const PEER_CONFIRM_LIMIT_SECS: u64 = 75;

/// Cap on operator-supplied rotation bases. The defaults are 5_000 packets
/// and 600 s; the cap leaves several orders of magnitude of headroom while
/// keeping `base * 20 / 100` and the modulus-based jitter calc clear of
/// u64 / i64 boundary cases (`r % (2*j+1)`, `(base as i64) + jitter`).
const ROTATION_BASE_MAX: u64 = 1 << 48;

// Manual .min().max() instead of .clamp(1, ROTATION_BASE_MAX): the
// latter panics if max < min, which is impossible here but adds a panic
// path on a security-critical rotation-threshold callsite. Prefer the
// explicit panic-free form.
#[allow(clippy::manual_clamp)]
fn clamp_base(base: u64) -> u64 {
    base.min(ROTATION_BASE_MAX).max(1)
}

fn jitter_amount(base: u64) -> u64 {
    // `base` is pre-clamped to [1, 2^48] by `clamp_base`, so `base * 20`
    // fits comfortably in u64. Saturating mul is still used as belt-and-
    // suspenders in case future callers bypass the clamp.
    (base.saturating_mul(ROTATION_JITTER_PCT) / 100).max(1)
}

/// Apply ±[`ROTATION_JITTER_PCT`]% jitter to `base` using one CSPRNG
/// draw. Result is clamped at `1` so the returned threshold is never
/// zero. `base` is pre-clamped to `[1, ROTATION_BASE_MAX]` so the
/// internal `2 * j + 1` cannot overflow u64.
fn randomized_threshold(base: u64) -> u64 {
    let base = clamp_base(base);
    let j = jitter_amount(base);
    let mut rng_bytes = [0u8; 8];
    OsRng.fill_bytes(&mut rng_bytes);
    let r = u64::from_be_bytes(rng_bytes);
    // 2*j+1 fits in u64 because j ≤ 2^48 * 20 / 100 < 2^52.
    let jitter = (r % (2 * j + 1)) as i64 - j as i64;
    ((base as i64) + jitter).max(1) as u64
}

struct DirectionKeys {
    key: AesKey,
    nonce_gen: NonceGenerator,
}

impl DirectionKeys {
    fn new(key: LockedKey32, epoch: u32) -> Self {
        Self {
            key: AesKey::from_locked(key),
            nonce_gen: NonceGenerator::new(epoch),
        }
    }
}

/// Generate a fresh ephemeral X25519 secret from CSPRNG, written directly
/// into a mlock'd heap buffer.
pub fn gen_ephemeral_secret() -> Result<LockedKey32, String> {
    crate::secure_memory::random_locked_key32()
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
    rotation_packets: Option<u64>,
    rotation_seconds: Option<u64>,
) -> Result<SessionKeyManager, String> {
    // M-CRYPT-3: wrap the stack copy of the X25519 scalar in
    // Zeroizing so the unnamed temporary produced by `*our_secret_bytes`
    // is zeroed before the stack slot is reused. Without this, the
    // ephemeral bootstrap scalar (the source of forward secrecy for
    // the entire session) lives on the caller's stack frame until
    // overwritten by later activity — recoverable from a post-mortem.
    let scalar = Zeroizing::new(*our_secret_bytes);
    let our_secret = StaticSecret::from(*scalar);
    let peer_public = PublicKey::from(*peer_public_bytes);
    let shared = our_secret.diffie_hellman(&peer_public);

    // Reject low-order points to prevent shared secret = 0
    if !shared.was_contributory() {
        return Err("bootstrap: non-contributory shared secret (low-order public key)".into());
    }

    // `shared.as_bytes()` borrows from the zeroizing `SharedSecret`; consumed
    // inline so no copy escapes this function. The `SharedSecret` is dropped
    // at end-of-scope (x25519-dalek zeroizes on drop).
    SessionKeyManager::from_bootstrap_shared_secret(
        shared.as_bytes(),
        is_initiator,
        rotation_packets,
        rotation_seconds,
    )
}

/// Full session key state managing current and previous epoch keys,
/// replay protection, and rotation lifecycle.
pub struct SessionKeyManager {
    epoch: u32,
    send: DirectionKeys,
    recv: DirectionKeys,
    replay: ReplayWindow,

    /// Previous epoch recv key, kept after a rotation so late packets
    /// under the old key can still be read.
    prev_recv: Option<DirectionKeys>,
    prev_replay: Option<ReplayWindow>,
    /// When set, `prev_recv` is dropped `GRACE_PERIOD_SECS` after this.
    /// `None` while `prev_recv` is held open for an unconfirmed responder
    /// rotation (see `pending_new_send`).
    grace_start: Option<Instant>,

    /// H-BUG-2/3: the NEW send key on the responder side, parked until
    /// the peer proves it has the new keys. The responder swaps its recv
    /// key at once (new-key packets are read with `recv`, old-key ones
    /// with `prev_recv`) but keeps sending under the OLD key, because the
    /// initiator can only read new-key packets after it gets REKEY_ACK.
    /// The ACK can be lost, so the responder waits for the first packet
    /// that decrypts under the new recv key (only a peer that has the ACK
    /// can send one). Then it swaps to the new send key and starts the
    /// short grace for `prev_recv`. Until then `prev_recv` stays open, so
    /// a resent REKEY_INIT under the old key is still read and answered
    /// with the cached ACK under the old send key. `awaiting_peer_since`
    /// bounds the wait to `PEER_CONFIRM_LIMIT_SECS`.
    pending_new_send: Option<DirectionKeys>,
    awaiting_peer_since: Option<Instant>,

    packets_sent: u64,
    epoch_start: Instant,

    /// Per-session randomized rotation thresholds (see audit M1/M2).
    packet_threshold: u64,
    time_threshold: Duration,
    /// Bases used to re-randomize after rotation. Operator-supplied at
    /// session construction; persist so each new epoch uses the same base.
    packet_threshold_base: u64,
    time_threshold_base_secs: u64,
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
    ///
    /// **Insecure for production.** The Noise handshake hash is part of the
    /// public transcript — a passive on-path observer can recompute it and
    /// derive the same session keys. Production code uses
    /// `from_bootstrap_shared_secret` (the SECRET ephemeral-DH path).
    ///
    /// `#[cfg(test)]`-gated so this insecure path cannot be exposed to
    /// Python, called from other crates, or accidentally re-introduced
    /// into a non-test build. Kept for internal tests that exercise the
    /// HKDF/AEAD plumbing without needing to set up a DH peer.
    #[cfg(test)]
    pub(crate) fn from_handshake_hash(
        hash: &[u8],
        is_initiator: bool,
        rotation_packets: Option<u64>,
        rotation_seconds: Option<u64>,
    ) -> Result<Self, String> {
        Self::from_hkdf(
            Hkdf::<Sha256>::new(Some(b"dsm-v2-session-init"), hash),
            b"dsm-session-initiator",
            b"dsm-session-responder",
            b"dsm-session-epoch",
            is_initiator,
            rotation_packets,
            rotation_seconds,
        )
    }

    /// Create a session from a secret shared value (e.g., ephemeral DH or bootstrap).
    /// Unlike `from_handshake_hash` which uses the PUBLIC transcript hash, this
    /// derives keys from SECRET material, preventing passive observation.
    ///
    /// `shared_secret` must be the full 32-byte X25519 DH output. Shorter inputs
    /// would yield deterministic / low-entropy session keys (HKDF tolerates any
    /// IKM length but cannot manufacture entropy that isn't there). Rejecting
    /// anything other than 32 bytes is defense-in-depth: today the only caller
    /// is `bootstrap_keys_from_dh`, which produces exactly 32 bytes from the
    /// X25519 DH; the length check guards against a future Rust caller (or a
    /// re-introduced Python binding) handing us a wrong-sized buffer.
    ///
    /// `is_initiator`: true for client (initiator), false for server (responder).
    pub(crate) fn from_bootstrap_shared_secret(
        shared_secret: &[u8],
        is_initiator: bool,
        rotation_packets: Option<u64>,
        rotation_seconds: Option<u64>,
    ) -> Result<Self, String> {
        if shared_secret.len() != 32 {
            return Err(format!(
                "bootstrap shared_secret must be 32 bytes (X25519 DH output), got {}",
                shared_secret.len()
            ));
        }
        Self::from_hkdf(
            Hkdf::<Sha256>::new(Some(b"dsm-v2-bootstrap-hkdf"), shared_secret),
            b"dsm-bootstrap-initiator-send",
            b"dsm-bootstrap-responder-send",
            b"dsm-bootstrap-epoch",
            is_initiator,
            rotation_packets,
            rotation_seconds,
        )
    }

    /// Shared HKDF-expand-and-build path used by `from_handshake_hash`
    /// and `from_bootstrap_shared_secret`. Caller picks the salt + IKM
    /// (encoded into the `Hkdf`) and the per-direction info labels.
    ///
    fn from_hkdf(
        hk: Hkdf<Sha256>,
        initiator_label: &[u8],
        responder_label: &[u8],
        epoch_label: &[u8],
        is_initiator: bool,
        rotation_packets: Option<u64>,
        rotation_seconds: Option<u64>,
    ) -> Result<Self, String> {
        let mut key_a = LockedKey32::zeroed()?;
        let mut key_b = LockedKey32::zeroed()?;
        hk.expand(initiator_label, key_a.as_mut())
            .map_err(|e| format!("hkdf key_a: {e}"))?;
        hk.expand(responder_label, key_b.as_mut())
            .map_err(|e| format!("hkdf key_b: {e}"))?;

        // Derive initial epoch deterministically from the keying
        // material so both peers agree without an extra wire byte, and
        // so the epoch doesn't deterministically start at 1
        // (audit I3 — linkability).
        let mut epoch_bytes = [0u8; 4];
        hk.expand(epoch_label, &mut epoch_bytes)
            .map_err(|e| format!("hkdf epoch: {e}"))?;
        // Clamp to the low 28 bits so u32 rotation has ~16M headroom.
        let initial_epoch = u32::from_be_bytes(epoch_bytes) & 0x0FFF_FFFF;

        let (send_key, recv_key) = if is_initiator {
            (key_a, key_b)
        } else {
            (key_b, key_a)
        };

        Self::new(
            send_key,
            recv_key,
            initial_epoch,
            rotation_packets,
            rotation_seconds,
        )
    }

    /// Create a new session from initial handshake-derived keys.
    /// `rotation_packets` / `rotation_seconds` override the default thresholds;
    /// `None` means use the built-in defaults. Jitter is always applied.
    pub fn new(
        send_key: LockedKey32,
        recv_key: LockedKey32,
        initial_epoch: u32,
        rotation_packets: Option<u64>,
        rotation_seconds: Option<u64>,
    ) -> Result<Self, String> {
        let packet_base = rotation_packets.unwrap_or(ROTATION_PACKET_BASE);
        let time_base = rotation_seconds.unwrap_or(ROTATION_TIME_BASE_SECS);
        Ok(Self {
            epoch: initial_epoch,
            send: DirectionKeys::new(send_key, initial_epoch),
            recv: DirectionKeys::new(recv_key, initial_epoch),
            replay: ReplayWindow::new(),
            prev_recv: None,
            prev_replay: None,
            grace_start: None,
            pending_new_send: None,
            awaiting_peer_since: None,
            packets_sent: 0,
            epoch_start: Instant::now(),
            packet_threshold: randomized_threshold(packet_base),
            time_threshold: Duration::from_secs(randomized_threshold(time_base)),
            packet_threshold_base: packet_base,
            time_threshold_base_secs: time_base,
        })
    }

    /// Encrypt a packet. Returns (nonce, ciphertext) and the current epoch.
    ///
    /// H-CRYPT-1: `aad` MUST be exactly `seq.to_be_bytes()` (8 bytes) so wire-seq
    /// and authenticated AAD cannot drift apart; any other length is rejected.
    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<([u8; 12], Vec<u8>, u32), String> {
        if aad.len() != 8 {
            return Err(format!(
                "AAD must be 8 bytes (seq as big-endian u64), got {}",
                aad.len()
            ));
        }
        let nonce = self
            .send
            .nonce_gen
            .next()
            .ok_or("nonce counter exhausted — rotation overdue")?;
        let ciphertext = self.send.key.encrypt(&nonce, plaintext, aad)?;
        self.packets_sent += 1;
        // H-CRYPT: return the SEND direction's epoch, not self.epoch.
        // On a responder deferred send-swap self.epoch is already the
        // NEW epoch while self.send still holds the OLD key; returning
        // self.epoch would stamp a NEW nibble on an OLD-key packet and
        // the peer would drop it at the epoch_id check.
        Ok((nonce, ciphertext, self.send.nonce_gen.epoch()))
    }

    /// Decrypt a packet. Tries current epoch first, then previous if in grace period.
    /// `seq` is the sequence number for replay checking.
    ///
    /// To avoid leaking replay-vs-forgery distinction through timing or error
    /// strings (audit M3), the AEAD decrypt is always performed. The replay
    /// window result is folded into the final accept/reject decision, and
    /// both failure modes return the same opaque error string.
    ///
    /// H-CRYPT-1 defensive check: `aad` MUST equal `seq.to_be_bytes()`.
    /// Without this assertion, a future refactor that lets caller-side
    /// AAD drift from caller-side `seq` would silently desync the
    /// replay window from what was authenticated. We compute the
    /// expected AAD internally and reject any mismatch via opaque
    /// AUTH_FAILED (so the check is timing-uniform with a real auth
    /// failure — no separate side channel).
    pub fn decrypt(
        &mut self,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
        seq: u64,
        is_prev_epoch: bool,
    ) -> Result<Vec<u8>, String> {
        const AUTH_FAILED: &str = "authentication failed";

        // L-CRYPT-4: tick() the grace-period machinery at every decrypt
        // so a Python caller that forgets to invoke tick() externally
        // doesn't keep prev_recv alive indefinitely. The cost is one
        // Instant check per packet — negligible.
        self.tick();

        // H-CRYPT-1: enforce AAD-seq binding contract uniformly with
        // AEAD failure so the rejection path is timing-indistinguishable
        // from a forgery. The expected AAD is `seq.to_be_bytes()`; any
        // other shape is a caller contract violation.
        if aad.len() != 8 || aad != seq.to_be_bytes() {
            return Err(AUTH_FAILED.into());
        }

        if is_prev_epoch {
            let Some(prev) = self.prev_recv.as_ref() else {
                return Err(AUTH_FAILED.into());
            };
            let Some(prev_replay) = self.prev_replay.as_mut() else {
                return Err(AUTH_FAILED.into());
            };
            try_decrypt_dir(&prev.key, prev_replay, nonce, ciphertext, aad, seq)
        } else {
            let result = try_decrypt_dir(
                &self.recv.key,
                &mut self.replay,
                nonce,
                ciphertext,
                aad,
                seq,
            );
            if result.is_ok() {
                // A packet under the new recv key proves the peer has the
                // new keys, so a parked send swap can happen now.
                self.confirm_peer_has_new_keys();
            }
            result
        }
    }

    /// Check if key rotation is needed.
    ///
    /// Never true while a responder rotation is still waiting for the
    /// peer to use the new keys: starting another one before the last one
    /// is confirmed could leave the two sides two epochs apart.
    pub fn needs_rotation(&self) -> bool {
        self.pending_new_send.is_none()
            && (self.packets_sent >= self.packet_threshold
                || self.epoch_start.elapsed() >= self.time_threshold)
    }

    /// Initiate key rotation: generate an ephemeral keypair for the new epoch.
    pub fn initiate_rotation(&self) -> Result<RotationInit, String> {
        let secret = gen_ephemeral_secret()?;
        let ephemeral_pub = public_from_locked(&secret);
        let new_epoch = self.epoch.checked_add(1).ok_or("epoch overflow")?;
        Ok(RotationInit {
            new_epoch,
            ephemeral_pub,
            ephemeral_secret: secret,
        })
    }

    /// Complete rotation as the initiator after receiving the responder's ACK.
    pub fn complete_rotation_initiator(
        &mut self,
        init: RotationInit,
        remote_ephemeral_pub: &[u8; 32],
    ) -> Result<RotationComplete, String> {
        // Initiator: our ephemeral is the "initiator" pub, peer's is the
        // "responder" pub. The role binding inside derive_rotation_keys
        // guarantees that our i2r key is the peer's r2i key and vice
        // versa, even if a future refactor reorders the (send, recv)
        // tuple. See `derive_rotation_keys` for the cryptographic
        // binding rationale.
        let (new_send, new_recv) = derive_rotation_keys(
            init.ephemeral_secret.as_array(),
            remote_ephemeral_pub,
            &init.ephemeral_pub,
            /* is_initiator = */ true,
            init.new_epoch,
        )?;
        self.apply_rotation(new_send, new_recv, init.new_epoch)
    }

    /// Complete rotation as the responder after receiving the initiator's INIT.
    /// Returns (ephemeral_pub, RotationComplete) — send ephemeral_pub in ACK.
    ///
    /// Single-shot wrapper over `prepare_rotation_responder` + `apply_rotation_responder`,
    /// kept for tests. Network callers use the two-phase pair so REKEY_ACK is sent under the old keys.
    #[inline]
    #[cfg(test)]
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
        let our_pub = public_from_locked(&secret);

        // Responder: our ephemeral is the "responder" pub, peer's is the
        // "initiator" pub. With role binding inside derive_rotation_keys
        // the returned (send, recv) tuple is from THIS peer's
        // perspective — no caller-side swap required, no risk of a
        // future refactor accidentally re-collapsing both peers onto
        // the same key. The previous code relied on the caller swap
        // for direction safety; the new HKDF info binds the role
        // cryptographically instead.
        let (new_send, new_recv) = derive_rotation_keys(
            secret.as_array(),
            remote_ephemeral_pub,
            &our_pub,
            /* is_initiator = */ false,
            new_epoch,
        )?;

        Ok(ResponderPending {
            our_pub,
            new_epoch,
            new_send,
            new_recv,
        })
    }

    /// Second phase: consume the `ResponderPending` produced by
    /// `prepare_rotation_responder` and swap the session keys in.
    ///
    /// H-BUG-2/3: responder uses the deferred-send-swap variant.
    /// The recv-key swap is immediate, but `send` stays on the OLD key
    /// and `prev_recv` stays open until the first packet under the new
    /// recv key arrives (or `PEER_CONFIRM_LIMIT_SECS` passes). See
    /// `pending_new_send`.
    pub fn apply_rotation_responder(
        &mut self,
        pending: ResponderPending,
    ) -> Result<RotationComplete, String> {
        self.apply_rotation_with_grace(
            pending.new_send,
            pending.new_recv,
            pending.new_epoch,
            /* defer_send = */ true,
        )
    }

    /// Apply new keys, keeping old recv key for grace period.
    fn apply_rotation(
        &mut self,
        new_send_key: LockedKey32,
        new_recv_key: LockedKey32,
        new_epoch: u32,
    ) -> Result<RotationComplete, String> {
        self.apply_rotation_with_grace(new_send_key, new_recv_key, new_epoch, false)
    }

    /// Shared apply-rotation body with optional deferred send-key swap.
    /// When `defer_send=true` (responder), the new send key is parked in
    /// `pending_new_send`, `send` keeps the OLD key and `prev_recv` has no
    /// grace timer yet; the swap happens when the peer is confirmed (or at
    /// the hard limit). When `defer_send=false` (initiator), the swap is
    /// immediate and the grace timer starts now.
    fn apply_rotation_with_grace(
        &mut self,
        new_send_key: LockedKey32,
        new_recv_key: LockedKey32,
        new_epoch: u32,
        defer_send: bool,
    ) -> Result<RotationComplete, String> {
        let new_recv = DirectionKeys::new(new_recv_key, new_epoch);
        let new_send = DirectionKeys::new(new_send_key, new_epoch);

        // A still-parked send key from the last rotation: this new
        // rotation means the peer moved past that epoch, so use it now.
        // Leaving it parked would let a later promotion put an older key
        // back over the one set below.
        self.promote_pending_send();

        let old_recv = std::mem::replace(&mut self.recv, new_recv);
        let old_replay = std::mem::take(&mut self.replay);

        // Replacing prev_recv drops (and zeroizes) the older key, as before.
        self.prev_recv = Some(old_recv);
        self.prev_replay = Some(old_replay);

        let now = Instant::now();
        if defer_send {
            // Keep sending under the OLD key and keep prev_recv open (no
            // grace timer) until the peer is confirmed.
            self.pending_new_send = Some(new_send);
            self.awaiting_peer_since = Some(now);
            self.grace_start = None;
        } else {
            self.send = new_send;
            self.grace_start = Some(now);
        }

        self.epoch = new_epoch;
        self.packets_sent = 0;
        self.epoch_start = Instant::now();
        // Re-roll thresholds for the new epoch so the next rotation is also
        // unpredictable to a passive observer.
        self.packet_threshold = randomized_threshold(self.packet_threshold_base);
        self.time_threshold =
            Duration::from_secs(randomized_threshold(self.time_threshold_base_secs));

        Ok(RotationComplete { new_epoch })
    }

    #[cfg(test)]
    pub fn has_pending_send_swap(&self) -> bool {
        self.pending_new_send.is_some()
    }

    /// Move a parked send key into `send` and stop waiting for the peer.
    /// The old send key is dropped (and zeroized) here.
    fn promote_pending_send(&mut self) {
        if let Some(new_send) = self.pending_new_send.take() {
            self.send = new_send;
        }
        self.awaiting_peer_since = None;
    }

    /// The peer sent a packet under our current recv key. If a responder
    /// rotation was waiting on that, swap the send key now and start the
    /// short grace for the old recv key.
    fn confirm_peer_has_new_keys(&mut self) {
        if self.pending_new_send.is_some() {
            self.promote_pending_send();
            self.grace_start = Some(Instant::now());
        }
    }

    /// Call periodically to clean up expired grace period keys and to
    /// enforce the hard limit on a deferred send-key swap (H-BUG-2/3).
    ///
    /// L-AUDIT-2: call site (`decrypt`) wraps in `py.allow_threads` so
    /// the ~10ns branch asymmetry between grace-active and grace-
    /// inactive states isn't observable as wire timing under the
    /// network-resolution floor. Even so, we sample `Instant::now()`
    /// unconditionally and branch on the comparison only — both
    /// branches do constant per-instance work (taking an Option vs.
    /// leaving it alone), and the secret-dependent path (key swap) is
    /// gated by a time check, not by packet content. No observable
    /// timing leak from packet stream.
    pub fn tick(&mut self) {
        let now = Instant::now();
        let grace_expired = self
            .grace_start
            .map(|start| now.saturating_duration_since(start).as_secs() >= GRACE_PERIOD_SECS)
            .unwrap_or(false);
        let peer_wait_expired = self
            .awaiting_peer_since
            .map(|at| now.saturating_duration_since(at).as_secs() >= PEER_CONFIRM_LIMIT_SECS)
            .unwrap_or(false);

        if peer_wait_expired {
            // The peer never used the new keys: give up waiting, swap to
            // the new send key and drop the old recv key.
            self.promote_pending_send();
        }
        if grace_expired || peer_wait_expired {
            self.prev_recv = None;
            self.prev_replay = None;
            self.grace_start = None;
        }
    }

    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// Epoch of the SEND direction key. Differs from `epoch()` only during
    /// a responder deferred send-swap, where `self.epoch` has advanced to
    /// the new epoch but `self.send` still holds the old key.
    pub fn send_epoch(&self) -> u32 {
        self.send.nonce_gen.epoch()
    }

    /// True while the previous epoch's recv key is still usable.
    pub fn has_grace_period(&self) -> bool {
        self.prev_recv.is_some()
    }

    /// Test helper: move every stored timestamp `by` into the past, as if
    /// that much time had passed.
    #[cfg(test)]
    fn age_for_test(&mut self, by: Duration) {
        // On a machine that booted less than `by` ago the clock cannot go back
        // that far; keep the time as it is instead of panicking.
        let back = |t: Instant| t.checked_sub(by).unwrap_or(t);
        self.grace_start = self.grace_start.map(back);
        self.awaiting_peer_since = self.awaiting_peer_since.map(back);
        self.epoch_start = back(self.epoch_start);
    }
}

/// Shared decrypt-one-direction body for `SessionKeyManager::decrypt`'s
/// current-epoch and prev-epoch (grace) arms, which differ only in which key
/// and replay window they use. The AEAD decrypt runs unconditionally and its
/// result is folded with the replay-window check so both failure modes
/// (replayed or forged) return the SAME opaque error (audit M3). The replay
/// window is advanced only on a fresh, authenticated packet.
fn try_decrypt_dir(
    key: &AesKey,
    replay: &mut ReplayWindow,
    nonce: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
    seq: u64,
) -> Result<Vec<u8>, String> {
    let replay_ok = replay.check(seq);
    let aead_result = key.decrypt(nonce, ciphertext, aad);
    match (replay_ok, aead_result) {
        (true, Ok(pt)) => {
            replay.update(seq);
            Ok(pt)
        }
        _ => Err("authentication failed".into()),
    }
}

/// Derive send and recv keys from an ephemeral DH shared secret.
/// Returns (initiator_send_key, initiator_recv_key) — each derived directly
/// into a mlock'd heap buffer.
fn derive_rotation_keys(
    our_secret: &[u8; 32],
    remote_pub: &[u8; 32],
    our_pub: &[u8; 32],
    is_initiator: bool,
    epoch: u32,
) -> Result<(LockedKey32, LockedKey32), String> {
    // M-CRYPT-3: wrap the dereferenced scalar copy in Zeroizing.
    let scalar = Zeroizing::new(*our_secret);
    let secret = StaticSecret::from(*scalar);
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
    let hk = Hkdf::<Sha256>::new(Some(b"dsm-v2-rotation-hkdf-salt"), shared.as_bytes());

    // Role-binding HKDF info: bind BOTH ephemeral public keys (in a
    // canonical initiator-then-responder order) + the epoch + a fixed
    // direction label (`i2r` = initiator-to-responder, `r2i` = the
    // reverse). The previous code used `send`/`recv` labels that depend
    // on the caller for direction correctness — a refactor that dropped
    // the caller-side (send, recv) tuple swap in `prepare_rotation_
    // responder` would silently re-collapse both peers onto the SAME
    // per-direction key (catastrophic confused-deputy). With roles bound
    // into the info, the returned (send, recv) tuple is unambiguously
    // from THIS peer's perspective — no caller swap required.
    let (init_pub, resp_pub) = if is_initiator {
        (our_pub, remote_pub)
    } else {
        (remote_pub, our_pub)
    };
    let epoch_bytes = epoch.to_be_bytes();
    let build_info = |dir_label: &[u8]| -> Vec<u8> {
        let mut info = Vec::with_capacity(dir_label.len() + 4 + 32 + 32);
        info.extend_from_slice(dir_label);
        info.extend_from_slice(&epoch_bytes);
        info.extend_from_slice(init_pub);
        info.extend_from_slice(resp_pub);
        info
    };
    let expand_key = |info: &[u8], err_label: &str| -> Result<LockedKey32, String> {
        let mut key = LockedKey32::zeroed()?;
        hk.expand(info, key.as_mut())
            .map_err(|e| format!("hkdf {err_label}: {e}"))?;
        Ok(key)
    };

    let info_i2r = build_info(b"dsm-rot-i2r-v2-");
    let info_r2i = build_info(b"dsm-rot-r2i-v2-");

    if is_initiator {
        let send_key = expand_key(&info_i2r, "i2r")?;
        let recv_key = expand_key(&info_r2i, "r2i")?;
        Ok((send_key, recv_key))
    } else {
        let send_key = expand_key(&info_r2i, "r2i")?;
        let recv_key = expand_key(&info_i2r, "i2r")?;
        Ok((send_key, recv_key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression for H-BUG-2/3: after `apply_rotation_responder`, the
    /// responder MUST still be sending under the OLD key (deferred-
    /// send-swap) so the initiator — which hasn't applied its rotation
    /// yet (still mid-flight to receive REKEY_ACK) — can decrypt the
    /// responder's data using its CURRENT recv key. tick() promotes
    /// the parked pending_new_send only after grace expires.
    #[test]
    fn responder_defers_send_swap_so_pre_rotation_peer_can_decrypt() {
        let (mut client, mut server) = make_paired_managers();
        let aad = &1u64.to_be_bytes();

        // Server-side rotation: prepare + apply (deferred-send).
        let init_keypair = client.initiate_rotation().unwrap();
        let pending = server
            .prepare_rotation_responder(&init_keypair.ephemeral_pub, init_keypair.new_epoch)
            .unwrap();
        let _our_pub = pending.our_pub;
        server.apply_rotation_responder(pending).unwrap();

        // Server has applied its recv-key swap (epoch incremented) but
        // still has the OLD send key parked while pending_new_send is
        // waiting on tick().
        assert!(
            server.has_pending_send_swap(),
            "responder must defer send swap"
        );

        // Client has NOT yet applied. Server encrypts data: it should
        // use the OLD send key so the still-pre-rotation client can
        // decrypt with its current (still OLD) recv key.
        let (nonce, ct, _) = server.encrypt(b"mid-rotation data", aad).unwrap();
        let pt = client.decrypt(&nonce, &ct, aad, 1, false).unwrap();
        assert_eq!(pt, b"mid-rotation data");
    }

    /// Regression for A1: while a deferred send-swap is pending, the epoch
    /// returned by `encrypt()` MUST be the OLD (send-direction) epoch, not
    /// the already-advanced `self.epoch`. Otherwise Python stamps the NEW
    /// nibble onto an OLD-key packet and the peer drops it.
    #[test]
    fn encrypt_returns_old_epoch_while_send_swap_pending() {
        let (client, mut server) = make_paired_managers();
        let aad = &1u64.to_be_bytes();

        let old_epoch = server.epoch();
        let init_keypair = client.initiate_rotation().unwrap();
        let pending = server
            .prepare_rotation_responder(&init_keypair.ephemeral_pub, init_keypair.new_epoch)
            .unwrap();
        server.apply_rotation_responder(pending).unwrap();

        assert!(server.has_pending_send_swap());
        // self.epoch has advanced, but the send key (and thus the stamped
        // epoch) must still be the old one.
        assert_eq!(server.epoch(), old_epoch + 1);
        let (_nonce, _ct, epoch) = server.encrypt(b"data", aad).unwrap();
        assert_eq!(epoch, old_epoch, "encrypt must return the OLD send epoch");
        assert_eq!(server.send_epoch(), old_epoch);
    }

    /// Regression for H-CRYPT-2: `derive_rotation_keys` MUST NOT depend
    /// on a caller-side (send, recv) tuple swap for direction
    /// correctness. With role binding inside the HKDF info, the
    /// initiator's send key is the responder's recv key and vice
    /// versa, regardless of which order the caller unpacks the tuple.
    #[test]
    fn rotation_key_direction_binding_is_role_bound() {
        let mut init_secret = [0u8; 32];
        let mut resp_secret = [0u8; 32];
        OsRng.fill_bytes(&mut init_secret);
        OsRng.fill_bytes(&mut resp_secret);

        let init_pub = *PublicKey::from(&StaticSecret::from(init_secret)).as_bytes();
        let resp_pub = *PublicKey::from(&StaticSecret::from(resp_secret)).as_bytes();
        let epoch: u32 = 42;

        let (init_send, init_recv) = derive_rotation_keys(
            &init_secret,
            &resp_pub,
            &init_pub,
            /* is_initiator = */ true,
            epoch,
        )
        .unwrap();
        let (resp_send, resp_recv) = derive_rotation_keys(
            &resp_secret,
            &init_pub,
            &resp_pub,
            /* is_initiator = */ false,
            epoch,
        )
        .unwrap();

        // Cross-direction agreement: each peer's send == other's recv.
        assert_eq!(
            init_send.as_array(),
            resp_recv.as_array(),
            "initiator send key must equal responder recv key (i2r channel)",
        );
        assert_eq!(
            init_recv.as_array(),
            resp_send.as_array(),
            "responder send key must equal initiator recv key (r2i channel)",
        );
        // Direction separation: send key MUST differ from recv key.
        // Without role binding the previous code had this property only
        // by virtue of using two different HKDF info labels — but the
        // labels were caller-controlled. With role binding it's
        // unconditional.
        assert_ne!(
            init_send.as_array(),
            init_recv.as_array(),
            "initiator send and recv MUST be derived from different HKDF info",
        );
        assert_ne!(
            resp_send.as_array(),
            resp_recv.as_array(),
            "responder send and recv MUST be derived from different HKDF info",
        );
    }

    /// Defence-in-depth: if BOTH peers accidentally called with
    /// `is_initiator = true` (e.g. a refactor regression), they should
    /// derive INCOMPATIBLE keys — neither can decrypt the other —
    /// rather than silently end up with the same key both directions
    /// (catastrophic confused-deputy that the audit flagged as the
    /// failure mode of the previous design).
    #[test]
    fn rotation_key_both_initiator_yields_incompatible_keys() {
        let mut a_secret = [0u8; 32];
        let mut b_secret = [0u8; 32];
        OsRng.fill_bytes(&mut a_secret);
        OsRng.fill_bytes(&mut b_secret);
        let a_pub = *PublicKey::from(&StaticSecret::from(a_secret)).as_bytes();
        let b_pub = *PublicKey::from(&StaticSecret::from(b_secret)).as_bytes();

        let (a_send, _) = derive_rotation_keys(&a_secret, &b_pub, &a_pub, true, 1).unwrap();
        // B also calls with is_initiator=true (wrong!). HKDF info
        // canonicalizes (init_pub, resp_pub), so B's view of the
        // initiator-vs-responder ordering disagrees with A's whenever
        // a_pub != b_pub. As long as the canonical ordering picks a
        // different "init_pub" in B's call than in A's call, the keys
        // are different. The test asserts the strong property: the
        // first byte of A's send key is not equal to the first byte of
        // anything B derived.
        let (b_send, b_recv) = derive_rotation_keys(&b_secret, &a_pub, &b_pub, true, 1).unwrap();
        // Either of these two must differ — most likely both.
        let a_send_eq_b_send = a_send.as_array() == b_send.as_array();
        let a_send_eq_b_recv = a_send.as_array() == b_recv.as_array();
        assert!(
            !(a_send_eq_b_send && a_send_eq_b_recv),
            "two parties both claiming initiator must not converge on same key in both directions",
        );
    }

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
            None,
            None,
        )
        .unwrap();
        let server = SessionKeyManager::new(
            LockedKey32::from_array(recv_bytes).unwrap(),
            LockedKey32::from_array(send_bytes).unwrap(),
            1,
            None,
            None,
        )
        .unwrap();
        (client, server)
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (mut client, mut server) = make_paired_managers();
        let aad = &1u64.to_be_bytes();

        let (nonce, ct, epoch) = client.encrypt(b"hello", aad).unwrap();
        assert_eq!(epoch, client.epoch());
        assert_eq!(epoch, server.epoch());

        let pt = server.decrypt(&nonce, &ct, aad, 1, false).unwrap();
        assert_eq!(pt, b"hello");
    }

    #[test]
    fn test_replay_rejected() {
        let (mut client, mut server) = make_paired_managers();
        let aad = &1u64.to_be_bytes();

        let (nonce, ct, _) = client.encrypt(b"data", aad).unwrap();
        server.decrypt(&nonce, &ct, aad, 1, false).unwrap();
        assert!(server.decrypt(&nonce, &ct, aad, 1, false).is_err());
    }

    #[test]
    fn test_needs_rotation_by_packets() {
        let (mut client, _) = make_paired_managers();
        let aad = &1u64.to_be_bytes();

        // Upper bound of the randomized threshold is base + 20%.
        let upper = ROTATION_PACKET_BASE + jitter_amount(ROTATION_PACKET_BASE);
        for _ in 0..upper {
            client.encrypt(b"x", aad).unwrap();
        }
        assert!(client.needs_rotation());
    }

    #[test]
    fn test_key_rotation_flow() {
        let (mut client, mut server) = make_paired_managers();
        let aad = &1u64.to_be_bytes();

        let start_epoch = client.epoch();
        let (n, ct, _) = client.encrypt(b"before", aad).unwrap();
        let pt = server.decrypt(&n, &ct, aad, 1, false).unwrap();
        assert_eq!(pt, b"before");

        let init = client.initiate_rotation().unwrap();
        assert_eq!(init.new_epoch, start_epoch + 1);

        let (server_eph_pub, _) = server
            .complete_rotation_responder(&init.ephemeral_pub, init.new_epoch)
            .unwrap();

        client
            .complete_rotation_initiator(init, &server_eph_pub)
            .unwrap();

        assert_eq!(client.epoch(), start_epoch + 1);
        assert_eq!(server.epoch(), start_epoch + 1);

        let (n, ct, epoch) = client.encrypt(b"after", aad).unwrap();
        assert_eq!(epoch, start_epoch + 1);
        let pt = server.decrypt(&n, &ct, aad, 1, false).unwrap();
        assert_eq!(pt, b"after");
    }

    #[test]
    fn test_grace_period_accepts_old_epoch() {
        let (mut client, mut server) = make_paired_managers();
        let aad = &1u64.to_be_bytes();

        let (_n_old, _ct_old, _) = client.encrypt(b"old-data", aad).unwrap();

        let init = client.initiate_rotation().unwrap();
        let (server_eph, _) = server
            .complete_rotation_responder(&init.ephemeral_pub, init.new_epoch)
            .unwrap();
        client
            .complete_rotation_initiator(init, &server_eph)
            .unwrap();

        assert!(server.has_grace_period());
    }

    #[test]
    fn test_wrong_epoch_rejected() {
        let (_, mut server) = make_paired_managers();
        let mut eph = [0u8; 32];
        OsRng.fill_bytes(&mut eph);
        // Skipping ahead by more than 1 epoch must fail
        let bogus_epoch = server.epoch().wrapping_add(5);
        assert!(server
            .complete_rotation_responder(&eph, bogus_epoch)
            .is_err());
    }

    #[test]
    fn test_from_handshake_hash_roundtrip() {
        let mut hash = [0u8; 32];
        OsRng.fill_bytes(&mut hash);

        let mut client = SessionKeyManager::from_handshake_hash(&hash, true, None, None).unwrap();
        let mut server = SessionKeyManager::from_handshake_hash(&hash, false, None, None).unwrap();
        let aad = &1u64.to_be_bytes();

        assert_eq!(client.epoch(), server.epoch());
        let initial_epoch = client.epoch();

        let (nonce, ct, epoch) = client.encrypt(b"hello from client", aad).unwrap();
        assert_eq!(epoch, initial_epoch);
        let pt = server.decrypt(&nonce, &ct, aad, 1, false).unwrap();
        assert_eq!(pt, b"hello from client");

        let (nonce, ct, epoch) = server.encrypt(b"hello from server", aad).unwrap();
        assert_eq!(epoch, initial_epoch);
        let pt = client.decrypt(&nonce, &ct, aad, 1, false).unwrap();
        assert_eq!(pt, b"hello from server");
    }

    #[test]
    fn test_from_handshake_hash_rotation() {
        let mut hash = [0u8; 32];
        OsRng.fill_bytes(&mut hash);

        let mut client = SessionKeyManager::from_handshake_hash(&hash, true, None, None).unwrap();
        let mut server = SessionKeyManager::from_handshake_hash(&hash, false, None, None).unwrap();
        let aad = &1u64.to_be_bytes();
        let start_epoch = client.epoch();

        let init = client.initiate_rotation().unwrap();
        let (server_eph_pub, _) = server
            .complete_rotation_responder(&init.ephemeral_pub, init.new_epoch)
            .unwrap();
        client
            .complete_rotation_initiator(init, &server_eph_pub)
            .unwrap();

        assert_eq!(client.epoch(), start_epoch + 1);
        assert_eq!(server.epoch(), start_epoch + 1);

        let (nonce, ct, epoch) = client.encrypt(b"after rotation", aad).unwrap();
        assert_eq!(epoch, start_epoch + 1);
        let pt = server.decrypt(&nonce, &ct, aad, 1, false).unwrap();
        assert_eq!(pt, b"after rotation");

        // H-BUG-2/3: server defers its send-key swap during grace period.
        // So server.encrypt produces OLD-key ciphertext for the first
        // ~5s after responder apply. Client at this point has applied
        // its own swap (current recv = NEW; prev_recv = OLD). Production
        // Python `_decrypt_with_fallback` tries current first, then prev;
        // mirror that pattern here.
        let (nonce, ct, _) = server.encrypt(b"server after rotation", aad).unwrap();
        let pt = client
            .decrypt(&nonce, &ct, aad, 1, false)
            .or_else(|_| client.decrypt(&nonce, &ct, aad, 1, /* is_prev_epoch = */ true))
            .unwrap();
        assert_eq!(pt, b"server after rotation");
    }

    #[test]
    fn test_from_bootstrap_shared_secret_requires_32_bytes() {
        // The PyO3 binding for this constructor was retired in audit M4,
        // but the length check stays as defense-in-depth for any future
        // Rust caller. HKDF tolerates any IKM length; rejecting non-32
        // inputs prevents low-entropy keys from a short or empty buffer.
        for bad_len in [0usize, 1, 16, 31, 33, 64, 128] {
            let bad = vec![0u8; bad_len];
            match SessionKeyManager::from_bootstrap_shared_secret(&bad, true, None, None) {
                Ok(_) => panic!("len={bad_len} must be rejected"),
                Err(err) => assert!(
                    err.contains("32 bytes"),
                    "len={bad_len}: expected 32-byte rejection, got: {err}"
                ),
            }
        }
        // Exact 32 bytes must succeed.
        let good = vec![0xAAu8; 32];
        assert!(SessionKeyManager::from_bootstrap_shared_secret(&good, true, None, None).is_ok());
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
        let aad = &1u64.to_be_bytes();

        let (nonce, ct, _) = client.encrypt(b"legit", aad).unwrap();

        // Forge a packet with high seq (999) and invalid ciphertext
        let bad_ct = vec![0xDE; 32];
        let bad_nonce = [0u8; 12];
        let bad_aad = b"hdr";

        assert!(server
            .decrypt(&bad_nonce, &bad_ct, bad_aad, 999, false)
            .is_err());

        // The replay window must NOT have advanced to 999.
        // A legitimate packet at seq=1 must still be accepted.
        let pt = server.decrypt(&nonce, &ct, aad, 1, false).unwrap();
        assert_eq!(pt, b"legit");

        // Verify seq=999 is still fresh (not marked as seen) — second forged
        // attempt at same seq should fail on AEAD, not on replay
        assert!(server
            .decrypt(&bad_nonce, &bad_ct, bad_aad, 999, false)
            .is_err());
    }
    /// Send one packet from `from` to `to` and report whether `to` could
    /// read it, trying the current recv key first and then the old one,
    /// like `try_decrypt_with_fallback` in lib.rs.
    fn delivers(
        from: &mut SessionKeyManager,
        to: &mut SessionKeyManager,
        seq: u64,
        msg: &[u8],
    ) -> bool {
        let aad = seq.to_be_bytes();
        let (nonce, ct, _) = from.encrypt(msg, &aad).unwrap();
        to.decrypt(&nonce, &ct, &aad, seq, false)
            .or_else(|_| to.decrypt(&nonce, &ct, &aad, seq, true))
            .is_ok_and(|pt| pt == msg)
    }

    /// Responder applies a rotation; returns (init, responder ephemeral
    /// pub) so the test can later complete the initiator side, as if the
    /// REKEY_ACK arrived.
    fn responder_applies(
        client: &SessionKeyManager,
        server: &mut SessionKeyManager,
    ) -> (RotationInit, [u8; 32]) {
        let init = client.initiate_rotation().unwrap();
        let pending = server
            .prepare_rotation_responder(&init.ephemeral_pub, init.new_epoch)
            .unwrap();
        let server_pub = pending.our_pub;
        server.apply_rotation_responder(pending).unwrap();
        (init, server_pub)
    }

    /// The REKEY_ACK is lost and the initiator's resent INIT only arrives
    /// long after the old 5 s grace. The responder must still read the old
    /// key INIT and answer under the old send key; once the initiator has
    /// the ACK and sends under the new key, both sides talk on new keys.
    #[test]
    fn lost_ack_then_late_retry_recovers() {
        let (mut client, mut server) = make_paired_managers();
        let old_epoch = client.epoch();
        let (init, server_pub) = responder_applies(&client, &mut server);

        // ACK lost. Time passes well beyond GRACE_PERIOD_SECS but inside
        // the initiator's retry plan.
        server.age_for_test(Duration::from_secs(50));
        server.tick();
        assert!(server.has_grace_period(), "old recv key must stay open");
        assert_eq!(server.send_epoch(), old_epoch, "send must stay on old key");

        // Resent INIT (old key) reaches the server; the cached ACK goes
        // back under the old send key and the client can read it.
        assert!(delivers(&mut client, &mut server, 10, b"resent INIT"));
        assert!(delivers(&mut server, &mut client, 10, b"cached ACK"));

        client
            .complete_rotation_initiator(init, &server_pub)
            .unwrap();
        assert!(delivers(&mut client, &mut server, 11, b"first new-key"));
        assert_eq!(server.send_epoch(), old_epoch + 1);
        assert!(delivers(&mut server, &mut client, 11, b"server new-key"));
    }

    /// The first packet under the new recv key swaps the send key at once
    /// and starts the short grace; the old recv key goes after
    /// GRACE_PERIOD_SECS.
    #[test]
    fn first_new_key_packet_triggers_send_swap() {
        let (mut client, mut server) = make_paired_managers();
        let old_epoch = client.epoch();
        let (init, server_pub) = responder_applies(&client, &mut server);

        // An old-key packet does not count as proof.
        assert!(delivers(&mut client, &mut server, 1, b"old-key data"));
        assert!(server.has_pending_send_swap());

        client
            .complete_rotation_initiator(init, &server_pub)
            .unwrap();
        assert!(delivers(&mut client, &mut server, 2, b"new-key data"));
        assert!(!server.has_pending_send_swap());
        assert_eq!(server.send_epoch(), old_epoch + 1);
        assert!(server.has_grace_period(), "late old-key packets still read");

        server.age_for_test(Duration::from_secs(GRACE_PERIOD_SECS - 1));
        server.tick();
        assert!(server.has_grace_period());
        server.age_for_test(Duration::from_secs(1));
        server.tick();
        assert!(!server.has_grace_period());
    }

    /// If the peer never sends under the new keys, the responder stops
    /// waiting at PEER_CONFIRM_LIMIT_SECS: new send key, old recv key gone.
    #[test]
    fn peer_confirm_limit_falls_back_to_swap_and_drop() {
        let (mut client, mut server) = make_paired_managers();
        let old_epoch = client.epoch();
        let _ = responder_applies(&client, &mut server);

        server.age_for_test(Duration::from_secs(PEER_CONFIRM_LIMIT_SECS - 1));
        server.tick();
        assert!(server.has_pending_send_swap());
        assert!(server.has_grace_period());

        server.age_for_test(Duration::from_secs(1));
        server.tick();
        assert!(!server.has_pending_send_swap());
        assert!(!server.has_grace_period());
        assert_eq!(server.send_epoch(), old_epoch + 1);
        assert!(!delivers(&mut client, &mut server, 1, b"old-key data"));
    }

    /// Normal case, no loss: both sides end on the new keys and the old
    /// recv keys are dropped after the grace.
    #[test]
    fn normal_rotation_ends_on_new_keys() {
        let (mut client, mut server) = make_paired_managers();
        let new_epoch = client.epoch() + 1;
        let (init, server_pub) = responder_applies(&client, &mut server);
        client
            .complete_rotation_initiator(init, &server_pub)
            .unwrap();

        assert!(delivers(&mut client, &mut server, 1, b"c2s"));
        assert!(delivers(&mut server, &mut client, 1, b"s2c"));
        assert_eq!(client.send_epoch(), new_epoch);
        assert_eq!(server.send_epoch(), new_epoch);

        for keys in [&mut client, &mut server] {
            keys.age_for_test(Duration::from_secs(GRACE_PERIOD_SECS));
            keys.tick();
            assert!(!keys.has_grace_period());
        }
        assert!(delivers(&mut client, &mut server, 2, b"c2s later"));
        assert!(delivers(&mut server, &mut client, 2, b"s2c later"));
    }

    /// No new rotation starts while the last one waits for the peer.
    #[test]
    fn no_rotation_due_while_waiting_for_peer() {
        let mut send_bytes = [0u8; 32];
        let mut recv_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut send_bytes);
        OsRng.fill_bytes(&mut recv_bytes);
        let client = SessionKeyManager::new(
            LockedKey32::from_array(send_bytes).unwrap(),
            LockedKey32::from_array(recv_bytes).unwrap(),
            1,
            None,
            None,
        )
        .unwrap();
        // Rotation due after 1 or 2 packets.
        let mut server = SessionKeyManager::new(
            LockedKey32::from_array(recv_bytes).unwrap(),
            LockedKey32::from_array(send_bytes).unwrap(),
            1,
            Some(1),
            None,
        )
        .unwrap();
        let _ = responder_applies(&client, &mut server);
        for seq in 1..=3u64 {
            server.encrypt(b"x", &seq.to_be_bytes()).unwrap();
        }
        assert!(!server.needs_rotation());

        server.age_for_test(Duration::from_secs(PEER_CONFIRM_LIMIT_SECS));
        server.tick();
        assert!(server.needs_rotation());
    }

    /// A second responder rotation before the first was confirmed uses the
    /// first one's parked send key, so a stale key can never come back.
    #[test]
    fn second_rotation_promotes_parked_send_key() {
        let (mut client, mut server) = make_paired_managers();
        let start = client.epoch();
        let (init, server_pub) = responder_applies(&client, &mut server);
        client
            .complete_rotation_initiator(init, &server_pub)
            .unwrap();
        let (init2, server_pub2) = responder_applies(&client, &mut server);
        assert_eq!(server.send_epoch(), start + 1);
        assert!(delivers(&mut server, &mut client, 1, b"epoch+1 data"));

        client
            .complete_rotation_initiator(init2, &server_pub2)
            .unwrap();
        assert!(delivers(&mut client, &mut server, 1, b"epoch+2 data"));
        assert_eq!(server.send_epoch(), start + 2);
        assert!(delivers(&mut server, &mut client, 2, b"epoch+2 reply"));
    }
}
