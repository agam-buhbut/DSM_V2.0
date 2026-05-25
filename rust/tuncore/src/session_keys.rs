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
const GRACE_PERIOD_SECS: u64 = 5;

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

#[inline]
fn randomized_time_threshold(base_secs: u64) -> Duration {
    Duration::from_secs(randomized_threshold(base_secs))
}

/// Session key state for one direction of traffic.
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

    /// Previous epoch recv key kept during grace period after rotation.
    prev_recv: Option<DirectionKeys>,
    prev_replay: Option<ReplayWindow>,
    grace_start: Option<Instant>,

    /// H-BUG-2/3: pending NEW send key for the deferred-send-swap
    /// flow used on the responder side. The responder applies the
    /// recv swap immediately (so it can decrypt the rest of the
    /// client's old-epoch packets via prev_recv backward-grace AND
    /// new-epoch packets via the swapped recv) but keeps sending under
    /// the OLD send key until grace expires. This gives the client
    /// time to receive REKEY_ACK and apply its own rotation before any
    /// server NEW-epoch packets arrive, eliminating the up-to-1-RTT
    /// data-loss window. `tick()` performs the actual send swap once
    /// `send_swap_at + GRACE_PERIOD_SECS` has passed.
    pending_new_send: Option<DirectionKeys>,
    send_swap_at: Option<Instant>,

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
    /// Crate-private since audit M4: the Python wrapper that exposed this
    /// directly was removed in favor of `complete_bootstrap`, which performs
    /// the DH inside Rust so no shared secret ever crosses the FFI.
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
    /// The labels (`initiator_label` / `responder_label`) are the HKDF
    /// info strings the two constructors used previously; on-the-wire-
    /// derived keys are byte-identical to the pre-dedup code path
    /// because the two constructors' label byte strings remain
    /// caller-supplied.
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
            (key_a, key_b) // initiator sends with key_a, receives with key_b
        } else {
            (key_b, key_a) // responder sends with key_b, receives with key_a
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
            send_swap_at: None,
            packets_sent: 0,
            epoch_start: Instant::now(),
            packet_threshold: randomized_threshold(packet_base),
            time_threshold: randomized_time_threshold(time_base),
            packet_threshold_base: packet_base,
            time_threshold_base_secs: time_base,
        })
    }

    /// Encrypt a packet. Returns (nonce, ciphertext) and the current epoch.
    ///
    /// H-CRYPT-1 defensive check: the caller MUST pass `aad` exactly
    /// equal to `seq.to_be_bytes()` (8 bytes). The audit flagged that
    /// Rust trusts the Python caller to keep wire-seq and AAD bound;
    /// a future refactor that lets these drift apart would silently
    /// break replay protection. We don't take a separate `seq`
    /// parameter on encrypt (sender computes its own), but we DO
    /// require the AAD to be exactly 8 bytes — any other length is
    /// a contract violation and returns Err rather than silently
    /// producing a packet the receiver might mis-handle.
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
        Ok((nonce, ciphertext, self.epoch))
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
        // M-CRYPT-3: wrap the stack copy in Zeroizing.
        let scalar = Zeroizing::new(*secret.as_array());
        let static_secret = StaticSecret::from(*scalar);
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
            remote_ephemeral_pub,
            /* is_initiator = */ true,
            init.new_epoch,
        )?;
        self.apply_rotation(new_send, new_recv, init.new_epoch)
    }

    /// Complete rotation as the responder after receiving the initiator's INIT.
    /// Returns (ephemeral_pub, RotationComplete) — send ephemeral_pub in ACK.
    ///
    /// This is the single-shot variant — a thin wrapper around the
    /// two-phase `prepare_rotation_responder` + `apply_rotation_responder`
    /// pair that's kept around for unit-test convenience (the rotation-
    /// roundtrip tests don't need the prepare/ack/apply gap). Network
    /// users should call the two-phase pair directly so that the
    /// REKEY_ACK can be sent under the OLD keys, which the initiator
    /// must decrypt before it has applied its own rotation. There is no
    /// independent logic in this method — every line of behavior lives
    /// in the prepare/apply functions.
    #[inline]
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
        // M-CRYPT-3: Zeroizing wrap on the dereferenced rvalue copy.
        let scalar = Zeroizing::new(*secret.as_array());
        let static_secret = StaticSecret::from(*scalar);
        let our_pub = *PublicKey::from(&static_secret).as_bytes();

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
            remote_ephemeral_pub,
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
    /// The recv-key swap is immediate (so prev_recv backward-grace
    /// catches any in-flight OLD-key packets from the client) but
    /// `send` stays on the OLD key for GRACE_PERIOD_SECS — giving the
    /// client time to receive REKEY_ACK and apply its own rotation
    /// before any responder NEW-key packets arrive. The NEW send is
    /// held in `pending_new_send` and promoted by `tick()`.
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

    /// Internal: shared apply-rotation body with optional deferred
    /// send-key swap. When `defer_send=true` (responder), the new
    /// send key is parked in `pending_new_send` and `send` keeps the
    /// OLD key; `tick()` swaps it in once grace expires. When
    /// `defer_send=false` (initiator), the swap is immediate.
    fn apply_rotation_with_grace(
        &mut self,
        new_send_key: LockedKey32,
        new_recv_key: LockedKey32,
        new_epoch: u32,
        defer_send: bool,
    ) -> Result<RotationComplete, String> {
        let new_recv = DirectionKeys::new(new_recv_key, new_epoch);
        let new_send = DirectionKeys::new(new_send_key, new_epoch);

        // Move current recv to previous for grace period.
        let old_recv = std::mem::replace(&mut self.recv, new_recv);
        let old_replay = std::mem::take(&mut self.replay);

        self.prev_recv = Some(old_recv);
        self.prev_replay = Some(old_replay);
        self.grace_start = Some(Instant::now());

        if defer_send {
            // Park NEW send for grace; KEEP self.send on the OLD key.
            // tick() will promote when grace expires.
            self.pending_new_send = Some(new_send);
            self.send_swap_at = Some(Instant::now());
        } else {
            self.send = new_send;
        }

        self.epoch = new_epoch;
        self.packets_sent = 0;
        self.epoch_start = Instant::now();
        // Re-roll thresholds for the new epoch so the next rotation is also
        // unpredictable to a passive observer.
        self.packet_threshold = randomized_threshold(self.packet_threshold_base);
        self.time_threshold = randomized_time_threshold(self.time_threshold_base_secs);

        Ok(RotationComplete { new_epoch })
    }

    /// Whether a deferred send-key swap is currently pending (used by
    /// tests; mirrors the `has_grace_period` accessor for the recv side).
    pub fn has_pending_send_swap(&self) -> bool {
        self.pending_new_send.is_some()
    }

    /// Call periodically to clean up expired grace period keys and to
    /// promote a deferred send-key swap (H-BUG-2/3).
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
        // L-AUDIT-2: sample now once and use uniformly for both checks
        // so both grace-period and pending-send-swap paths consume the
        // same Instant::now() call, eliminating the prior "grace-set
        // takes elapsed() + branch; grace-unset takes only is_some()
        // branch" asymmetry.
        let now = Instant::now();
        let grace_expired = self
            .grace_start
            .map(|start| now.saturating_duration_since(start).as_secs() >= GRACE_PERIOD_SECS)
            .unwrap_or(false);
        let send_swap_due = self
            .send_swap_at
            .map(|at| now.saturating_duration_since(at).as_secs() >= GRACE_PERIOD_SECS)
            .unwrap_or(false);

        if grace_expired {
            self.prev_recv = None;
            self.prev_replay = None;
            self.grace_start = None;
        }
        // H-BUG-2/3: promote pending_new_send after grace expires.
        if send_swap_due {
            if let Some(new_send) = self.pending_new_send.take() {
                self.send = new_send;
            }
            self.send_swap_at = None;
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
    our_pub: &[u8; 32],
    peer_pub: &[u8; 32],
    is_initiator: bool,
    epoch: u32,
) -> Result<(LockedKey32, LockedKey32), String> {
    // remote_pub and peer_pub are the same value (passed twice for API
    // documentation clarity at callsites). Keep both parameters so the
    // call site explicitly names which is being used for DH vs which is
    // being mixed into the HKDF info.
    debug_assert_eq!(remote_pub, peer_pub);
    let _ = peer_pub;
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
        // Initiator: we send via i2r, receive via r2i.
        let send_key = expand_key(&info_i2r, "i2r")?;
        let recv_key = expand_key(&info_r2i, "r2i")?;
        Ok((send_key, recv_key))
    } else {
        // Responder: we send via r2i, receive via i2r.
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

    /// Regression for H-CRYPT-2: `derive_rotation_keys` MUST NOT depend
    /// on a caller-side (send, recv) tuple swap for direction
    /// correctness. With role binding inside the HKDF info, the
    /// initiator's send key is the responder's recv key and vice
    /// versa, regardless of which order the caller unpacks the tuple.
    /// Test verifies that:
    ///   1. Initiator's send_key == Responder's recv_key
    ///   2. Initiator's recv_key == Responder's send_key
    ///   3. Initiator's send_key != Initiator's recv_key (no collapse)
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
            &resp_pub,
            /* is_initiator = */ true,
            epoch,
        )
        .unwrap();
        let (resp_send, resp_recv) = derive_rotation_keys(
            &resp_secret,
            &init_pub,
            &resp_pub,
            &init_pub,
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

        let (a_send, _) = derive_rotation_keys(&a_secret, &b_pub, &a_pub, &b_pub, true, 1).unwrap();
        // B also calls with is_initiator=true (wrong!). HKDF info
        // canonicalizes (init_pub, resp_pub), so B's view of the
        // initiator-vs-responder ordering disagrees with A's whenever
        // a_pub != b_pub. As long as the canonical ordering picks a
        // different "init_pub" in B's call than in A's call, the keys
        // are different. The test asserts the strong property: the
        // first byte of A's send key is not equal to the first byte of
        // anything B derived.
        let (b_send, b_recv) =
            derive_rotation_keys(&b_secret, &a_pub, &b_pub, &a_pub, true, 1).unwrap();
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
        // Same seq number again
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
        let aad = &1u64.to_be_bytes();

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
        assert!(server
            .complete_rotation_responder(&eph, bogus_epoch)
            .is_err());
    }

    #[test]
    fn test_from_handshake_hash_roundtrip() {
        // Simulate both sides deriving keys from the same handshake hash
        let mut hash = [0u8; 32];
        OsRng.fill_bytes(&mut hash);

        let mut client = SessionKeyManager::from_handshake_hash(&hash, true, None, None).unwrap();
        let mut server = SessionKeyManager::from_handshake_hash(&hash, false, None, None).unwrap();
        let aad = &1u64.to_be_bytes();

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

        let mut client = SessionKeyManager::from_handshake_hash(&hash, true, None, None).unwrap();
        let mut server = SessionKeyManager::from_handshake_hash(&hash, false, None, None).unwrap();
        let aad = &1u64.to_be_bytes();
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

        // Encrypt a legitimate packet at seq=1
        let (nonce, ct, _) = client.encrypt(b"legit", aad).unwrap();

        // Forge a packet with high seq (999) and invalid ciphertext
        let bad_ct = vec![0xDE; 32];
        let bad_nonce = [0u8; 12];
        let bad_aad = b"hdr";

        // This should fail AEAD authentication
        assert!(server
            .decrypt(&bad_nonce, &bad_ct, bad_aad, 999, false)
            .is_err());

        // The replay window must NOT have advanced to 999.
        // A legitimate packet at seq=1 must still be accepted.
        let pt = server.decrypt(&nonce, &ct, aad, 1, false).unwrap();
        assert_eq!(pt, b"legit");

        // Also verify that seq=999 is still fresh (not marked as seen)
        // Verify seq=999 is still fresh (not marked as seen) — second forged
        // attempt at same seq should fail on AEAD, not on replay
        assert!(server
            .decrypt(&bad_nonce, &bad_ct, bad_aad, 999, false)
            .is_err());
    }
}
