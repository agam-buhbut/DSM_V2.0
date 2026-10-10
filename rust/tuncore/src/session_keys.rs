use crate::aes_gcm::AesKey;
use crate::header_key::HeaderKey;
use crate::nonce::NonceGenerator;
use crate::replay_window::ReplayWindow;
use crate::secure_memory::{public_from_locked, LockedKey32};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
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
pub const PEER_CONFIRM_LIMIT_SECS: u64 = 110;

/// Cap on operator-supplied rotation bases. The defaults are 5_000 packets
/// and 600 s; the cap leaves several orders of magnitude of headroom while
/// keeping `base * 20 / 100` and the modulus-based jitter calc clear of
/// u64 / i64 boundary cases (`r % (2*j+1)`, `(base as i64) + jitter`).
const ROTATION_BASE_MAX: u64 = 1 << 48;

/// Bytes before the AEAD output in a wire v2 data packet: the protected
/// 16-byte block (seq ‖ epoch ‖ counter) and the 4 random nonce bytes.
pub const HEADER_LEN: usize = 20;
/// The shortest packet `open` reads: the header and a 16-byte GCM tag.
pub const MIN_WIRE_LEN: usize = HEADER_LEN + 16;

/// HKDF salt for the keys made at session start. `dsm-v2` is the product
/// name (DSM 2.0), not the wire version; changing it would change today's
/// AEAD keys for no gain.
const BOOTSTRAP_SALT: &[u8] = b"dsm-v2-bootstrap-hkdf";

/// HKDF info labels for the keys of one session start.
struct StartLabels {
    initiator: &'static [u8],
    responder: &'static [u8],
    initiator_hp: &'static [u8],
    responder_hp: &'static [u8],
    epoch: &'static [u8],
}

/// Wire v2 spec §6.3: the two `-hp` labels are new; the rest are today's.
const BOOTSTRAP_LABELS: StartLabels = StartLabels {
    initiator: b"dsm-bootstrap-initiator-send",
    responder: b"dsm-bootstrap-responder-send",
    initiator_hp: b"dsm-bootstrap-initiator-hp",
    responder_hp: b"dsm-bootstrap-responder-hp",
    epoch: b"dsm-bootstrap-epoch",
};

/// Labels of the test-only `from_handshake_hash` path.
#[cfg(test)]
const HASH_LABELS: StartLabels = StartLabels {
    initiator: b"dsm-session-initiator",
    responder: b"dsm-session-responder",
    initiator_hp: b"dsm-session-initiator-hp",
    responder_hp: b"dsm-session-responder-hp",
    epoch: b"dsm-session-epoch",
};

/// One direction's secrets for one key set: the AEAD key and its header key.
/// Siblings from the same HKDF secret with their own labels; neither can be
/// computed from the other.
pub struct DirSecrets {
    pub aead: LockedKey32,
    pub hp: LockedKey32,
}

/// A packet that `open` read.
pub struct Opened {
    pub seq: u64,
    pub plaintext: Vec<u8>,
    /// True when the previous key set (grace period) opened it.
    pub used_prev: bool,
}

#[cfg(test)]
thread_local! {
    /// AEAD runs on this thread, for the tests that check junk runs none.
    static AEAD_RUNS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

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
    /// The header key of the same key set: it lives and dies with `key`, so
    /// it can never be paired with the wrong AEAD key or epoch, also during
    /// the responder's delayed send swap.
    hp: HeaderKey,
    nonce_gen: NonceGenerator,
}

impl DirectionKeys {
    fn new(secrets: DirSecrets, epoch: u32) -> Self {
        Self {
            key: AesKey::from_locked(secrets.aead),
            hp: HeaderKey::from_locked(secrets.hp),
            nonce_gen: NonceGenerator::new(epoch),
        }
    }

    /// The epoch this key set was made for: the first 4 nonce bytes.
    fn epoch(&self) -> u32 {
        self.nonce_gen.epoch()
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
    new_send: DirSecrets,
    new_recv: DirSecrets,
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
            &Hkdf::<Sha256>::new(Some(b"dsm-v2-session-init"), hash),
            &HASH_LABELS,
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
            &Hkdf::<Sha256>::new(Some(BOOTSTRAP_SALT), shared_secret),
            &BOOTSTRAP_LABELS,
            is_initiator,
            rotation_packets,
            rotation_seconds,
        )
    }

    /// Shared HKDF-expand-and-build path used by `from_handshake_hash` and
    /// `from_bootstrap_shared_secret`. The caller picks the salt and IKM
    /// (inside `hk`) and the labels.
    fn from_hkdf(
        hk: &Hkdf<Sha256>,
        labels: &StartLabels,
        is_initiator: bool,
        rotation_packets: Option<u64>,
        rotation_seconds: Option<u64>,
    ) -> Result<Self, String> {
        let (initiator, responder, initial_epoch) = expand_start_keys(hk, labels)?;
        let (send, recv) = if is_initiator {
            (initiator, responder)
        } else {
            (responder, initiator)
        };
        Self::new(
            send,
            recv,
            initial_epoch,
            rotation_packets,
            rotation_seconds,
        )
    }

    /// Create a new session from initial handshake-derived keys.
    /// Each `DirSecrets` holds a direction's AEAD key and header key.
    /// `rotation_packets` / `rotation_seconds` override the default thresholds;
    /// `None` means use the built-in defaults. Jitter is always applied.
    pub fn new(
        send: DirSecrets,
        recv: DirSecrets,
        initial_epoch: u32,
        rotation_packets: Option<u64>,
        rotation_seconds: Option<u64>,
    ) -> Result<Self, String> {
        let packet_base = rotation_packets.unwrap_or(ROTATION_PACKET_BASE);
        let time_base = rotation_seconds.unwrap_or(ROTATION_TIME_BASE_SECS);
        Ok(Self {
            epoch: initial_epoch,
            send: DirectionKeys::new(send, initial_epoch),
            recv: DirectionKeys::new(recv, initial_epoch),
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

    /// Seal one data packet (wire v2, spec §6.4). Returns the whole wire
    /// packet: `AES-256(header key, seq ‖ epoch ‖ counter)` ‖ the 4 random
    /// nonce bytes ‖ AES-GCM output with AAD = seq. Uses the send key set,
    /// which during the responder's delayed swap is still the old one, with
    /// its header key.
    ///
    /// # Errors
    /// The nonce counter is used up (a key change is overdue).
    pub fn seal(&mut self, seq: u64, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let nonce = self
            .send
            .nonce_gen
            .next()
            .ok_or("nonce counter exhausted — rotation overdue")?;
        self.seal_with_nonce(seq, &nonce, plaintext)
    }

    fn seal_with_nonce(
        &mut self,
        seq: u64,
        nonce: &[u8; 12],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, String> {
        let seq_be = seq.to_be_bytes();
        // H-CRYPT-1: the AAD is the seq, built here, so no caller can pass a
        // different one.
        let ciphertext = self.send.key.encrypt(nonce, plaintext, &seq_be)?;
        let mut block = [0u8; 16];
        block[..8].copy_from_slice(&seq_be);
        block[8..].copy_from_slice(&nonce[..8]);
        let header = self.send.hp.protect(&block);
        let mut wire = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        wire.extend_from_slice(&header);
        wire.extend_from_slice(&nonce[8..]);
        wire.extend_from_slice(&ciphertext);
        self.packets_sent += 1;
        Ok(wire)
    }

    /// Test-only `seal` with the 4 random nonce bytes fixed, for vector VP1.
    #[cfg(test)]
    fn seal_fixed_tail(
        &mut self,
        seq: u64,
        plaintext: &[u8],
        tail: [u8; 4],
    ) -> Result<Vec<u8>, String> {
        let mut nonce = self
            .send
            .nonce_gen
            .next()
            .ok_or("nonce counter exhausted")?;
        nonce[8..].copy_from_slice(&tail);
        self.seal_with_nonce(seq, &nonce, plaintext)
    }

    /// Open one data packet (wire v2, spec §6.5). `None` for anything that
    /// does not open: too short, no epoch match, a failed AEAD, or a replay.
    /// Never panics.
    ///
    /// Both header decryptions always run, so the work for junk does not
    /// depend on whether a grace period is on (audit M1); with no previous
    /// key set the current header key runs twice and the second result is
    /// never used. The AEAD runs only for a key set whose epoch matches, so
    /// junk costs two AES blocks. Nothing is allocated before the AEAD, and
    /// a `None` changes no replay window and no grace state (spec §24.1).
    pub fn open(&mut self, wire: &[u8]) -> Option<Opened> {
        self.tick();
        if wire.len() < MIN_WIRE_LEN {
            return None;
        }
        let mut block = [0u8; 16];
        block.copy_from_slice(&wire[..16]);
        let current = self.recv.hp.unprotect(&block);
        let (previous, previous_epoch) = match &self.prev_recv {
            Some(prev) => (prev.hp.unprotect(&block), Some(prev.epoch())),
            // black_box: the result is never read here, so without it the
            // optimizer may drop this AES block and break the M1 rule.
            None => (std::hint::black_box(self.recv.hp.unprotect(&block)), None),
        };
        // A genuine packet matches exactly one key set (but once in 2^32,
        // and then the second try still finds it); junk matches by chance
        // once in 2^32 per key set.
        if epoch_matches(&current, self.recv.epoch()) {
            if let Some(opened) = self.open_with(&current, wire, false) {
                return Some(opened);
            }
        }
        if previous_epoch.is_some_and(|epoch| epoch_matches(&previous, epoch)) {
            return self.open_with(&previous, wire, true);
        }
        None
    }

    /// The per-key-set step of `open`: today's `decrypt` (replay check, the
    /// AEAD always runs, the window moves only on success, and success under
    /// the current key confirms a parked send swap).
    fn open_with(&mut self, block: &[u8; 16], wire: &[u8], is_prev: bool) -> Option<Opened> {
        let mut seq_be = [0u8; 8];
        seq_be.copy_from_slice(&block[..8]);
        let seq = u64::from_be_bytes(seq_be);
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&block[8..]);
        nonce[8..].copy_from_slice(&wire[16..HEADER_LEN]);
        let plaintext = self
            .decrypt(&nonce, &wire[HEADER_LEN..], &seq_be, seq, is_prev)
            .ok()?;
        Some(Opened {
            seq,
            plaintext,
            used_prev: is_prev,
        })
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
        new_send_key: DirSecrets,
        new_recv_key: DirSecrets,
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
        new_send_key: DirSecrets,
        new_recv_key: DirSecrets,
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
    #[cfg(test)]
    AEAD_RUNS.with(|runs| runs.set(runs.get() + 1));
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

/// Whether a decrypted header block names `epoch` (its bytes 8-11).
fn epoch_matches(block: &[u8; 16], epoch: u32) -> bool {
    bool::from(block[8..12].ct_eq(&epoch.to_be_bytes()))
}

/// Derive both directions' `DirSecrets` from a rotation DH: (send, recv)
/// from this side's view. Each key is derived directly into a mlock'd heap
/// buffer.
fn derive_rotation_keys(
    our_secret: &[u8; 32],
    remote_pub: &[u8; 32],
    our_pub: &[u8; 32],
    is_initiator: bool,
    epoch: u32,
) -> Result<(DirSecrets, DirSecrets), String> {
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

    // Spec §6.3: each direction's header key is a sibling of its AEAD key;
    // the `-hp-` labels are 15 bytes like the AEAD ones, so no info string
    // is a prefix of another.
    let i2r = DirSecrets {
        aead: expand_locked(&hk, &build_info(b"dsm-rot-i2r-v2-"), "i2r")?,
        hp: expand_locked(&hk, &build_info(b"dsm-rot-i2r-hp-"), "i2r hp")?,
    };
    let r2i = DirSecrets {
        aead: expand_locked(&hk, &build_info(b"dsm-rot-r2i-v2-"), "r2i")?,
        hp: expand_locked(&hk, &build_info(b"dsm-rot-r2i-hp-"), "r2i hp")?,
    };
    if is_initiator {
        Ok((i2r, r2i))
    } else {
        Ok((r2i, i2r))
    }
}

/// Expand one HKDF output straight into a fresh locked key.
fn expand_locked(hk: &Hkdf<Sha256>, info: &[u8], what: &str) -> Result<LockedKey32, String> {
    let mut key = LockedKey32::zeroed()?;
    hk.expand(info, key.as_mut())
        .map_err(|e| format!("hkdf {what}: {e}"))?;
    Ok(key)
}

/// The keys made at session start: the initiator's, the responder's, and
/// the initial epoch. The epoch comes from the keying material, so both
/// peers agree on it without an extra wire byte and it does not start at 1
/// (audit I3); only its low 28 bits are kept, so u32 rotation has ~16M
/// headroom.
fn expand_start_keys(
    hk: &Hkdf<Sha256>,
    labels: &StartLabels,
) -> Result<(DirSecrets, DirSecrets, u32), String> {
    let initiator = DirSecrets {
        aead: expand_locked(hk, labels.initiator, "initiator")?,
        hp: expand_locked(hk, labels.initiator_hp, "initiator hp")?,
    };
    let responder = DirSecrets {
        aead: expand_locked(hk, labels.responder, "responder")?,
        hp: expand_locked(hk, labels.responder_hp, "responder hp")?,
    };
    let mut epoch_bytes = [0u8; 4];
    hk.expand(labels.epoch, &mut epoch_bytes)
        .map_err(|e| format!("hkdf epoch: {e}"))?;
    Ok((
        initiator,
        responder,
        u32::from_be_bytes(epoch_bytes) & 0x0FFF_FFFF,
    ))
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
            init_send.aead.as_array(),
            resp_recv.aead.as_array(),
            "initiator send key must equal responder recv key (i2r channel)",
        );
        assert_eq!(
            init_recv.aead.as_array(),
            resp_send.aead.as_array(),
            "responder send key must equal initiator recv key (r2i channel)",
        );
        assert_eq!(
            init_send.hp.as_array(),
            resp_recv.hp.as_array(),
            "the i2r header keys must pair up like the i2r AEAD keys",
        );
        assert_eq!(
            init_recv.hp.as_array(),
            resp_send.hp.as_array(),
            "the r2i header keys must pair up like the r2i AEAD keys",
        );
        // Direction separation: send key MUST differ from recv key.
        // Without role binding the previous code had this property only
        // by virtue of using two different HKDF info labels — but the
        // labels were caller-controlled. With role binding it's
        // unconditional.
        assert_ne!(
            init_send.aead.as_array(),
            init_recv.aead.as_array(),
            "initiator send and recv MUST be derived from different HKDF info",
        );
        assert_ne!(
            resp_send.aead.as_array(),
            resp_recv.aead.as_array(),
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
        let a_send_eq_b_send = a_send.aead.as_array() == b_send.aead.as_array();
        let a_send_eq_b_recv = a_send.aead.as_array() == b_recv.aead.as_array();
        assert!(
            !(a_send_eq_b_send && a_send_eq_b_recv),
            "two parties both claiming initiator must not converge on same key in both directions",
        );
        let hp_send_eq = a_send.hp.as_array() == b_send.hp.as_array();
        let hp_recv_eq = a_send.hp.as_array() == b_recv.hp.as_array();
        assert!(
            !(hp_send_eq && hp_recv_eq),
            "two parties both claiming initiator must not share header keys either",
        );
    }

    fn make_paired_managers() -> (SessionKeyManager, SessionKeyManager) {
        // Each direction: an AEAD key and its header key.
        let mut c2s = [[0u8; 32]; 2];
        let mut s2c = [[0u8; 32]; 2];
        for key in c2s.iter_mut().chain(s2c.iter_mut()) {
            OsRng.fill_bytes(key);
        }
        let dir = |keys: [[u8; 32]; 2]| DirSecrets {
            aead: LockedKey32::from_array(keys[0]).unwrap(),
            hp: LockedKey32::from_array(keys[1]).unwrap(),
        };

        // Client sends with c2s, server receives with c2s.
        // Server sends with s2c, client receives with s2c.
        let client = SessionKeyManager::new(dir(c2s), dir(s2c), 1, None, None).unwrap();
        let server = SessionKeyManager::new(dir(s2c), dir(c2s), 1, None, None).unwrap();
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
        let mut c2s = [[0u8; 32]; 2];
        let mut s2c = [[0u8; 32]; 2];
        for key in c2s.iter_mut().chain(s2c.iter_mut()) {
            OsRng.fill_bytes(key);
        }
        let dir = |keys: [[u8; 32]; 2]| DirSecrets {
            aead: LockedKey32::from_array(keys[0]).unwrap(),
            hp: LockedKey32::from_array(keys[1]).unwrap(),
        };
        let client = SessionKeyManager::new(dir(c2s), dir(s2c), 1, None, None).unwrap();
        // Rotation due after 1 or 2 packets.
        let mut server = SessionKeyManager::new(dir(s2c), dir(c2s), 1, Some(1), None).unwrap();
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

    // ---- wire v2: seal and open (spec §16.1 tests 4-13) ----

    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use sha2::Digest;

    fn aead_runs() -> u64 {
        AEAD_RUNS.with(std::cell::Cell::get)
    }

    fn reset_aead_runs() {
        AEAD_RUNS.with(|runs| runs.set(0));
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write;
        bytes.iter().fold(String::new(), |mut out, b| {
            write!(out, "{b:02x}").unwrap();
            out
        })
    }

    fn fixed_dir(aead: u8, hp: u8) -> DirSecrets {
        DirSecrets {
            aead: LockedKey32::from_array([aead; 32]).unwrap(),
            hp: LockedKey32::from_array([hp; 32]).unwrap(),
        }
    }

    /// A client and a server on fixed keys, so whether a header matches is
    /// the same on every run (spec §16.1: the AEAD-counting tests).
    fn fixed_pair() -> (SessionKeyManager, SessionKeyManager) {
        let epoch = 0x0123_4567;
        let client =
            SessionKeyManager::new(fixed_dir(1, 2), fixed_dir(3, 4), epoch, None, None).unwrap();
        let server =
            SessionKeyManager::new(fixed_dir(3, 4), fixed_dir(1, 2), epoch, None, None).unwrap();
        (client, server)
    }

    /// Both sides move to fixed new keys at epoch + 1 at once; each keeps its
    /// old receive keys for the grace period.
    fn fixed_rotation(client: &mut SessionKeyManager, server: &mut SessionKeyManager) {
        let next = client.epoch() + 1;
        client
            .apply_rotation(fixed_dir(5, 6), fixed_dir(7, 8), next)
            .unwrap();
        server
            .apply_rotation(fixed_dir(7, 8), fixed_dir(5, 6), next)
            .unwrap();
    }

    /// `count` packets of `len` pseudo-random bytes from a fixed seed.
    fn junk(seed: u64, len: usize, count: usize) -> Vec<Vec<u8>> {
        let mut rng = StdRng::seed_from_u64(seed);
        (0..count)
            .map(|_| {
                let mut packet = vec![0u8; len];
                rng.fill_bytes(&mut packet);
                packet
            })
            .collect()
    }

    /// Test 4: round trip both ways; the wire is 36 + plaintext bytes.
    #[test]
    fn seal_open_round_trip_both_ways() {
        let (mut client, mut server) = make_paired_managers();
        for (seq, len) in [(1u64, 0usize), (2, 92), (3, 1364)] {
            let msg = vec![0xA5u8; len];
            let wire = client.seal(seq, &msg).unwrap();
            assert_eq!(wire.len(), MIN_WIRE_LEN + len);
            let opened = server.open(&wire).unwrap();
            assert_eq!(opened.seq, seq);
            assert_eq!(opened.plaintext, msg);
            assert!(!opened.used_prev);
            let back = server.seal(seq, &msg).unwrap();
            assert_eq!(client.open(&back).unwrap().plaintext, msg);
        }
    }

    /// Test 5: every header byte, the tag, the length and the direction.
    #[test]
    fn open_rejects_changed_short_and_wrong_direction_packets() {
        let (mut client, mut server) = make_paired_managers();
        let wire = client.seal(7, b"payload").unwrap();
        for i in 0..HEADER_LEN {
            let mut bad = wire.clone();
            bad[i] ^= 0x01;
            assert!(server.open(&bad).is_none(), "header byte {i} flipped");
        }
        let mut bad_tag = wire.clone();
        let last = bad_tag.len() - 1;
        bad_tag[last] ^= 0x01;
        assert!(server.open(&bad_tag).is_none());
        assert!(server.open(&wire[..MIN_WIRE_LEN - 1]).is_none());
        // A packet this side sealed itself is in the other direction's keys.
        let own = server.seal(1, b"own").unwrap();
        assert!(server.open(&own).is_none());
        // None of the refusals moved anything: the genuine packet opens.
        assert!(server.open(&wire).is_some());
    }

    /// Test 6 (audit M1): junk runs no AEAD at all, with or without a grace
    /// period. Fixed keys and fixed bytes, so a 1-in-2^32 epoch match cannot
    /// make this flaky.
    #[test]
    fn junk_runs_no_aead_with_or_without_grace() {
        let (mut client, mut server) = fixed_pair();
        for grace in [false, true] {
            if grace {
                fixed_rotation(&mut client, &mut server);
                assert!(server.has_grace_period());
            }
            for &size in &crate::shaper::SIZE_CLASSES {
                reset_aead_runs();
                for packet in junk(u64::from(size) + u64::from(grace), usize::from(size), 1000) {
                    assert!(server.open(&packet).is_none());
                }
                assert_eq!(aead_runs(), 0, "size {size}, grace {grace}");
            }
        }
    }

    /// Test 7: the 16-byte block never repeats, even for one seq: the nonce
    /// counter keeps the input unique.
    #[test]
    fn header_blocks_never_repeat() {
        let (mut client, _server) = make_paired_managers();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..10_000 {
            let wire = client.seal(1, b"x").unwrap();
            assert!(seen.insert(wire[..16].to_vec()));
        }
    }

    /// Test 8 (audit M3): a replay matches its header, so the AEAD runs once
    /// for it, and it is refused.
    #[test]
    fn a_replay_runs_the_aead_once_and_is_refused() {
        let (mut client, mut server) = fixed_pair();
        let wire = client.seal(1, b"once").unwrap();
        assert!(server.open(&wire).is_some());
        reset_aead_runs();
        assert!(server.open(&wire).is_none());
        assert_eq!(aead_runs(), 1);
    }

    /// Test 9 (owner Q2): an old-key packet opens during the grace period
    /// with `used_prev`; after it ends, the next one is refused with no AEAD.
    #[test]
    fn an_old_key_packet_opens_in_grace_and_costs_no_aead_after() {
        let (mut client, mut server) = fixed_pair();
        let early = client.seal(1, b"early").unwrap();
        let late = client.seal(2, b"late").unwrap();
        fixed_rotation(&mut client, &mut server);
        assert!(server.open(&early).unwrap().used_prev);
        server.age_for_test(Duration::from_secs(GRACE_PERIOD_SECS));
        reset_aead_runs();
        assert!(server.open(&late).is_none());
        assert!(!server.has_grace_period());
        assert_eq!(aead_runs(), 0);
    }

    /// Test 10: during the responder's delayed send swap its packets keep the
    /// old key set and its header key; the client's first new-key packet
    /// makes it swap, and from then on it uses the new header key.
    #[test]
    fn delayed_send_swap_keeps_the_old_header_key_until_confirmed() {
        let (mut client, mut server) = make_paired_managers();
        let (init, server_pub) = responder_applies(&client, &mut server);

        let s1 = server.seal(1, b"before the client applied").unwrap();
        assert!(!client.open(&s1).unwrap().used_prev);

        client
            .complete_rotation_initiator(init, &server_pub)
            .unwrap();
        let s2 = server.seal(2, b"still the old keys").unwrap();
        assert!(client.open(&s2).unwrap().used_prev);

        let c1 = client.seal(1, b"first new-key packet").unwrap();
        assert!(!server.open(&c1).unwrap().used_prev);
        assert!(!server.has_pending_send_swap());

        let s3 = server.seal(3, b"new keys now").unwrap();
        assert!(!client.open(&s3).unwrap().used_prev);
    }

    /// Test 11: the REKEY_ACK is lost; a REKEY_INIT resent under the old keys
    /// still opens at the server while it waits, and the cached ACK under the
    /// old send key opens at the client.
    #[test]
    fn lost_ack_resend_opens_with_the_old_header_key() {
        let (mut client, mut server) = make_paired_managers();
        let (_init, _server_pub) = responder_applies(&client, &mut server);
        server.age_for_test(Duration::from_secs(PEER_CONFIRM_LIMIT_SECS - 10));
        server.tick();
        assert!(server.has_grace_period());
        let resent_init = client.seal(10, b"resent REKEY_INIT").unwrap();
        assert!(server.open(&resent_init).unwrap().used_prev);
        let cached_ack = server.seal(10, b"cached REKEY_ACK").unwrap();
        assert!(!client.open(&cached_ack).unwrap().used_prev);
    }

    /// Test 12, VK1 (spec §16.3): bootstrap keys, also today's AEAD keys and
    /// epoch.
    #[test]
    fn vk1_bootstrap_keys() {
        let shared = unhex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
        let hk = Hkdf::<Sha256>::new(Some(BOOTSTRAP_SALT), &shared);
        let (initiator, responder, epoch) = expand_start_keys(&hk, &BOOTSTRAP_LABELS).unwrap();
        assert_eq!(
            hex(initiator.aead.as_array()),
            "88220f5148079ff91f54719a285399c8e1811e6c9d68afc281a9a7ea13c6a979"
        );
        assert_eq!(
            hex(responder.aead.as_array()),
            "20ad2743ee98b788954f62a76f205d3822926b499bbb5e83ca2dade71da73e9e"
        );
        assert_eq!(
            hex(initiator.hp.as_array()),
            "908cda00df7a83348258c102a5ba3cb953030cdb868ee51e9baa69c89538905d"
        );
        assert_eq!(
            hex(responder.hp.as_array()),
            "31f64011dfcf5a95045a34fa48e492908a0c3f29450d56109a546f4cf882f0f6"
        );
        assert_eq!(epoch, 0x07fe_d369);
    }

    /// Test 12, VR1: rotation keys (X25519 secrets before clamping).
    #[test]
    fn vr1_rotation_keys() {
        let init_secret = [0x11u8; 32];
        let resp_secret = [0x22u8; 32];
        let init_pub = *PublicKey::from(&StaticSecret::from(init_secret)).as_bytes();
        let resp_pub = *PublicKey::from(&StaticSecret::from(resp_secret)).as_bytes();
        assert_eq!(
            hex(&init_pub),
            "7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13"
        );
        assert_eq!(
            hex(&resp_pub),
            "0faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f20"
        );
        let new_epoch = 0x0123_4568;
        let (send, recv) =
            derive_rotation_keys(&init_secret, &resp_pub, &init_pub, true, new_epoch).unwrap();
        assert_eq!(
            hex(send.aead.as_array()),
            "8f583326eb3b68a9a8caf1b19724d72b7d5ad0be939b5da088b92f51c7dc42c4"
        );
        assert_eq!(
            hex(recv.aead.as_array()),
            "bb96d00f3e3b331c892bbd6b7fa49a24511a0eee282940518609b7b38327ada9"
        );
        assert_eq!(
            hex(send.hp.as_array()),
            "f88339633c3b437eea19c6e803411abcb10b444a679b96278bcc3a4c7e99d667"
        );
        assert_eq!(
            hex(recv.hp.as_array()),
            "d522c1878642596575cf69ce6ec5cb457cdb6e3d78e48b4d15094e2b8e5820f2"
        );
        let (r_send, r_recv) =
            derive_rotation_keys(&resp_secret, &init_pub, &resp_pub, false, new_epoch).unwrap();
        assert_eq!(r_send.hp.as_array(), recv.hp.as_array());
        assert_eq!(r_recv.hp.as_array(), send.hp.as_array());
    }

    /// Test 12, VP1: a full 128-byte packet with fixed random nonce bytes.
    #[test]
    fn vp1_full_packet() {
        let mut hp = [0u8; 32];
        let mut aead = [0u8; 32];
        for (i, (h, a)) in hp.iter_mut().zip(aead.iter_mut()).enumerate() {
            *h = i as u8;
            *a = 0x40 + i as u8;
        }
        let send = DirSecrets {
            aead: LockedKey32::from_array(aead).unwrap(),
            hp: LockedKey32::from_array(hp).unwrap(),
        };
        let mut keys =
            SessionKeyManager::new(send, fixed_dir(9, 9), 0x0123_4567, None, None).unwrap();
        let mut plaintext = vec![0x00, 0x70, 0x00, 0x05];
        plaintext.extend_from_slice(b"hello");
        plaintext.resize(92, 0);
        let wire = keys
            .seal_fixed_tail(1, &plaintext, [0xde, 0xad, 0xbe, 0xef])
            .unwrap();
        assert_eq!(wire.len(), 128);
        assert_eq!(
            hex(&wire[..HEADER_LEN]),
            "2bac181b9b28b24c91fc508da5d7baa5deadbeef"
        );
        assert_eq!(
            hex(&wire[wire.len() - 16..]),
            "9f6acb6e62011a00d7b39cec3a8020af"
        );
        assert_eq!(
            hex(&Sha256::digest(&wire)),
            "d280eda98b7a931b039fb2b8f76952003374d39989b9777d05f486b5a87293a2"
        );
    }

    /// Test 13: send vs receive header key, epoch E vs E+1, header key vs
    /// AEAD key all differ.
    #[test]
    fn every_key_differs() {
        let mut shared = [0u8; 32];
        OsRng.fill_bytes(&mut shared);
        let hk = Hkdf::<Sha256>::new(Some(BOOTSTRAP_SALT), &shared);
        let (initiator, responder, _) = expand_start_keys(&hk, &BOOTSTRAP_LABELS).unwrap();
        assert_ne!(initiator.hp.as_array(), responder.hp.as_array());
        assert_ne!(initiator.hp.as_array(), initiator.aead.as_array());
        assert_ne!(responder.hp.as_array(), responder.aead.as_array());

        let mut ours = [0u8; 32];
        let mut theirs = [0u8; 32];
        OsRng.fill_bytes(&mut ours);
        OsRng.fill_bytes(&mut theirs);
        let our_pub = *PublicKey::from(&StaticSecret::from(ours)).as_bytes();
        let their_pub = *PublicKey::from(&StaticSecret::from(theirs)).as_bytes();
        let (epoch5_send, epoch5_recv) =
            derive_rotation_keys(&ours, &their_pub, &our_pub, true, 5).unwrap();
        let (epoch6_send, _) = derive_rotation_keys(&ours, &their_pub, &our_pub, true, 6).unwrap();
        assert_ne!(epoch5_send.hp.as_array(), epoch6_send.hp.as_array());
        assert_ne!(epoch5_send.hp.as_array(), epoch5_recv.hp.as_array());
        assert_ne!(epoch5_send.hp.as_array(), epoch5_send.aead.as_array());
    }

    /// Review Focus 2 (spec §24.1): a packet that does not open changes
    /// nothing. Multi-client will try a packet on each session in turn; a
    /// miss must not move that session's replay windows or end its grace.
    #[test]
    fn a_none_from_open_changes_nothing() {
        let (mut client, mut server) = fixed_pair();
        let old = client.seal(5, b"old key set").unwrap();
        fixed_rotation(&mut client, &mut server);
        let mut forged_far = client.seal(300, b"its header matches").unwrap();
        let last = forged_far.len() - 1;
        forged_far[last] ^= 0x01;
        let later = client.seal(9, b"new keys, seq 9").unwrap();
        let earlier = client.seal(3, b"new keys, seq 3").unwrap();
        let (mut other, _) = make_paired_managers();
        let stranger = other.seal(9, b"another session").unwrap();

        for miss in [vec![0x5Au8; 128], stranger, vec![0u8; 20], forged_far] {
            assert!(server.open(&miss).is_none());
        }
        assert!(server.has_grace_period());
        // Had the forged packet moved the window to 300, seq 3 would now be
        // too old; it still opens, after seq 9, and the old key set still
        // opens its packet.
        assert!(server.open(&later).is_some());
        assert!(server.open(&earlier).is_some());
        assert!(server.open(&old).unwrap().used_prev);
    }
}
