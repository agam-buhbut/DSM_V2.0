//! UniFFI bindings for the `tuncore` crypto/handshake core.
//!
//! This module exposes the MINIMAL, CLIENT-ONLY primitive surface a native
//! Android (Kotlin) DSM client needs to drive a handshake + session, wrapping
//! the SAME core types the PyO3 surface (`src/python.rs`) wraps — NOT the
//! pyo3-typed `Py*` wrappers. Bytes cross the boundary as `Vec<u8>`; secret
//! key material never does (handles are opaque, exactly as on the Python side).
//!
//! It is gated behind the `uniffi-bindings` Cargo feature so the crypto/packet
//! core still compiles pyo3-free AND uniffi-free for the default build and the
//! Python wheel.
//!
//! ## Surface (client-only)
//! - [`IdentityKeyPair`] — long-term X25519 Noise static (load/use/store).
//! - [`NoiseInitiator`] — Noise XX *initiator* (the client is always the
//!   initiator; the responder is intentionally NOT exposed — see note below).
//! - [`NoiseTransport`] — post-handshake transport AEAD (bootstrap frames).
//! - [`BootstrapEphemeral`] + [`complete_bootstrap`] — secret-DH session
//!   bootstrap (mirrors the Python path; the X25519 scalar stays in mlock'd
//!   Rust heap).
//! - [`SessionKeyManager`] — data-path AEAD + bidirectional rekey.
//! - [`ReplayWindow`] — outer wire-sequence replay window (the client data path
//!   uses one, see `dsm/session.py`).
//! - [`AttestSigner`] — callback interface: Kotlin signs the handshake
//!   attestation binding with its Keystore/StrongBox key; the signing scalar
//!   stays in StrongBox.
//!
//! ## Intentionally OMITTED (vs `python.rs`)
//! - `NoiseResponder` — a client never plays the Noise responder.
//! - `NonceGenerator` — internal to `SessionKeyManager`; no direct client use.
//! - `disable_core_dumps` / `harden_process` — Linux-process hardening; the
//!   Android runtime owns process hardening, so these are not part of the
//!   client primitive surface.
//!
//! ## Orchestration lives in Kotlin
//! Handshake/session *sequencing* (snapshotting the handshake hash, building
//! and parsing the attestation payload, cert-chain verification, framing,
//! retransmit) is deliberately NOT in this module — it mirrors `dsm/client.py`
//! and will live in the Kotlin app (Task A6) calling these primitives, exactly
//! as the Python client drives the equivalent `tuncore` primitives.

use std::sync::{Arc, Mutex};

use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::secure_memory::LockedKey32;
use crate::{identity, noise_xx, replay_window, session_keys};

// ── Errors ──

/// Errors crossing the UniFFI boundary. The core returns `Result<_, String>`
/// everywhere; [`FfiError::Crypto`] carries that message. [`FfiError::InvalidInput`]
/// flags a wrong-shaped argument caught at the boundary, and [`FfiError::Callback`]
/// wraps a failure raised by a foreign [`AttestSigner`] implementation.
#[derive(Debug, uniffi::Error)]
pub enum FfiError {
    /// A cryptographic / protocol operation in the core failed.
    Crypto { msg: String },
    /// An argument crossing the FFI boundary had the wrong shape (e.g. a
    /// nonce that was not exactly 12 bytes).
    InvalidInput { msg: String },
    /// A foreign (Kotlin) `AttestSigner` callback returned an error or threw.
    Callback { msg: String },
}

impl std::fmt::Display for FfiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FfiError::Crypto { msg } => write!(f, "crypto error: {msg}"),
            FfiError::InvalidInput { msg } => write!(f, "invalid input: {msg}"),
            FfiError::Callback { msg } => write!(f, "attest-signer callback failed: {msg}"),
        }
    }
}

impl std::error::Error for FfiError {}

impl From<String> for FfiError {
    fn from(msg: String) -> Self {
        FfiError::Crypto { msg }
    }
}

// Required so a foreign `AttestSigner` that throws an unexpected exception is
// surfaced as a typed error rather than aborting across the FFI boundary.
impl From<uniffi::UnexpectedUniFFICallbackError> for FfiError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        FfiError::Callback { msg: e.reason }
    }
}

/// Uniform error for a poisoned internal lock (a previous call panicked while
/// holding it). Surfaces as a typed error instead of a propagated panic.
fn lock_poisoned() -> FfiError {
    FfiError::Crypto {
        msg: "internal lock poisoned".into(),
    }
}

/// Error for an opaque handle that has already been consumed (e.g. an
/// initiator transitioned to transport mode).
fn consumed() -> FfiError {
    FfiError::InvalidInput {
        msg: "handle already consumed".into(),
    }
}

/// Copy a byte slice into a fixed-size array, returning a boundary error whose
/// message names the field on a length mismatch.
fn fixed<const N: usize>(data: &[u8], what: &str) -> Result<[u8; N], FfiError> {
    if data.len() != N {
        return Err(FfiError::InvalidInput {
            msg: format!("{what} must be {N} bytes, got {}", data.len()),
        });
    }
    let mut arr = [0u8; N];
    arr.copy_from_slice(data);
    Ok(arr)
}

// ── Record (by-value) types ──
// UniFFI does not support tuples across the boundary, so multi-value returns
// use named records.

/// Result of [`NoiseInitiator::read_message_2`].
#[derive(uniffi::Record)]
pub struct Msg2Result {
    /// The responder's 32-byte X25519 Noise static public key.
    pub remote_static: Vec<u8>,
    /// The responder's attestation payload — exactly
    /// `HANDSHAKE_ATTEST_PAYLOAD_SIZE` bytes; the caller parses the internal
    /// cert/sig framing.
    pub attest_payload: Vec<u8>,
}

/// Result of [`SessionKeyManager::encrypt`].
#[derive(uniffi::Record)]
pub struct EncryptResult {
    /// 12-byte AEAD nonce.
    pub nonce: Vec<u8>,
    /// Ciphertext with appended 16-byte GCM tag.
    pub ciphertext: Vec<u8>,
    /// Epoch the packet was encrypted under.
    pub epoch: u32,
}

/// Result of [`SessionKeyManager::try_decrypt_with_fallback`].
#[derive(uniffi::Record)]
pub struct DecryptFallback {
    pub plaintext: Vec<u8>,
    /// True if the packet decrypted under the previous epoch's grace key.
    pub used_prev_epoch: bool,
}

/// Result of [`SessionKeyManager::initiate_rotation`].
#[derive(uniffi::Record)]
pub struct RotationInitResult {
    pub new_epoch: u32,
    pub ephemeral_pub: Vec<u8>,
}

/// Result of the responder-side rotation phases.
#[derive(uniffi::Record)]
pub struct RotationResponderResult {
    pub our_ephemeral_pub: Vec<u8>,
    pub new_epoch: u32,
}

/// Result of [`attest_signer_probe`] — the three values an [`AttestSigner`]
/// returns, captured in one round trip.
#[derive(uniffi::Record)]
pub struct AttestProbe {
    pub signature: Vec<u8>,
    pub public_spki_der: Vec<u8>,
    pub cert_chain: Vec<Vec<u8>>,
}

// ── Identity ──

/// Long-term X25519 Noise static identity keypair. The secret lives in mlock'd,
/// zeroize-on-drop Rust heap and never crosses the boundary.
#[derive(uniffi::Object)]
pub struct IdentityKeyPair {
    inner: Mutex<identity::IdentityKeyPair>,
}

#[uniffi::export]
impl IdentityKeyPair {
    /// Generate a fresh random identity keypair.
    #[uniffi::constructor]
    pub fn generate() -> Result<Arc<Self>, FfiError> {
        let inner = identity::IdentityKeyPair::generate()?;
        Ok(Arc::new(Self {
            inner: Mutex::new(inner),
        }))
    }

    /// Restore an identity from a passphrase-sealed blob.
    #[uniffi::constructor]
    pub fn decrypt_from_store(blob: Vec<u8>, passphrase: Vec<u8>) -> Result<Arc<Self>, FfiError> {
        let inner = identity::IdentityKeyPair::decrypt_from_store(&blob, &passphrase)?;
        Ok(Arc::new(Self {
            inner: Mutex::new(inner),
        }))
    }

    /// The 32-byte X25519 Noise static public key.
    pub fn public_key(&self) -> Result<Vec<u8>, FfiError> {
        let g = self.inner.lock().map_err(|_| lock_poisoned())?;
        Ok(g.public_key().to_vec())
    }

    /// Seal this keypair to a passphrase-protected blob (Argon2id +
    /// XChaCha20-Poly1305).
    pub fn encrypt_to_store(&self, passphrase: Vec<u8>) -> Result<Vec<u8>, FfiError> {
        let g = self.inner.lock().map_err(|_| lock_poisoned())?;
        Ok(g.encrypt_to_store(&passphrase)?)
    }

    /// HMAC-SHA256 over `data` keyed by a key derived from this identity
    /// (HKDF info = `context`). The derived key never leaves Rust.
    pub fn compute_hmac(&self, context: Vec<u8>, data: Vec<u8>) -> Result<Vec<u8>, FfiError> {
        let g = self.inner.lock().map_err(|_| lock_poisoned())?;
        Ok(g.compute_hmac(&context, &data).map(|t| t.to_vec())?)
    }

    /// Zeroize the secret key in place. Idempotent; the handle is unusable
    /// afterward.
    pub fn zeroize(&self) -> Result<(), FfiError> {
        let mut g = self.inner.lock().map_err(|_| lock_poisoned())?;
        g.zeroize();
        Ok(())
    }
}

// ── Noise XX initiator (client) ──

/// Noise XX initiator (client) handshake state. Methods mutate the inner snow
/// state under a `Mutex` (UniFFI objects expose `&self` only). The handle is
/// consumed by [`NoiseInitiator::into_transport`].
#[derive(uniffi::Object)]
pub struct NoiseInitiator {
    inner: Mutex<Option<noise_xx::NoiseInitiator>>,
}

#[uniffi::export]
impl NoiseInitiator {
    /// Create an initiator bound to `identity`'s X25519 static secret.
    #[uniffi::constructor]
    pub fn new(identity: Arc<IdentityKeyPair>) -> Result<Arc<Self>, FfiError> {
        let id = identity.inner.lock().map_err(|_| lock_poisoned())?;
        let init = noise_xx::NoiseInitiator::new(id.secret_key())?;
        Ok(Arc::new(Self {
            inner: Mutex::new(Some(init)),
        }))
    }

    /// Message 1: `-> e`. Returns the padded wire frame.
    pub fn write_message_1(&self) -> Result<Vec<u8>, FfiError> {
        let mut g = self.inner.lock().map_err(|_| lock_poisoned())?;
        let init = g.as_mut().ok_or_else(consumed)?;
        Ok(init.write_message_1()?)
    }

    /// Message 2: `<- e, ee, s, es [+ attest]`. Returns the responder's Noise
    /// static + attest payload. Snapshot [`get_handshake_hash`](Self::get_handshake_hash)
    /// BEFORE calling this — it advances the Noise state past the hash that
    /// signs msg2's binding.
    pub fn read_message_2(&self, msg: Vec<u8>) -> Result<Msg2Result, FfiError> {
        let mut g = self.inner.lock().map_err(|_| lock_poisoned())?;
        let init = g.as_mut().ok_or_else(consumed)?;
        let (remote_static, attest_payload) = init.read_message_2(&msg)?;
        Ok(Msg2Result {
            remote_static,
            attest_payload,
        })
    }

    /// Message 3: `-> s, se [+ attest]`. `attest_payload` must be exactly
    /// `HANDSHAKE_ATTEST_PAYLOAD_SIZE` bytes.
    pub fn write_message_3(&self, attest_payload: Vec<u8>) -> Result<Vec<u8>, FfiError> {
        let mut g = self.inner.lock().map_err(|_| lock_poisoned())?;
        let init = g.as_mut().ok_or_else(consumed)?;
        Ok(init.write_message_3(&attest_payload)?)
    }

    /// The current handshake hash. Snapshot before each `read_message_2` /
    /// `write_message_3` to bind the attestation signature.
    pub fn get_handshake_hash(&self) -> Result<Vec<u8>, FfiError> {
        let g = self.inner.lock().map_err(|_| lock_poisoned())?;
        let init = g.as_ref().ok_or_else(consumed)?;
        Ok(init.get_handshake_hash())
    }

    /// Consume the initiator and transition to transport mode.
    // UniFFI objects expose `&self` only, so `into_transport` cannot take
    // `self` by value; the handle is consumed via the inner `Option::take`.
    #[allow(clippy::wrong_self_convention)]
    pub fn into_transport(&self) -> Result<Arc<NoiseTransport>, FfiError> {
        let mut g = self.inner.lock().map_err(|_| lock_poisoned())?;
        let init = g.take().ok_or_else(consumed)?;
        let transport = init.into_transport()?;
        Ok(Arc::new(NoiseTransport {
            inner: Mutex::new(transport),
        }))
    }
}

// ── Noise transport ──

/// Post-handshake Noise transport cipher pair (used to encrypt the bootstrap
/// ephemeral-key exchange frames).
#[derive(uniffi::Object)]
pub struct NoiseTransport {
    inner: Mutex<noise_xx::NoiseTransport>,
}

#[uniffi::export]
impl NoiseTransport {
    pub fn encrypt(&self, plaintext: Vec<u8>) -> Result<Vec<u8>, FfiError> {
        let mut g = self.inner.lock().map_err(|_| lock_poisoned())?;
        Ok(g.encrypt(&plaintext)?)
    }

    pub fn decrypt(&self, ciphertext: Vec<u8>) -> Result<Vec<u8>, FfiError> {
        let mut g = self.inner.lock().map_err(|_| lock_poisoned())?;
        Ok(g.decrypt(&ciphertext)?)
    }
}

// ── Bootstrap ephemeral + session derivation ──

/// Opaque handle holding a fresh X25519 ephemeral keypair for the secret-DH
/// session bootstrap. The secret lives in mlock'd, zeroize-on-drop heap and
/// never crosses the boundary; [`complete_bootstrap`] consumes it in place.
#[derive(uniffi::Object)]
pub struct BootstrapEphemeral {
    secret: Mutex<Option<LockedKey32>>,
    pub_bytes: [u8; 32],
}

#[uniffi::export]
impl BootstrapEphemeral {
    /// Generate a fresh X25519 ephemeral keypair.
    #[uniffi::constructor]
    pub fn generate() -> Result<Arc<Self>, FfiError> {
        let secret = session_keys::gen_ephemeral_secret()?;
        // Mirror python.rs (M-CRYPT-3): scrub the transient stack copy of the
        // scalar — the source of session forward secrecy — once the dalek
        // copy holds the live value.
        let scalar = Zeroizing::new(*secret.as_array());
        let static_secret = StaticSecret::from(*scalar);
        let pub_bytes = *PublicKey::from(&static_secret).as_bytes();
        Ok(Arc::new(Self {
            secret: Mutex::new(Some(secret)),
            pub_bytes,
        }))
    }

    /// The 32-byte X25519 public key to transmit on the wire.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.pub_bytes.to_vec()
    }

    /// True until [`complete_bootstrap`] consumes the secret.
    pub fn is_live(&self) -> Result<bool, FfiError> {
        let g = self.secret.lock().map_err(|_| lock_poisoned())?;
        Ok(g.is_some())
    }
}

/// Derive a [`SessionKeyManager`] from a [`BootstrapEphemeral`] and the peer's
/// public key. Consumes the ephemeral's secret in place; the X25519 DH + HKDF
/// happen entirely in Rust.
#[uniffi::export]
pub fn complete_bootstrap(
    ephemeral: Arc<BootstrapEphemeral>,
    peer_public: Vec<u8>,
    is_initiator: bool,
    rotation_packets: Option<u64>,
    rotation_seconds: Option<u64>,
) -> Result<Arc<SessionKeyManager>, FfiError> {
    let secret = ephemeral
        .secret
        .lock()
        .map_err(|_| lock_poisoned())?
        .take()
        .ok_or_else(|| FfiError::InvalidInput {
            msg: "BootstrapEphemeral already consumed".into(),
        })?;
    let peer = fixed::<32>(&peer_public, "peer public key")?;
    let inner = session_keys::bootstrap_keys_from_dh(
        secret.as_array(),
        &peer,
        is_initiator,
        rotation_packets,
        rotation_seconds,
    )?;
    // `secret` drops here: munlock + zeroize via LockedKey32::Drop.
    Ok(Arc::new(SessionKeyManager {
        inner: Mutex::new(SkmInner {
            inner,
            pending_rotation: None,
            pending_responder_rotation: None,
        }),
    }))
}

// ── Session key manager ──

struct SkmInner {
    inner: session_keys::SessionKeyManager,
    pending_rotation: Option<session_keys::RotationInit>,
    pending_responder_rotation: Option<session_keys::ResponderPending>,
}

/// Data-path AEAD with key rotation. Holds the manager plus the in-progress
/// rotation state (mirrors `python.rs`'s `pending_rotation` /
/// `pending_responder_rotation`). Rekey is bidirectional — the client may
/// initiate a rotation OR respond to a server-initiated one (the mutual-init
/// tie-break), so both rotation roles are exposed.
#[derive(uniffi::Object)]
pub struct SessionKeyManager {
    inner: Mutex<SkmInner>,
}

#[uniffi::export]
impl SessionKeyManager {
    /// Encrypt a packet. `aad` MUST equal `seq.to_be_bytes()` (8 bytes).
    pub fn encrypt(&self, plaintext: Vec<u8>, aad: Vec<u8>) -> Result<EncryptResult, FfiError> {
        let mut g = self.inner.lock().map_err(|_| lock_poisoned())?;
        let (nonce, ciphertext, epoch) = g.inner.encrypt(&plaintext, &aad)?;
        Ok(EncryptResult {
            nonce: nonce.to_vec(),
            ciphertext,
            epoch,
        })
    }

    /// Decrypt a packet (current epoch, or previous during grace when
    /// `is_prev_epoch`). `aad` MUST equal `seq.to_be_bytes()`.
    pub fn decrypt(
        &self,
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        aad: Vec<u8>,
        seq: u64,
        is_prev_epoch: bool,
    ) -> Result<Vec<u8>, FfiError> {
        let n = fixed::<12>(&nonce, "nonce")?;
        let mut g = self.inner.lock().map_err(|_| lock_poisoned())?;
        Ok(g.inner.decrypt(&n, &ciphertext, &aad, seq, is_prev_epoch)?)
    }

    /// Non-raising decrypt: tries the current epoch, then the previous epoch
    /// when grace is active. Returns `None` on auth failure (no error
    /// construction on the hot forgery-reject path). Mirrors the Python
    /// `try_decrypt_with_fallback` timing-uniform pattern.
    pub fn try_decrypt_with_fallback(
        &self,
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        aad: Vec<u8>,
        seq: u64,
    ) -> Result<Option<DecryptFallback>, FfiError> {
        let n = fixed::<12>(&nonce, "nonce")?;
        let mut g = self.inner.lock().map_err(|_| lock_poisoned())?;
        if let Ok(pt) = g.inner.decrypt(&n, &ciphertext, &aad, seq, false) {
            return Ok(Some(DecryptFallback {
                plaintext: pt,
                used_prev_epoch: false,
            }));
        }
        // Keep failure-path timing uniform regardless of grace state (mirrors
        // python.rs M1): always do a second AEAD on the failure path.
        if g.inner.has_grace_period() {
            if let Ok(pt) = g.inner.decrypt(&n, &ciphertext, &aad, seq, true) {
                return Ok(Some(DecryptFallback {
                    plaintext: pt,
                    used_prev_epoch: true,
                }));
            }
        } else {
            let _ = g.inner.decrypt(&n, &ciphertext, &aad, seq, false);
        }
        Ok(None)
    }

    /// Whether rotation is due (packet count or time threshold).
    pub fn needs_rotation(&self) -> Result<bool, FfiError> {
        let g = self.inner.lock().map_err(|_| lock_poisoned())?;
        Ok(g.inner.needs_rotation())
    }

    /// Initiate rotation. Stores the ephemeral secret internally for
    /// [`complete_rotation_initiator`](Self::complete_rotation_initiator).
    pub fn initiate_rotation(&self) -> Result<RotationInitResult, FfiError> {
        let mut g = self.inner.lock().map_err(|_| lock_poisoned())?;
        if g.pending_rotation.is_some() {
            return Err(FfiError::InvalidInput {
                msg: "rotation already in progress".into(),
            });
        }
        let init = g.inner.initiate_rotation()?;
        let new_epoch = init.new_epoch;
        let ephemeral_pub = init.ephemeral_pub.to_vec();
        g.pending_rotation = Some(init);
        Ok(RotationInitResult {
            new_epoch,
            ephemeral_pub,
        })
    }

    /// Complete an initiator-side rotation after receiving the responder's ACK.
    pub fn complete_rotation_initiator(
        &self,
        remote_ephemeral_pub: Vec<u8>,
    ) -> Result<u32, FfiError> {
        let pub_bytes = fixed::<32>(&remote_ephemeral_pub, "remote ephemeral public key")?;
        let mut g = self.inner.lock().map_err(|_| lock_poisoned())?;
        let init = g
            .pending_rotation
            .take()
            .ok_or_else(|| FfiError::InvalidInput {
                msg: "no pending rotation".into(),
            })?;
        let complete = g.inner.complete_rotation_initiator(init, &pub_bytes)?;
        Ok(complete.new_epoch)
    }

    /// Abort a pending initiator rotation (mutual-init tie-break yield path).
    /// Idempotent; returns true if a pending rotation was dropped.
    pub fn abort_rotation(&self) -> Result<bool, FfiError> {
        let mut g = self.inner.lock().map_err(|_| lock_poisoned())?;
        Ok(g.pending_rotation.take().is_some())
    }

    /// Single-shot responder rotation: derive + apply immediately. Network
    /// users should prefer the two-phase prepare/apply pair so the ACK can be
    /// sent under the old keys.
    pub fn complete_rotation_responder(
        &self,
        remote_ephemeral_pub: Vec<u8>,
        new_epoch: u32,
    ) -> Result<RotationResponderResult, FfiError> {
        let pub_bytes = fixed::<32>(&remote_ephemeral_pub, "remote ephemeral public key")?;
        let mut g = self.inner.lock().map_err(|_| lock_poisoned())?;
        let (our_pub, complete) = g.inner.complete_rotation_responder(&pub_bytes, new_epoch)?;
        Ok(RotationResponderResult {
            our_ephemeral_pub: our_pub.to_vec(),
            new_epoch: complete.new_epoch,
        })
    }

    /// Phase 1 of two-phase responder rotation: derive the new keys + our
    /// ephemeral public WITHOUT mutating session state. A stale pending (from
    /// a timed-out ACK send) is dropped and prepared fresh (mirrors python.rs).
    pub fn prepare_rotation_responder(
        &self,
        remote_ephemeral_pub: Vec<u8>,
        new_epoch: u32,
    ) -> Result<RotationResponderResult, FfiError> {
        let pub_bytes = fixed::<32>(&remote_ephemeral_pub, "remote ephemeral public key")?;
        let mut g = self.inner.lock().map_err(|_| lock_poisoned())?;
        let _ = g.pending_responder_rotation.take();
        let pending = g.inner.prepare_rotation_responder(&pub_bytes, new_epoch)?;
        let our_pub = pending.our_pub.to_vec();
        let epoch = pending.new_epoch;
        g.pending_responder_rotation = Some(pending);
        Ok(RotationResponderResult {
            our_ephemeral_pub: our_pub,
            new_epoch: epoch,
        })
    }

    /// Phase 2 of two-phase responder rotation: apply the prepared keys.
    pub fn apply_rotation_responder(&self) -> Result<u32, FfiError> {
        let mut g = self.inner.lock().map_err(|_| lock_poisoned())?;
        let pending =
            g.pending_responder_rotation
                .take()
                .ok_or_else(|| FfiError::InvalidInput {
                    msg: "no prepared responder rotation".into(),
                })?;
        let complete = g.inner.apply_rotation_responder(pending)?;
        Ok(complete.new_epoch)
    }

    /// Periodic maintenance: expire grace-period keys, promote a deferred
    /// send-key swap.
    pub fn tick(&self) -> Result<(), FfiError> {
        let mut g = self.inner.lock().map_err(|_| lock_poisoned())?;
        g.inner.tick();
        Ok(())
    }

    pub fn epoch(&self) -> Result<u32, FfiError> {
        let g = self.inner.lock().map_err(|_| lock_poisoned())?;
        Ok(g.inner.epoch())
    }

    pub fn packets_sent(&self) -> Result<u64, FfiError> {
        let g = self.inner.lock().map_err(|_| lock_poisoned())?;
        Ok(g.inner.packets_sent())
    }

    pub fn has_grace_period(&self) -> Result<bool, FfiError> {
        let g = self.inner.lock().map_err(|_| lock_poisoned())?;
        Ok(g.inner.has_grace_period())
    }
}

// ── Replay window ──

/// Outer wire-sequence replay window. The client data path uses one to drop
/// replays BEFORE the AEAD work (see `dsm/session.py`); it is distinct from the
/// per-epoch replay window inside [`SessionKeyManager`].
#[derive(uniffi::Object)]
pub struct ReplayWindow {
    inner: Mutex<replay_window::ReplayWindow>,
}

#[uniffi::export]
impl ReplayWindow {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(replay_window::ReplayWindow::new()),
        })
    }

    /// Check `seq` and, if fresh, mark it seen. Returns false if it is a replay.
    pub fn check_and_update(&self, seq: u64) -> Result<bool, FfiError> {
        let mut g = self.inner.lock().map_err(|_| lock_poisoned())?;
        Ok(g.check_and_update(seq))
    }

    /// Read-only freshness check (does not advance the window).
    pub fn check(&self, seq: u64) -> Result<bool, FfiError> {
        let g = self.inner.lock().map_err(|_| lock_poisoned())?;
        Ok(g.check(seq))
    }

    /// Mark `seq` as seen. Call only after successful authentication.
    pub fn update(&self, seq: u64) -> Result<(), FfiError> {
        let mut g = self.inner.lock().map_err(|_| lock_poisoned())?;
        g.update(seq);
        Ok(())
    }

    pub fn max_seq(&self) -> Result<u64, FfiError> {
        let g = self.inner.lock().map_err(|_| lock_poisoned())?;
        Ok(g.max_seq())
    }
}

// ── Attestation signer callback ──

/// Callback interface implemented by the Kotlin app over its Android
/// Keystore/StrongBox key. The Rust attestation backend (Task A4) calls
/// [`sign`](Self::sign) to produce the per-handshake binding signature without
/// the signing scalar ever entering Rust (it stays in StrongBox).
#[uniffi::export(with_foreign)]
pub trait AttestSigner: Send + Sync {
    /// Sign `challenge` (the handshake-binding message) with the Keystore key.
    /// Returns an ASN.1 DER ECDSA signature.
    fn sign(&self, challenge: Vec<u8>) -> Result<Vec<u8>, FfiError>;

    /// SubjectPublicKeyInfo DER of the Keystore key's public key.
    fn public_spki_der(&self) -> Result<Vec<u8>, FfiError>;

    /// The Android Key-Attestation certificate chain (leaf first), each cert
    /// DER-encoded. The server (Task A5) verifies this against the Google
    /// hardware-attestation root.
    fn attestation_cert_chain(&self) -> Result<Vec<Vec<u8>>, FfiError>;
}

/// Exercise an [`AttestSigner`] end to end: sign `challenge`, fetch the public
/// SPKI, and fetch the attestation cert chain, returning all three.
///
/// This is the A3 plumbing hook — it proves a foreign (or Rust) signer drives
/// correctly across the boundary. The real Android attestation backend
/// (Task A4) will hold the same `Arc<dyn AttestSigner>` and delegate its
/// `sign` / `public_spki_der` to it.
#[uniffi::export]
pub fn attest_signer_probe(
    signer: Arc<dyn AttestSigner>,
    challenge: Vec<u8>,
) -> Result<AttestProbe, FfiError> {
    let signature = signer.sign(challenge)?;
    let public_spki_der = signer.public_spki_der()?;
    let cert_chain = signer.attestation_cert_chain()?;
    Ok(AttestProbe {
        signature,
        public_spki_der,
        cert_chain,
    })
}

// ── Module-level constants ──

/// Fixed attestation-payload size carried in Noise XX msg2/msg3. Kotlin needs
/// it to build the padded attest payload before `write_message_3`.
#[uniffi::export]
pub fn handshake_attest_payload_size() -> u32 {
    noise_xx::HANDSHAKE_ATTEST_PAYLOAD_SIZE as u32
}

/// True when the active compile-time attestation backend is the software
/// (extractable-key) backend. Lets the app gate startup on a hardware backend.
#[uniffi::export]
pub fn attest_backend_is_software() -> bool {
    crate::device_attest::BACKEND_IS_SOFTWARE
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use rand::RngCore;

    fn random_secret() -> [u8; 32] {
        let mut k = [0u8; 32];
        OsRng.fill_bytes(&mut k);
        k
    }

    /// Drive the FFI Noise *initiator* + transport against a core
    /// `NoiseResponder` (the responder is not exposed over FFI — a client
    /// never plays it — so the test stands one up directly).
    #[test]
    fn ffi_initiator_handshake_with_core_responder() {
        let server_secret = random_secret();
        let mut responder = noise_xx::NoiseResponder::new(&server_secret).unwrap();
        let server_pub = *PublicKey::from(&StaticSecret::from(server_secret)).as_bytes();

        let identity = IdentityKeyPair::generate().unwrap();
        let initiator = NoiseInitiator::new(identity.clone()).unwrap();

        let msg1 = initiator.write_message_1().unwrap();
        responder.read_message_1(&msg1).unwrap();

        let server_payload = vec![7u8; noise_xx::HANDSHAKE_ATTEST_PAYLOAD_SIZE];
        let msg2 = responder.write_message_2(&server_payload).unwrap();

        // Snapshot the binding hash before read_message_2, as the orchestration
        // layer must.
        let _hash = initiator.get_handshake_hash().unwrap();
        let m2 = initiator.read_message_2(msg2).unwrap();
        assert_eq!(m2.remote_static, server_pub.to_vec());
        assert_eq!(m2.attest_payload, server_payload);

        let client_payload = vec![9u8; noise_xx::HANDSHAKE_ATTEST_PAYLOAD_SIZE];
        let msg3 = initiator.write_message_3(client_payload.clone()).unwrap();
        let (client_static, got) = responder.read_message_3(&msg3).unwrap();
        assert_eq!(got, client_payload);
        assert_eq!(client_static, identity.public_key().unwrap());

        // Transport round trip both directions.
        let c_transport = initiator.into_transport().unwrap();
        let mut s_transport = responder.into_transport().unwrap();
        let ct = c_transport.encrypt(b"hi server".to_vec()).unwrap();
        assert_eq!(s_transport.decrypt(&ct).unwrap(), b"hi server");
        let ct2 = s_transport.encrypt(b"hi client").unwrap();
        assert_eq!(c_transport.decrypt(ct2).unwrap(), b"hi client");

        // Consumed handle errors cleanly, not panics.
        assert!(matches!(
            initiator.write_message_1().unwrap_err(),
            FfiError::InvalidInput { .. }
        ));
    }

    /// Build two paired managers via the FFI bootstrap path and round-trip a
    /// packet through `encrypt` / `decrypt`.
    fn paired_managers() -> (Arc<SessionKeyManager>, Arc<SessionKeyManager>) {
        let client_eph = BootstrapEphemeral::generate().unwrap();
        let server_eph = BootstrapEphemeral::generate().unwrap();
        let client_pub = client_eph.public_key_bytes();
        let server_pub = server_eph.public_key_bytes();

        let client = complete_bootstrap(client_eph.clone(), server_pub, true, None, None).unwrap();
        let server = complete_bootstrap(server_eph, client_pub, false, None, None).unwrap();
        assert!(!client_eph.is_live().unwrap());
        (client, server)
    }

    #[test]
    fn ffi_session_bootstrap_and_aead_roundtrip() {
        let (client, server) = paired_managers();
        let aad = 1u64.to_be_bytes().to_vec();

        let enc = client.encrypt(b"hello".to_vec(), aad.clone()).unwrap();
        assert_eq!(enc.epoch, client.epoch().unwrap());
        let pt = server
            .decrypt(enc.nonce, enc.ciphertext, aad.clone(), 1, false)
            .unwrap();
        assert_eq!(pt, b"hello");

        // Consumed ephemeral cannot bootstrap twice.
        let spent = BootstrapEphemeral::generate().unwrap();
        let peer = BootstrapEphemeral::generate().unwrap().public_key_bytes();
        complete_bootstrap(spent.clone(), peer.clone(), true, None, None).unwrap();
        assert!(complete_bootstrap(spent, peer, true, None, None).is_err());
    }

    #[test]
    fn ffi_session_rekey_roundtrip() {
        let (client, server) = paired_managers();
        let aad = 1u64.to_be_bytes().to_vec();
        let start = client.epoch().unwrap();

        let init = client.initiate_rotation().unwrap();
        assert_eq!(init.new_epoch, start + 1);
        let resp = server
            .complete_rotation_responder(init.ephemeral_pub.clone(), init.new_epoch)
            .unwrap();
        let new_epoch = client
            .complete_rotation_initiator(resp.our_ephemeral_pub)
            .unwrap();
        assert_eq!(new_epoch, start + 1);
        assert_eq!(client.epoch().unwrap(), start + 1);

        let enc = client.encrypt(b"after".to_vec(), aad.clone()).unwrap();
        assert_eq!(enc.epoch, start + 1);
        let pt = server
            .decrypt(enc.nonce, enc.ciphertext, aad, 1, false)
            .unwrap();
        assert_eq!(pt, b"after");

        // abort_rotation is idempotent.
        assert!(!client.abort_rotation().unwrap());
    }

    #[test]
    fn ffi_replay_window() {
        let w = ReplayWindow::new();
        assert!(w.check_and_update(1).unwrap());
        assert!(!w.check_and_update(1).unwrap());
        assert!(w.check(2).unwrap());
        w.update(2).unwrap();
        assert!(!w.check(2).unwrap());
    }

    #[test]
    fn ffi_identity_store_roundtrip() {
        let id = IdentityKeyPair::generate().unwrap();
        let pub_key = id.public_key().unwrap();
        assert_ne!(pub_key, vec![0u8; 32]);
        let blob = id.encrypt_to_store(b"correct horse".to_vec()).unwrap();
        let restored =
            IdentityKeyPair::decrypt_from_store(blob, b"correct horse".to_vec()).unwrap();
        assert_eq!(restored.public_key().unwrap(), pub_key);
    }

    // Fake in-Rust AttestSigner exercising the callback plumbing without a
    // device (the real impl is Kotlin over the Android Keystore — Task A4/A6).
    struct FakeSigner {
        sig: Vec<u8>,
        spki: Vec<u8>,
        chain: Vec<Vec<u8>>,
        fail: bool,
    }

    impl AttestSigner for FakeSigner {
        fn sign(&self, challenge: Vec<u8>) -> Result<Vec<u8>, FfiError> {
            if self.fail {
                return Err(FfiError::Callback {
                    msg: "strongbox unavailable".into(),
                });
            }
            // Bind the challenge into the output so the round trip is observable.
            let mut out = self.sig.clone();
            out.extend_from_slice(&challenge);
            Ok(out)
        }

        fn public_spki_der(&self) -> Result<Vec<u8>, FfiError> {
            Ok(self.spki.clone())
        }

        fn attestation_cert_chain(&self) -> Result<Vec<Vec<u8>>, FfiError> {
            Ok(self.chain.clone())
        }
    }

    #[test]
    fn ffi_attest_signer_probe_roundtrip() {
        let signer = Arc::new(FakeSigner {
            sig: vec![0xAB; 4],
            spki: vec![0xCD; 8],
            chain: vec![vec![1, 2, 3], vec![4, 5]],
            fail: false,
        });
        let probe = attest_signer_probe(signer, vec![9, 9, 9]).unwrap();
        assert_eq!(probe.signature, vec![0xAB, 0xAB, 0xAB, 0xAB, 9, 9, 9]);
        assert_eq!(probe.public_spki_der, vec![0xCD; 8]);
        assert_eq!(probe.cert_chain, vec![vec![1, 2, 3], vec![4, 5]]);
    }

    #[test]
    fn ffi_attest_signer_probe_propagates_error() {
        let signer = Arc::new(FakeSigner {
            sig: vec![],
            spki: vec![],
            chain: vec![],
            fail: true,
        });
        let result = attest_signer_probe(signer, vec![1]);
        assert!(matches!(result, Err(FfiError::Callback { .. })));
    }
}
