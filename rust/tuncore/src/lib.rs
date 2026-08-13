// CI runs clippy with `-D warnings -W clippy::pedantic -W clippy::unwrap_used`.
// The pedantic-group lints allowed below are opt-in style/doc lints that are
// noise for this FFI crypto core; declining them disables NO default clippy
// lint (correctness / suspicious / complexity / perf / style stay -D blocking):
//   doc_markdown, missing_errors_doc, missing_panics_doc, must_use_candidate
//     - exhaustive rustdoc is not required on this internal, fully-tested crate.
//   cast_possible_truncation / cast_sign_loss / cast_possible_wrap
//     - the casts are intentional, audited width conversions (u32 nonce
//       counters/epochs, byte lengths); flagged for a one-time reviewer glance.
//   items_after_statements, needless_pass_by_value, map_unwrap_or, ptr_as_ptr,
//   borrow_as_ptr, match_wildcard_for_single_variants, unnecessary_wraps,
//   module_name_repetitions, redundant_closure_for_method_calls
//     - stylistic; not worth restructuring audited code in a lint pass.
#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::items_after_statements,
    clippy::needless_pass_by_value,
    clippy::map_unwrap_or,
    clippy::ptr_as_ptr,
    clippy::borrow_as_ptr,
    clippy::match_wildcard_for_single_variants,
    clippy::unnecessary_wraps,
    clippy::module_name_repetitions,
    clippy::redundant_closure_for_method_calls
)]
// unwrap()/expect() are fine in tests — a panic IS the failure signal — so
// allow clippy::unwrap_used in test builds only; it stays denied in lib code.
#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod aes_gcm;
pub mod device_attest;
#[cfg(feature = "dev-soft-attest")]
pub mod device_attest_soft;
#[cfg(feature = "tpm-attest")]
pub mod device_attest_tpm;
pub mod identity;
pub mod noise_xx;
pub mod nonce;
pub mod passphrase_store;
pub mod replay_window;
pub mod secure_memory;
pub mod secure_noise;
pub mod session_keys;
pub mod tpm_blob;

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

// Raw key bytes never cross the FFI boundary for secret keys.
// Python receives opaque handles and public keys only.

macro_rules! require_inner {
    ($self:expr, $msg:expr) => {
        $self.inner.as_mut().ok_or_else(|| py_err($msg))?
    };
}

fn py_err(e: impl std::fmt::Display) -> PyErr {
    PyRuntimeError::new_err(e.to_string())
}

/// Copy a Python byte slice into a fixed-size array, returning an error
/// whose message names the expected field.
///
/// `desc` is the human-readable field name (e.g. "nonce", "public key");
/// it lands in the Python exception so misuse prints the precise mismatch.
fn fixed_from_slice<const N: usize>(data: &[u8], desc: &str) -> PyResult<[u8; N]> {
    if data.len() != N {
        return Err(py_err(format!("{desc} must be {N} bytes")));
    }
    let mut arr = [0u8; N];
    arr.copy_from_slice(data);
    Ok(arr)
}

fn nonce_from_slice(nonce: &[u8]) -> PyResult<[u8; 12]> {
    fixed_from_slice::<12>(nonce, "nonce")
}

fn pub_key_from_slice(data: &[u8]) -> PyResult<[u8; 32]> {
    fixed_from_slice::<32>(data, "public key")
}

#[pyclass(name = "IdentityKeyPair")]
struct PyIdentityKeyPair {
    inner: identity::IdentityKeyPair,
}

#[pymethods]
impl PyIdentityKeyPair {
    #[staticmethod]
    fn generate() -> PyResult<Self> {
        let inner = identity::IdentityKeyPair::generate().map_err(py_err)?;
        Ok(Self { inner })
    }

    #[getter]
    fn public_key(&self) -> Vec<u8> {
        self.inner.public_key().to_vec()
    }

    fn encrypt_to_store(&self, passphrase: &[u8]) -> PyResult<Vec<u8>> {
        self.inner.encrypt_to_store(passphrase).map_err(py_err)
    }

    #[staticmethod]
    fn decrypt_from_store(blob: &[u8], passphrase: &[u8]) -> PyResult<Self> {
        let inner =
            identity::IdentityKeyPair::decrypt_from_store(blob, passphrase).map_err(py_err)?;
        Ok(Self { inner })
    }

    /// Zeroize the secret key in place. After this call, the keypair is unusable.
    /// Safe to call multiple times.
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

#[pyclass(name = "ReplayWindow")]
struct PyReplayWindow {
    inner: replay_window::ReplayWindow,
}

#[pymethods]
impl PyReplayWindow {
    #[new]
    fn new() -> Self {
        Self {
            inner: replay_window::ReplayWindow::new(),
        }
    }

    /// Read-only check: returns true if seq would be accepted.
    fn check(&self, seq: u64) -> bool {
        self.inner.check(seq)
    }

    /// Mark seq as seen. Call only after successful authentication.
    fn update(&mut self, seq: u64) {
        self.inner.update(seq);
    }
}

#[pyclass(name = "NoiseInitiator")]
struct PyNoiseInitiator {
    inner: Option<noise_xx::NoiseInitiator>,
}

#[pymethods]
impl PyNoiseInitiator {
    #[new]
    fn new(identity: &PyIdentityKeyPair) -> PyResult<Self> {
        let init = noise_xx::NoiseInitiator::new(identity.inner.secret_key()).map_err(py_err)?;
        Ok(Self { inner: Some(init) })
    }

    fn write_message_1(&mut self) -> PyResult<Vec<u8>> {
        require_inner!(self, "already consumed")
            .write_message_1()
            .map_err(py_err)
    }

    /// Decrypt msg2. Returns `(remote_static_pub, attest_payload)`. The
    /// attest_payload is exactly HANDSHAKE_ATTEST_PAYLOAD_SIZE bytes —
    /// the caller parses cert + signature + pad framing.
    fn read_message_2(&mut self, msg: &[u8]) -> PyResult<(Vec<u8>, Vec<u8>)> {
        require_inner!(self, "already consumed")
            .read_message_2(msg)
            .map_err(py_err)
    }

    /// Send msg3 carrying the initiator's attestation payload. The payload
    /// must be exactly HANDSHAKE_ATTEST_PAYLOAD_SIZE bytes.
    fn write_message_3(&mut self, attest_payload: &[u8]) -> PyResult<Vec<u8>> {
        require_inner!(self, "already consumed")
            .write_message_3(attest_payload)
            .map_err(py_err)
    }

    #[allow(clippy::wrong_self_convention)]
    fn into_transport(&mut self) -> PyResult<PyNoiseTransport> {
        let init = self
            .inner
            .take()
            .ok_or_else(|| py_err("already consumed"))?;
        let transport = init.into_transport().map_err(py_err)?;
        Ok(PyNoiseTransport {
            inner: Some(transport),
        })
    }

    /// Must be called after the handshake completes, before into_transport().
    fn get_handshake_hash(&self) -> PyResult<Vec<u8>> {
        Ok(self
            .inner
            .as_ref()
            .ok_or_else(|| py_err("already consumed"))?
            .get_handshake_hash())
    }
}

#[pyclass(name = "NoiseResponder")]
struct PyNoiseResponder {
    inner: Option<noise_xx::NoiseResponder>,
}

#[pymethods]
impl PyNoiseResponder {
    #[new]
    fn new(identity: &PyIdentityKeyPair) -> PyResult<Self> {
        let resp = noise_xx::NoiseResponder::new(identity.inner.secret_key()).map_err(py_err)?;
        Ok(Self { inner: Some(resp) })
    }

    fn read_message_1(&mut self, msg: &[u8]) -> PyResult<()> {
        require_inner!(self, "already consumed")
            .read_message_1(msg)
            .map_err(py_err)
    }

    /// Send msg2 carrying the responder's attestation payload. The payload
    /// must be exactly HANDSHAKE_ATTEST_PAYLOAD_SIZE bytes.
    fn write_message_2(&mut self, attest_payload: &[u8]) -> PyResult<Vec<u8>> {
        require_inner!(self, "already consumed")
            .write_message_2(attest_payload)
            .map_err(py_err)
    }

    /// Decrypt msg3. Returns `(remote_static_pub, attest_payload)`. The
    /// attest_payload is exactly HANDSHAKE_ATTEST_PAYLOAD_SIZE bytes.
    fn read_message_3(&mut self, msg: &[u8]) -> PyResult<(Vec<u8>, Vec<u8>)> {
        require_inner!(self, "already consumed")
            .read_message_3(msg)
            .map_err(py_err)
    }

    #[allow(clippy::wrong_self_convention)]
    fn into_transport(&mut self) -> PyResult<PyNoiseTransport> {
        let resp = self
            .inner
            .take()
            .ok_or_else(|| py_err("already consumed"))?;
        let transport = resp.into_transport().map_err(py_err)?;
        Ok(PyNoiseTransport {
            inner: Some(transport),
        })
    }

    /// Must be called after the handshake completes, before into_transport().
    fn get_handshake_hash(&self) -> PyResult<Vec<u8>> {
        Ok(self
            .inner
            .as_ref()
            .ok_or_else(|| py_err("already consumed"))?
            .get_handshake_hash())
    }
}

#[pyclass(name = "NoiseTransport")]
struct PyNoiseTransport {
    inner: Option<noise_xx::NoiseTransport>,
}

#[pymethods]
impl PyNoiseTransport {
    fn encrypt(&mut self, plaintext: &[u8]) -> PyResult<Vec<u8>> {
        require_inner!(self, "transport closed")
            .encrypt(plaintext)
            .map_err(py_err)
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> PyResult<Vec<u8>> {
        require_inner!(self, "transport closed")
            .decrypt(ciphertext)
            .map_err(py_err)
    }
}

/// Python-visible session key manager with key rotation support.
// Audit H2: per-direction ownership is a documented invariant; with
// `py.allow_threads(...)` releasing the GIL during AEAD, a second OS
// thread calling encrypt/decrypt on the SAME SessionKeyManager would
// hit a `&mut self` borrow conflict and PyO3 would panic. `unsendable`
// fences this at the type system: passing this class to
// `loop.run_in_executor` / `asyncio.to_thread` raises a clear
// `RuntimeError: ... unsendable` instead of corrupting state under
// a thread switch. Costs nothing in normal usage (asyncio runs on
// one thread); just locks the invariant in.
#[pyclass(name = "SessionKeyManager", unsendable)]
struct PySessionKeyManager {
    inner: session_keys::SessionKeyManager,
    pending_rotation: Option<session_keys::RotationInit>,
    // For the two-phase responder flow: derived-but-not-yet-applied rotation
    // held here between prepare_rotation_responder and apply_rotation_responder
    // so the ACK can be sent with old keys in between.
    pending_responder_rotation: Option<session_keys::ResponderPending>,
}

// Concurrency invariant for the encrypt/decrypt hot path:
// Exactly one Python coroutine per direction owns this SessionKeyManager.
// Concurrent calls from different OS threads on the same instance are
// undefined behavior. The `&mut self` borrow guards the nonce counter
// and packets_sent on a single-thread basis; Python's asyncio scheduler
// runs at most one coroutine per thread, which is sufficient because
// the application creates a separate manager per direction (send / recv).
// `py.allow_threads(...)` below releases the GIL during the AEAD core
// so other Python threads can make progress; the `&mut self` exclusivity
// across that boundary is preserved by Rust's borrow checker, not the GIL.
#[pymethods]
impl PySessionKeyManager {
    // Audit M2 / M4: every former Python constructor for SessionKeyManager
    // has been retired in favor of `complete_bootstrap`.
    //
    //   * `from_handshake_hash` derived keys from the PUBLIC Noise transcript
    //     hash — a passive observer could recompute it.
    //   * `from_bootstrap_shared_secret` accepted a SECRET shared-secret
    //     through Python `bytes`, which cannot be reliably zeroed.
    //
    // The underlying Rust functions still exist (gated `#[cfg(test)]` and
    // crate-private respectively) for unit-test plumbing; only the safe
    // path — `BootstrapEphemeral` + `complete_bootstrap` — is reachable
    // from Python.

    /// Encrypt a packet. Returns (nonce, ciphertext, epoch).
    ///
    /// The AEAD core runs without holding the GIL (H-PERF-2); see the
    /// impl-block comment above for the per-direction ownership invariant.
    /// Returns ciphertext as `PyBytes` directly (H-PERF-3) so Python
    /// callers can hand it to `struct.unpack_from` / `os.write` without
    /// a redundant `bytes(...)` copy.
    fn encrypt<'py>(
        &mut self,
        py: Python<'py>,
        plaintext: &[u8],
        aad: &[u8],
    ) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>, u32)> {
        let (nonce, ciphertext, epoch) =
            py.allow_threads(|| self.inner.encrypt(plaintext, aad).map_err(py_err))?;
        Ok((
            PyBytes::new(py, &nonce),
            PyBytes::new(py, &ciphertext),
            epoch,
        ))
    }

    /// Decrypt a packet. Returns plaintext as `PyBytes`.
    ///
    /// The AEAD core runs without holding the GIL (H-PERF-2); see the
    /// impl-block comment above for the per-direction ownership invariant.
    fn decrypt<'py>(
        &mut self,
        py: Python<'py>,
        nonce: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
        seq: u64,
        is_prev_epoch: bool,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let n = nonce_from_slice(nonce)?;
        let plaintext = py.allow_threads(|| {
            self.inner
                .decrypt(&n, ciphertext, aad, seq, is_prev_epoch)
                .map_err(py_err)
        })?;
        Ok(PyBytes::new(py, &plaintext))
    }

    /// M-PERF-5: non-raising decrypt that tries current epoch first and
    /// falls back to prev epoch if grace is active. Returns
    /// `Some((plaintext, used_prev_epoch))` on success, `None` on auth
    /// failure — no Python exception is constructed.
    ///
    /// Exception-driven control flow in CPython costs ~30µs per
    /// traceback build. A forgery flood at 100k pkt/s would burn ~3s
    /// of CPU per real second just on tracebacks. This API lets the
    /// caller distinguish auth-fail from programming-error without
    /// paying the traceback tax.
    fn try_decrypt_with_fallback<'py>(
        &mut self,
        py: Python<'py>,
        nonce: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
        seq: u64,
    ) -> PyResult<Option<(Bound<'py, PyBytes>, bool)>> {
        let n = nonce_from_slice(nonce)?;
        // Audit M1 fix: always attempt the prev-epoch decrypt on the
        // failure path, even when has_grace_period() would have been
        // false. Combined with the constant-AEAD-time pattern this
        // makes the function's timing uniform regardless of whether
        // grace is active — an adversary probing forgery-reject
        // latency cannot infer rekey timing. The dummy decrypt against
        // current keys (when prev_recv is None) costs ~one extra AEAD
        // tag verify on failure; the success path is unchanged.
        let result = py.allow_threads(|| {
            // Try current epoch first.
            if let Ok(pt) = self.inner.decrypt(&n, ciphertext, aad, seq, false) {
                return Some((pt, false));
            }
            // Prev-epoch attempt (see M1 note above); the grace check itself
            // is one load + one branch, far cheaper than the AEAD.
            // A SECOND current-epoch attempt fills in when prev isn't
            // available, keeping the failure path = 2 AEAD ops regardless
            // of grace state.
            if self.inner.has_grace_period() {
                if let Ok(pt) = self.inner.decrypt(&n, ciphertext, aad, seq, true) {
                    return Some((pt, true));
                }
            } else {
                // No grace; do a dummy current-epoch decrypt against
                // the same ciphertext to keep failure-path timing
                // uniform. Result is discarded (always Err here since
                // the first attempt also failed).
                let _ = self.inner.decrypt(&n, ciphertext, aad, seq, false);
            }
            None
        });
        Ok(result.map(|(pt, used_prev)| (PyBytes::new(py, &pt), used_prev)))
    }

    /// Check if key rotation is needed (packet count or time threshold).
    fn needs_rotation(&self) -> bool {
        self.inner.needs_rotation()
    }

    /// Initiate key rotation. Returns (new_epoch, ephemeral_pub).
    /// Stores the ephemeral secret internally for `complete_rotation_initiator`.
    fn initiate_rotation(&mut self) -> PyResult<(u32, Vec<u8>)> {
        if self.pending_rotation.is_some() {
            return Err(py_err("rotation already in progress"));
        }
        let init = self.inner.initiate_rotation().map_err(py_err)?;
        let new_epoch = init.new_epoch;
        let ephemeral_pub = init.ephemeral_pub.to_vec();
        self.pending_rotation = Some(init);
        Ok((new_epoch, ephemeral_pub))
    }

    /// Complete rotation as the initiator after receiving the responder's ACK.
    fn complete_rotation_initiator(&mut self, remote_ephemeral_pub: &[u8]) -> PyResult<u32> {
        let init = self
            .pending_rotation
            .take()
            .ok_or_else(|| py_err("no pending rotation"))?;
        let pub_bytes = pub_key_from_slice(remote_ephemeral_pub)?;
        let complete = self
            .inner
            .complete_rotation_initiator(init, &pub_bytes)
            .map_err(py_err)?;
        Ok(complete.new_epoch)
    }

    /// Abort a pending *initiator* rotation, discarding the stored ephemeral.
    ///
    /// Idempotent: returns true if a pending rotation was dropped, false if
    /// none was pending; never errors. Used on the mutual-init tie-break
    /// "yield" path (dsm/rekey.py) — the yielding side has already called
    /// `initiate_rotation` (which set `pending_rotation`) but will never call
    /// `complete_rotation_initiator`. Without dropping that pending init the
    /// next `initiate_rotation` fails with "rotation already in progress" and
    /// tears down a healthy session (DSM-003). `Option::take` drops the
    /// `RotationInit`, whose `ephemeral_secret: LockedKey32` is munlock'd and
    /// zeroized on drop, so the abandoned ephemeral scalar is wiped. No secret
    /// crosses the FFI — the method returns only a bool.
    fn abort_rotation(&mut self) -> bool {
        self.pending_rotation.take().is_some()
    }

    /// First phase of two-phase responder rotation. Derives the new keys
    /// and our ephemeral public key WITHOUT mutating session state; stores
    /// the derived keys internally. Caller sends REKEY_ACK with the still
    /// current (old) keys, then calls `apply_rotation_responder`.
    /// Returns (our_ephemeral_pub, new_epoch).
    fn prepare_rotation_responder(
        &mut self,
        remote_ephemeral_pub: &[u8],
        new_epoch: u32,
    ) -> PyResult<(Vec<u8>, u32)> {
        // Phase 1.2: a prior responder rotation whose REKEY_ACK send timed
        // out (dsm/rekey.py ACK-send-timeout path) leaves its pending here
        // with no apply. That is the ONLY way a pending lingers — a
        // successful rotation applies-and-clears within the same
        // handle_rekey_init call, and apply_rotation_responder().take()s the
        // pending even on its own error path. So any pending we find here is
        // always stale: drop it (zeroizing its LockedKey32 send/recv keys via
        // ResponderPending's Drop) and prepare fresh, rather than erroring
        // and wedging the responder forever.
        let _ = self.pending_responder_rotation.take();
        let pub_bytes = pub_key_from_slice(remote_ephemeral_pub)?;
        let pending = self
            .inner
            .prepare_rotation_responder(&pub_bytes, new_epoch)
            .map_err(py_err)?;
        let our_pub = pending.our_pub.to_vec();
        let epoch = pending.new_epoch;
        self.pending_responder_rotation = Some(pending);
        Ok((our_pub, epoch))
    }

    /// Second phase of two-phase responder rotation. Consumes the pending
    /// state left by `prepare_rotation_responder` and swaps the session keys.
    /// Returns the new epoch.
    fn apply_rotation_responder(&mut self) -> PyResult<u32> {
        let pending = self
            .pending_responder_rotation
            .take()
            .ok_or_else(|| py_err("no prepared responder rotation"))?;
        let complete = self
            .inner
            .apply_rotation_responder(pending)
            .map_err(py_err)?;
        Ok(complete.new_epoch)
    }

    /// Call periodically to clean up expired grace period keys.
    fn tick(&mut self) {
        self.inner.tick();
    }

    #[getter]
    fn epoch(&self) -> u32 {
        self.inner.epoch()
    }

    #[getter]
    fn send_epoch(&self) -> u32 {
        self.inner.send_epoch()
    }

    #[getter]
    fn has_grace_period(&self) -> bool {
        self.inner.has_grace_period()
    }
}

/// Python-visible device-attestation key. Backend selected at compile time
/// (see `device_attest.rs`). Holds an opaque handle; raw private-key bytes
/// never cross the FFI boundary.
#[pyclass(name = "AttestKey")]
struct PyAttestKey {
    inner: device_attest::AttestKey,
}

#[pymethods]
impl PyAttestKey {
    #[staticmethod]
    fn generate() -> PyResult<Self> {
        let inner = device_attest::AttestKey::generate().map_err(py_err)?;
        Ok(Self { inner })
    }

    /// Return the verifying key as SubjectPublicKeyInfo DER. Raises if
    /// the attest key has been zeroized.
    fn public_spki_der(&self) -> PyResult<Vec<u8>> {
        self.inner
            .public_spki_der()
            .map(<[u8]>::to_vec)
            .map_err(py_err)
    }

    /// Sign `msg` with the attestation key. Returns ASN.1 DER ECDSA signature.
    fn sign(&self, msg: &[u8]) -> PyResult<Vec<u8>> {
        self.inner.sign(msg).map_err(py_err)
    }

    /// Encrypt/seal the attest key to disk, binding the operator passphrase.
    ///
    /// The passphrase is LOAD-BEARING on BOTH backends:
    /// - Soft backend: the signing scalar is wrapped under the passphrase
    ///   (Argon2id + XChaCha20-Poly1305).
    /// - TPM backend: the key is TPM-resident (non-extractable), so the
    ///   passphrase is bound as the key's TPM authorization value via
    ///   `TPM2_ObjectChangeAuth` (defense-in-depth — TPM residency AND the
    ///   passphrase are then both required to sign). An empty passphrase keeps
    ///   the key empty-auth (back-compat).
    fn encrypt_to_store(&self, passphrase: &[u8]) -> PyResult<Vec<u8>> {
        self.inner.encrypt_to_store(passphrase).map_err(py_err)
    }

    /// Restore an attest key from a stored blob, applying the passphrase.
    ///
    /// Soft backend: unwraps the scalar. TPM backend: caches the
    /// passphrase-derived TPM auth so the next `sign` authorizes with it; a
    /// WRONG passphrase parses fine here but fails the next `sign` (TPM
    /// authorization rejection).
    #[staticmethod]
    fn decrypt_from_store(blob: &[u8], passphrase: &[u8]) -> PyResult<Self> {
        let inner =
            device_attest::AttestKey::decrypt_from_store(blob, passphrase).map_err(py_err)?;
        Ok(Self { inner })
    }

    /// Build a CA-ready DER CSR for this attest key. CN is the device's
    /// subject CommonName; `noise_static_pub` is the 32-byte X25519 Noise
    /// static that goes into the critical `id-dsm-noiseStaticBinding`
    /// extension. The PKCS#8 export of the signing scalar stays inside
    /// Rust (audit M4) — no key bytes cross the FFI boundary.
    fn build_csr(&self, cn: &str, noise_static_pub: &[u8]) -> PyResult<Vec<u8>> {
        self.inner.build_csr(cn, noise_static_pub).map_err(py_err)
    }

    /// Zeroize the attest signing scalar in place. After this call the
    /// instance is unusable; callers MUST drop the wrapping reference
    /// immediately. Mirrors `IdentityKeyPair.zeroize`. Safe to call
    /// multiple times; idempotent.
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

/// Harden the process: no core dumps, non-dumpable, no-new-privs.
#[pyfunction]
fn harden_process() -> PyResult<()> {
    secure_memory::harden_process().map_err(py_err)
}

// Audit M4: `generate_ephemeral` and `bootstrap_session_from_dh` (the older
// "raw-bytes" bootstrap pair) were dropped from the Python surface. Both
// moved the 32-byte X25519 scalar through a Python `bytes` object that
// CPython cannot reliably zero on garbage collection — leaving the secret
// scalar in process memory for the lifetime of the bytes object and any
// of its later allocator-slot reuses. The surviving path —
// `BootstrapEphemeral` + `complete_bootstrap` — keeps the secret in an
// mlock'd, zeroize-on-drop Rust heap buffer and consumes it in place.

/// Opaque handle holding a fresh X25519 ephemeral keypair for bootstrap DH.
///
/// The secret scalar lives in an mlock'd, zeroize-on-drop heap buffer and
/// never crosses the FFI boundary. Python sees only the matching public key.
/// `complete_bootstrap` consumes the handle and derives session keys without
/// ever copying the secret into Python-managed memory.
#[pyclass(name = "BootstrapEphemeral")]
struct PyBootstrapEphemeral {
    secret: Option<secure_memory::LockedKey32>,
    pub_bytes: [u8; 32],
}

#[pymethods]
impl PyBootstrapEphemeral {
    /// Generate a fresh X25519 ephemeral keypair. The secret is written
    /// directly into an mlock'd heap buffer; only the public key is
    /// reachable from Python.
    #[staticmethod]
    fn generate() -> PyResult<Self> {
        let secret = session_keys::gen_ephemeral_secret().map_err(py_err)?;
        // public_from_locked wraps the transient `*secret.as_array()` rvalue in
        // Zeroizing (M-CRYPT-3) so the bootstrap ephemeral scalar — the source
        // of forward secrecy for the whole session — is scrubbed off this stack
        // frame once the public key is derived.
        let pub_bytes = secure_memory::public_from_locked(&secret);
        Ok(Self {
            secret: Some(secret),
            pub_bytes,
        })
    }

    #[getter]
    fn public_key_bytes(&self) -> Vec<u8> {
        self.pub_bytes.to_vec()
    }

    /// True until ``complete_bootstrap`` consumes the secret.
    #[getter]
    fn is_live(&self) -> bool {
        self.secret.is_some()
    }
}

/// Derive session keys from a `BootstrapEphemeral` and the peer's public key.
///
/// Consumes the ephemeral's secret in place (so a second call returns an error).
/// The X25519 DH and the subsequent HKDF expansion happen entirely in Rust;
/// the secret scalar never crosses the FFI boundary.
#[pyfunction]
#[pyo3(signature = (ephemeral, peer_public, is_initiator,
                    rotation_packets=None, rotation_seconds=None))]
fn complete_bootstrap(
    ephemeral: &mut PyBootstrapEphemeral,
    peer_public: &[u8],
    is_initiator: bool,
    rotation_packets: Option<u64>,
    rotation_seconds: Option<u64>,
) -> PyResult<PySessionKeyManager> {
    let secret = ephemeral
        .secret
        .take()
        .ok_or_else(|| py_err("BootstrapEphemeral already consumed"))?;
    let peer = pub_key_from_slice(peer_public)?;
    let inner = session_keys::bootstrap_keys_from_dh(
        secret.as_array(),
        &peer,
        is_initiator,
        rotation_packets,
        rotation_seconds,
    )
    .map_err(py_err)?;
    // `secret` drops here: munlock + zeroize via LockedKey32::Drop.
    Ok(PySessionKeyManager {
        inner,
        pending_rotation: None,
        pending_responder_rotation: None,
    })
}

#[pymodule]
fn tuncore(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyIdentityKeyPair>()?;
    m.add_class::<PyReplayWindow>()?;
    m.add_class::<PyNoiseInitiator>()?;
    m.add_class::<PyNoiseResponder>()?;
    m.add_class::<PyNoiseTransport>()?;
    m.add_class::<PySessionKeyManager>()?;
    m.add_class::<PyAttestKey>()?;
    m.add_class::<PyBootstrapEphemeral>()?;
    m.add_function(wrap_pyfunction!(harden_process, m)?)?;
    m.add_function(wrap_pyfunction!(complete_bootstrap, m)?)?;
    m.add(
        "HANDSHAKE_ATTEST_PAYLOAD_SIZE",
        noise_xx::HANDSHAKE_ATTEST_PAYLOAD_SIZE,
    )?;
    m.add(
        "ATTEST_BACKEND_IS_SOFTWARE",
        device_attest::BACKEND_IS_SOFTWARE,
    )?;
    Ok(())
}

// NOTE: the Phase-1.2 fix (prepare_rotation_responder overwrites a stale
// pending instead of erroring) is covered by the FFI-level regression
// tests/test_rekey_responder_abort.py. An inline #[cfg(test)] test here that
// referenced the PyO3 wrapper type would pull libpython symbols into the
// crate's single test binary, which fails to link under the
// `extension-module` feature (pyo3 suppresses the libpython link directive),
// breaking `cargo test` for the WHOLE crate. The Python end-to-end test runs
// cleanly under pytest and verifies the same behavior through the FFI.
