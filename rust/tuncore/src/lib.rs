pub mod aes_gcm;
pub mod device_attest;
#[cfg(feature = "dev-soft-attest")]
pub mod device_attest_soft;
pub mod identity;
pub mod nonce;
pub mod noise_xx;
pub mod replay_window;
pub mod secure_memory;
pub mod session_keys;

use pyo3::prelude::*;
use pyo3::exceptions::PyRuntimeError;

// ── PyO3 Wrappers ──
// Raw key bytes never cross the FFI boundary for secret keys.
// Python receives opaque handles and public keys only.

/// Get a mutable reference to the inner `Option`, returning a PyErr if already consumed.
macro_rules! require_inner {
    ($self:expr, $msg:expr) => {
        $self.inner.as_mut().ok_or_else(|| py_err($msg))?
    };
}

/// Convert a Rust error into a PyRuntimeError.
fn py_err(e: impl std::fmt::Display) -> PyErr {
    PyRuntimeError::new_err(e.to_string())
}

/// Parse a Python byte slice into a fixed 12-byte nonce array.
fn nonce_from_slice(nonce: &[u8]) -> PyResult<[u8; 12]> {
    if nonce.len() != 12 {
        return Err(py_err("nonce must be 12 bytes"));
    }
    let mut n = [0u8; 12];
    n.copy_from_slice(nonce);
    Ok(n)
}

/// Parse a Python byte slice into a fixed 32-byte public key array.
fn pub_key_from_slice(data: &[u8]) -> PyResult<[u8; 32]> {
    if data.len() != 32 {
        return Err(py_err("public key must be 32 bytes"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(data);
    Ok(arr)
}

/// Python-visible identity keypair.
#[pyclass(name = "IdentityKeyPair")]
struct PyIdentityKeyPair {
    inner: identity::IdentityKeyPair,
}

#[pymethods]
impl PyIdentityKeyPair {
    #[staticmethod]
    fn generate() -> PyResult<Self> {
        let inner = identity::IdentityKeyPair::generate()
            .map_err(py_err)?;
        Ok(Self { inner })
    }

    #[getter]
    fn public_key(&self) -> Vec<u8> {
        self.inner.public_key().to_vec()
    }

    fn encrypt_to_store(&self, passphrase: &[u8]) -> PyResult<Vec<u8>> {
        self.inner
            .encrypt_to_store(passphrase)
            .map_err(py_err)
    }

    #[staticmethod]
    fn decrypt_from_store(blob: &[u8], passphrase: &[u8]) -> PyResult<Self> {
        let inner = identity::IdentityKeyPair::decrypt_from_store(blob, passphrase)
            .map_err(py_err)?;
        Ok(Self { inner })
    }

    /// Compute HMAC-SHA256 over `data` using a key derived from this identity's
    /// secret key. The derived key never crosses the FFI boundary — Python
    /// receives only the 32-byte tag. `context` is HKDF info (domain separator).
    fn compute_hmac(&self, context: &[u8], data: &[u8]) -> PyResult<Vec<u8>> {
        self.inner
            .compute_hmac(context, data)
            .map(|tag| tag.to_vec())
            .map_err(py_err)
    }

    /// Zeroize the secret key in place. After this call, the keypair is unusable.
    /// Safe to call multiple times.
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

/// Python-visible replay window.
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

    fn check_and_update(&mut self, seq: u64) -> bool {
        self.inner.check_and_update(seq)
    }

    /// Read-only check: returns true if seq would be accepted.
    fn check(&self, seq: u64) -> bool {
        self.inner.check(seq)
    }

    /// Mark seq as seen. Call only after successful authentication.
    fn update(&mut self, seq: u64) {
        self.inner.update(seq)
    }

    #[getter]
    fn max_seq(&self) -> u64 {
        self.inner.max_seq()
    }
}

/// Python-visible nonce generator.
#[pyclass(name = "NonceGenerator")]
struct PyNonceGenerator {
    inner: nonce::NonceGenerator,
}

#[pymethods]
impl PyNonceGenerator {
    #[new]
    fn new(epoch: u32) -> Self {
        Self {
            inner: nonce::NonceGenerator::new(epoch),
        }
    }

    fn next(&self) -> PyResult<Vec<u8>> {
        self.inner
            .next()
            .map(|n| n.to_vec())
            .ok_or_else(|| py_err("nonce counter exhausted"))
    }

    #[getter]
    fn count(&self) -> u32 {
        self.inner.count()
    }

    #[getter]
    fn epoch(&self) -> u32 {
        self.inner.epoch()
    }
}

/// Python-visible Noise XX initiator.
#[pyclass(name = "NoiseInitiator")]
struct PyNoiseInitiator {
    inner: Option<noise_xx::NoiseInitiator>,
}

#[pymethods]
impl PyNoiseInitiator {
    /// Create an initiator. `identity` must be a PyIdentityKeyPair.
    #[new]
    fn new(identity: &PyIdentityKeyPair) -> PyResult<Self> {
        let init = noise_xx::NoiseInitiator::new(identity.inner.secret_key())
            .map_err(py_err)?;
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

    fn into_transport(&mut self) -> PyResult<PyNoiseTransport> {
        let init = self
            .inner
            .take()
            .ok_or_else(|| py_err("already consumed"))?;
        let transport = init
            .into_transport()
            .map_err(py_err)?;
        Ok(PyNoiseTransport {
            inner: Some(transport),
        })
    }

    /// Get the handshake hash for deriving session keys.
    /// Must be called after handshake completes, before into_transport().
    fn get_handshake_hash(&self) -> PyResult<Vec<u8>> {
        Ok(self
            .inner
            .as_ref()
            .ok_or_else(|| py_err("already consumed"))?
            .get_handshake_hash())
    }
}

/// Python-visible Noise XX responder.
#[pyclass(name = "NoiseResponder")]
struct PyNoiseResponder {
    inner: Option<noise_xx::NoiseResponder>,
}

#[pymethods]
impl PyNoiseResponder {
    #[new]
    fn new(identity: &PyIdentityKeyPair) -> PyResult<Self> {
        let resp = noise_xx::NoiseResponder::new(identity.inner.secret_key())
            .map_err(py_err)?;
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

    fn into_transport(&mut self) -> PyResult<PyNoiseTransport> {
        let resp = self
            .inner
            .take()
            .ok_or_else(|| py_err("already consumed"))?;
        let transport = resp
            .into_transport()
            .map_err(py_err)?;
        Ok(PyNoiseTransport {
            inner: Some(transport),
        })
    }

    /// Get the handshake hash for deriving session keys.
    /// Must be called after handshake completes, before into_transport().
    fn get_handshake_hash(&self) -> PyResult<Vec<u8>> {
        Ok(self
            .inner
            .as_ref()
            .ok_or_else(|| py_err("already consumed"))?
            .get_handshake_hash())
    }
}

/// Python-visible Noise transport (post-handshake).
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
#[pyclass(name = "SessionKeyManager")]
struct PySessionKeyManager {
    inner: session_keys::SessionKeyManager,
    pending_rotation: Option<session_keys::RotationInit>,
    // For the two-phase responder flow: derived-but-not-yet-applied rotation
    // held here between prepare_rotation_responder and apply_rotation_responder
    // so the ACK can be sent with old keys in between.
    pending_responder_rotation: Option<session_keys::ResponderPending>,
}

#[pymethods]
impl PySessionKeyManager {
    /// Create a session key manager from the Noise handshake hash.
    /// The initial epoch is derived from the handshake hash (same on both
    /// peers) to avoid the deterministic "start at 1" linkability.
    /// `rotation_packets` / `rotation_seconds` override the default base
    /// thresholds (5000 packets / 600 s); jitter is always applied.
    #[staticmethod]
    #[pyo3(signature = (hash, is_initiator, rotation_packets=None, rotation_seconds=None))]
    fn from_handshake_hash(
        hash: &[u8],
        is_initiator: bool,
        rotation_packets: Option<u64>,
        rotation_seconds: Option<u64>,
    ) -> PyResult<Self> {
        let inner = session_keys::SessionKeyManager::from_handshake_hash(
            hash,
            is_initiator,
            rotation_packets,
            rotation_seconds,
        )
        .map_err(py_err)?;
        Ok(Self {
            inner,
            pending_rotation: None,
            pending_responder_rotation: None,
        })
    }

    /// Create a session key manager from a secret shared value (e.g., bootstrap ephemeral DH).
    /// Unlike from_handshake_hash which uses the PUBLIC transcript hash, this derives
    /// keys from SECRET material, preventing passive observation.
    /// `rotation_packets` / `rotation_seconds` override the default base
    /// thresholds (5000 packets / 600 s); jitter is always applied.
    #[staticmethod]
    #[pyo3(signature = (shared_secret, is_initiator, rotation_packets=None, rotation_seconds=None))]
    fn from_bootstrap_shared_secret(
        shared_secret: &[u8],
        is_initiator: bool,
        rotation_packets: Option<u64>,
        rotation_seconds: Option<u64>,
    ) -> PyResult<Self> {
        let inner = session_keys::SessionKeyManager::from_bootstrap_shared_secret(
            shared_secret,
            is_initiator,
            rotation_packets,
            rotation_seconds,
        )
        .map_err(py_err)?;
        Ok(Self {
            inner,
            pending_rotation: None,
            pending_responder_rotation: None,
        })
    }

    /// Encrypt a packet. Returns (nonce, ciphertext, epoch).
    fn encrypt(&mut self, plaintext: &[u8], aad: &[u8]) -> PyResult<(Vec<u8>, Vec<u8>, u32)> {
        let (nonce, ciphertext, epoch) = self
            .inner
            .encrypt(plaintext, aad)
            .map_err(py_err)?;
        Ok((nonce.to_vec(), ciphertext, epoch))
    }

    /// Decrypt a packet. Returns plaintext.
    fn decrypt(
        &mut self,
        nonce: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
        seq: u64,
        is_prev_epoch: bool,
    ) -> PyResult<Vec<u8>> {
        let n = nonce_from_slice(nonce)?;
        self.inner
            .decrypt(&n, ciphertext, aad, seq, is_prev_epoch)
            .map_err(py_err)
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
        let init = self
            .inner
            .initiate_rotation()
            .map_err(py_err)?;
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

    /// Complete rotation as the responder. Returns (our_ephemeral_pub, new_epoch).
    ///
    /// Single-shot: applies rotation immediately. Network users should prefer
    /// `prepare_rotation_responder` + `apply_rotation_responder` so the
    /// REKEY_ACK can be sent with the old keys.
    fn complete_rotation_responder(
        &mut self,
        remote_ephemeral_pub: &[u8],
        new_epoch: u32,
    ) -> PyResult<(Vec<u8>, u32)> {
        let pub_bytes = pub_key_from_slice(remote_ephemeral_pub)?;
        let (our_pub, complete) = self
            .inner
            .complete_rotation_responder(&pub_bytes, new_epoch)
            .map_err(py_err)?;
        Ok((our_pub.to_vec(), complete.new_epoch))
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
        if self.pending_responder_rotation.is_some() {
            return Err(py_err("responder rotation already prepared"));
        }
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
    fn packets_sent(&self) -> u64 {
        self.inner.packets_sent()
    }

    #[getter]
    fn has_grace_period(&self) -> bool {
        self.inner.has_grace_period()
    }
}

/// Python-visible AES-256-GCM key handle.
#[pyclass(name = "AesKey")]
struct PyAesKey {
    inner: aes_gcm::AesKey,
}

#[pymethods]
impl PyAesKey {
    // No #[new] — keys must not be created from Python with raw bytes.
    // PyAesKey instances are only produced by Rust-side key derivation.

    fn encrypt(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> PyResult<Vec<u8>> {
        let n = nonce_from_slice(nonce)?;
        self.inner
            .encrypt(&n, plaintext, aad)
            .map_err(py_err)
    }

    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> PyResult<Vec<u8>> {
        let n = nonce_from_slice(nonce)?;
        self.inner
            .decrypt(&n, ciphertext, aad)
            .map_err(py_err)
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
    /// Generate a fresh attestation keypair using the active backend.
    #[staticmethod]
    fn generate() -> PyResult<Self> {
        let inner = device_attest::AttestKey::generate().map_err(py_err)?;
        Ok(Self { inner })
    }

    /// Return the verifying key as SubjectPublicKeyInfo DER.
    fn public_spki_der(&self) -> Vec<u8> {
        self.inner.public_spki_der().to_vec()
    }

    /// Sign `msg` with the attestation key. Returns ASN.1 DER ECDSA signature.
    fn sign(&self, msg: &[u8]) -> PyResult<Vec<u8>> {
        self.inner.sign(msg).map_err(py_err)
    }

    /// Encrypt the attest key to a passphrase-protected blob (Argon2id +
    /// XChaCha20-Poly1305). Soft backend only — TPM/Keystore backends use
    /// platform-native sealing and reject this call.
    fn encrypt_to_store(&self, passphrase: &[u8]) -> PyResult<Vec<u8>> {
        self.inner.encrypt_to_store(passphrase).map_err(py_err)
    }

    /// Restore an attest key from a stored blob. Soft backend only.
    #[staticmethod]
    fn decrypt_from_store(blob: &[u8], passphrase: &[u8]) -> PyResult<Self> {
        let inner = device_attest::AttestKey::decrypt_from_store(blob, passphrase)
            .map_err(py_err)?;
        Ok(Self { inner })
    }

    /// PKCS#8 DER export of the private key. Soft backend only — used by
    /// the `dsm enroll --csr-out` flow to hand the key to the
    /// ``cryptography`` library's CSR builder. TPM / Keystore backends
    /// will not expose this method; they sign the CSR via platform APIs.
    fn private_pkcs8_der(&self) -> PyResult<Vec<u8>> {
        self.inner.private_pkcs8_der().map_err(py_err)
    }
}

/// Disable core dumps (call once at startup).
#[pyfunction]
fn disable_core_dumps() -> PyResult<()> {
    secure_memory::disable_core_dumps().map_err(py_err)
}

/// Harden the process: no core dumps, non-dumpable, no-new-privs.
#[pyfunction]
fn harden_process() -> PyResult<()> {
    secure_memory::harden_process().map_err(py_err)
}

/// Generate a fresh ephemeral X25519 keypair for bootstrap.
/// Returns (secret_bytes, public_bytes) where secret must be kept secret.
/// Caller is responsible for securely handling secret_bytes.
#[pyfunction]
fn generate_ephemeral() -> PyResult<(Vec<u8>, Vec<u8>)> {
    use x25519_dalek::{PublicKey, StaticSecret};
    use rand::RngCore;
    use zeroize::Zeroize;

    let mut secret_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret_bytes);
    let secret = StaticSecret::from(secret_bytes);
    let public = PublicKey::from(&secret);

    let out_secret = secret_bytes.to_vec();
    secret_bytes.zeroize();
    Ok((out_secret, public.as_bytes().to_vec()))
}

/// Compute session keys from bootstrap ephemeral DH.
/// This derives keys from the SECRET shared secret, not the PUBLIC handshake hash.
///
/// Args:
///     our_secret: 32-byte ephemeral secret (must be protected)
///     peer_public: 32-byte peer ephemeral public key
///     is_initiator: true for client, false for server
///     rotation_packets: optional override for the per-epoch packet
///         rotation base (default 5000). Jitter is always applied.
///     rotation_seconds: optional override for the per-epoch time
///         rotation base (default 600s).
///
/// Returns: SessionKeyManager instance
#[pyfunction]
#[pyo3(signature = (our_secret, peer_public, is_initiator, rotation_packets=None, rotation_seconds=None))]
fn bootstrap_session_from_dh(
    our_secret: &[u8],
    peer_public: &[u8],
    is_initiator: bool,
    rotation_packets: Option<u64>,
    rotation_seconds: Option<u64>,
) -> PyResult<PySessionKeyManager> {
    use zeroize::Zeroize;

    if our_secret.len() != 32 {
        return Err(py_err("secret must be 32 bytes"));
    }
    if peer_public.len() != 32 {
        return Err(py_err("peer public must be 32 bytes"));
    }

    let mut secret_arr = [0u8; 32];
    secret_arr.copy_from_slice(our_secret);
    let mut public_arr = [0u8; 32];
    public_arr.copy_from_slice(peer_public);

    let result = session_keys::bootstrap_keys_from_dh(
        &secret_arr,
        &public_arr,
        is_initiator,
        rotation_packets,
        rotation_seconds,
    );

    secret_arr.zeroize();
    public_arr.zeroize();

    let inner = result.map_err(py_err)?;

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
    m.add_class::<PyNonceGenerator>()?;
    m.add_class::<PyNoiseInitiator>()?;
    m.add_class::<PyNoiseResponder>()?;
    m.add_class::<PyNoiseTransport>()?;
    m.add_class::<PySessionKeyManager>()?;
    m.add_class::<PyAesKey>()?;
    m.add_class::<PyAttestKey>()?;
    m.add_function(wrap_pyfunction!(disable_core_dumps, m)?)?;
    m.add_function(wrap_pyfunction!(harden_process, m)?)?;
    m.add_function(wrap_pyfunction!(generate_ephemeral, m)?)?;
    m.add_function(wrap_pyfunction!(bootstrap_session_from_dh, m)?)?;
    m.add("HANDSHAKE_ATTEST_PAYLOAD_SIZE", noise_xx::HANDSHAKE_ATTEST_PAYLOAD_SIZE)?;
    Ok(())
}
