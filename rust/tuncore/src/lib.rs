pub mod aes_gcm;
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
            .map_err(|e| PyRuntimeError::new_err(e))?;
        Ok(Self { inner })
    }

    #[getter]
    fn public_key(&self) -> Vec<u8> {
        self.inner.public_key().to_vec()
    }

    fn encrypt_to_store(&self, passphrase: &[u8]) -> PyResult<Vec<u8>> {
        self.inner
            .encrypt_to_store(passphrase)
            .map_err(|e| PyRuntimeError::new_err(e))
    }

    #[staticmethod]
    fn decrypt_from_store(blob: &[u8], passphrase: &[u8]) -> PyResult<Self> {
        let inner = identity::IdentityKeyPair::decrypt_from_store(blob, passphrase)
            .map_err(|e| PyRuntimeError::new_err(e))?;
        Ok(Self { inner })
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
            .ok_or_else(|| PyRuntimeError::new_err("nonce counter exhausted"))
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
            .map_err(|e| PyRuntimeError::new_err(e))?;
        Ok(Self { inner: Some(init) })
    }

    fn write_message_1(&mut self) -> PyResult<Vec<u8>> {
        self.inner
            .as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("already consumed"))?
            .write_message_1()
            .map_err(|e| PyRuntimeError::new_err(e))
    }

    fn read_message_2(&mut self, msg: &[u8]) -> PyResult<Vec<u8>> {
        self.inner
            .as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("already consumed"))?
            .read_message_2(msg)
            .map_err(|e| PyRuntimeError::new_err(e))
    }

    fn write_message_3(&mut self) -> PyResult<Vec<u8>> {
        self.inner
            .as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("already consumed"))?
            .write_message_3()
            .map_err(|e| PyRuntimeError::new_err(e))
    }

    fn into_transport(&mut self) -> PyResult<PyNoiseTransport> {
        let init = self
            .inner
            .take()
            .ok_or_else(|| PyRuntimeError::new_err("already consumed"))?;
        let transport = init
            .into_transport()
            .map_err(|e| PyRuntimeError::new_err(e))?;
        Ok(PyNoiseTransport {
            inner: Some(transport),
        })
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
            .map_err(|e| PyRuntimeError::new_err(e))?;
        Ok(Self { inner: Some(resp) })
    }

    fn read_message_1(&mut self, msg: &[u8]) -> PyResult<()> {
        self.inner
            .as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("already consumed"))?
            .read_message_1(msg)
            .map_err(|e| PyRuntimeError::new_err(e))
    }

    fn write_message_2(&mut self) -> PyResult<Vec<u8>> {
        self.inner
            .as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("already consumed"))?
            .write_message_2()
            .map_err(|e| PyRuntimeError::new_err(e))
    }

    fn read_message_3(&mut self, msg: &[u8]) -> PyResult<Vec<u8>> {
        self.inner
            .as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("already consumed"))?
            .read_message_3(msg)
            .map_err(|e| PyRuntimeError::new_err(e))
    }

    fn into_transport(&mut self) -> PyResult<PyNoiseTransport> {
        let resp = self
            .inner
            .take()
            .ok_or_else(|| PyRuntimeError::new_err("already consumed"))?;
        let transport = resp
            .into_transport()
            .map_err(|e| PyRuntimeError::new_err(e))?;
        Ok(PyNoiseTransport {
            inner: Some(transport),
        })
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
        self.inner
            .as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("transport closed"))?
            .encrypt(plaintext)
            .map_err(|e| PyRuntimeError::new_err(e))
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> PyResult<Vec<u8>> {
        self.inner
            .as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("transport closed"))?
            .decrypt(ciphertext)
            .map_err(|e| PyRuntimeError::new_err(e))
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
        if nonce.len() != 12 {
            return Err(PyRuntimeError::new_err("nonce must be 12 bytes"));
        }
        let mut n = [0u8; 12];
        n.copy_from_slice(nonce);
        self.inner
            .encrypt(&n, plaintext, aad)
            .map_err(|e| PyRuntimeError::new_err(e))
    }

    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> PyResult<Vec<u8>> {
        if nonce.len() != 12 {
            return Err(PyRuntimeError::new_err("nonce must be 12 bytes"));
        }
        let mut n = [0u8; 12];
        n.copy_from_slice(nonce);
        self.inner
            .decrypt(&n, ciphertext, aad)
            .map_err(|e| PyRuntimeError::new_err(e))
    }
}

/// Disable core dumps (call once at startup).
#[pyfunction]
fn disable_core_dumps() -> PyResult<()> {
    secure_memory::disable_core_dumps().map_err(|e| PyRuntimeError::new_err(e))
}

#[pymodule]
fn tuncore(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyIdentityKeyPair>()?;
    m.add_class::<PyReplayWindow>()?;
    m.add_class::<PyNonceGenerator>()?;
    m.add_class::<PyNoiseInitiator>()?;
    m.add_class::<PyNoiseResponder>()?;
    m.add_class::<PyNoiseTransport>()?;
    m.add_class::<PyAesKey>()?;
    m.add_function(wrap_pyfunction!(disable_core_dumps, m)?)?;
    Ok(())
}
