//! Device attestation backend selector.
//!
//! Re-exports the active backend's key type as `AttestKey`. Backend is chosen
//! at compile time:
//!
//!   * `dev-soft-attest` — software ECDSA P-256 (dev/CI only).
//!   * `tpm-attest`      — TPM 2.0 ECDSA P-256 via tss-esapi (Phase 1 step 5).
//!
//! Exactly one backend feature must be enabled.

#[cfg(feature = "dev-soft-attest")]
pub use crate::device_attest_soft::SoftAttestKey as AttestKey;

#[cfg(not(any(feature = "dev-soft-attest")))]
compile_error!(
    "no device-attestation backend selected; enable Cargo feature `dev-soft-attest` (dev/CI) \
     or `tpm-attest` (production, Phase 1 step 5)"
);
