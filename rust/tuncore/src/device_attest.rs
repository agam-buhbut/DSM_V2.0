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

// Enforce EXACTLY ONE backend at compile time. `tpm-attest` is still
// commented out in Cargo.toml (Phase 1 step 5), but the guard is written to
// be correct the moment it is enabled — both arms must hold for any valid
// build.
#[cfg(all(feature = "dev-soft-attest", feature = "tpm-attest"))]
compile_error!(
    "multiple device-attestation backends selected; enable exactly one of \
     `dev-soft-attest` (dev/CI) or `tpm-attest` (production, Phase 1 step 5)"
);

#[cfg(not(any(feature = "dev-soft-attest", feature = "tpm-attest")))]
compile_error!(
    "no device-attestation backend selected; enable Cargo feature `dev-soft-attest` (dev/CI) \
     or `tpm-attest` (production, Phase 1 step 5)"
);
