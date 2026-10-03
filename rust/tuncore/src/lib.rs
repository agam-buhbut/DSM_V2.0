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

/// PyO3 Python bindings — the `tuncore` extension module (the `Py*` wrapper
/// classes, `#[pyfunction]`s, and `#[pymodule] fn tuncore`). Gated behind the
/// `python-bindings` Cargo feature so the crypto/packet core compiles
/// pyo3-free for cross-compilation (e.g. Android `--no-default-features`).
/// With the feature on, the generated module/classes/ABI are byte-identical to
/// the pre-split single-file build — only the bindings' physical location moved.
#[cfg(feature = "python-bindings")]
mod python;

// UniFFI Kotlin/Android bindings — the `ffi` module (below) exposes the SAME
// pyo3-free crypto/handshake core primitives (identity, Noise XX initiator,
// transport, session-key manager / rekey, replay window, AES-GCM) to a native
// Android (Kotlin) client over UniFFI (proc-macro / library mode), plus an
// `AttestSigner` callback interface so Kotlin signs the handshake attestation
// binding with an Android Keystore/StrongBox key (the signing scalar never
// enters Rust). Gated behind the `uniffi-bindings` Cargo feature so the
// default/Python/bare-cross-compile builds never pull uniffi. The
// `setup_scaffolding!` call registers the crate's UniFFI component once at the
// crate root (required by library-mode bindgen).
#[cfg(feature = "uniffi-bindings")]
uniffi::setup_scaffolding!();

#[cfg(feature = "uniffi-bindings")]
mod ffi;
