//! Host-only `uniffi-bindgen` entry point (library mode).
//!
//! Built only under the `uniffi-cli` feature. Generates the Kotlin (and other)
//! foreign-language bindings for the `tuncore` UniFFI surface directly from the
//! compiled cdylib, e.g.:
//!
//! ```text
//! cargo run --no-default-features --features dev-soft-attest,uniffi-cli \
//!     --bin uniffi-bindgen -- \
//!     generate --library target/debug/libtuncore.so \
//!     --language kotlin --out-dir <dir>
//! ```

fn main() {
    uniffi::uniffi_bindgen_main()
}
