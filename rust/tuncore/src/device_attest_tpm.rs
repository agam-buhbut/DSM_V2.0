//! TPM 2.0 ECDSA P-256 device-attestation backend (key-residency).
//!
//! Behind the `tpm-attest` Cargo feature. The private scalar is created by
//! and never leaves the TPM; signing happens in-TPM via `TPM2_Sign`. The
//! on-disk artifact is a TPM-bound `DSMT` context blob, useless on any
//! other TPM.
//!
//! ## Security core: the child key template
//!
//! The child (attest) key's TPMA_OBJECT attributes ARE the non-extractability
//! guarantee. `sign | fixedTPM | fixedParent | sensitiveDataOrigin |
//! userWithAuth` SET and `restricted | decrypt | encryptedDuplication` CLEAR
//! means: the private scalar is generated inside the TPM, can never be
//! duplicated off it (`fixedTPM`), can never be re-parented/migrated
//! (`fixedParent`), and signs externally supplied digests (`!restricted`). A
//! single wrong attribute bit silently loses key residency, so
//! [`child_template`] is the most security-sensitive function in the crate and
//! [`TpmAttestKey::child_object_attributes`] exists so the integration tests
//! can lock the exact bitmask.

use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

use hkdf::Hkdf;
use sha2::{Digest as _, Sha256};
use tss_esapi::attributes::ObjectAttributes;
use tss_esapi::constants::tss::{TPM2_RH_NULL, TPM2_ST_HASHCHECK};
use tss_esapi::constants::{StartupType, Tss2ResponseCodeKind};
use tss_esapi::handles::KeyHandle;
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::structures::{
    Auth, Digest, EccPoint, EccScheme, HashScheme, HashcheckTicket, Private, Public, PublicBuilder,
    PublicEccParametersBuilder, Signature, SignatureScheme, SymmetricDefinitionObject,
};
use tss_esapi::tcti_ldr::TctiNameConf;
use tss_esapi::traits::{Marshall, UnMarshall};
use tss_esapi::tss2_esys::{TPM2B_DIGEST, TPMT_TK_HASHCHECK};
use tss_esapi::Context;
use zeroize::Zeroizing;

use crate::tpm_blob::{self, DsmtBlob};

/// HKDF-SHA256 domain-separation `info` for the TPM-auth derivation. Bumping
/// the version suffix would intentionally invalidate every previously stored
/// blob's auth binding.
const TPM_AUTH_INFO: &[u8] = b"dsm-tpm-attest-auth-v1";

/// Width of the derived TPM auth value, in bytes. 32 == the SHA-256
/// name-algorithm digest size (`Auth::MAX_SIZE` is the TPMU_HA union width, so
/// 32 fits comfortably), matching the child's `with_name_hashing_algorithm`.
const TPM_AUTH_LEN: usize = 32;

/// Derive the child key's TPM authorization value from the operator passphrase.
///
/// HKDF-SHA256 with a fixed domain-separation `info` and NO salt; the derived
/// 32 bytes become the child's `TPM2B_AUTH`.
///
/// ## Why a fast KDF with no salt / no Argon2id is cryptographically sufficient
/// The child's sensitive area (the private scalar) is wrapped by the `fixedTPM`
/// parent and never leaves the chip, so an attacker holding the DSMT blob CANNOT
/// mount an offline brute-force against the passphrase: there is no offline
/// oracle to test guesses against. The ONLY way to test a passphrase guess is an
/// online `TPM2_Load` + sign attempt against the real TPM, which the TPM's
/// dictionary-attack lockout rate-limits (failed auths increment the DA counter
/// and eventually lock the hierarchy). Residency + DA-lockout together make a
/// memory-hard KDF and a per-blob salt unnecessary here: there is no offline
/// attack surface for them to defend, and the blob stores nothing extra.
fn derive_tpm_auth(passphrase: &[u8]) -> Zeroizing<[u8; TPM_AUTH_LEN]> {
    let hk = Hkdf::<Sha256>::new(None, passphrase);
    let mut out = Zeroizing::new([0u8; TPM_AUTH_LEN]);
    // `expand` only fails if the output length exceeds 255*HashLen (8160 bytes
    // for SHA-256); 32 bytes is always valid, so this cannot error.
    hk.expand(TPM_AUTH_INFO, out.as_mut())
        .expect("HKDF-SHA256 expand of 32 bytes is always within the length bound");
    out
}

/// Default production TCTI: the in-kernel resource manager. Tests pass an
/// explicit swtpm TCTI to [`TpmAttestKey::generate_with_tcti`] instead.
const DEFAULT_TCTI: &str = "device:/dev/tpmrm0";

/// Maximum message length accepted by [`TpmAttestKey::sign`], in parity with
/// the soft backend's `L-CRYPT-3` cap (`device_attest_soft::SoftAttestKey::sign`).
/// DSM binding signatures cover ~86 bytes; 1 MiB is far above any legitimate
/// use and bounds the SHA-256 pre-hash a malicious caller could force.
const SIGN_MSG_MAX: usize = 1 << 20;

/// Closure error type for [`Context::execute_with_nullauth_session`], whose
/// bound is `E: From<tss_esapi::Error>`. `String` does not implement
/// `From<tss_esapi::Error>` in tss-esapi 7.7.0, so it cannot be used as `E`
/// directly. This newtype satisfies the bound and is unwrapped back to the
/// crate's `Result<_, String>` convention at the call boundary.
struct TpmOpError(String);

impl From<tss_esapi::Error> for TpmOpError {
    fn from(e: tss_esapi::Error) -> Self {
        TpmOpError(format!("TPM error: {e}"))
    }
}

/// Why one sign try failed: a TPM or ESYS error, kept typed so `sign` can
/// tell a refused passphrase from a stale connection, or anything else.
enum SignError {
    Tpm(tss_esapi::Error),
    Other(String),
}

impl From<tss_esapi::Error> for SignError {
    fn from(e: tss_esapi::Error) -> Self {
        SignError::Tpm(e)
    }
}

impl SignError {
    /// True when the TPM refused the key's authorization (a wrong
    /// passphrase) or is locked out after such refusals. The TPM counts each
    /// refused try toward its dictionary-attack lockout, so `sign` never
    /// tries these again.
    fn is_refused_auth(&self) -> bool {
        matches!(
            self,
            SignError::Tpm(tss_esapi::Error::Tss2Error(rc))
                if matches!(
                    rc.kind(),
                    Some(
                        Tss2ResponseCodeKind::AuthFail
                            | Tss2ResponseCodeKind::BadAuth
                            | Tss2ResponseCodeKind::Lockout
                    )
                )
        )
    }

    /// The caller's error text, worded as it always was (`TPM error: ...`).
    fn into_message(self) -> String {
        match self {
            SignError::Tpm(e) => format!("TPM error: {e}"),
            SignError::Other(s) => s,
        }
    }
}

/// One open TPM connection with the parent (Owner storage primary) loaded.
///
/// Without one, each sign makes the parent again with `TPM2_CreatePrimary`.
/// A key that keeps one of these between signs skips that: on the server
/// box's TPM it saved about 40 ms of a 214 ms sign (2026-10-09). The bigger
/// win is elsewhere: the server signs in a thread without the GIL, so a sign
/// no longer stalls its event loop (longest stall 219 ms before, 6 ms
/// after). Through the kernel resource manager
/// (`/dev/tpmrm0`) the loaded parent lives in this connection's own space:
/// no other program can see or use it, and closing the connection frees
/// it. The attest key's secret never leaves the TPM either way.
struct TpmConnection {
    ctx: Context,
    parent: KeyHandle,
}

// SAFETY: `Context` is not `Send` only because it owns raw pointers: the
// ESYS context and its TCTI context. Neither keeps per-thread state; they
// must only never run two calls at once. A kept `TpmConnection` is reached
// only through the `Mutex` in `TpmAttestKey::connection`, and one that is not
// kept is made, used and dropped by `sign` while it holds that Mutex's
// guard, so one thread at a time uses it.
unsafe impl Send for TpmConnection {}

impl TpmConnection {
    /// Open a connection to `tcti` and make the parent key in it.
    fn open(tcti: &str) -> Result<Self, SignError> {
        let mut ctx = open_context(tcti).map_err(SignError::Other)?;
        let parent = ctx.execute_with_nullauth_session(|ctx| -> Result<KeyHandle, SignError> {
            // The SAME deterministic Owner storage parent every time: an
            // identical template under the stable Owner primary seed yields
            // the identical primary, so the child loads under it.
            let template = parent_template().map_err(SignError::Other)?;
            Ok(ctx
                .create_primary(Hierarchy::Owner, template, None, None, None, None)?
                .key_handle)
        })?;
        Ok(Self { ctx, parent })
    }

    /// Load the child under the parent, sign `digest`, flush the child.
    fn sign(
        &mut self,
        child_public: Public,
        child_private: Private,
        auth: Option<Auth>,
        digest: Digest,
    ) -> Result<Signature, SignError> {
        let parent = self.parent;
        self.ctx
            .execute_with_nullauth_session(|ctx| -> Result<Signature, SignError> {
                // Build the TPM_RC_NULL hashcheck ticket before loading
                // anything, so an unexpected failure here cannot leak a
                // transient slot.
                let validation = build_null_hashcheck().map_err(|e| SignError::Other(e.0))?;
                let child = ctx.load(parent, child_private, child_public)?;
                // Bind the operator passphrase as the key's TPM auth: a WRONG
                // passphrase gives the wrong auth and the TPM rejects the sign
                // (and counts it toward its lockout). `None` keeps empty auth.
                // Flush the child on this error path too.
                if let Some(auth) = auth {
                    if let Err(e) = ctx.tr_set_auth(child.into(), auth) {
                        let _ = ctx.flush_context(child.into());
                        return Err(e.into());
                    }
                }
                let scheme = SignatureScheme::EcDsa {
                    hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
                };
                // Capture the result without returning early, so the child is
                // always flushed, even on a sign error.
                let result = ctx.sign(child, digest, scheme, validation);
                let _ = ctx.flush_context(child.into());
                Ok(result?)
            })
    }
}

impl Drop for TpmConnection {
    fn drop(&mut self) {
        // Best effort: on a stale connection the flush fails, and through
        // /dev/tpmrm0 closing the connection frees the parent anyway; swtpm
        // and a raw /dev/tpm0 need the flush. `Context`'s own drop then
        // closes the connection.
        let _ = self.ctx.flush_context(self.parent.into());
    }
}

/// True when `tcti` goes through a TPM resource manager, which lets several
/// connections use the TPM at once: the kernel's `/dev/tpmrm*` or the
/// tpm2-abrmd daemon. Only then does a key keep its connection by default.
/// A raw `/dev/tpm*` takes one opener at a time and swtpm serves one
/// connection at a time, so a kept connection there would lock every other
/// TPM user out.
fn tcti_shares_the_tpm(tcti: &str) -> bool {
    tcti.starts_with("device:/dev/tpmrm") || tcti == "tabrmd" || tcti.starts_with("tabrmd:")
}

/// Lock a key's kept connection. A sign that panicked while it held the
/// lock may have left the connection half used, so drop it and go on.
fn lock_connection(lock: &Mutex<Option<TpmConnection>>) -> MutexGuard<'_, Option<TpmConnection>> {
    match lock.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            let mut guard = poisoned.into_inner();
            *guard = None;
            lock.clear_poison();
            guard
        }
    }
}

/// In-TPM ECDSA P-256 attestation key. The private scalar is generated by and
/// never leaves the TPM; signing happens via `TPM2_Sign`.
///
/// Holds the persistable child key material — `Public` (the TPM-exported public
/// area, whose attribute bitmask IS the residency lock) and `Private` (the
/// TPM-encrypted sensitive area, the `DSMT` payload) — plus the cached SPKI and
/// the TCTI string used to reach the owning TPM.
///
/// Note on the Esys context: through a resource manager (`/dev/tpmrm*` or
/// tpm2-abrmd) the key keeps one open connection, with its parent key loaded,
/// from its first [`sign`] until [`zeroize`] or drop, so a sign skips
/// `TPM2_CreatePrimary`. A live `tss_esapi::Context` is neither `Send` nor
/// `Sync`; it sits in a `TpmConnection` behind a `Mutex`, which keeps this
/// type, and the `#[pyclass]` that wraps it, `Send + Sync`, and makes signs
/// from several threads take turns. On a raw `/dev/tpm*` or swtpm, which
/// serve one connection at a time, `sign` opens a connection, makes the
/// parent, signs and closes again. `generate` and `encrypt_to_store` always
/// use their own short-lived connection.
///
/// [`sign`]: Self::sign
/// [`zeroize`]: Self::zeroize
pub struct TpmAttestKey {
    // The TCTI to re-reach the owning TPM (used by `sign` / `from_store_blob_with_tcti`),
    // and the child's exported public + TPM-encrypted private areas which reload
    // only on the TPM that created them (`sign` reloads them; `to_store_blob`
    // persists them; `zeroize` scrubs `child_private`).
    tcti: String,
    child_public: Public,
    child_private: Private,
    spki_der: Vec<u8>,
    // The child key's TPM authorization value, derived from the operator
    // passphrase. `None` == empty-auth key (a freshly `generate`d
    // key, or one restored from a blob with an empty passphrase). `Some(_)` is
    // the 32-byte HKDF-derived auth that `sign` installs via `tr_set_auth`
    // before signing; a wrong passphrase yields the wrong auth and the TPM
    // rejects the sign. Held in a `Zeroizing<[u8;32]>` so it is scrubbed on
    // drop and explicitly cleared in `zeroize`.
    auth: Option<Zeroizing<[u8; TPM_AUTH_LEN]>>,
    // Keep one TPM connection, with the parent loaded, between signs? On by
    // default only through a resource manager (`tcti_shares_the_tpm`).
    keep_connection: bool,
    // The kept connection, made by the first sign. The Mutex also makes signs
    // from several threads take turns: one ESYS context must never run two
    // commands at once, and a raw /dev/tpm0 takes one opener at a time.
    connection: Mutex<Option<TpmConnection>>,
    // How many times this key made its parent in the TPM.
    parents_made: AtomicU64,
}

impl TpmAttestKey {
    /// Provision a NEW attest key using the default production TCTI
    /// (`device:/dev/tpmrm0`, overridable via the `TPM2TOOLS_TCTI`/`TCTI`
    /// environment variables).
    ///
    /// # Errors
    /// Returns a `String` describing the failure (the TPM return-code name +
    /// operation context, never raw internal TPM state) on any TPM error.
    pub fn generate() -> Result<Self, String> {
        let tcti = resolve_tcti();
        Self::generate_with_tcti(&tcti)
    }

    /// Provision a NEW attest key against an explicit TCTI string. Tests pass
    /// the per-test swtpm TCTI here; production uses [`generate`].
    ///
    /// Opens an Esys context, runs the key provisioning inside a nullauth HMAC
    /// session (TPM Owner empty-auth path): derive the deterministic Owner
    /// storage parent, `TPM2_Create` the residency-locked child under it, and
    /// `TPM2_Load` the child to prove it is loadable. Both transient handles are
    /// flushed before the context drops; the exported `Public`/`Private` are
    /// retained and the SPKI is cached for [`public_spki_der`].
    ///
    /// # Errors
    /// Returns a `String` on TCTI/startup/TPM-command failure or if the
    /// returned public key is not a valid P-256 point.
    ///
    /// [`generate`]: Self::generate
    /// [`public_spki_der`]: Self::public_spki_der
    pub fn generate_with_tcti(tcti: &str) -> Result<Self, String> {
        let mut ctx = open_context(tcti)?;

        // The closure's error type is `TpmOpError` (it satisfies
        // `E: From<Error>`); the `String`-returning template helpers are mapped
        // into it, and the whole result is unwrapped back to `String` after.
        let (child_public, child_private) = ctx
            .execute_with_nullauth_session(|ctx| -> Result<_, TpmOpError> {
                let parent = ctx.create_primary(
                    Hierarchy::Owner,
                    parent_template().map_err(TpmOpError)?,
                    None,
                    None,
                    None,
                    None,
                )?;
                let created = ctx.create(
                    parent.key_handle,
                    child_template().map_err(TpmOpError)?,
                    None,
                    None,
                    None,
                    None,
                )?;
                let child_public = created.out_public.clone();
                let child_private = created.out_private.clone();
                // Load the child to prove it is loadable under the parent, then
                // flush both transient handles so the TPM's scarce transient
                // slots are not leaked. `flush_context` deregisters each handle
                // from the handle manager, so the session teardown does not
                // double-flush.
                let child_handle =
                    ctx.load(parent.key_handle, created.out_private, created.out_public)?;
                ctx.flush_context(child_handle.into())?;
                ctx.flush_context(parent.key_handle.into())?;
                Ok((child_public, child_private))
            })
            .map_err(|e: TpmOpError| e.0)?;

        let spki_der = spki_from_public(&child_public)?;
        Ok(Self {
            tcti: tcti.to_string(),
            child_public,
            child_private,
            spki_der,
            // A freshly generated key has EMPTY TPM auth: the one-time enroll
            // CSR sign (proof-of-possession, before `encrypt_to_store`) must
            // succeed without a passphrase. The auth is bound later, at store
            // time, by `encrypt_to_store`.
            auth: None,
            keep_connection: tcti_shares_the_tpm(tcti),
            connection: Mutex::new(None),
            parents_made: AtomicU64::new(0),
        })
    }

    /// SubjectPublicKeyInfo DER of the in-TPM verifying key (the same SPKI
    /// byte-format the soft backend emits: `id-ecPublicKey` + `prime256v1`
    /// over the uncompressed point). Returns `Err` once the key is zeroized.
    ///
    /// # Errors
    /// Returns `Err("attest key has been zeroized")` after the cached SPKI has
    /// been cleared by `zeroize`.
    pub fn public_spki_der(&self) -> Result<&[u8], String> {
        if self.spki_der.is_empty() {
            return Err("attest key has been zeroized".into());
        }
        Ok(&self.spki_der)
    }

    /// The child key's TPMA_OBJECT attributes, read from the `Public` the TPM
    /// returned for the loaded child. Used by the integration tests to lock the
    /// residency-critical bitmask — a flipped attribute bit fails those asserts.
    #[must_use]
    pub fn child_object_attributes(&self) -> ObjectAttributes {
        self.child_public.object_attributes()
    }
}

impl TpmAttestKey {
    /// Sign `msg` in-TPM via `TPM2_Sign`, returning an ASN.1 DER ECDSA
    /// signature byte-identical in shape to the soft backend's output
    /// (`SEQUENCE { r INTEGER, s INTEGER }`), so a verifier cannot distinguish
    /// a TPM-produced signature from a soft one.
    ///
    /// Contract parity with `device_attest_soft::SoftAttestKey::sign`:
    /// - the FULL message is SHA-256 hashed here (the soft backend's
    ///   `p256` `Signer::sign(msg)` likewise hashes the whole message), then
    ///   the 32-byte digest is signed — callers pass the message, never a
    ///   pre-computed digest;
    /// - messages over [`SIGN_MSG_MAX`] (1 MiB) are rejected with the same
    ///   error text as the soft backend;
    /// - the output is `p256::ecdsa::Signature::to_der()` bytes, identical to
    ///   what the soft backend emits.
    ///
    /// The signing scalar NEVER leaves the TPM — only the public `(r, s)` of
    /// the resulting signature is read out and re-encoded.
    ///
    /// # Connection
    /// With a kept connection (see [`keeps_connection`]) the first sign opens
    /// it and makes the parent; later signs only load the child, sign and
    /// flush the child. Signs from several threads take turns. If the kept
    /// connection went stale (the TPM was reset, or the resource manager
    /// restarted), the sign drops it and tries once more on a new one, except
    /// after a refused authorization. Very rarely the TPM's answer to a
    /// wrong passphrase is lost on the way (the connection breaks right
    /// then): the sign sees a connection error, tries once more, and the TPM
    /// counts the wrong passphrase twice. Without a kept connection every
    /// sign opens its own connection, re-derives the SAME deterministic
    /// Owner primary, loads the child, signs and closes.
    ///
    /// # Persistence proof
    /// The parent is always re-derived from [`parent_template`] (never
    /// stored), so a successful sign proves the child reloads under a
    /// re-derived primary — the key truly persists in the TPM.
    ///
    /// # Errors
    /// Returns a `String` if the key has been zeroized, the message exceeds the
    /// cap, the TCTI/TPM command fails, or the TPM returns a non-ECDSA
    /// signature. No raw internal TPM state is leaked beyond the return-code
    /// name and operation context.
    ///
    /// [`keeps_connection`]: Self::keeps_connection
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, String> {
        if self.spki_der.is_empty() {
            return Err("attest key has been zeroized".into());
        }
        if msg.len() > SIGN_MSG_MAX {
            return Err(format!(
                "sign msg too large: {} > {SIGN_MSG_MAX}",
                msg.len()
            ));
        }

        // Hash the whole message to a 32-byte SHA-256 digest — the same input
        // the soft backend's `p256` signer derives internally.
        let digest_bytes = Sha256::digest(msg);
        let mut kept = lock_connection(&self.connection);
        let reused = kept.is_some();
        let signature = match self.sign_digest(&mut kept, digest_bytes.as_slice()) {
            Ok(signature) => signature,
            // A kept connection can go stale between signs: the TPM was
            // reset, or the resource manager restarted. Drop it and try once
            // more on a new one. Never after a refused authorization.
            Err(e) if reused && !e.is_refused_auth() => {
                *kept = None;
                self.sign_digest(&mut kept, digest_bytes.as_slice())
                    .map_err(SignError::into_message)?
            }
            Err(e) => return Err(e.into_message()),
        };
        ecdsa_signature_to_der(&signature)
    }

    /// One sign try: on the kept connection, or on a new one, which is kept
    /// afterwards with `keep_connection` and closed otherwise.
    fn sign_digest(
        &self,
        kept: &mut Option<TpmConnection>,
        digest_bytes: &[u8],
    ) -> Result<Signature, SignError> {
        let digest = Digest::try_from(digest_bytes)
            .map_err(|e| SignError::Other(format!("wrap SHA-256 digest for TPM: {e}")))?;
        // Build the child's auth value (if any) before touching the TPM, so a
        // size error surfaces as a typed crate error. `Auth::try_from` cannot
        // fail for 32 bytes (well under `Auth::MAX_SIZE`), but it is mapped
        // rather than unwrapped to honor the no-`unwrap` rule.
        let auth = self
            .auth
            .as_ref()
            .map(|a| {
                Auth::try_from(a.as_slice())
                    .map_err(|e| SignError::Other(format!("wrap TPM auth value: {e}")))
            })
            .transpose()?;
        let mut connection = if let Some(connection) = kept.take() {
            connection
        } else {
            let connection = TpmConnection::open(&self.tcti)?;
            self.parents_made.fetch_add(1, Ordering::Relaxed);
            connection
        };
        // Clones: `load` takes the child's areas by value, and this key
        // needs them again for a retry and for every later sign.
        let result = connection.sign(
            self.child_public.clone(),
            self.child_private.clone(),
            auth,
            digest,
        );
        if self.keep_connection {
            *kept = Some(connection);
        }
        result
    }

    /// True when this key keeps one TPM connection, with its parent loaded,
    /// between signs. On by default only through a resource manager
    /// (`/dev/tpmrm*` or tpm2-abrmd), where other programs can use the TPM
    /// at the same time.
    #[must_use]
    pub fn keeps_connection(&self) -> bool {
        self.keep_connection
    }

    /// Turn the kept connection on or off. Off closes a kept one now.
    ///
    /// Turn it on only where the TPM takes several connections at once, or
    /// where this key is the only TPM user: a raw `/dev/tpm0` takes one
    /// opener at a time and swtpm serves one connection at a time, so a kept
    /// connection there blocks every other connection, this key's own
    /// `encrypt_to_store` included, until the key is zeroized or dropped.
    pub fn set_keep_connection(&mut self, keep: bool) {
        self.keep_connection = keep;
        if !keep {
            *lock_connection(&self.connection) = None;
        }
    }

    /// How many times this key has made its parent key in the TPM: once with
    /// a kept connection (plus once per recovery from a stale one), once per
    /// sign without.
    #[must_use]
    pub fn parents_made(&self) -> u64 {
        self.parents_made.load(Ordering::Relaxed)
    }

    /// Serialize the persistable reference to the in-TPM key as a versioned
    /// `DSMT` blob: the marshalled `TPMT_PUBLIC` plus the raw `TPM2B_PRIVATE`
    /// buffer bytes wrapped in the [`tpm_blob`] header. There is NO passphrase
    /// and NO scalar in the blob — the sensitive area is TPM-encrypted and
    /// reloads only on the TPM that created it (`fixedTPM`), so a stolen blob is
    /// inert off-device. This is the inverse of [`from_store_blob_with_tcti`].
    ///
    /// `Public` is marshalled via [`Marshall::marshall`] (TPMT_PUBLIC bytes).
    /// `Private` has no `Marshall` impl in tss-esapi 7.7.0, so its raw buffer is
    /// persisted via `Private::value()` and restored with `Private::try_from` —
    /// exactly how tss-esapi's own transient-key abstraction persists keys.
    ///
    /// # Errors
    /// Returns a `String` if the public area cannot be marshalled.
    ///
    /// [`from_store_blob_with_tcti`]: Self::from_store_blob_with_tcti
    pub fn to_store_blob(&self) -> Result<Vec<u8>, String> {
        if self.spki_der.is_empty() {
            return Err("attest key has been zeroized".into());
        }
        serialize_dsmt(&self.child_public, &self.child_private)
    }

    /// Reconstitute from a `DSMT` blob against an explicit TCTI. The blob header
    /// is validated FIRST by [`tpm_blob::parse`] (typed rejection of any
    /// malformed/tampered input — bad magic, version, hierarchy, key_kind,
    /// curve, truncation, trailing bytes), so a tampered blob fails closed with
    /// a typed error BEFORE any TPM interaction. The `TPMT_PUBLIC` is
    /// unmarshalled and the `TPM2B_PRIVATE` buffer is rebuilt, the SPKI is
    /// re-derived from the reconstructed public (reusing [`spki_from_public`]),
    /// and the stateless key struct is returned.
    ///
    /// This function does NOT touch the TPM. The actual load-under-primary is
    /// lazy: it happens on the first [`sign`], which re-opens a context, re-
    /// derives the deterministic Owner primary, and `TPM2_Load`s the child. A
    /// blob from a different TPM parses fine here but FAILS at `sign` time
    /// (`TPM2_Load` rejects a private area wrapped to a primary this TPM cannot
    /// re-derive) — that is the cross-TPM residency proof.
    ///
    /// # Errors
    /// Returns a `String` if the blob header/length is invalid (typed
    /// [`tpm_blob::DsmtError`] surfaced as text), the `TPMT_PUBLIC` cannot be
    /// unmarshalled, the private buffer is over the TPM2B_PRIVATE size bound, or
    /// the reconstructed public is not a valid P-256 point.
    ///
    /// [`sign`]: Self::sign
    pub fn from_store_blob_with_tcti(blob: &[u8], tcti: &str) -> Result<Self, String> {
        // Header validation first: typed, fail-closed, NO TPM interaction.
        let parsed = tpm_blob::parse(blob).map_err(|e| e.to_string())?;
        let child_public = Public::unmarshall(&parsed.public_tpmt)
            .map_err(|e| format!("unmarshall TPMT_PUBLIC: {e}"))?;
        let child_private = Private::try_from(parsed.private_buf.as_slice())
            .map_err(|e| format!("rebuild TPM2B_PRIVATE: {e}"))?;
        // Re-derive the SPKI from the reconstructed public — the inverse of
        // `to_store_blob`'s marshall; reuses the same helper as `generate`.
        let spki_der = spki_from_public(&child_public)?;
        Ok(Self {
            tcti: tcti.to_string(),
            child_public,
            child_private,
            spki_der,
            // The passphrase-bound auth (if any) is installed by
            // `decrypt_from_store`, which wraps this constructor; the raw
            // no-passphrase `from_store_blob*` path yields an empty-auth key.
            auth: None,
            keep_connection: tcti_shares_the_tpm(tcti),
            connection: Mutex::new(None),
            parents_made: AtomicU64::new(0),
        })
    }

    /// Serialize to a DSMT blob, binding the operator passphrase as the child
    /// key's TPM authorization value.
    ///
    /// If `passphrase` is non-empty: re-open a context, re-derive the parent,
    /// `TPM2_Load` the child, and `TPM2_ObjectChangeAuth` it to set its auth =
    /// [`derive_tpm_auth`]`(passphrase)`. `object_change_auth` returns a NEW
    /// `Private` (the same sensitive area re-wrapped with the new authValue; the
    /// public area — and thus the SPKI — is UNCHANGED). The blob is serialized
    /// with that new `Private`, so the on-disk key now requires the passphrase
    /// as its TPM auth on every future `sign`. Both transient handles are flushed
    /// on all paths. The in-memory `self.child_private`/`self.auth` are left as
    /// they were (empty-auth): the immediate post-`generate` enroll CSR sign uses
    /// this in-memory empty-auth key, while the persisted blob carries the
    /// auth-bound private for the daemon to load with the passphrase.
    ///
    /// If `passphrase` is empty (`b""`): no auth is bound (back-compat / soft
    /// parity) and this is exactly [`to_store_blob`].
    ///
    /// The auth is baked into the TPM-encrypted sensitive area of the wrapped
    /// `Private`; because the derivation is salt-free, NOTHING extra is stored in
    /// the DSMT blob and its format is unchanged.
    ///
    /// # Errors
    /// Returns a `String` if the key is zeroized, the TCTI/TPM command fails
    /// (load / object-change-auth), or the public area cannot be marshalled.
    ///
    /// [`to_store_blob`]: Self::to_store_blob
    pub fn encrypt_to_store(&self, passphrase: &[u8]) -> Result<Vec<u8>, String> {
        if self.spki_der.is_empty() {
            return Err("attest key has been zeroized".into());
        }
        if passphrase.is_empty() {
            // Empty passphrase: keep the empty-auth key (soft parity / back-compat).
            return self.to_store_blob();
        }

        // Re-wrap the sensitive area with the passphrase-derived auth. The
        // derived bytes live in a `Zeroizing` and are wrapped into `Auth`
        // (whose inner buffer is itself zeroizing) before any TPM call.
        let derived = derive_tpm_auth(passphrase);
        let new_auth =
            Auth::try_from(derived.as_slice()).map_err(|e| format!("wrap TPM auth value: {e}"))?;

        let mut ctx = open_context(&self.tcti)?;
        let child_public = self.child_public.clone();
        let child_private = self.child_private.clone();
        let new_private = ctx
            .execute_with_nullauth_session(|ctx| -> Result<Private, TpmOpError> {
                let parent = ctx.create_primary(
                    Hierarchy::Owner,
                    parent_template().map_err(TpmOpError)?,
                    None,
                    None,
                    None,
                    None,
                )?;
                let child = match ctx.load(parent.key_handle, child_private, child_public) {
                    Ok(h) => h,
                    Err(e) => {
                        let _ = ctx.flush_context(parent.key_handle.into());
                        return Err(e.into());
                    }
                };
                // The freshly loaded child still has EMPTY auth, so the nullauth
                // session authorizes the change. `object_change_auth` returns the
                // re-wrapped `Private`; capture it WITHOUT early-returning so both
                // handles are always flushed, even on error.
                let result =
                    ctx.object_change_auth(child.into(), parent.key_handle.into(), new_auth);
                let _ = ctx.flush_context(child.into());
                let _ = ctx.flush_context(parent.key_handle.into());
                Ok(result?)
            })
            .map_err(|e: TpmOpError| e.0)?;

        // Serialize the blob with the NEW (auth-bound) private; the public is
        // unchanged.
        serialize_dsmt(&self.child_public, &new_private)
    }

    /// Reconstitute from a DSMT blob, deriving and CACHING the passphrase-bound
    /// TPM auth so the next [`sign`] authorizes with it.
    ///
    /// Delegates parsing/reconstruction to [`from_store_blob_with_tcti`] (default TCTI),
    /// then sets `self.auth`: a non-empty passphrase caches
    /// [`derive_tpm_auth`]`(passphrase)`; an empty passphrase (`b""`) leaves it
    /// `None` (empty-auth key). A WRONG passphrase parses fine here — the
    /// derived auth is simply wrong, and the failure surfaces at `sign` time as
    /// a TPM authorization rejection.
    ///
    /// # Errors
    /// See [`from_store_blob_with_tcti`].
    ///
    /// [`sign`]: Self::sign
    /// [`from_store_blob_with_tcti`]: Self::from_store_blob_with_tcti
    pub fn decrypt_from_store(blob: &[u8], passphrase: &[u8]) -> Result<Self, String> {
        let tcti = resolve_tcti();
        Self::decrypt_from_store_with_tcti(blob, &tcti, passphrase)
    }

    /// [`decrypt_from_store`] against an explicit TCTI. Tests pass the per-test
    /// swtpm TCTI here; production uses [`decrypt_from_store`], which resolves
    /// the default TCTI. Parses/reconstructs via [`from_store_blob_with_tcti`]
    /// (no TPM call) and caches the passphrase-derived auth for the next
    /// [`sign`]; an empty passphrase leaves the key empty-auth.
    ///
    /// # Errors
    /// See [`from_store_blob_with_tcti`].
    ///
    /// [`decrypt_from_store`]: Self::decrypt_from_store
    /// [`from_store_blob_with_tcti`]: Self::from_store_blob_with_tcti
    /// [`sign`]: Self::sign
    pub fn decrypt_from_store_with_tcti(
        blob: &[u8],
        tcti: &str,
        passphrase: &[u8],
    ) -> Result<Self, String> {
        let mut key = Self::from_store_blob_with_tcti(blob, tcti)?;
        if !passphrase.is_empty() {
            key.auth = Some(derive_tpm_auth(passphrase));
        }
        Ok(key)
    }

    /// The TPM backend does NOT build the CSR in Rust (there is no scalar to
    /// feed an in-Rust DER builder). `dsm.crypto.enroll.build_csr` assembles the
    /// CSR in Python from [`public_spki_der`] + [`sign`]. This method
    /// exists only to keep the FFI `AttestKey` surface total so `lib.rs` needs no
    /// `cfg` branch; it is never reached because the Python enroll path branches
    /// on the backend first. It returns a typed error (never panics across the
    /// FFI boundary) directing callers to the Python path.
    ///
    /// # Errors
    /// Always — returns the "assembled in Python" guidance error.
    ///
    /// [`public_spki_der`]: Self::public_spki_der
    /// [`sign`]: Self::sign
    pub fn build_csr(&self, _cn: &str, _noise_static_pub: &[u8]) -> Result<Vec<u8>, String> {
        Err(
            "TPM backend assembles the CSR in Python (enroll.build_csr); \
             build_csr is not implemented on the Rust TPM backend"
                .into(),
        )
    }

    /// Render the key permanently unusable, parity with `SoftAttestKey::zeroize`: every
    /// accessor then returns `"attest key has been zeroized"`. Closes the kept TPM
    /// connection (flushing its parent), clears `child_private` and the cached `auth`
    /// (both scrub via their inner `Zeroizing`) and `spki_der`, whose emptiness is the
    /// single "consumed" flag. Idempotent.
    pub fn zeroize(&mut self) {
        use zeroize::Zeroize;

        *lock_connection(&self.connection) = None;
        let old_private = std::mem::take(&mut self.child_private);
        drop(old_private);
        let old_auth = self.auth.take();
        drop(old_auth);
        self.spki_der.zeroize();
    }
}

/// Marshall `public` + `private` into a versioned `DSMT` blob.
///
/// `Private::value()` hands out a plain `&[u8]`; copying it into a Vec for
/// serialization makes an extra un-`Zeroizing` copy of the TPM-encrypted
/// private area. `serialize` copies those bytes into the returned blob
/// (carrying the TPM-bound private area is by design), so this intermediate
/// `DsmtBlob.private_buf` copy is wiped afterwards so no extra unwiped
/// duplicate lingers in the heap.
///
/// # Errors
/// Returns a `String` if the public area cannot be marshalled.
fn serialize_dsmt(public: &Public, private: &Private) -> Result<Vec<u8>, String> {
    use zeroize::Zeroize;

    let public_tpmt = public
        .marshall()
        .map_err(|e| format!("marshall TPMT_PUBLIC: {e}"))?;
    let mut dsmt = DsmtBlob {
        public_tpmt,
        private_buf: private.value().to_vec(),
    };
    let blob = tpm_blob::serialize(&dsmt);
    dsmt.private_buf.zeroize();
    Ok(blob)
}

/// Build the residency-critical child (attest) key template:
/// `sign | fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth` SET,
/// `restricted | decrypt | encryptedDuplication` CLEAR, ECDSA-SHA256 over
/// NIST P-256. These attribute bits ARE the non-extractability guarantee.
fn child_template() -> Result<Public, String> {
    let object_attributes = ObjectAttributes::builder()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_sign_encrypt(true)
        .with_decrypt(false)
        .with_restricted(false)
        .with_encrypted_duplication(false)
        .build()
        .map_err(|e| format!("child object attributes: {e}"))?;
    let ecc_params = PublicEccParametersBuilder::new_unrestricted_signing_key(
        EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)),
        EccCurve::NistP256,
    )
    .build()
    .map_err(|e| format!("child ecc params: {e}"))?;
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_ecc_parameters(ecc_params)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .map_err(|e| format!("child public build: {e}"))
}

/// Build the Owner-hierarchy storage parent template: restricted ECC P-256
/// decryption key, AES-128-CFB wrapping, empty auth. With this fixed template
/// under the stable Owner primary seed, `TPM2_CreatePrimary` re-derives the
/// same parent each boot, so the parent itself is never persisted — only the
/// child's `DSMT` blob is.
fn parent_template() -> Result<Public, String> {
    let object_attributes = ObjectAttributes::builder()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .with_restricted(true)
        .with_sign_encrypt(false)
        .build()
        .map_err(|e| format!("parent object attributes: {e}"))?;
    let ecc_params = PublicEccParametersBuilder::new_restricted_decryption_key(
        SymmetricDefinitionObject::AES_128_CFB,
        EccCurve::NistP256,
    )
    .build()
    .map_err(|e| format!("parent ecc params: {e}"))?;
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_ecc_parameters(ecc_params)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .map_err(|e| format!("parent public build: {e}"))
}

/// Open an Esys context against `tcti` and bring the TPM up. A hardware TPM is
/// already started, in which case `TPM2_Startup` returns `TPM2_RC_INITIALIZE`,
/// which is benign and swallowed; swtpm needs the explicit startup.
fn open_context(tcti: &str) -> Result<Context, String> {
    let conf = TctiNameConf::from_str(tcti)
        .map_err(|_| "invalid TPM TCTI; expected e.g. device:/dev/tpmrm0".to_string())?;
    let mut ctx = Context::new(conf).map_err(|e| map_tpm_err("open TPM context", e))?;
    if let Err(e) = ctx.startup(StartupType::Clear) {
        if !is_already_initialized(e) {
            return Err(map_tpm_err("TPM2_Startup", e));
        }
    }
    Ok(ctx)
}

/// Resolve the TCTI: `TPM2TOOLS_TCTI`/`TCTI` env > `device:/dev/tpmrm0`.
fn resolve_tcti() -> String {
    for var in ["TPM2TOOLS_TCTI", "TCTI"] {
        if let Ok(t) = std::env::var(var) {
            if !t.is_empty() {
                return t;
            }
        }
    }
    DEFAULT_TCTI.to_string()
}

/// Assemble a SubjectPublicKeyInfo DER from a TPM ECC `Public`, byte-identical
/// to the soft backend's output: the uncompressed SEC1 point `0x04 || X || Y`
/// re-encoded through `p256`'s `VerifyingKey::to_public_key_der` (same
/// `id-ecPublicKey` + `prime256v1` OIDs).
///
/// The TPM may emit big-endian coordinates with leading zeros stripped, so
/// each coordinate is left-padded to 32 bytes before assembling the point.
fn spki_from_public(public: &Public) -> Result<Vec<u8>, String> {
    use p256::pkcs8::EncodePublicKey;

    let Public::Ecc { unique, .. } = public else {
        return Err("attest key is not ECC".into());
    };
    let mut point = Vec::with_capacity(65);
    point.push(0x04); // SEC1 uncompressed-point tag
    point.extend_from_slice(&left_pad32(unique.x().value()));
    point.extend_from_slice(&left_pad32(unique.y().value()));

    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&point)
        .map_err(|e| format!("TPM point is not a valid P-256 key: {e}"))?;
    Ok(vk
        .to_public_key_der()
        .map_err(|e| format!("encode SPKI DER: {e}"))?
        .as_bytes()
        .to_vec())
}

/// Left-pad a big-endian byte slice into a fixed 32-byte array (P-256
/// coordinate width). Truncates from the left if longer than 32 (never happens
/// for a valid P-256 coordinate, but keeps the function total).
fn left_pad32(b: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let n = b.len().min(32);
    out[32 - n..].copy_from_slice(&b[b.len() - n..]);
    out
}

/// Map a tss-esapi error to a `String` without leaking internal TPM state
/// beyond the return-code name and the operation context. The raw TCTI
/// connection string is deliberately NOT interpolated: it is environment/path
/// info that should not surface in Python exceptions or logs, so the message
/// names only the operation and the TPM return code.
fn map_tpm_err(op: &str, e: tss_esapi::Error) -> String {
    format!("{op} failed on TPM: {e}")
}

/// True for the benign "TPM already started" (`TPM2_RC_INITIALIZE`) condition
/// a redundant `TPM2_Startup` returns on an already-running TPM. Matches the
/// typed tss-esapi return code rather than a stringified message, which is
/// fragile across libtss2 versions and locales on real hardware.
fn is_already_initialized(e: tss_esapi::Error) -> bool {
    matches!(
        e,
        tss_esapi::Error::Tss2Error(rc)
            if rc.kind() == Some(Tss2ResponseCodeKind::Initialize)
    )
}

/// Build the `TPM_RC_NULL` hashcheck ticket required by `TPM2_Sign`. The digest
/// is supplied externally (not the output of a prior `TPM2_Hash` under TPM
/// control), and an unrestricted signing key signs such a digest with a null
/// ticket — this matches how tss-esapi's own integration tests sign an external
/// digest.
fn build_null_hashcheck() -> Result<HashcheckTicket, TpmOpError> {
    let raw = TPMT_TK_HASHCHECK {
        tag: TPM2_ST_HASHCHECK,
        hierarchy: TPM2_RH_NULL,
        digest: TPM2B_DIGEST::default(),
    };
    HashcheckTicket::try_from(raw).map_err(|e| TpmOpError(format!("build null hashcheck: {e}")))
}

/// Assemble an ASN.1 DER ECDSA signature (`SEQUENCE { r INTEGER, s INTEGER }`)
/// from a TPM `Signature::EcDsa`, byte-for-byte identical to the soft backend's
/// `p256::ecdsa::Signature::to_der()` output, so a verifier cannot tell a
/// TPM-signed value from a soft-signed one.
///
/// The TPM may strip leading zero bytes from the big-endian `r`/`s`
/// coordinates, so each is left-padded to the fixed 32-byte P-256 scalar width
/// before the fixed-width `(r || s)` is handed to `p256` for canonical DER
/// encoding.
fn ecdsa_signature_to_der(sig: &Signature) -> Result<Vec<u8>, String> {
    let Signature::EcDsa(ecc) = sig else {
        return Err("TPM returned a non-ECDSA signature".into());
    };
    let mut scalars = [0u8; 64];
    scalars[..32].copy_from_slice(&left_pad32(ecc.signature_r().value()));
    scalars[32..].copy_from_slice(&left_pad32(ecc.signature_s().value()));
    let signature = p256::ecdsa::Signature::from_slice(&scalars)
        .map_err(|e| format!("invalid ECDSA (r,s) from TPM: {e}"))?;
    Ok(signature.to_der().as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tss_esapi::constants::tss::{TPM2_RC_FAILURE, TPM2_RC_INITIALIZE};
    use tss_esapi::constants::Tss2ResponseCode;

    fn tss_err(rc: u32) -> tss_esapi::Error {
        tss_esapi::Error::Tss2Error(Tss2ResponseCode::from(rc))
    }

    #[test]
    fn initialize_rc_is_benign() {
        assert!(is_already_initialized(tss_err(TPM2_RC_INITIALIZE)));
    }

    #[test]
    fn other_rc_is_not_benign() {
        assert!(!is_already_initialized(tss_err(TPM2_RC_FAILURE)));
    }
}
