# Phase 3 — TPM 2.0 Attestation Backend (Key-Residency) — Architecture & Contract

**Status:** Proposed (design/contract only — no implementation code beyond
interface/trait signatures).
**Scope:** Owner-confirmed. TPM 2.0 is REQUIRED for v1. Key-residency only.
**Author:** architect agent.
**Date:** 2026-06-12.
**Drives:** a subsequent TDD implementation plan, then subagent-driven
execution against swtpm.

---

## 0. Owner-confirmed scope (NOT up for redesign)

These are inputs, restated so the implementation plan inherits them verbatim:

- TPM 2.0 is **required** for v1 (overrides the README "planned" deferral).
- **Key-residency** scope only. The device attestation ECDSA P-256 key is
  **generated inside the TPM**, is **non-extractable**, and **signs in-TPM**.
  Its public key is exported for the X.509 device cert + the per-handshake
  binding signature.
- **Explicitly OUT of scope for v1** (post-v1): PCR-bound policy, remote
  attestation / `TPM2_Quote`, endorsement-key (EK) certificate validation,
  credential-activation enrollment. The design leaves seams for these but
  ships none of them.
- `tss-esapi` is **approved**. Use a **stable** release. (8.0.0-alpha is
  forbidden.)
- CI/tests via **swtpm** (host has `swtpm` + `swtpm_setup` + `/dev/tpm0` +
  `/dev/tpmrm0` + `libtss2-esys.so` + `tpm2_startup`).

---

## 1. Summary + the key-residency property delivered

### 1.1 What this delivers

Phase 0 shipped a backend selector (`device_attest.rs`) with a software
backend (`SoftAttestKey`) and a compile-time `compile_error!` guard that
already references a not-yet-implemented `tpm-attest` feature. Phase 3
implements that `tpm-attest` backend: a `TpmAttestKey` that satisfies the
**exact same contract surface** the PyO3 wrapper (`PyAttestKey`) and the
Python cert/enroll/handshake flow already call — `generate`/provision,
`sign(msg) -> DER ECDSA sig`, `public_spki_der() -> SPKI DER`, `build_csr`,
load/store, `zeroize` — but the private scalar **never exists outside the
TPM**. The ECDSA signature is computed by the TPM.

### 1.2 The key-residency property (the security guarantee)

> The ECDSA P-256 attestation private key is created by `TPM2_CreatePrimary`/
> `TPM2_Create` with the `fixedTPM | fixedParent | sign` attributes set and
> the `decrypt` / `restricted` attributes cleared. `fixedTPM | fixedParent`
> makes the key **non-duplicable and non-migratable**: there is no TPM
> command sequence that exports the private portion in any form (wrapped or
> plaintext) off this physical TPM. Signing happens via `TPM2_Sign` inside
> the TPM. The host process — and anyone with code execution as root on the
> host — can request signatures but cannot extract the key.

This is strictly stronger than `dev-soft-attest`, whose scalar is
Argon2id-wrapped at rest but lives extractably in process memory while the
daemon runs. With `tpm-attest`, `ATTEST_BACKEND_IS_SOFTWARE = false`, so the
Phase-0 startup gate (`enforce_attest_backend_policy`) passes without the
`allow_soft_attest` acknowledgement.

### 1.3 What does NOT change (load-bearing)

The **wire/protocol/cert contract is unchanged.** The cert binds a P-256
SPKI; the per-handshake binding signature is DER ECDSA-with-SHA256 over the
86-byte pre-image (`dsm/crypto/attest.py`). The verifier
(`verify_attest_payload`) does ECDSA verification against the cert's pubkey
and **does not care where the private key lives.** A TPM-enrolled device and
a (legacy) soft-enrolled device are indistinguishable on the wire and to the
server allowlist. This is the property that makes a mixed fleet and a
soft→TPM migration trivial (see §8 and §12).

---

## 2. Component diagram

```
 ┌──────────────────────── Python (dsm/) ─────────────────────────┐
 │  dsm enroll  ──► enroll.py ──► AttestStore (attest_store.py)    │
 │  daemon start ─► _stores.py ─► AttestStore                      │
 │                                   │                             │
 │           build_attest_payload (attest.py) / build_csr          │
 │                                   │ calls .sign()/.public_spki  │
 └───────────────────────────────────┼─────────────────────────────┘
                                      │  PyO3 FFI (UNCHANGED surface)
 ┌──────────────────────── Rust (tuncore) ───────────┼─────────────┐
 │  PyAttestKey (lib.rs) ── inner: device_attest::AttestKey         │
 │                              │ (cfg-selected type alias)         │
 │   #[cfg(dev-soft-attest)] = SoftAttestKey   (Phase 0, unchanged) │
 │   #[cfg(tpm-attest)]      = TpmAttestKey     (Phase 3, NEW)      │
 │                              │                                   │
 │   TpmAttestKey ──► tss-esapi 7.7.0 ──► libtss2-esys.so          │
 │        │  (Esys context, TCTI handle)        (system, 4.1.3)     │
 └────────┼─────────────────────────────────────────┼──────────────┘
          │ TCTI selection (runtime)                 │
   ┌──────┴───────────┐                       ┌──────┴──────────┐
   │ PROD: device TCTI │                       │ TEST: swtpm TCTI │
   │ /dev/tpmrm0       │                       │ unix:path=<sock> │
   │ (resource mgr)    │                       │ (mssim/swtpm)    │
   └───────────────────┘                       └──────────────────┘
```

- **Rust `TpmAttestKey`** owns an `Esys` context + a reference to the
  in-TPM attest key (a loaded transient handle, restored each process from a
  persisted context blob — see §4). It exposes the SoftAttestKey method
  surface.
- **PyO3 surface** (`PyAttestKey` in `lib.rs`) is **unchanged** at the Python
  call sites, with two semantic deltas behind the FFI: `decrypt_from_store`
  and `encrypt_to_store` change meaning for TPM (see §3 and §5).
- **Python `attest_store.py` / `enroll.py` / `__main__.py`** gain a thin
  backend-aware branch (see §5). The **cert/binding flow (`attest.py`,
  `cert.py`) is untouched.**

---

## 3. The two semantic deltas the rest of the design hangs on

Everything below follows from two facts about TPM key-residency that differ
from the soft backend:

1. **There is no passphrase-wrapped private blob.** The private key is in the
   TPM. "Loading at startup" means *reconstituting a handle to an in-TPM
   key*, not Argon2id-decrypting a scalar. So `decrypt_from_store(blob,
   passphrase)` cannot have its soft meaning. **Decision (§4):** the on-disk
   artifact is a **TPM key context blob** (a `TPM2B_PRIVATE` + `TPM2B_PUBLIC`
   pair, opaque, TPM-bound, useless on any other TPM). "Load" = `TPM2_Load`
   that blob under the primary, yielding a transient handle. The "passphrase"
   for TPM is the optional **key authValue**, not a KDF input.

2. **The primary/parent must be deterministically re-derivable.** A TPM
   primary key created from a fixed template under a hierarchy is
   *deterministic*: `TPM2_CreatePrimary` with the same template + same
   hierarchy seed reproduces the same primary. So the daemon can re-create
   the parent each boot (no need to persist the parent), then `TPM2_Load` the
   saved child blob under it. This is the **context-blob persistence model**
   (chosen over persistent handles — see §4.2).

---

## 4. Persistence model (IRREVERSIBLE — versioned format)

### 4.1 Decision: **context-blob on disk**, not a persistent handle

Two candidate models:

| | (a) Persistent handle (`evictControl` to e.g. `0x81010001`) | (b) Context blob on disk (`TPM2_Create` child, save `TPM2B_PUBLIC`+`TPM2B_PRIVATE`, `TPM2_Load` each boot) |
|---|---|---|
| Key leaves TPM? | Never | Never (private blob is TPM-bound; decrypts only inside this TPM) |
| Survives restart | Yes (in NV) | Yes (blob on disk; parent re-derived deterministically) |
| NV wear / NV slot scarcity | Consumes a scarce persistent slot; collides if slot reused | None — NV untouched |
| Handle collision failure mode | "handle already in use" needs operator cleanup | None |
| Multiple keys / re-enroll | Manual evict dance | Just write a new blob file |
| Backup / disaster recovery | Cannot back up (NV-resident) | Blob is a file → fits existing backup story, still useless off-TPM |
| Mirrors existing model | No (daemon currently reads a *file* at `attest_key_file`) | **Yes** — `attest_key_file` stays a file path |
| swtpm test hermeticity | Persistent-handle state survives across swtpm restarts → harder to make hermetic | Each test writes its own blob → trivially hermetic |

**Recommendation: (b) context blob.** Rationale: it keeps `attest_key_file`
as a *file path* (no config-shape change, no `_stores.py` plumbing change for
the "where is it" question), avoids consuming a scarce NV persistent slot,
avoids the "handle already in use" operator failure mode, is trivially
backup-able and trivially hermetic for swtpm tests, and the private blob is
TPM-bound so the residency guarantee is identical to (a). The key still
*never leaves the TPM in usable form* — the blob's sensitive area is
encrypted to the parent under the TPM's seed.

> **IRREVERSIBLE-1:** the on-disk artifact format and the parent-key template
> are baked into every enrolled device. Once a fleet enrolls, the daemon must
> be able to `TPM2_Load` those exact blobs forever (or via a migration
> path). Hence the **versioned, magic-prefixed format** below, mirroring the
> Phase-0 sealed-blob lesson (`passphrase_store.rs`: `DSMK` magic + version
> byte + params bound into AAD).

### 4.2 Why NOT a persistent handle as the primary mechanism

A persistent handle is the "obvious" TPM idiom but it (1) changes
`attest_key_file` from a file to a numeric handle reference (config + store
plumbing churn), (2) burns a finite NV slot and forces a fixed handle value
that becomes its own IRREVERSIBLE decision and a fleet-wide collision risk,
(3) makes swtpm tests stateful, and (4) cannot be backed up. We keep the
persistent-handle path documented as a **future option** (a `key_kind` byte
in the format header reserves room for it — see §4.4) but do not ship it.

### 4.3 Hierarchy, primary template, attest-key template (concrete)

- **Hierarchy: Owner (`TPM_RH_OWNER`).** Rationale: the Endorsement
  hierarchy is reserved for privacy-sensitive EK operations (out of scope —
  no quotes/EK in v1); the Null hierarchy resets on every TPM reboot (a Null
  child blob would fail to `TPM2_Load` after a power cycle — unusable for a
  daemon that must survive reboots). Owner hierarchy is the correct home for
  a long-lived application signing key and survives reboots.
  > **IRREVERSIBLE-2:** hierarchy choice. Owner is recommended and recorded
  > in the format header (`hierarchy` byte) so a future migration can detect
  > and convert.

- **Primary (parent) key template — deterministic, restricted decrypt:**
  - Type: **ECC P-256** (NIST P-256), `restricted | decrypt | fixedTPM |
    fixedParent | sensitiveDataOrigin | userWithAuth`.
  - Symmetric wrapping: AES-128-CFB (the standard storage-parent scheme).
  - Auth: **empty authValue** (parent needs no secret; the parent is not the
    security boundary — the child's residency is).
  - Created with `TPM2_CreatePrimary` under Owner each boot. Deterministic
    given the same template + the (persistent) Owner primary seed, so it need
    NOT be persisted.
  - We pin a **fixed `unique` field / template** so the parent is reproducible
    byte-for-byte across boots; the daemon recreates it and `TPM2_Load`s the
    child under it.

- **Attest (child) key template — the residency-critical one:**
  - Type: **ECC NIST P-256**, scheme **ECDSA with SHA-256**.
  - Attributes: **`sign` SET; `fixedTPM` SET; `fixedParent` SET;
    `sensitiveDataOrigin` SET; `userWithAuth` SET; `restricted` CLEAR;
    `decrypt` CLEAR; `encryptedDuplication` CLEAR.**
    - `sign` + `restricted=clear` ⇒ a general-purpose signing key that can
      sign arbitrary externally-supplied digests (our 86-byte binding
      pre-image hashes to one SHA-256 digest). A *restricted* signing key
      would refuse to sign data not produced by the TPM — wrong for us.
    - `fixedTPM | fixedParent` ⇒ **non-migratable / non-duplicable**: the
      residency guarantee.
    - `sensitiveDataOrigin` ⇒ the TPM generates the private scalar; no
      external scalar is imported.
  - Created with `TPM2_Create` under the primary; we save the returned
    `outPublic` (`TPM2B_PUBLIC`) and `outPrivate` (`TPM2B_PRIVATE`) into the
    versioned file.
  - **Key authValue:** see §4.5.

### 4.4 The versioned on-disk format (`DSMT` blob)

Mirror `passphrase_store.rs` exactly in spirit (magic + version + a fixed
header; reject unknown versions loudly):

```
 offset  size  field
 0       4     magic = b"DSMT"            (DSM-TPM; distinct from soft "DSMK")
 4       1     format_version = 0x01
 5       1     hierarchy      (0x01 = OWNER)         ; reserved 0x02=ENDORSEMENT
 6       1     key_kind       (0x01 = CONTEXT_BLOB)  ; reserved 0x02=PERSISTENT_HANDLE
 7       1     curve_id       (0x01 = NIST_P256)
 8       2 BE  pub_len
 10      N     TPM2B_PUBLIC   (marshalled, N = pub_len)
 10+N    2 BE  priv_len
 12+N    M     TPM2B_PRIVATE  (marshalled, M = priv_len)
```

- All header bytes are integrity-relevant. They are **not** secret (the blob
  carries no usable secret — the sensitive area is TPM-encrypted), so we do
  not need an AEAD; but a tampered header must fail closed. **`TPM2_Load`
  itself is the integrity check:** a corrupted `TPM2B_PRIVATE` fails to load
  (the TPM HMACs the private area under the parent's seed). The parser
  additionally rejects unknown `magic` / `format_version` / `key_kind` /
  `hierarchy` / `curve_id` with a typed error before touching the TPM.
- `key_kind` / `hierarchy` / `curve_id` reserved values give a clean
  migration seam to persistent-handle or P-384 without a v2 reparse rewrite.

> **IRREVERSIBLE-3 (mitigated):** the format is the migration boundary. The
> magic + version byte make a future v2 format detectable and convertible,
> exactly as Phase 0 did. **This is the single most important reversibility
> safeguard in the design** — do not ship a headerless blob.

### 4.5 Key authValue (the "passphrase" for TPM)

The attest child key MAY carry a TPM `authValue` (a secret the TPM checks
before `TPM2_Sign`). Options:

- **(A) Empty authValue.** Residency already prevents extraction; an attacker
  with root can request signatures whether or not there is an authValue,
  *unless* the authValue is not present in process memory — but the daemon
  must present it to sign, so it would be in memory at sign time anyway.
- **(B) Authvalue = the operator passphrase** (the same one that today
  unlocks the soft store), bound at enroll and presented at each sign.

**Recommendation: (A) empty authValue for v1**, because (B) buys little
against the root-on-host threat (the value must be resident to sign) while
adding a passphrase-prompt coupling that complicates non-interactive systemd
restarts (the daemon today can run with a stashed passphrase, but the *value*
would have to be fed into every `TPM2_Sign`). The residency guarantee — the
actual Phase-3 deliverable — is independent of the authValue. The format
header has room to add an `auth_kind` byte in a future version if policy
changes. **This is a reversible default; flagged as an open confirmation
(§11, Q3).**

---

## 5. The Rust `TpmAttestKey` contract

`TpmAttestKey` lives in a new module `rust/tuncore/src/device_attest_tpm.rs`,
gated `#[cfg(feature = "tpm-attest")]`, and is re-exported as `AttestKey` from
`device_attest.rs` under that feature. It **must expose every method the
PyO3 wrapper calls** so `lib.rs` needs no `cfg` branching at call sites.

### 5.1 Method surface (signatures only — NO bodies)

```rust
// rust/tuncore/src/device_attest_tpm.rs   (#[cfg(feature = "tpm-attest")])

/// In-TPM ECDSA P-256 attestation key. The private scalar never leaves the
/// TPM. Holds an Esys context and a loaded transient handle to the key.
pub struct TpmAttestKey { /* esys ctx, parent handle, key handle, cached SPKI */ }

impl TpmAttestKey {
    /// Provision a NEW attest key inside the TPM (enroll path).
    /// Recreates the deterministic Owner primary, runs TPM2_Create with the
    /// sign-only fixedTPM|fixedParent P-256 template, loads it, caches the
    /// exported SPKI. Does NOT persist — caller persists via `to_store_blob`.
    pub fn generate() -> Result<Self, String>;

    /// SubjectPublicKeyInfo DER of the in-TPM key's public point.
    /// Same return contract as SoftAttestKey::public_spki_der (Err once the
    /// handle is flushed/zeroized).
    pub fn public_spki_der(&self) -> Result<&[u8], String>;

    /// Sign `msg` with the in-TPM key: hash to SHA-256, TPM2_Sign, return
    /// ASN.1 DER ECDSA (r,s). Same DER output contract as the soft backend.
    /// Enforces the SIGN_MSG_MAX 1 MiB cap (parity with soft L-CRYPT-3).
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, String>;

    /// Build a CA-ready DER CSR. UNLIKE the soft backend this CANNOT export
    /// a PKCS#8 scalar to feed rcgen. Instead it builds the
    /// CertificationRequestInfo (subject CN + critical noiseStaticBinding
    /// extension, byte-identical to the soft encoding) and signs it with the
    /// in-TPM key. See §5.3.
    pub fn build_csr(&self, cn: &str, noise_static_pub: &[u8]) -> Result<Vec<u8>, String>;

    /// Serialize the persistable reference: the versioned `DSMT` blob
    /// (TPM2B_PUBLIC + TPM2B_PRIVATE + header). REPLACES `encrypt_to_store`.
    /// Takes NO passphrase (the key is in the TPM, not a sealed scalar).
    pub fn to_store_blob(&self) -> Result<Vec<u8>, String>;

    /// Reconstitute from a `DSMT` blob: parse+validate header, recreate the
    /// deterministic primary, TPM2_Load the child blob → transient handle,
    /// cache SPKI. REPLACES `decrypt_from_store`. Takes NO passphrase.
    pub fn from_store_blob(blob: &[u8]) -> Result<Self, String>;

    /// Flush the loaded transient handle and drop the Esys context. The
    /// private key is unaffected (it is in the TPM, addressed only by the
    /// saved blob). Clears the cached SPKI so accessors fail post-zeroize,
    /// matching SoftAttestKey::zeroize semantics. Idempotent.
    pub fn zeroize(&mut self);
}
```

### 5.2 FFI compatibility shim (so `lib.rs` does not branch)

The PyO3 wrapper calls `encrypt_to_store(passphrase)` and
`decrypt_from_store(blob, passphrase)`. Two options to keep `lib.rs`
unchanged:

- **Option A (recommended): keep the method *names* on both backends but make
  the TPM versions ignore the passphrase argument.** `TpmAttestKey` provides
  `encrypt_to_store(&self, _passphrase: &[u8]) -> Result<Vec<u8>>` that
  forwards to `to_store_blob()` (passphrase ignored, documented), and
  `decrypt_from_store(blob, _passphrase)` that forwards to
  `from_store_blob(blob)`. Then `lib.rs` and `attest_store.py` need **zero**
  signature changes — the Python side simply passes an empty/sentinel
  passphrase for TPM (see §6). This is the least-churn path and keeps the
  feature flag the *only* thing that switches behavior.
- Option B: change the PyO3 signatures to drop the passphrase for TPM, which
  forces `#[cfg]` branching in `lib.rs` and a Python-side `if backend` fork.
  More honest, more churn, more surface to break.

**Recommendation: Option A.** The passphrase argument becomes a documented
no-op on the TPM backend. (A `debug_assert!` that the passphrase is empty on
the TPM path catches accidental misuse in dev.) This is a **reversible**
choice — if a future authValue policy (§4.5 option B) wants the passphrase,
the parameter is already threaded.

> Note: `private_pkcs8_der` exists on the soft backend but is **crate-private
> and only called by the soft `build_csr`.** The TPM backend does **not**
> implement it (and must not — exporting a scalar is exactly what residency
> forbids). Because it is not on the PyO3 surface, omitting it costs nothing.

### 5.3 CSR construction without scalar export

The soft backend exports PKCS#8 and hands it to `rcgen`. The TPM cannot.
The TPM `build_csr` must construct the PKCS#10 `CertificationRequest`
manually and sign the `CertificationRequestInfo` with `TPM2_Sign`:

- Build the DER `CertificationRequestInfo` (version, subject `CN`, the
  in-TPM key's `SubjectPublicKeyInfo`, and the **same** critical
  `id-dsm-noiseStaticBinding` (1.3.6.1.4.1.99999.1.1) extension with the
  `OCTET STRING(32) || raw pub` value — byte-identical to the soft encoding
  in `device_attest_soft.rs` so the CA review step and the cert binding are
  unchanged).
- SHA-256 the `CertificationRequestInfo`, `TPM2_Sign`, wrap as
  `ecdsa-with-SHA256`, emit the full `CertificationRequest`.
- Use a DER builder that does **not** require a private key object — either a
  small hand-rolled PKCS#10 assembler (the structure is tiny and fixed) or
  the `picky`/`x509-cert` builder family. **Dependency note:** this MAY need
  a DER/PKCS#10 helper crate. `tss-esapi` already pulls `picky-asn1`
  transitively; prefer reusing the ASN.1 toolkit already in the tree over
  adding a new top-level dep. **Flagged as a dependency decision (§11, Q4) —
  do not add a new crate without approval.**

This keeps the CA workflow (`deploy/GUIDE.txt §3c`: inspect CSR → sign →
import) completely unchanged — the CSR is structurally identical, only the
signer moved into the TPM.

### 5.4 Esys context & handle lifecycle

- `TpmAttestKey` owns one `tss_esapi::Context` (Esys). Open it lazily in
  `generate`/`from_store_blob`, keep it for the object's life, close on
  `zeroize`/`Drop`.
- The loaded child key is a **transient** ESYS handle; flush it
  (`flush_context`) on drop so the TPM's limited transient-object slots are
  not leaked across daemon restarts/crashes (a TPM has ~3 transient slots;
  leaking them wedges the TPM until reset).
- The deterministic primary is also transient; flush it after `TPM2_Load`
  (the child handle does not need the parent resident once loaded). This
  keeps slot pressure to one handle.
- `Context` is **not `Send`/`Sync`-friendly to share**: the daemon already
  uses `AttestKey` from one place (the handshake builder calls `.sign()`
  under the GIL). Keep `PyAttestKey` single-owner; do not add threading. The
  existing `PyAttestKey` is not `unsendable`-marked, but `.sign()` is only
  called from the handshake coroutine — document the single-owner invariant
  and (recommended) mark `PyAttestKey` `unsendable` under the TPM feature so
  accidental `to_thread` use raises instead of corrupting the Esys context.
  **(Reversible hardening; flagged §11, Q5.)**

---

## 6. Python-side contract changes

The Python changes are deliberately tiny because of the §5.2 shim. The cert
flow (`attest.py`, `cert.py`) and the binding-signature flow are **untouched.**

### 6.1 `attest_store.py` — `AttestStore`

Today `AttestStore` calls `AttestKey.generate()` →
`encrypt_to_store(passphrase)` → `atomic_write`, and on load
`decrypt_from_store(blob, passphrase)`. With the §5.2 shim, the *call shapes
stay the same*; the only change is that for the TPM backend the passphrase is
a no-op. Two clean ways to express that:

- **(Recommended) Backend-aware passphrase sourcing inside `AttestStore`.**
  Add a module-level helper `attest_backend_is_software()` reading
  `tuncore.ATTEST_BACKEND_IS_SOFTWARE`. When the backend is TPM,
  `generate()`/`load()` pass `b""` (the documented no-op passphrase) to the
  Rust shim instead of the operator passphrase. The on-disk file at
  `attest_key_file` now holds a `DSMT` blob instead of a `DSMK` blob — same
  path, same `atomic_write`, same 0o600 perms, same `check_user_file_
  permissions` gate. **No signature change to `AttestStore`'s public
  methods.**

This means `_stores.py` (`loaded_stores_cli` / `load_daemon_stores`) and the
daemon startup in `client.py`/`server.py` need **no change at all** — they
still read the passphrase once and hand it to both stores; the attest store
simply ignores it on the TPM path. (The *identity* keystore still genuinely
uses the passphrase — the X25519 Noise static is NOT in the TPM; see §6.4.)

`AttestStore.load()` keeps `check_user_file_permissions(self._path)`: the
`DSMT` blob is not secret, but file substitution is still an integrity
concern (a swapped blob = a different attest key), so the existing perm gate
is correct and retained.

### 6.2 `enroll.py` — `generate_enrollment`

Today: `attest_store.generate(passphrase)` makes a soft key, seals it, returns
SPKI; then `build_csr`. With the shim, `attest_store.generate(passphrase)`
**provisions the key in the TPM** and writes the `DSMT` blob — the function
body is unchanged because the polymorphism is behind the Rust feature + the
store's passphrase shim. `build_csr` calls `attest_key.build_csr(...)` which
now signs in-TPM (§5.3). **`enroll.py` needs no structural change.**

The only operator-visible wording change is the passphrase prompt: today it
says "will protect identity + attest key". For TPM the passphrase protects
**only the identity** (the attest key is TPM-resident). Update the prompt
string in `__main__.py` to be backend-accurate (see §6.3). This is cosmetic
but important for operator trust.

### 6.3 `__main__.py` — `_run_enroll`

- The passphrase prompt text becomes backend-aware: TPM →
  `"New passphrase (protects the identity key; attest key is TPM-resident): "`.
- `--import` flow is **unchanged**: `import_signed_cert` compares the cert's
  SPKI to `attest_store.public_spki_der()` — which for TPM is the in-TPM
  key's exported SPKI. The comparison is identical.
- Add a small, explicit **enroll-time TPM preflight** (see §8 failure modes):
  on the TPM backend, before provisioning, open the TCTI and confirm the TPM
  responds (`TPM2_GetCapability` / startup check); fail with an actionable
  message ("no TPM at <tcti>; is /dev/tpmrm0 present and is the daemon in
  group tss?") rather than a raw tss-esapi error. This is the one genuinely
  new code path on the Python side, and it is thin.

### 6.4 Identity key is NOT in the TPM (confirm scoping)

`identity.rs` (`IdentityKeyPair`, the X25519 Noise static) is **out of TPM
scope** for Phase 3. TPM 2.0 has no native X25519; binding the Noise static
into the TPM would require ECDH-P256-as-Noise (a protocol change — forbidden)
or a sealed-blob (no residency win over the current `LockedKey32` +
Argon2id). The identity stays passphrase-sealed exactly as today. **Only the
attest key is TPM-resident.** This is consistent with the cert design: the
cert's `noiseStaticBinding` extension binds the (software) X25519 static, and
the (TPM) attest key signs that binding — the residency guarantee covers the
*attestation signer*, which is the credential an attacker would forge.

### 6.5 `attest_gate.py` default

No code change needed in `attest_gate.py` itself — it already returns early
when `ATTEST_BACKEND_IS_SOFTWARE` is false. With `tpm-attest` as the default
build (§7), `enforce_attest_backend_policy` becomes a no-op pass on
production wheels and only engages its gate when someone deliberately builds
the `dev-soft-attest` feature. The `allow_soft_attest` config knob and its
gate semantics stay exactly as Phase 0 designed them.

---

## 7. Cargo feature / default-backend design

### 7.1 The change

Phase 0: `default = ["dev-soft-attest"]`. Phase 3 flips the production
default to TPM while keeping soft available for CI/dev that lacks a TPM.

```toml
# rust/tuncore/Cargo.toml
[features]
default = ["tpm-attest"]            # production wheels are TPM by default
dev-soft-attest = ["dep:p256", "dep:rcgen"]
tpm-attest = ["dep:tss-esapi"]     # NEW: real backend deps wired

[dependencies]
# ... existing ...
tss-esapi = { version = "7.7.0", optional = true }
# NOTE: tss-esapi pulls tss-esapi-sys 0.6.0 which ships PREGENERATED bindings
# for x86_64-unknown-linux-gnu and links the system tss2-esys via pkg-config.
# No bindgen/libclang needed for the default build (libclang IS present if a
# future `generate-bindings` rebuild is ever required).
```

- The existing `device_attest.rs` exactly-one-backend `compile_error!` guard
  **already handles this** — it errors if both or neither feature is on. No
  change to that file's guard logic; just the Cargo default flips and the
  `tpm-attest = []` placeholder gains `dep:tss-esapi`.
- `BACKEND_IS_SOFTWARE` is already `false` under `#[cfg(feature =
  "tpm-attest")]` in `device_attest.rs` (Phase 0 wrote it correctly in
  advance). So `ATTEST_BACKEND_IS_SOFTWARE` flips to `false` for free.

### 7.2 What the release wheel builds with

- **Production wheel:** default features → `tpm-attest`. Requires
  libtss2-esys at build time (present) and at runtime on the target. The
  GUIDE must state the runtime dependency (`libtss2-esys0` /
  `tpm2-tools`/`tpm-udev` package) — see §10.
- **CI/dev (no real TPM required for unit tests of the *soft* backend, swtpm
  required for the TPM backend tests):**
  `cargo test --no-default-features --features dev-soft-attest` runs the
  soft-backend unit tests (unchanged).
  `cargo test --no-default-features --features tpm-attest` runs the
  TPM-backend tests **against swtpm** (the harness in §9 sets the TCTI env).
- **Mutual exclusion + tooling:** because the two backends are mutually
  exclusive at compile time, a single `cargo build` cannot exercise both;
  CI runs two jobs (one per backend). The existing `.github/workflows/ci.yml`
  gains a `tpm-attest` job that provisions swtpm before `cargo test`.

> **IRREVERSIBLE-4 (operational, not data):** flipping the default to
> `tpm-attest` means a plain `pip install` / `maturin build` now needs
> libtss2 present. This is the intended production posture but it changes the
> build prerequisites for everyone. Reversible by building
> `--no-default-features --features dev-soft-attest`, but the *default*
> changing is a conscious posture shift — flagged for owner awareness.

### 7.3 TCTI selection at runtime

- **Default (production): the device resource-mgr TCTI → `/dev/tpmrm0`.**
  Selected when no override is present. `/dev/tpmrm0` (the in-kernel resource
  manager) is preferred over `/dev/tpm0` because it multiplexes
  transient-object slots and avoids the daemon having to manage raw TPM
  context swapping.
- **Override order (highest first):**
  1. An explicit config knob (recommended new optional field
     `attest_tpm_tcti` in `Config`, default `None` → device:/dev/tpmrm0).
     A config knob is more auditable than an env var for a daemon. **(New
     optional config field — flagged §11, Q2; it is additive and
     backward-compatible.)**
  2. The conventional `TPM2TOOLS_TCTI` / `TCTI` env var, honored so the
     swtpm test harness and operators familiar with tpm2-tools can redirect
     without a config edit.
  3. Built-in default `device:/dev/tpmrm0`.
- The TCTI string is parsed by tss-esapi's `TctiNameConf` (e.g.
  `device:/dev/tpmrm0`, `swtpm:host=...,port=...`, or
  `mssim:host=...,port=...`). The harness uses the swtpm/mssim TCTI on a unix
  socket (§9).

---

## 8. Enrollment flow change + operator UX + failure modes

### 8.1 New `dsm enroll --csr-out` behavior (TPM backend)

1. Preflight: open TCTI, `TPM2_Startup` if needed (swtpm), confirm TPM
   responds. Fail actionably if not (§6.3).
2. Identity: `keystore.generate(passphrase)` — unchanged (X25519, passphrase-
   sealed).
3. Attest: `attest_store.generate(passphrase-noop)` → `TpmAttestKey::generate`
   provisions the in-TPM key, exports SPKI, writes the `DSMT` blob to
   `attest_key_file` (0o600).
4. CSR: `build_csr(cn, noise_static_pub)` signs the PKCS#10 in-TPM (§5.3).
5. Write CSR, print CN + noise_static_pub, instruct operator to walk to CA
   (GUIDE §3c) — unchanged messaging except the passphrase-scope wording.

### 8.2 `--import` (unchanged)

`import_signed_cert` validates chain + binding-extension-matches-identity +
**cert-SPKI-matches-`attest_store.public_spki_der()`** (the in-TPM key's
exported SPKI) + validity window, then writes `cert_file`. Identical logic.

### 8.3 Operator UX deltas

- **One fewer secret to protect.** The passphrase now protects only the
  identity key; the attest key needs no passphrase (empty authValue, §4.5).
  Update GUIDE §3b wording.
- **TPM ownership / auth:** with empty Owner-hierarchy authorization (the
  common default on a freshly-cleared TPM), no owner password is needed. If
  the TPM Owner hierarchy has a non-empty `ownerAuth`, `TPM2_CreatePrimary`
  under Owner requires it. **Decision:** v1 assumes **empty ownerAuth** (the
  default for `swtpm_setup` and most server TPMs that have not been taken
  ownership of by another stack). Document in GUIDE that if ownerAuth is set,
  the operator must clear it or a future version must accept an ownerAuth
  input. **(Reversible; the format/template do not depend on it. Flagged
  §11, Q6.)**
- **/dev/tpmrm0 access:** it is `tss:tss 0660`. The daemon runs as **root**
  (per `deploy/dsm.service`), so it can open it. But least-privilege is
  better: add **supplementary group `tss`** to the service
  (`SupplementaryGroups=tss`) so the daemon accesses the TPM via group
  membership, and document the option to drop from root if other caps allow
  (out of scope to actually de-root here). For `dsm enroll` run interactively
  by the operator, the operator's user must be in group `tss` (or run via
  sudo). GUIDE addition required (§10).

### 8.4 Failure modes (each → a typed, actionable error)

| Condition | Detection | Behavior |
|---|---|---|
| No TPM / TCTI open fails | TCTI connect error at preflight | Refuse enroll/start: "no TPM at <tcti>; check /dev/tpmrm0 and group tss" |
| TPM present, Owner hierarchy has ownerAuth | `TPM2_CreatePrimary` returns `TPM_RC_AUTH_FAIL` (or `BAD_AUTH`) | Refuse: "TPM Owner hierarchy is password-protected; v1 requires empty ownerAuth (clear it or take ownership with empty auth)" |
| `attest_key_file` already exists | existing `enroll.py` check | Refuse (unchanged): re-enroll must be explicit |
| `DSMT` blob present but `TPM2_Load` fails (wrong TPM / corrupt / TPM cleared) | `from_store_blob` load error | Daemon refuses to start: "attest key blob does not load on this TPM (TPM cleared or hardware changed?) — re-enroll" |
| Transient handle slots exhausted | `TPM2_Load`/`CreatePrimary` `TPM_RC_OBJECT_MEMORY` | Flush-and-retry once; else fail with "TPM out of object slots; restart or use /dev/tpmrm0" |
| swtpm not started (tests) | TCTI connect error | Harness fails loudly (no silent fallback to real TPM) |

Critically: **`from_store_blob` failing on a different TPM is the
soft→TPM-binding made concrete** — a blob stolen off one device is useless on
another (residency). That is a feature, surfaced as an actionable error.

---

## 9. swtpm test harness design (hermetic, CI-friendly)

### 9.1 Goals

- **No dependency on the host's real `/dev/tpmrm0`** for the test suite (CI
  may have no physical TPM). Tests run against a **per-test swtpm** instance
  on a unix socket.
- Hermetic: each test spins up its own swtpm with its own state dir, runs
  provision+sign+verify (+ load-after-restart), tears down. Deterministic
  (no network, `tmp_path`-scoped state).

### 9.2 Rust integration test harness (`rust/tuncore/tests/tpm_swtpm.rs`)

Gated `#[cfg(feature = "tpm-attest")]`. A small harness module:

1. Allocate a temp dir (`tempfile`).
2. Launch `swtpm socket --tpmstate dir=<tmp> --ctrl type=unixio,path=<tmp>/ctrl
   --server type=unixio,path=<tmp>/sock --tpm2 --flags not-need-init` as a
   child process (record PID; kill on drop via an RAII guard).
3. Point tss-esapi at it via the **swtpm TCTI**:
   `swtpm:path=<tmp>/sock` (libtss2-tcti-swtpm.so is present), OR the mssim
   TCTI if swtpm is run in mssim mode. (Harness picks the swtpm TCTI; it is
   the modern path and the lib is installed.)
4. `TPM2_Startup(CLEAR)` via the Esys context.
5. Run the test body (provision → sign → verify with `p256`/`ecdsa` crate as
   an independent verifier → reload blob → sign again → verify).
6. RAII guard kills swtpm and removes the temp dir on scope exit, even on
   panic.

Tests to cover (TDD targets — see §13):
- provision → `public_spki_der` parses as a P-256 SPKI.
- sign → verify under the exported SPKI with an **independent** verifier
  (`p256`), proving the TPM signature is valid DER ECDSA-with-SHA256.
- tamper message → verify fails.
- `to_store_blob` → drop → `from_store_blob` → sign → still verifies under
  the **same** SPKI (persistence/residency roundtrip).
- `from_store_blob` of a blob from a *different* swtpm instance → load fails
  (residency: blob is TPM-bound).
- header tamper (bad magic / version / curve) → typed parse error, no TPM
  call.
- `build_csr` → CSR parses, the embedded SPKI matches, the
  `noiseStaticBinding` extension bytes match the soft encoding, and the CSR
  self-signature verifies.
- `zeroize` → accessors fail; idempotent; transient handle flushed (no slot
  leak — a follow-up provision in the same context succeeds).
- sign-msg-size cap parity (1 MiB).

### 9.3 Python-side test harness (`tests/conftest.py` fixture)

A `pytest` fixture `swtpm_tcti` that (only when the installed `tuncore` is the
TPM build) launches swtpm the same way, sets `TPM2TOOLS_TCTI` /
`TCTI`/config so `AttestStore`/`enroll` talk to it, yields, tears down. The
existing soft-backend Python tests run under the soft build and are skipped
under the TPM build (and vice versa) via a marker keyed on
`tuncore.ATTEST_BACKEND_IS_SOFTWARE`. **No existing test file is modified to
pass; new tests are added** (per the project test policy — this design does
not authorize editing existing tests).

### 9.4 CI

Add a `tpm-attest` job to `.github/workflows/ci.yml`: install `swtpm` +
`libtss2-dev`, build `--no-default-features --features tpm-attest`, run the
swtpm integration tests. The existing soft job stays as the
`dev-soft-attest` matrix entry. No real-TPM dependency anywhere in CI.

---

## 10. Operator UX & GUIDE changes (documentation deltas to land with code)

`deploy/GUIDE.txt` needs (do NOT change the CA/CRL workflow — only the attest
provenance and TPM prereqs):

- **§1 (intro):** replace the "hardware binding ... not yet implemented" /
  "treat as a software credential" caveat with: TPM 2.0 key-residency is the
  default; the attest key is non-extractable and TPM-resident.
- **New prerequisite block:** target host needs a TPM 2.0 + `/dev/tpmrm0` +
  `libtss2-esys` (runtime) + `tpm2-tools` (optional, for inspection). swtpm
  is for CI only, not production.
- **§3b (enroll):** passphrase now protects identity only; attest key is
  TPM-resident (no `attest.key` scalar to back up — instead `attest_key_file`
  holds a TPM-bound `DSMT` blob that is useless off this TPM; still back it
  up so a re-enroll is not forced if the file is lost while the TPM persists).
- **`deploy/dsm.service`:** add `SupplementaryGroups=tss` (so the daemon can
  open `/dev/tpmrm0` via group, not only via root); add a `DeviceAllow=
  /dev/tpmrm0 rw` line if `DevicePolicy`/`PrivateDevices` is tightened later
  (note: `PrivateDevices=yes` would hide `/dev/tpmrm0` — must NOT be set, or
  must be paired with an explicit `DeviceAllow`).
- **`config.example.toml`:** document the optional `attest_tpm_tcti` knob
  (default device:/dev/tpmrm0) and note `allow_soft_attest` is now only
  relevant to dev-soft builds.
- **`deploy/openssl-ca.cnf`:** **no change** — the CSR/cert structure is
  identical (same SPKI algorithm, same critical extension), so the CA's
  signing config and the operator's CSR-inspection step are unchanged. (Worth
  an explicit note in the design: the offline CA does not need to know the key
  is TPM-resident; it signs the same CSR shape.)

---

## 11. Risks + open questions for the owner (short — scope is decided)

These are implementation-fork confirmations, not scope reopenings. Each has a
recommended reversible default already chosen so implementation is **not
blocked** waiting on them; they are flagged for a conscious yes/no.

- **Q1 (persistence model):** RESOLVED in design → **context blob (`DSMT`),
  Owner hierarchy, versioned header.** IRREVERSIBLE once a fleet enrolls;
  mitigated by the magic+version header. Recommend the owner explicitly bless
  the format header layout (§4.4) before first enroll on real hardware.
- **Q2 (TCTI config knob):** add optional `attest_tpm_tcti` to `Config`
  (default device:/dev/tpmrm0). Additive/backward-compatible. Recommend yes.
- **Q3 (key authValue):** default **empty** (§4.5). Reversible via a future
  header `auth_kind` byte. Confirm: ship v1 with no attest-key passphrase?
  (Recommended yes — it buys little against root-on-host and simplifies
  non-interactive restarts.)
- **Q4 (PKCS#10 builder dep):** `build_csr` needs a DER/PKCS#10 assembler
  that signs an externally-provided signature. Prefer reusing `picky-asn1`
  (already transitive via tss-esapi) or a hand-rolled assembler over a new
  top-level crate. **Hard stop per CLAUDE.md: no new dependency without
  approval.** Recommend: hand-rolled PKCS#10 (structure is small/fixed) OR
  approve `x509-cert`/`der` if the team prefers a maintained builder.
- **Q5 (`unsendable` on PyAttestKey for TPM):** recommend marking it
  `unsendable` so the Esys context cannot be moved across threads. Reversible.
- **Q6 (empty ownerAuth assumption):** v1 assumes the TPM Owner hierarchy has
  empty auth. Confirm the target fleet's TPMs are not owned by another stack
  with a set ownerAuth (common on shared/enterprise hardware). If they are,
  we need an ownerAuth input (small follow-up; format unaffected).

**None of Q2–Q6 block starting implementation** — they are reversible
defaults. **Q1's format header is the one thing worth an explicit owner ack
before the first real-hardware enroll**, because it is the data-format
commitment.

---

## 12. Migration / coexistence

- **Soft → TPM migration = re-enroll.** A device currently on `dev-soft-attest`
  re-runs `dsm enroll --csr-out` on the TPM build: new in-TPM attest key, new
  SPKI, new CSR, new CA-signed cert. The X25519 identity MAY be preserved
  (it is not TPM-bound) but a clean re-enroll regenerates both — the GUIDE's
  existing "re-enrollment must be explicit (remove the file by hand)" guard
  applies. No in-place blob conversion is possible or desirable (you cannot
  import a software scalar into the TPM as a `fixedTPM` key — that would
  defeat residency).
- **Mixed fleet is a non-issue.** The server allowlist matches on **CN**; the
  cert binds the **attest SPKI**; the verifier
  (`verify_attest_payload`/`cert.py`) does ECDSA verification **agnostic of
  where the private key lives.** A TPM device and a soft device present
  structurally identical certs + binding signatures. The server needs **zero
  changes** to accept both. (Confirmed by reading `attest.py` — step 4 is a
  pure `leaf.public_key.verify(...)`; nothing inspects key provenance.)
- **Server-side verification is backend-agnostic — confirmed.** No server
  code changes are in scope for Phase 3.

---

## 13. Suggested ordered task breakdown (for the TDD plan)

Ordered so each step is independently testable against swtpm and the soft
backend never regresses. TDD: write the failing test first at each step.

1. **Cargo wiring + build proof.** Add `tss-esapi = "7.7.0"` (optional),
   `tpm-attest = ["dep:tss-esapi"]`, keep `default = ["dev-soft-attest"]`
   *temporarily* so the soft suite stays green. Prove `cargo build
   --no-default-features --features tpm-attest` links libtss2 (pregenerated
   bindings, pkg-config). No behavior yet — just the link.
2. **swtpm harness (Rust).** `tests/tpm_swtpm.rs` RAII swtpm launcher +
   `TPM2_Startup`. A trivial `GetCapability`/`GetRandom` test proves the
   Esys-context-over-swtpm plumbing before any DSM logic.
3. **Versioned `DSMT` format (pure, TPM-free).** Header
   serialize/parse/validate with magic+version+kind+curve, reject-unknown
   tests. No TPM needed — fast unit tests.
4. **`TpmAttestKey::generate` + `public_spki_der`.** Deterministic primary +
   `TPM2_Create` sign-only `fixedTPM|fixedParent` P-256 + export SPKI. Test:
   SPKI parses as P-256.
5. **`sign` + independent verify.** `TPM2_Sign` → DER ECDSA; verify with the
   `p256` crate. Tamper test. Msg-size-cap parity.
6. **`to_store_blob` / `from_store_blob` roundtrip + residency.** Persist,
   drop, reload, sign-still-verifies; cross-instance load fails.
7. **`build_csr` in-TPM.** Hand-rolled (or approved-crate) PKCS#10 signed in
   TPM; CSR parses, SPKI + `noiseStaticBinding` bytes match soft encoding,
   self-sig verifies. (Resolve Q4 before this step.)
8. **`zeroize` + handle-flush.** Accessors fail post-zeroize; no transient
   slot leak; idempotent.
9. **FFI shim.** `encrypt_to_store`/`decrypt_from_store` no-op-passphrase
   forwarders so `lib.rs`/`PyAttestKey` need no change; optional `unsendable`
   (Q5).
10. **Python `AttestStore` backend-aware passphrase + enroll preflight.**
    Backend detection helper; TPM passes `b""`; enroll-time TPM preflight with
    actionable errors. New Python tests under a swtpm fixture.
11. **Flip the default + CI.** `default = ["tpm-attest"]`; add the
    `tpm-attest` CI job (swtpm); confirm `ATTEST_BACKEND_IS_SOFTWARE=false`
    flows to `attest_gate` as a pass. Keep the `dev-soft-attest` CI job.
12. **Docs.** GUIDE / dsm.service (`SupplementaryGroups=tss`) /
    config.example.toml / README; note openssl-ca.cnf unchanged.

---

## 14. Security properties checklist (Phase 3 security lens)

- **Untrusted input entry points:** the `DSMT` blob on disk (parsed before
  any TPM call; `TPM2_Load` HMAC is the integrity check); `msg` into `sign`
  (1 MiB cap, parity with soft); `cn`/`noise_static_pub` into `build_csr`
  (length-checked, byte-identical encoding to soft). No new network input.
- **AuthN/Z boundaries:** TPM Owner hierarchy auth (assumed empty, §8.3);
  `/dev/tpmrm0` perms (group `tss`); file perms on `attest_key_file`
  (existing 0o600 + `check_user_file_permissions`).
- **Sensitive data crossing boundaries:** **none new** — the private scalar
  never crosses the FFI (it never leaves the TPM). The SPKI (public) and DER
  signatures (public) cross, as today. The `DSMT` blob is non-secret
  (TPM-encrypted sensitive area). This is a **net reduction** in secret
  surface vs the soft backend (no extractable scalar in memory).
- **Key material handling:** `TPM2_Sign` in-TPM; no zeroization needed for a
  key that is never in host memory; transient *handles* are flushed (slot
  hygiene, not a secrecy issue). Any transient host-side buffers (marshalled
  TPM2B structures, the SHA-256 digest) are non-secret.
  → **security agent review recommended** for: the exact `TPMA_OBJECT`
  attribute bitmask on the child template (must be `sign |
  fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth`, with
  `restricted`/`decrypt`/`encryptedDuplication` clear), and the deterministic-
  primary template (must not accidentally make the child importable). A
  mis-set attribute is the one way to silently lose the residency guarantee.
- **Blast radius if host root is compromised:** attacker can request
  signatures while the TPM is accessible (same as any local signing oracle)
  but **cannot extract the key** — so post-compromise the key cannot be
  exfiltrated and used elsewhere; CRL-revoke + re-enroll on new hardware
  recovers. With the soft backend, root compromise = key exfiltration. This
  is the core upgrade.
- **TOCTOU/races:** `from_store_blob` reads the file once
  (`check_user_file_permissions` then read); single-owner `AttestKey` (no
  concurrent `sign`). No new race surface.
- **Determinism / nonce safety of the ECDSA signature:** the **TPM** chooses
  the per-signature ECDSA nonce `k` from its internal hardware RNG inside
  `TPM2_Sign`. This is **not** the catastrophic `k`-reuse risk — a hardware
  RNG `k` is exactly what FIPS-186 ECDSA specifies; the danger is *repeated*
  or *low-entropy* `k`, which a conformant TPM does not produce. (The soft
  backend used RFC-6979 deterministic `k`; the TPM uses random `k`. Both are
  safe. The verifier does not care which — it is plain ECDSA verification.)
  Confirmed: no `k`-reuse exposure.

---

## 15. Implementer instructions (hand-off)

- **Implement** `rust/tuncore/src/device_attest_tpm.rs` exposing the §5.1
  surface + the §5.2 no-op-passphrase shim. Re-export as `AttestKey` under
  `#[cfg(feature = "tpm-attest")]` in `device_attest.rs`. Do **not** touch the
  `compile_error!` guard logic (already correct).
- **Templates are load-bearing:** child = `sign | fixedTPM | fixedParent |
  sensitiveDataOrigin | userWithAuth`, ECDSA-SHA256, P-256, `restricted` and
  `decrypt` CLEAR. Parent = `restricted | decrypt | fixedTPM | fixedParent |
  sensitiveDataOrigin | userWithAuth`, ECC P-256, AES-128-CFB, empty auth,
  deterministic template. **Get these reviewed by the security agent.**
- **Format:** `DSMT` magic + version `0x01` + hierarchy/kind/curve bytes +
  length-prefixed `TPM2B_PUBLIC`/`TPM2B_PRIVATE` (§4.4). Reject unknown
  header bytes with a typed error *before* any TPM call. Mirror the Phase-0
  `passphrase_store` versioning discipline.
- **Do NOT** implement `private_pkcs8_der` on the TPM backend, and do **not**
  add any code path that exports the private scalar. That is the residency
  invariant.
- **Do NOT** modify the cert flow (`attest.py`, `cert.py`), the binding
  signature shape, the protocol, or any existing test file. New tests only.
- **TCTI:** default `device:/dev/tpmrm0`; honor `attest_tpm_tcti` config
  (Q2) and `TPM2TOOLS_TCTI`/`TCTI` env (for swtpm). Never silently fall back
  from a configured TCTI to a different TPM.
- **Resolve Q4 (PKCS#10 builder dependency) with the owner before step 7** —
  it is a hard-stop dependency decision.
- **Error mapping:** map tss-esapi `Error`/`ReturnCode` into the crate's
  `Result<_, String>` convention with actionable messages (§8.4); no
  `unwrap`/`expect` outside tests (clippy `unwrap_used` is `-W`); never leak
  raw TPM internal state into the message beyond the return code name.

---

## 16. Status

**COMPLETE** — design fully specified. Implementation is unblocked on
reversible defaults (Q2, Q3, Q5, Q6). One hard-stop confirmation needed
before the relevant step: **Q4 (PKCS#10 builder dependency)** before task 7.
One recommended explicit owner ack before first real-hardware enroll: **Q1
(the `DSMT` format header + Owner hierarchy + context-blob model)** — the
single IRREVERSIBLE data-format commitment.
