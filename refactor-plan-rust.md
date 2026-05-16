# Rust Refactor Plan — DSM_V2.0 / tuncore

Scope: every `.rs` file under `rust/tuncore/src/` plus `Cargo.toml`.
Out of scope: `dsm/`, `tests/`, `deploy/`, `backup/`.

All proposed changes are **behavior-preserving** and do **not** alter the
PyO3 surface listed in `lib.rs`'s `#[pymodule]` block. Anything that
*would* alter the PyO3 boundary is recorded under "Out of scope" only.

## Summary

- HIGH severity: 3 items
- MEDIUM severity: 7 items
- LOW (cosmetic / clippy-style): 12 items

Totals after sweep: 22 actionable items. 8 additional concerns flagged
under "Out of scope" (bugs, security questions, audit-locked surfaces).

## Out of scope (flagging only — bugs / security / API)

The refactor agent does NOT propose changes for any of these. They are
recorded so the maintainer can decide separately whether to file a
bugfix, security, or feature task.

1. **`secure_memory.rs:128` — `as_mut` shadows `AsMut::as_mut`.** Clippy
   default (`clippy::should_implement_trait`) flags
   `LockedKey32::as_mut(&mut self) -> &mut [u8; 32]` as confusable with
   the standard `AsMut` trait method. Renaming would ripple through
   roughly a dozen call sites in `identity.rs`, `aes_gcm.rs`,
   `session_keys.rs`, `secure_noise.rs`, `passphrase_store.rs`. The
   internal API is consistent and audit-locked; flagging here for a
   future API-cleanup task, not as a refactor candidate.

2. **`secure_memory.rs:125,129` — `&**self.bytes` / `&mut **self.bytes`.**
   Clippy's `explicit_auto_deref` would let the double-deref collapse
   to `&self.bytes` / `&mut self.bytes`. The explicit form is **load-
   bearing for the security invariant**: it documents that the locked
   page is reached through `Box<Zeroizing<[u8; 32]>>`. Auto-deref
   produces a `&Box<Zeroizing<[u8; 32]>>` instead of a `&[u8; 32]`,
   which would force every caller to add a `.deref()` chain anyway and
   would obscure the "key bytes live at this exact heap address" intent
   that the audit pin requires. **DO NOT change.**

3. **`device_attest_soft.rs:75 (`zeroize`)` — replacement key generation
   on zeroize.** The replacement `SigningKey::random(&mut OsRng)` is
   never used to sign anything that verifies under the original SPKI,
   but generating a fresh ECDSA P-256 key on `zeroize()` is non-obvious
   overhead, and a future maintainer may wonder why we burn entropy on
   the destruction path. The doc-comment explains it, but the design
   could probably be replaced with a sentinel "tombstone" pattern. Not
   a refactor — it is an API/design question for the security
   reviewer.

4. **`secure_noise.rs:122–134` — `Dh::set` poisoning semantics.**
   The `Dh` trait has no `Result` channel, so `set` poisons on
   wrong-length input. This is correct, but `secure_noise.rs:319`'s
   test shows poisoning is sticky even after a follow-up valid `set`,
   which differs from snow's documented contract. Flagging for security
   review, not a refactor.

5. **`nonce.rs:39 (`next`)` — `Ordering::SeqCst` on every atomic op.**
   The CAS loop uses `SeqCst` for all five atomic operations on
   `counter` and `exhausted`. A `Release`/`Acquire` mix would likely be
   sufficient for the producer/observer relationship the doc-comment
   describes. This is a **performance** question, not refactoring —
   route to performance-systems with a measured baseline. Do NOT
   weaken memory ordering on a security-critical nonce counter without
   formal review.

6. **`lib.rs:213, 274` — `fn into_transport(&mut self)` takes `&mut self`
   rather than `self`.** Clippy default warns this is the wrong
   self-convention for `into_*`. The signature is forced by PyO3:
   `#[pymethods]` cannot consume `self`. **API-bound — flag, don't
   touch.**

7. **`session_keys.rs:34` — `clamp_base` uses `.min().max()` rather
   than `.clamp()`.** Switching to `.clamp(1, ROTATION_BASE_MAX)` is
   the clippy default recommendation; **clamp panics if `max < min`**,
   which is never the case here, so the safety profile is identical.
   Listed under LOW below — but flagging here too because `.clamp()`
   has a panic path that `.min().max()` does not, and on a
   security-critical hot path I would prefer the panic-free form
   unless the maintainer specifies otherwise.

8. **`lib.rs:610` — `PyBootstrapEphemeral::generate` allocates a
   transient `StaticSecret` on the stack.** Code comment in `identity.rs`
   `derive_static_pub` already discusses this leak-window. The same
   pattern recurs here. Possibly a security task to consolidate the
   stack-copy minimization into a single helper. Not a refactor.

---

## HIGH-impact refactors

### 1. Deduplicate `from_handshake_hash` / `from_bootstrap_shared_secret` in `session_keys.rs`

- **File:** `rust/tuncore/src/session_keys.rs:177-209` and `:228-262`
- **Change:** The two constructors are 85% identical:
  - both build an `Hkdf::<Sha256>` keyed by different salts,
  - both expand two 32-byte session keys into mlock'd `LockedKey32`,
  - both expand a 4-byte epoch and mask to 28 bits,
  - both run the identical send/recv swap based on `is_initiator`,
  - both delegate to `Self::new`.

  Extract a private helper:
  ```
  fn from_hkdf(
      hk: Hkdf<Sha256>,
      send_label: &[u8],
      recv_label: &[u8],
      epoch_label: &[u8],
      is_initiator: bool,
      rotation_packets: Option<u64>,
      rotation_seconds: Option<u64>,
  ) -> Result<Self, String>
  ```
  Both constructors then become a 3-line caller that builds the `Hkdf`
  with its specific salt + IKM and forwards. The salts (`b"dsm-v2-session-init"`
  vs `b"dsm-v2-bootstrap-hkdf"`) and labels (`b"dsm-session-initiator"` /
  `b"dsm-session-responder"` / `b"dsm-session-epoch"` vs
  `b"dsm-bootstrap-initiator-send"` / `b"dsm-bootstrap-responder-send"` /
  `b"dsm-bootstrap-epoch"`) remain caller-supplied, so on-wire-derived
  keys are byte-identical to before.

- **Why:** Removes ~40 lines of duplicated key-derivation logic; future
  audits of the HKDF schedule only have to read one function. The two
  callers' security invariants — different salts (domain separation),
  different IKM source (transcript hash vs DH output) — remain caller-
  visible in the construction.
- **Behavior preserved:** Labels and salts are pulled from each caller
  unchanged; identical HKDF output bytes; the `#[cfg(test)]` gate on
  `from_handshake_hash` remains; the `pub(crate)` visibility on both
  remains.
- **Tests affected:** `mod tests::test_from_handshake_hash_roundtrip`,
  `test_from_handshake_hash_rotation`,
  `test_from_bootstrap_shared_secret_requires_32_bytes` (all in
  `session_keys.rs`); `test_handshake_hash_to_session_keys` in
  `noise_xx.rs:811`. No test changes required.

### 2. Collapse `complete_rotation_responder` into a thin wrapper

- **File:** `rust/tuncore/src/session_keys.rs:386-401`
- **Change:** The single-shot `complete_rotation_responder` already
  delegates to `prepare_rotation_responder` + `apply_rotation_responder`
  internally; the body is 5 lines wrapping the two-phase pair. After
  HIGH-1 above lands the pattern is even more obvious. Keep the public
  signature but make the body literally `let p = self.prepare(...)?; let
  pub = p.our_pub; let c = self.apply(p)?; Ok((pub, c))`. (This is what
  is already done — the refactor here is to add a `#[inline]` and a
  comment explaining the wrapper is only kept for the unit-test API,
  not because it has independent logic.) Then audit whether the
  single-shot variant has any production caller; if it does not (it
  does not — `lib.rs:409–420` is the only Python-facing wrapper, and
  that wrapper itself only forwards to the same single-shot), consider
  removing the single-shot variant entirely in a follow-up — **but
  that would be a public-API change on the Rust side, so flag and
  defer.** This item is the inline-and-comment refactor only.
- **Why:** The single-shot exists for test convenience but is now
  three lines of glue around two methods that do the real work; a
  reader currently has to follow four function calls (`PySessionKeyManager::complete_rotation_responder`
  → `SessionKeyManager::complete_rotation_responder` →
  `prepare_rotation_responder` → `apply_rotation_responder`). The
  inline comment makes that explicit.
- **Behavior preserved:** Body is already a thin wrapper; this change
  is purely a doc-comment + `#[inline]` hint. Output keys are
  byte-identical.
- **Tests affected:** `mod tests::test_key_rotation_flow`,
  `test_grace_period_accepts_old_epoch`, `test_from_handshake_hash_rotation`,
  `test_rotation_rejects_low_order_pub`, `test_wrong_epoch_rejected`
  (all in `session_keys.rs`). No test changes required.

### 3. Extract `NoiseInitiator::new` / `NoiseResponder::new` shared builder in `noise_xx.rs`

- **File:** `rust/tuncore/src/noise_xx.rs:159-170` and `:274-285`
- **Change:** The two constructors are 95% identical:
  - both call `Builder::with_resolver(NOISE_PATTERN.parse()?, Box::new(SecureResolver::new()))`,
  - both `.local_private_key(static_secret)`,
  - both `.prologue(PROLOGUE)`,
  - they diverge only on the final `.build_initiator()` vs `.build_responder()`.

  Extract a private helper:
  ```
  fn build_handshake_state(
      static_secret: &[u8; 32],
      build: impl FnOnce(Builder<'_>) -> Result<HandshakeState, snow::Error>,
  ) -> Result<HandshakeState, String>
  ```
  `NoiseInitiator::new` calls it with `|b| b.build_initiator()` and
  `NoiseResponder::new` with `|b| b.build_responder()`. Both error
  formatters (`"build initiator"` / `"build responder"`) can stay as
  context strings the helper appends.

  Alternative if the closure pollutes lifetimes: extract a struct
  `pub(super) struct NoiseBuilder` that holds the partially-built
  state and exposes two `.finalize_*()` methods.

- **Why:** ~12 lines of duplicate setup code; future changes to the
  prologue, pattern, or resolver only have to be made once. Audit M2's
  custom resolver invariant becomes load-bearing in one place rather
  than two.
- **Behavior preserved:** Identical pattern parse, identical resolver
  instance, identical prologue, identical local-private-key call. The
  only thing that changes is the build call, which is passed in.
- **Tests affected:** `mod tests::test_full_handshake`,
  `test_all_messages_same_size`, `test_attest_payload_wrong_size_rejected`,
  `test_attest_payload_roundtrips_byte_for_byte`,
  `test_transport_tampered_ciphertext_fails`,
  `test_multiple_transport_messages`,
  `test_handshake_rejects_low_order_ephemeral_in_msg1`,
  `test_handshake_rejects_short_frame`,
  `test_handshake_rejects_long_frame`,
  `test_handshake_tampered_msg2_fails`,
  `fuzz_handshake_state_machine_no_panic_on_random_bytes`,
  `fuzz_handshake_wrong_order_no_panic`,
  `fuzz_replay_handshake_message_no_panic`,
  `test_handshake_hash_to_session_keys` (all in `noise_xx.rs`).
  Many of these go through `do_handshake` which exercises both
  constructors. No test changes required.

---

## MEDIUM-impact refactors

### 4. Remove unnecessary `Result` from `IdentityKeyPair::from_locked` and `AesKey::from_locked`

- **File:** `rust/tuncore/src/identity.rs:65-68` and
  `rust/tuncore/src/aes_gcm.rs:18-20`
- **Change:** Both `from_locked` methods take a `LockedKey32` by value
  and unconditionally return `Ok(Self { ... })`. There is no fallible
  operation in the body. Drop the `Result<Self, String>` return type
  and the `Ok(...)` wrap. Clippy's `unnecessary_wraps` flags both.

  Internal call sites that need updating:
  - `identity.rs:144` (`Self::from_locked(secret)` at the end of
    `decrypt_from_store`) — drop the `?`.
  - `aes_gcm.rs:26` (`AesKey::from_locked(...)` inside `from_array`) —
    drop the `?` and the outer `Ok(...)` adapts.
  - `session_keys.rs:73` (`DirectionKeys::new` → `AesKey::from_locked(key)?`)
    — drop the `?`. `DirectionKeys::new` itself has no other fallible
    operation, so the function becomes `pub fn new(key: LockedKey32,
    epoch: u32) -> Self` and the callers at `:278, :279, :448, :449`
    drop their `?`s.
- **Why:** Removes a vestigial `Result` from three layers of API. The
  closest fallible operation is `LockedKey32::zeroed()` which already
  happens before any of these calls. Caller error-handling currently
  has to thread a `Result` through what is actually infallible code.
- **Behavior preserved:** All call sites currently propagate the `Ok`
  case with `?` and never observe an `Err`. Removing the `Result`
  changes no observable behavior.
- **Tests affected:** Indirectly all tests that build a
  `SessionKeyManager`, an `AesKey`, or an `IdentityKeyPair` (~30 tests
  across `aes_gcm.rs`, `identity.rs`, `session_keys.rs`). No test
  changes required — `.unwrap()` still works on the new infallible
  return, and direct `let x = Foo::new(...)` still compiles.
- **Note:** This is also propagated by clippy `unnecessary_wraps` for
  `DirectionKeys::new` (line 71) — propagating the change is what
  unblocks that warning too.

### 5. Hoist `LockedKey32::zeroed() + OsRng.fill_bytes(...)` into a shared helper

- **File:** Three call sites:
  - `rust/tuncore/src/identity.rs:56-61` (in `IdentityKeyPair::generate`)
  - `rust/tuncore/src/session_keys.rs:82-85` (in `gen_ephemeral_secret`)
  - `rust/tuncore/src/secure_noise.rs:137-138` (in `SecureDh25519::generate`,
    which delegates to the snow-supplied RNG, so it's not OsRng — leave
    that one alone).

  The first two are byte-identical:
  ```
  let mut k = LockedKey32::zeroed()?;
  OsRng.fill_bytes(k.as_mut());
  Ok(k)  // or `Ok(Self { ... })` adapting
  ```

  **Change:** Add a `secure_memory::random_locked_key32() -> Result<LockedKey32, String>`
  helper. Replace `IdentityKeyPair::generate`'s body's first two lines
  with a single call. Replace `gen_ephemeral_secret`'s entire body
  with a single call (or make `gen_ephemeral_secret` an alias).
- **Why:** Eliminates a duplicate "allocate-mlocked-then-fill" idiom
  that is security-relevant (it is the *only* path that writes a fresh
  scalar directly into mlock'd memory without a stack copy). Putting
  this in one helper means an audit reviewer reads the pattern once.
  The helper sits next to `LockedKey32` definitions where the
  invariants are documented.
- **Behavior preserved:** The byte-pattern of the produced key
  (`OsRng.fill_bytes` over a mlock'd 32-byte buffer) is identical;
  errors propagate the same way.
- **Tests affected:** `identity.rs::test_generate_keypair`,
  `test_public_key_derives_from_secret`, every test that calls
  `IdentityKeyPair::generate()` (~12 in `identity.rs`);
  `session_keys.rs::test_key_rotation_flow`,
  `test_grace_period_accepts_old_epoch`, every test that triggers
  rotation (uses `gen_ephemeral_secret` via `initiate_rotation`).
  No test changes required.

### 6. Remove redundant `expect()` / `Ok()` adapter in `lib.rs::PyAttestKey::public_spki_der`

- **File:** `rust/tuncore/src/lib.rs:526-528`
- **Change:** `public_spki_der(&self) -> Vec<u8> { self.inner.public_spki_der().to_vec() }`
  is fine, but the matching code in `device_attest_soft.rs:52` returns
  `&[u8]`. The `.to_vec()` here copies the SPKI into a fresh `Vec<u8>`
  for PyO3 to convert into Python `bytes`. This pattern is present
  also at `lib.rs:73` (`IdentityKeyPair.public_key`). Both are correct.

  The actual refactor: at `lib.rs:73`, `public_key()` calls
  `self.inner.public_key().to_vec()`. The inner method returns
  `&[u8; 32]`. PyO3 accepts `[u8; 32]` by value via `IntoPy<PyAny>`
  for fixed-size arrays in 0.24 — but **flagging only**: switching to
  `[u8; 32]` may change the Python type from `bytes` to a different
  view. **Do NOT change** unless the PyO3 surface invariant in the
  task says otherwise. Treat this as a no-op item; struck from the
  refactor list. **Demoted to "Out of scope".**

  Replacement MEDIUM item with the same numbering: **Use
  `bool::then_some` / `?` chain in `complete_bootstrap`'s consume-once
  guard.** Skipped — `.ok_or_else(|| py_err(...))?` is already
  idiomatic and the most precise. **No change proposed.** Skip slot.

- **Resolution:** This MEDIUM slot is dropped. Numbering continues at
  MEDIUM-7. Documenting the dropped item explicitly so a re-read
  matches the count.

### 7. Replace `let _ = munlock_slice(...)` with `.ok()` and a comment

- **File:** `rust/tuncore/src/secure_memory.rs:137`
- **Change:** `let _ = munlock_slice(&**self.bytes);` discards the
  `Result` silently. The current behavior is correct — `Drop` cannot
  propagate errors and a failure to munlock during teardown is not
  recoverable — but clippy default's `let_underscore_drop` /
  `must_use` family considers `let _` slightly opaque. Change to
  `munlock_slice(&**self.bytes).ok();` (no behavior change) and add
  a one-line comment: `// munlock failure during teardown is
  unrecoverable; kernel will clean the mapping on process exit.`
- **Why:** The discard becomes intentional in the type system (`.ok()`
  is the canonical "I know this returns Result, I'm choosing to drop
  the error"). Defensive comment makes the security implication
  explicit.
- **Behavior preserved:** `let _ = expr;` and `expr.ok();` produce
  identical machine code for `Result<(), _>`.
- **Tests affected:** `secure_memory.rs::test_mlock_munlock_roundtrip`.
  No test changes required.

### 8. Tighten `pack_handshake` / `unpack_handshake` lifetime annotation

- **File:** `rust/tuncore/src/noise_xx.rs:122`
- **Change:** Clippy default flags
  `fn unpack_handshake<'a>(buf: &'a [u8], expected_len: usize) -> Result<&'a [u8], String>`
  for needless lifetime annotation. Replace with
  `fn unpack_handshake(buf: &[u8], expected_len: usize) -> Result<&[u8], String>`.
  Lifetime elision rules produce the same bound (input lifetime ties
  to output lifetime when there is exactly one input reference).
- **Why:** Strictly cosmetic, but it is a clippy warning at the
  *default* level (not pedantic) so it is fair game for cleanup.
- **Behavior preserved:** Lifetime elision and explicit annotation
  produce the same generated borrow checker constraints; no machine
  code or semantic change.
- **Tests affected:** `noise_xx.rs::unpack_handshake_random_lengths_never_panic`,
  `unpack_handshake_random_byte_content_never_panic`, and every test
  that goes through the wire-frame readers (~14 tests). No test
  changes required.

### 9. Combine the two `compare_exchange` retry branches in `NonceGenerator::next`

- **File:** `rust/tuncore/src/nonce.rs:53-69`
- **Change:** The CAS loop body has a defensive double check —
  `loop { load(); check exhausted; check current ∈ {0, MAX}; cas; on
  fail re-load }`. Inside the failure arm there is a second
  `self.exhausted.load(Ordering::SeqCst)` check. That re-check is
  redundant: the next iteration's `loop` head will re-load
  `self.exhausted` anyway. Drop the inner `if self.exhausted.load(...)
  { return None; }` and rely on the top-of-loop check.

  *Wait — re-reading:* this is **subtly load-bearing for the security
  invariant.** The original committer's intent is that under wrap
  contention, a thread that lost the CAS race because another thread
  just transitioned to exhausted MUST return None immediately rather
  than re-enter the loop and possibly observe a non-exhausted state if
  the latching write hasn't propagated. With SeqCst on all the
  atomics, the propagation guarantee is total ordering — so the inner
  check is redundant under the current ordering. But the safety margin
  is "if anyone ever weakens the ordering" (see Out-of-scope #5).

  **Recommendation: do not drop the check.** Move it into a `// belt
  and suspenders` comment instead. The actual refactor here is the
  comment, not the code. Listed as MEDIUM-9 because the
  inadvertent removal would be a security bug. Documenting why the
  apparently-redundant check is there protects against a future
  cleanup pass that does drop it.

- **Why:** Code is correct but the structure invites a future
  "simplification" PR that breaks the assumption. A comment converts
  tribal knowledge into source-code knowledge.
- **Behavior preserved:** No code change.
- **Tests affected:** `nonce.rs::test_concurrent_wrap_no_nonce_reuse`,
  `test_property_no_duplicate_counts_under_contention`,
  `test_property_random_starting_state_no_reuse`,
  `test_exhaustion_is_sticky_no_nonce_reuse`. No test changes required.

### 10. Deduplicate the `is_initiator` send/recv swap in two constructors

- **File:** `rust/tuncore/src/session_keys.rs:202-206` and `:255-259`
- **Change:** Both blocks are identical:
  ```
  let (send_key, recv_key) = if is_initiator {
      (key_a, key_b)
  } else {
      (key_b, key_a)
  };
  ```
  After HIGH-1 lands, this swap is naturally part of the shared
  helper. If HIGH-1 is NOT taken, factor it out separately into:
  ```
  fn swap_on_initiator(a: T, b: T, is_initiator: bool) -> (T, T) {
      if is_initiator { (a, b) } else { (b, a) }
  }
  ```
  generic over `T: Sized`. Both call sites become one line.
- **Why:** Removes a 5-line duplicate. The naming `swap_on_initiator`
  makes the cryptographic semantics (which side sends with which
  HKDF-expanded key) obvious from the call site.
- **Behavior preserved:** Output tuple is byte-identical.
- **Tests affected:** Same set as HIGH-1.
- **Note:** **Subsumed by HIGH-1** if that lands; keep this as a
  separate item only if HIGH-1 is rejected.

---

## LOW / cosmetic / clippy-style

### 11. Doc-comment backtick fixes (clippy `doc_markdown`, pedantic only)

- **File:** `rust/tuncore/src/lib.rs:21, 28, 182, 197, 206, 227, 259, 267, 288, 374, 404, 408, 424, 426, 525, 551` (and several more in `device_attest_soft.rs`, `session_keys.rs`).
- **Change:** Wrap identifiers in `\`backticks\`` per clippy's
  `doc_markdown` pedantic lint. Items: `PyErr`, `PyRuntimeError`,
  `PyIdentityKeyPair`, `HANDSHAKE_ATTEST_PAYLOAD_SIZE`,
  `into_transport()`, `new_epoch`, `ephemeral_pub`, `our_ephemeral_pub`,
  `REKEY_ACK`, `SubjectPublicKeyInfo`, `CommonName`, `NonZeroScalar`,
  `ZeroizeOnDrop`, `PyAttestKey`, `initiator_send_key`,
  `initiator_recv_key`.
- **Why:** Cosmetic. Tooling renders identifiers correctly in
  `cargo doc`. Pedantic-level lint; project does not currently fail
  on pedantic.
- **Behavior preserved:** Comments only.
- **Tests affected:** None.
- **Note:** This is a **single sweep** rather than per-line. Recommend
  doing all 30+ doc-markdown items in one commit so the diff is
  reviewable as a single category. Skip if maintainer does not want
  to enable pedantic checks.

### 12. Replace `as u8` truncation with `u8::try_from(...).unwrap()` (or `_ as u8` allow)

- **File:** `rust/tuncore/src/device_attest_soft.rs:157`
  (`ext_value.push(noise_static_pub.len() as u8);`) and two test sites
  `rust/tuncore/src/noise_xx.rs:539, :547`.
- **Change:** Production site at `device_attest_soft.rs:157` already
  has an explicit length check `noise_static_pub.len() != 32` at line
  135–140, so the cast is guaranteed safe. Either:
  - (a) leave the cast and add `#[allow(clippy::cast_possible_truncation)]`
    with a comment pointing to the bounds check above, OR
  - (b) replace with `u8::try_from(noise_static_pub.len()).expect("len already bounded to 32")`.
  Recommend (a) — adds clarity without introducing an `.expect()`
  panic path.

  Test sites (`(i & 0xFF) as u8`) are intentional byte-pattern
  generators where truncation IS the intent; mark with
  `#[allow(clippy::cast_possible_truncation)]` at the test level.
- **Why:** Silences pedantic-level lint without losing safety.
- **Behavior preserved:** Allow attribute is metadata only.
- **Tests affected:** `device_attest_soft.rs::encrypt_decrypt_roundtrip`
  and similar (no change); `noise_xx.rs::test_attest_payload_roundtrips_byte_for_byte`
  (no change).

### 13. Replace `999999` with `999_999` (clippy `unreadable_literal`, pedantic)

- **File:** `rust/tuncore/src/replay_window.rs:166-167`
- **Change:** Add underscores per Rust style.
- **Why:** Readability.
- **Behavior preserved:** Identical literal value.
- **Tests affected:** `test_first_packet_any_value`. No test changes.

### 14. Replace `1..(10_000 - ReplayWindow::WINDOW_SIZE + 1)` with `1..=(...)` (clippy `range_plus_one`, pedantic)

- **File:** `rust/tuncore/src/replay_window.rs:240`
- **Change:** Use inclusive range.
- **Why:** Idiomatic Rust.
- **Behavior preserved:** Same iteration set.
- **Tests affected:** `property_too_old_seqs_always_rejected`. No
  test changes.

### 15. Add semicolon to `self.inner.update(seq)` in PyO3 wrapper (clippy `semicolon_if_nothing_returned`, pedantic)

- **File:** `rust/tuncore/src/lib.rs:132`
- **Change:** `self.inner.update(seq)` → `self.inner.update(seq);`
  (the method returns `()` so the trailing-expression form is
  technically equivalent but stylistically inconsistent with the rest
  of the file).
- **Why:** Cosmetic consistency.
- **Behavior preserved:** Identical (last expression `()` and
  semicolon-statement `()` are the same).
- **Tests affected:** None.

### 16. Apply `#[must_use]` attribute to pure getters returning non-`()` (clippy `must_use_candidate`, pedantic)

- **File:** `rust/tuncore/src/device_attest_soft.rs:52` (`public_spki_der`),
  plus `replay_window.rs:84` (`max_seq`), `nonce.rs:81, 85`
  (`count`, `epoch`), etc.
- **Change:** Add `#[must_use]` so the compiler warns when the caller
  drops the returned value.
- **Why:** Most are pure getters; ignoring their return is almost
  certainly a bug.
- **Behavior preserved:** Attribute is metadata; no codegen impact.
- **Tests affected:** None at call sites that actually use the return.
- **Note:** Sweep, like LOW-11. Pick a consistent set and apply
  everywhere in one diff.

### 17. `#[allow(clippy::manual_clamp)]` on `clamp_base` or switch to `.clamp(1, ROTATION_BASE_MAX)`

- **File:** `rust/tuncore/src/session_keys.rs:34`
- **Change:** Option A — switch to `base.clamp(1, ROTATION_BASE_MAX)`.
  Option B — add `#[allow(clippy::manual_clamp)]` with a comment that
  `.min().max()` avoids the panic path that `.clamp` has if `max < min`.
  See Out-of-scope #7. Recommend B — keep the explicit form on the
  security-critical path. **Refactor item is the allow attribute +
  comment.**
- **Why:** Silences default-level clippy warning without weakening the
  panic-free guarantee.
- **Behavior preserved:** No code change.
- **Tests affected:** `test_needs_rotation_by_packets`. No test
  changes.

### 18. Use `std::mem::take` instead of `std::mem::replace(.., ReplayWindow::new())` (clippy default)

- **File:** `rust/tuncore/src/session_keys.rs:453`
- **Change:** `ReplayWindow` has a `Default` impl that defers to `new()`.
  Replace `std::mem::replace(&mut self.replay, ReplayWindow::new())`
  with `std::mem::take(&mut self.replay)`.
- **Why:** Slightly more idiomatic; one less explicit allocation
  expression in the rotation hot path.
- **Behavior preserved:** `Default::default()` for `ReplayWindow`
  produces exactly `Self::new()` (see `replay_window.rs:89-93`).
- **Tests affected:** `test_key_rotation_flow`,
  `test_grace_period_accepts_old_epoch`, `test_from_handshake_hash_rotation`.
  No test changes.

### 19. Drop `unused_import` warnings in `secure_memory.rs:74`

- **File:** `rust/tuncore/src/secure_memory.rs:74`
- **Change:** `secure_zero` does `use zeroize::Zeroize;` inside the
  function body even though the top of the file already has
  `use zeroize::Zeroizing;`. The function-local `use` is fine but
  could move to module-level to match the rest of the file. Recommend
  no change unless project style guide prefers function-local imports
  for unused-elsewhere cases.
- **Why:** Tiny consistency cleanup.
- **Behavior preserved:** Identical.
- **Tests affected:** `test_secure_zero`. No changes.
- **Status:** Marginal — recommend SKIP. Listed for completeness.

### 20. `Default` derivation for `NoiseTransport`

- **File:** `rust/tuncore/src/noise_xx.rs:148-150`
- **Status:** **NOT a refactor candidate.** `NoiseTransport` owns a
  `TransportState` which is not `Default` — no change possible. Listed
  to document the deliberate omission so a future clippy sweep
  doesn't flag it as missing.

### 21. Compact `epoch_bytes` derivation in `from_handshake_hash` / `from_bootstrap_shared_secret`

- **File:** `rust/tuncore/src/session_keys.rs:194-200, :250-253`
- **Change:** Both blocks materialize a 4-byte buffer, expand HKDF
  into it, parse back to `u32::from_be_bytes`, then mask `& 0x0FFF_FFFF`.
  After HIGH-1 lands this becomes part of the shared helper and the
  duplication is gone. If HIGH-1 is NOT taken, factor out:
  ```
  fn derive_initial_epoch(hk: &Hkdf<Sha256>, label: &[u8]) -> Result<u32, String> {
      let mut bytes = [0u8; 4];
      hk.expand(label, &mut bytes).map_err(|e| format!("hkdf epoch: {e}"))?;
      Ok(u32::from_be_bytes(bytes) & 0x0FFF_FFFF)
  }
  ```
  Two callers → one line each.
- **Why:** Removes a 6-line duplicate.
- **Behavior preserved:** Identical mask, identical encoding.
- **Tests affected:** Same set as HIGH-1.
- **Subsumed by HIGH-1** if that lands.

### 22. `derive_pubkey` in `SecureDh25519::derive_pubkey` could use a `[u8; 32]` reference

- **File:** `rust/tuncore/src/secure_noise.rs:85-91`
- **Change:** Comment `let s = StaticSecret::from(*self.secret.as_array());`
  performs the same unavoidable stack copy that `identity::derive_static_pub`
  describes. The two are functionally identical to the function in
  `identity.rs:40` modulo argument source. Could share a helper, but
  doing so would force the helper to take a `&[u8; 32]` reference, and
  the dalek API forces a by-value copy regardless. **Recommendation:
  no change** — the duplicate is forced by the upstream API. Document
  the duplication with a cross-reference comment pointing each
  function at the other (`// see identity::derive_static_pub for the
  shared rationale`). Listed for completeness.
- **Why:** Cross-reference comments only.
- **Behavior preserved:** Identical.
- **Tests affected:** None.
- **Status:** Marginal — recommend the comment-only version.

---

## Approval gates

These refactors are **interlinked**. Recommended order:

1. HIGH-1 (session_keys constructor extraction) → subsumes MEDIUM-10
   and LOW-21.
2. HIGH-3 (noise_xx builder extraction) — independent of HIGH-1.
3. HIGH-2 (rotation responder comment) — independent.
4. MEDIUM-4 (drop unnecessary `Result` from `from_locked` chain) — needs
   small coordinated diff across `identity.rs`, `aes_gcm.rs`,
   `session_keys.rs`.
5. MEDIUM-5 (random_locked_key32 helper).
6. MEDIUM-7, MEDIUM-8, MEDIUM-9 — independent each.
7. LOW items — one sweep per category (doc backticks, must_use,
   pedantic numeric).

**Total proposed code changes (excluding LOW comment/sweep items):**
- 4 files touched: `session_keys.rs`, `noise_xx.rs`, `identity.rs`,
  `aes_gcm.rs`, `secure_memory.rs`.
- Net line-count change: estimated **-60 to -80 lines** of duplicate
  code, **+30 lines** of new helpers / comments.
- All 103 existing tests should pass with no changes. (Confirmed: every
  `.unwrap()` outside tests is in `secure_noise.rs` `expect()` calls
  with documented panic-on-mlock-failure semantics; every test
  `.unwrap()` works against either the unchanged signature or the new
  infallible signature in MEDIUM-4.)

## What this plan does NOT touch

- `Drop for LockedKey32` munlock ordering (`secure_memory.rs:133-139`)
  — audit-locked.
- `LockedKey32::zeroed` / `from_array` ownership semantics
  (`secure_memory.rs:97-122`) — audit-locked.
- The `Zeroize::zeroize` calls in `identity::IdentityKeyPair::zeroize`
  (`identity.rs:87-89`), `SecureDh25519::poison` (`secure_noise.rs:97-106`),
  `validate_ephemeral_not_low_order` probe scrubbing (`noise_xx.rs:78`)
  — audit-locked.
- The `Zeroizing<Vec<u8>>` wrappers in `device_attest_soft.rs:95-101`
  (`private_pkcs8_der`) and `device_attest_soft.rs:183` (`encrypt_to_store`)
  — audit-locked: returning `Zeroizing` is the security invariant.
- The `BootstrapEphemeral` consume-once path (`lib.rs:595-664`) —
  audit M4 lock.
- The `#[cfg(test)]` gate on `SessionKeyManager::from_handshake_hash`
  (`session_keys.rs:176`) — audit M2 lock.
- The `pub(crate)` gate on `from_bootstrap_shared_secret`
  (`session_keys.rs:228`) — audit M4 lock.
- The 32-byte length check at `session_keys.rs:234` — audit M4 lock.
- The PyO3 `#[pymodule]` surface in `lib.rs:666-683`.
- The PROLOGUE constant (`noise_xx.rs:12`) — wire-format lock.
- HANDSHAKE_PAD_SIZE / HANDSHAKE_ATTEST_PAYLOAD_SIZE / MSG[123]_SNOW_LEN
  (`noise_xx.rs:18-39`) — wire-format lock.
- Argon2 parameters (`passphrase_store.rs:28-34`) — on-disk-blob
  compatibility lock.
- All `Cargo.toml` dependencies — adding/removing any dependency is
  out of scope.
