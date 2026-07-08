# DSM Ponytail-Audit + Refactoring Pass — 2026-07-07

Repo-wide over-engineering + behavior-preserving-refactor scan (5 parallel
reviewer agents: dsm core/session/rekey, dsm/net, dsm/crypto+traffic,
rust/tuncore, android kotlin). **Correctness / security / perf were OUT of
scope** — a separate review (`DSM_REVIEW_2026-07-02.md`) owns those. This pass
is *only* dead code, stdlib/native reinvention, YAGNI surface, and idiomatic
shrink/dedup.

Legend: `delete`/`stdlib`/`native`/`yagni`/`shrink` = ponytail cuts · `dedupe`/
`extract`/`idiom`/`const`/`move` = refactors. All `file:line` verified by the
agents against actual callers.

**Net if fully applied: ≈ −585 lines, −2 Rust deps (`hmac`, `serde`), −1 probable (`rand_core`).**

---

## GROUP 1 — SAFE (prod-only, no test changes). Recommend apply.

### rust/tuncore  (biggest wins — also drops 2 deps)
- `delete` `compute_hmac` end-to-end (0 callers anywhere) → **drops the whole `hmac` dep** + `type HmacSha256`. [identity.rs:107-120 · lib.rs:125-133 · Cargo.toml]
- `delete` `serde` dependency — referenced nowhere in the crate (only the word in a doc comment). [Cargo.toml]
- `delete` PyO3 `disable_core_dumps` wrapper + its `m.add_function` (dead FFI; Python calls `harden_process`, keep the inner Rust fn). [lib.rs:677-680,796]
- `delete` PyO3 `complete_rotation_responder` wrapper (no Python caller; keep inner Rust fn for its tests). [lib.rs:515-526]
- `dedupe` `public_from_locked(&LockedKey32)->[u8;32]` — the `Zeroizing`→`StaticSecret`→`PublicKey` dance is copy-pasted ~7×. [identity.rs · secure_noise.rs · session_keys.rs · lib.rs]
- `idiom` `self.auth.as_ref().map(|a| Auth::try_from(a.as_slice())).transpose()?` (6 lines→1). [device_attest_tpm.rs:314-319]
- `shrink` `decrypt` prev/current-epoch arms are identical → `try_decrypt_dir(...)`. [session_keys.rs:416-442]
- `yagni` `derive_rotation_keys`: drop `peer_pub` (asserted==`remote_pub` then discarded); fix 4 call sites. [session_keys.rs:707-720]
- `stdlib` `secure_zero()` wrapper → call `.zeroize()` directly (only its own test uses it → moves to Group 2 if kept). [secure_memory.rs:79-84]
- verify+drop probable-dead `rand_core` direct dep (`cargo tree -i rand_core` first). [Cargo.toml]

### dsm/net
- `native` `TcpTimestampsDisabler` hand-rolls procfs save/restore that `SysctlOverride` already does → delegate. *(review: confirm SysctlOverride semantics match)* [nftables.py:56-90]
- `delete` `flush_cache` — zero callers incl. tests. [dns.py:499-502]
- `delete` `DNSResolver.close` no-op "API compat" + its stale caller line. [dns.py:504-509 · server.py:319]
- `dedupe` `_save_backup`/`_save_backup_symlink` are byte-identical → one `_save_backup(bytes)`. [resolv_conf.py:72-97]
- `dedupe` `_redact(hostname,debug)` — the sha256 ternary is pasted 3× across dns.py + dns_proxy.py. [dns.py:246-271 · dns_proxy.py:44]
- `dedupe` `_parse_and_cache(hostname,wire)` — DoH/DoT tails identical. [dns.py:389-443]
- `dedupe` `MasqueradeManager.remove` → call `nftables._delete_tables(TABLE)`. [forwarding.py:132-144]
- `dedupe` `_atomic_symlink_restore(target)` shared by cleanup + manager. [cleanup.py:114-124 · resolv_conf.py:239-247]
- `extract` split `resolv_conf.apply()` (~96 lines/3 jobs) → `_warn_conflicting_dns_service()` + `_capture_original()`. [resolv_conf.py:114-210]
- `dedupe` `_ip_proto(server_ip)` (`"ip6"/"ip"` twice) + `_validate_tun_name(name)` (dup'd in 2 ctors) + import shared `DSM_TUN_NAME_RE` instead of inline regex. [nftables.py · forwarding.py]
- `delete` unused `IP_FORWARD_PATH` constant. [forwarding.py:30]
- `shrink` drop the belt-and-suspenders 2nd `_apply_fwmark()` (documented no-op). *(review: security-adjacent)* [transport/tcp.py:76]
- `dict-as-struct` type the `send: Any` callback `Callable[[bytes,tuple[str,int]],None]`. [dns_proxy.py:206,352]
- `dedupe` `_DSM_TABLES` should reference the existing class constants, not re-list literals. [cleanup.py:41-47]

### dsm/crypto + traffic
- `delete` dead pair `load_or_generate_interactive` + `load_or_generate` (0 callers incl. tests). [keystore.py:136,161]
- `delete` 3 dead `.pyi` stubs with no matching Rust `#[pyclass]`/`#[pymethods]`: `NonceGenerator`, `AesKey`, `SessionKeyManager.has_pending_send_swap`. [tuncore.pyi:37,153,147]
- `extract` `_harden_and_gate(config)` — the harden/nondumpable/attest-gate block is verbatim in both entry points. [client.py:88 · server.py:532]
- `dedupe` `_pin_source(transport,got,expected,what)` — UDP source-pin guard pasted 4×. [handshake.py:210,294,399,445]
- `dedupe` scheduler keep-alive `except` block triplicated → one wrapper. [scheduler.py:163,212,230]
- `dedupe` shaper `_fallback_classes(padding_min)` (pasted in `__init__`+`set_size_class_ceiling`). [shaper.py:129,184]
- `extract` `_load_crl(config,ca_root)` out of the ~150-line `load_cert_materials`. [auth_loader.py:121]
- `shrink` `_ClientAddr` 18-line `__slots__` guard class → minimal holder/closure. [server.py:371]
- `shrink` `_CLIENT_HANDSHAKE_ERR_LABELS` dict+mro-walk → 4-branch isinstance (matches server side). [client.py:236]
- `move` hoist per-hot-path imports to module top: `csprng_float` (session tun-send loop), `secrets` (chaff), `hmac` (path validate). [session.py:1307,463 · shaper.py:506]
- `const` `IP_UDP_OVERHEAD = 28` for the duplicated `path_mtu - 28`. [session.py:1140,1168]

### dsm core / session / init
- `dedupe` `_frame_encrypted(...)` — `make_addr_send_fn` duplicates `make_send_fn`'s entire AEAD frame path (epoch-nibble patch + aad + encrypt + serialize are byte-identical). [session.py:201 ≡ 286]
- `yagni` collapse `rand.py` per-thread `SystemRandom` machinery → shared instance (`SystemRandom` is stateless+thread-safe; the "serializes buffer refill" comment is factually wrong). [core/rand.py:11-25]
- `yagni` drop `_decrypt_with_fallback`'s `getattr(...,"try_decrypt_with_fallback",None)` legacy probe — the method is always present in a coherent build. [session.py:487-506]
- `idiom` `_fail(...) -> typing.NoReturn` → deletes ~5 unreachable `return`/`return 2` stubs. [init.py:38]
- `dedupe` one module-level `log = getLogger(__name__)` (4 function-local `import logging` warns). [core/config.py:286,306,519,548]
- `const` `FRAG_SPREAD_S = 0.05` (already named in the comment). [session.py:1322]
- `idiom` `default_factory=dict` not `lambda: {}`. [core/protocol.py:284]
- `yagni` drop `atomic_write(dir_mode=...)` param — no call site overrides it. [core/atomic_io.py:21]

### android kotlin
- `shrink` collapse the 37-line AND-2 TODO essay → one tracked-ticket line. [config/Provisioning.kt:73-109]
- `dedupe` `readDerLength(buf,idx)` — DER length decode pasted in `readTlv`+`derUnwrapOctetString`. [core/ServerAttestVerifier.kt:358-465]
- `stdlib` `readU32Be`/`writeU32Be` → `ByteBuffer.getInt/putInt` (as WireFraming already does). [core/RekeyEngine.kt:267-278]
- `dedupe` one shared seq→8-byte-BE-AAD helper (built in 3 spots). [core/SessionRunner.kt:423 · core/WireFraming.kt:47]
- `stdlib` `buildSizePriorCumulative` — index the weights array, drop the `zip().toMap()` build. [core/RealShaper.kt:121-123]
- `delete` stale KDoc blocks referencing removed methods. [attest/AndroidKeystoreKeyHandle.kt:64-71 · core/ClientCore.kt:52]

---

## GROUP 2 — TEST-TOUCHING (dead/parity code whose *only* refs are tests).
Applying = deleting the code **and its orphaned test(s)** → this is the
"modify/delete test files" hard-stop. **Needs explicit approval.**

### dsm
- `delete` `pick_random_size_class` (shaper does its own draw) + `test_protocol.py:139`. [protocol.py:168-177]
- `delete` `SessionFSM.is_active()` (test-only) + its test. [core/fsm.py:67]
- `delete` `netaudit.is_enabled()` (test-only; `emit()` reads `_enabled` direct) + its test. [core/netaudit.py:52]
- `delete` `A_RECORD` const + `_build_dns_query(qtype=)` (only ever `A`) → inline `dns.rdatatype.A`; updates `test_dns_padding.py`. [dns.py:34,512]
- `yagni` drop `dns_proxy` `resolve_detailed` getattr-fallback + `resolve()`-only branch → test stubs must implement `resolve_detailed`. [dns_proxy.py:254-263]
- `yagni` drop DoH `reverify_pin` param + block (speculative regression guard). [dns.py:287,308-319]
- `delete` `TunDevice.write` (sync; data path uses `awrite`) — confirm no test. [tunnel.py:400-402]

### rust/tuncore  (gate test-only `pub` behind `#[cfg(test)]` or delete + drop tests)
- `mlock_slice`/`munlock_slice` + roundtrip test [secure_memory.rs:28,39]
- `NonceGenerator::count`, `is_handshake_finished`×2, `has_pending_send_swap` [nonce.rs:90 · noise_xx.rs:306,408 · session_keys.rs:638]
- `ReplayWindow::check_and_update` + `max_seq` + PyO3 wrappers [replay_window.rs:76,85 · lib.rs:157-174]
- `AesKey::from_array` (bench-only) → inline at `benches/aead.rs`.

### android kotlin  (Python-parity surface the client never calls; each has test refs)
- `delete` `SessionCrypto.packetsSent()`, `ReplayGate.checkAndUpdate()`, `SessionCrypto.hasGracePeriod()` [core/SessionCrypto.kt:50,83,52]
- `delete` `HandshakeInputs.mtu` field+param (never read) [core/HandshakeWiring.kt:23,38,51]
- `delete` `WireFraming.OuterPacket.aad()` (one test) [core/WireFraming.kt:47]
- `delete` `SessionState.TEARDOWN,IDLE` (unreferenced) [core/RekeyEngine.kt:9]
- `delete` `Liveness.lastSendMs` (write-only) [core/SessionRunner.kt:141,428]
- `yagni` `setSizeClassCeiling`, `envelopePps`/`idleFloorPps`, `SendScheduler.queueDepth`, `isStrongBoxBacked` — test/parity-only inspectors.
- `yagni` relocate `AndroidKeystoreKeyHandle.generate/tryGenerate/generateKey` (~55 lines) to the enroll writer (only androidTest calls it).
- `delete` `UnimplementedServerAttestVerifier` — test can inline a throwing lambda (`fun interface`). [core/ServerAttestVerifier.kt:46-66]

---

## GROUP 3 — DELICATE / JUDGMENT. Recommend SKIP or careful individual review.

- `dns.py` `_cache_result` 3-tier min-heap → plain dict + lazy expiry: changes eviction O(log n)→O(n) (fine at cap 2000) but it's a real perf/behavior change, not a pure cut. [dns.py:459-497]
- rust `device_attest_tpm.rs` TPM `with_child_loaded(...)` scaffold dedup (~40 lines): **on-error flush ordering differs per site** — behavior-preserving only if done very carefully. [179-210,320-368,518-545]
- android `DsmConfig.Transport.TCP` arm is parsed but `openProtectedChannel` throws for it — dropping it is a *feature* decision (Phase B), not a refactor. [config/DsmConfig.kt:64]
- android `HandshakeDriver` re-checks CN that the verifier already enforces — it's a **defense-in-depth security check**; keep unless you tighten the `verify()` contract. [core/HandshakeDriver.kt:84-88]

---

## STATUS — APPLIED 2026-07-08 (owner approved "everything"; NO commits)
- [x] **Groups 1+2+3 applied** across Python (main tree), Rust (`rust/tuncore`), Kotlin (`.worktrees/dsm-android`).
- **Net:** Rust −130 lines / −3 deps (`hmac`,`serde`,`rand_core`); Kotlin −237 lines; Python ~−115 lines.
- **SKIPPED (guardrails, correctly):** Rust TPM `with_child_loaded` scaffold dedup (per-site flush ordering can't unify); Kotlin CN recheck (defense-in-depth — verifier's interface doesn't guarantee CN) + StrongBox `generate*` relocation (no enroll-writer destination); Python `TcpTimestampsDisabler→SysctlOverride` only if semantics matched.
- **Python agent died mid-apply (session limit) → repaired by hand:** 3 cross-module helpers made public (`atomic_symlink_restore`/`redact`/`delete_tables`), reverted `protocol.py default_factory=dict→lambda:{}` (broke pyright-strict), isort `client.py`, removed 5 now-stale `tuncore.pyi` stubs matching Rust cuts.

### Gate results
- **Python: GREEN — 643 passed, 0 regressions.** ruff/black/isort clean; pyright 0 (via editable venv — NOTE stale `~/.local/dsm` copy shadows default pyright). `tuncore` rebuilt from refactored Rust ✓.
  - 5 failures are **PRE-EXISTING** (proven via `git stash` → same 5 fail at committed baseline): 3× CRL tests write to root-owned `/opt/mtun` (test doesn't override `config_dir`; env-specific), 1× `_FakeSessionKeys` missing `send_epoch` (committed A1 gap), 1× `crl_rollback` not in `EXPECTED_EVENT_NAMES` (committed B1 gap). **FLAGGED for owner — not fixed (out of refactor scope + test edits).**
- **Rust:** `cargo fmt` ✓, `cargo clippy` (dev-soft-attest, all-targets) ✓ clean, `cargo check` both features ✓ (agent). `cargo test` RUN deferred — box swap-thrash (3.4 GiB swap) times out the codegen; recommend owner run `cargo test` on a roomier box.
- **Kotlin: GREEN — 84 tests pass, 0 failures** (BUILD SUCCESSFUL 2m14s; 89→84 = the 5 now-orphaned tests removed with the dead inspectors they covered).

### Bottom line
Refactor is **verified behavior-preserving**: Python 643-pass/0-regression, Kotlin 84-pass, Rust fmt+clippy+check clean. Only `cargo test` RUN is unverified (box hardware). No commits — owner reviews + commits.
