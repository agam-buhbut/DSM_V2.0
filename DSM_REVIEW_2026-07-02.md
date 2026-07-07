# DSM Ultra-Review — 2026-07-02

**Status:** review complete (26/27 units; W4 android worktree pending — died on session
limit). All high/medium findings statically verified by direct code-read. Fix execution +
plan-review agent are **staged for the 21:30 Jerusalem budget reset** (subagents are
session-limited until then). This file is the durable hand-off.

Two multi-agent sweeps produced **51 findings** (0 critical, 7 high, 12 medium, 32 low).
The first sweep (Rust R1–R7, Python crypto/session/transport P1–P7) and second sweep
(DNS/kill-switch/rekey/anonymity/protocol/config/CLI/deploy + worktrees) were both cut
short by session limits; findings were salvaged from the run outputs.

Run outputs (source of truth for full detail):
- `…/tasks/waantu0wp.output` (run 1: 23 findings)
- `…/tasks/ws7u01lwe.output` (run 2: 28 new findings)

---

## Execution status (updated 2026-07-06)

**Main-tree fixes: DONE & verified green** (uncommitted, no commits — owner commits). A1, A2,
pkg-supply (abi3 wheel confirmed), B1, B2, B4, B5, B7 (2 unit tests), D, E-rand, E-sysctl, the
init bundle, and the 4 owner-approved code+test deletions. Evidence: rust `session_keys` 16/16 +
`device_attest_tpm` 2/2; targeted pytest **209 passed**; pylint 10.00, pyright 0, black/isort/ruff/
clippy/fmt clean. (Build/test notes: 3.6 GiB box — run rust `--test-threads=1`, pytest serial, never
concurrent; soft-backend test venv via `maturin develop --no-default-features --features dev-soft-attest`.)

**Android worktree (dsm-android): in progress via agents, UNVERIFIED here** — no gradle/SDK, so the
owner must build + on-device test. AND-1 (CRITICAL IPv6 `::/0` route), AND-2 (StrongBox-wrap
`identity.blob` + remove the `"b1-enroll-test"` constant + remove the logcat secret dump), AND-3
(kill-switch fail-closed teardown), AND-4 (attestation revocation list + optional deviceLocked),
AND-5 (`setUnlockedDeviceRequired`). Review AND-2/AND-3 carefully — design-sensitive crypto/kill-switch.

**nftables reconcile: DEFERRED to merge-time (owner).** Decision locked = keep dsm-ux's package-data
layout (`dsm/net/_templates/` + `importlib.resources` loader + pyproject `include`). At merge:
take dsm-ux's `dsm/net/_templates/{nftables,pre_handshake,server}.conf` as canonical and port
dsm-hardening's edits to the **repo-root** `nftables/*.conf` (ICMP gating etc.) INTO those template
files; drop dsm-hardening's repo-root `nftables/` and switch its `nftables.py` to the importlib loader.
Not done pre-merge because it is cross-worktree surgery best done when the branches actually merge.

## Verification verdicts (high/medium — verified against real code)

| # | File | Sev | Verdict |
|---|------|-----|---------|
| 1 | `rust/tuncore/src/session_keys.rs:620` | HIGH | **CONFIRMED** — `apply_rotation_with_grace` sets `self.epoch=new_epoch` even when `defer_send` keeps the send key OLD. `encrypt()` returns `self.epoch`; `session.py:231` stamps the inner epoch nibble from it. Responder grace-window packets = OLD key + NEW nibble → client decrypts with prev(old) key, drops on `epoch_id!=expected_eid` (`session.py:556`). Defeats the H-BUG-2/3 deferred-send. |
| 8 | `dsm/net/tunnel.py:412` | HIGH | **CONFIRMED** — fd is `O_NONBLOCK` (`:235`); `awrite` fallback `run_in_executor(os.write, fd)` still can't block → re-raises `BlockingIOError` → session teardown. |
| N1 | `install.sh:116` | HIGH | **CONFIRMED** — pins `cp311-abi3`; `Cargo.toml:31` has no abi3 feature, `release.yml` builds on py3.12 → wheel is `cp312-cp312`. Signed SHA256SUMS never contains the pinned name → every verified install aborts. (Fails safe, but product is un-installable.) |
| N2 | `.github/workflows/release.yml:144` | HIGH | **CONFIRMED** — `pip download` with no `--require-hashes`, no `-r requirements.lock`; lockfile referenced nowhere. Tampered PyPI wheel in range gets minisigned + installed as root. |
| 2 | `rust/tuncore/src/device_attest_tpm.rs:827` | HIGH | **PLAUSIBLE/LATENT** — `is_already_initialized` = `format!("{e}").contains("INITIALIZE")`. tss-esapi 7.7.0 not vendored → casing unconfirmed. swtpm exercises the success branch, not this one. Fix defensively: match the typed return code. |
| 3 | `dsm/crypto/handshake.py:398` | HIGH | **CONFIRMED on main; ALREADY FIXED in `dsm-hardening`** (`handshake_acceptor.py` — bounded-concurrent acceptor written for exactly this). |
| 5 | `dsm/crypto/crl.py:130` | MED | **CONFIRMED** — no `crl_number`/`this_update` monotonicity; replay an older signed, still-valid CRL to un-revoke. `crl_number` property exists but is unused. |
| N3 | `dsm/net/resolv_conf.py:220` & `:106` | MED×2 | **CONFIRMED** — `remove()` `finally` deletes the backup + clears in-memory original even when the restore write raised → DNS config unrecoverable. Symlink layout (systemd-resolved default) is never persisted → crash loses the original. |
| N4 | `dsm/net/forwarding.py:75` | MED | **CONFIRMED** — `net.ipv4.conf.all.rp_filter=2` loosens RPF on the WAN too; per-TUN set at `:79` already suffices (effective = max(all,iface)). Drop the `all` write. |
| N5 | `dsm/rekey.py:296` | MED | **PLAUSIBLE** — mutual-init yield path doesn't clear `last_rekey_time`, so the peer's winning REKEY_INIT is rate-limit-dropped. |
| N6 | `dsm/traffic/scheduler.py:436` | MED | **PLAUSIBLE (anonymity)** — unbounded `release_credit += pps*dt`; a send stall → proportional catch-up burst, a timing side-channel. Clamp `dt`. |
| N7 | `dsm/init.py:232` | MED | **PLAUSIBLE** — `--force` bypasses the state guard but `generate_enrollment` still refuses to clobber existing keys → `--force` can never restart. |
| 4 | `dsm/crypto/handshake.py` | MED | **PLAUSIBLE** — bootstrap retransmit resends msg3 into server bootstrap-recv → abort. |
| 9 | `dsm/net/transport/tcp.py` | MED | **PLAUSIBLE; NOT fixed in hardening** — `recv()` cancel mid-frame desyncs the stream. |
| W2 | `dsm/net/nftables.py` (ux vs hardening) | MED | **CONFIRMED integration conflict** — `dsm-ux` moves `nftables/*.conf`→`dsm/net/_templates/` (package data); `dsm-hardening` edits them in place at repo root. Merging both loses one side. |
| 7 | `dsm/server.py` | LOW↓ | Partially mitigated — `process_shutdown` machinery already present. |
| 6 | `dsm/session.py:261` | LOW↓ | Silent crash already fixed (DSM-002); only shutdown-vs-drop choice remains. |

Security-relevant LOWs worth doing: `init.py:137` wizard hard-codes `crl_strict=false`
(revocation fails open by default); `deploy/openssl-ca.cnf:47` `copy_extensions=copy`
lets an enrolling device inject a SAN; `dns.py:365` DoH `User-Agent: dsm/1.0` fingerprints
DSM; `server.conf:28` per-source rate meters exhaustible by spoofed-source flood.

---

## W4 — android worktree (completed 2026-07-02; was the one unreviewed unit)

FFI memory safety, `attest_android.py` DER/chain parsing, and manifest exposure all **clean**.
Defects are in on-device egress + key-at-rest:

- **AND-1 · CRITICAL** `.worktrees/dsm-android/android/…/DsmVpnService.kt:191` — TUN adds only IPv4 address/route (`addRoute("0.0.0.0",0)`, no `::/0`). All IPv6 traffic + AAAA DNS bypasses the tunnel in cleartext on dual-stack networks. **Fix:** add a ULA v6 address + `addRoute("::",0)` (capture or blackhole v6); regression-test that every `establish()` has a `::/0` route.
- **AND-2 · HIGH** `DsmConfig.kt:94,139` + `Provisioning.kt` + `AttestExtractionTest.kt:37-38` — Noise static private key sealed with the constant `"b1-enroll-test"` (default when `identity_passphrase` unset) and written to logcat at enroll. **Fix:** wrap `identity.blob` with a StrongBox/TEE non-extractable AES key (or user passphrase never on disk); delete the logcat dump; remove the constant fallback (fail closed).
- **AND-3 · MED** `DsmVpnService.kt:238-246` (teardown) — closing the TUN on any session drop reverts all apps to cleartext (no kill switch). **Fix:** keep TUN up + blackhole while re-establishing; document/require Android always-on + lockdown.
- **AND-4 · MED** `dsm/crypto/attest_android.py:446-576` — no attestation revocation-list check and no `RootOfTrust` verified-boot/deviceLocked check. **Fix:** accept a pinned offline revocation list (mirror the CRL model); optionally require `deviceLocked==true` behind a flag. Additive, fail-closed.
- **AND-5 · LOW** `AndroidKeystoreKeyHandle.kt:126-141` — signing key generated without `setUnlockedDeviceRequired(true)`. **Fix:** add it (and time-boxed `setUserAuthenticationRequired` if UX permits).
- Process note: `android/app/build/…/app-debug.apk` (debuggable) is present on disk (now gitignored) — ensure release build is non-debuggable and that artifact is never distributed. Run `cargo audit` (uniffi 0.29 added, +437 lock lines) before release.

AND-2 (StrongBox wrapping) and AND-3 (kill-switch redesign) are **design changes**, not surgical
fixes — flag for owner sign-off on approach; AND-1/AND-4/AND-5 + the logcat-dump/constant removal
are clear and land in execution.

---

## Fix plan (grouped; for the review-agent + execution workflow at 21:30)

**Owner decisions — LOCKED 2026-07-02:**
1. **Fix target:** edit **in place, no new worktree**. Main-branch findings → uncommitted
   edits in the main tree; each worktree's findings → edits in that worktree. **No commits**
   (owner commits). No new worktree.
2. **Scope:** **everything** — Groups A + B + D + E (incl. the over-eng cut-list, ~200 lines).
3. **N1 wheel tag:** add `abi3-py311` to pyo3 features so maturin emits `cp311-abi3` to match
   `install.sh` (interpreter-independent; the lazy/correct option). Pin/verify in `release.yml`.
4. **`crl_strict` default:** **flip to `true`** (revocation fail-closed) in the init wizard.
5. **W2 nftables layout:** **keep repo-root `nftables/`** (dsm-hardening's in-place layout wins).
   Port dsm-ux's `importlib.resources` loader in `nftables.py` back to repo-root paths; the
   dsm-ux file-move into `dsm/net/_templates/` is reverted.
   ⚠ **Residual (B1):** repo-root templates must still reach the installed wheel — shipping
   them in the wheel was pentest finding B1, which dsm-ux fixed *via* the move now reverted.
   Execution MUST verify the templates land in the installed location (e.g. `pyproject`
   `data-files`/`MANIFEST`/build step) and **flag to owner if not cleanly possible** rather
   than reintroduce B1.

**Group A — HIGH (confirmed):**
- A1 `session_keys.rs` #1 — stamp/return the **send direction's own epoch**, not `self.epoch`, while a send-swap is deferred (or hold `self.epoch` at old until the swap). Add a Rust rotation test: responder grace-window packet decrypts on the client. *Security-critical path — careful, tests first.*
- A2 `tunnel.py` #8 — fix the backpressure fallback: poll for writability via `loop.add_writer`/retry, or drop+count, instead of `run_in_executor(os.write)` on a non-blocking fd.
- A3 `release.yml` N2 — `pip download --require-hashes -r requirements.lock …`; fail the release if the resolved set diverges. Uses the **existing** lockfile.
- A4 `install.sh`/`Cargo.toml` N1 — per owner decision #2.

**Group B — MED (confirmed/plausible):**
- B1 `crl.py` #5 — enforce non-decreasing `crl_number` (pin last-seen); reject rollback.
- B2 `resolv_conf.py` N3 — only drop backup after a **successful** restore; persist symlink target for crash recovery; `cleanup.py` reconstructs the symlink.
- B3 `forwarding.py` N4 — remove the `all.rp_filter` write; rely on per-TUN.
- B4 `rekey.py` N5 — clear `last_rekey_time` in the mutual-init yield branch.
- B5 `scheduler.py` N6 — clamp `dt` (catch-up ≤ latency budget) before accruing credit.
- B6 `init.py` N7 — on `--force`, unlink identity/attest keys + state before enrolling.
- B7 `device_attest_tpm.rs` #2 — match the typed `ReturnCode`/`BaseError`, not a string.
- B8 `handshake.py` #4 / `tcp.py` #9 — retransmit-state + cancellation-safety.

**Group C — cross-worktree integration:** per owner decision #3 (nftables layout).

**Group D — security-relevant LOWs:** `crl_strict` default (decision #4); `openssl-ca.cnf`
drop `copy_extensions=copy` (or whitelist); DoH generic/empty UA; server.conf rate meters.

---

## Ponytail-audit — over-engineering cut-list (ranked, biggest cut first)

`delete:` FSM callback subsystem — dead, and buggy if wired. Nothing. [dsm/core/fsm.py:43]
`delete:` `PyNonceGenerator` pyclass — exported, zero callers. Nothing. [rust/tuncore/src/lib.rs:178]
`delete:` `OuterPacket.deserialize` + `.aad` — dead; protocol forbids the scenario. Nothing. [dsm/core/protocol.py:167]
`delete:` `PyAesKey` pyclass — unconstructible; latent nonce-reuse footgun. Nothing. [rust/tuncore/src/lib.rs:629]
`shrink:` `rand.py` thread-local `SystemRandom` scaffolding — false "batches 56B/~10x" premise, no syscall win. Plain `os.urandom`. [dsm/core/rand.py:8]
`delete:` `csprng_exponential` — no caller; rate-vs-scale param trap. Nothing. [dsm/core/rand.py:48]
`yagni:` per-blob Argon2 params in `passphrase_store` — never varied; forced-KDF/OOM vector. Derive from version byte. [rust/tuncore/src/passphrase_store.rs:268]
`native:` hand-rolled low-order ephemeral check — snow/`SecureDh25519::dh` already rejects it. `x25519_dalek was_contributory`. [rust/tuncore/src/noise_xx.rs:63] *(verify snow coverage before removing)*
`yagni:` `_apply_ruleset(fatal=…)` — `fatal=True` at every call site. Drop the param + bool return. [dsm/net/nftables.py:23]
`yagni:` `SysctlOverride(only_log_on_change=…)` — dead flag; sole other caller unused. Drop it. [dsm/core/sysctl.py:47]
`delete:` `--non-interactive` flag — declared, never referenced. Nothing. [dsm/init.py:368]
`delete:` `_MAX_INBOXES` 4096 cap — unreachable; semaphore already bounds inboxes. Nothing. [.worktrees/dsm-hardening/dsm/net/handshake_acceptor.py:507]
`delete:` on-tunnel ICMP accept rules — shadowed by the blanket tun-accept. Nothing. [.worktrees/dsm-hardening/nftables/nftables.conf:48]

net: ~-200 lines, -0 deps possible. (Security holes/correctness routed to the fix plan above, per ponytail-audit scope.)

---

## Continuation state (for the 21:30 resume)

Done: both sweeps salvaged; all high/med findings verified; report + plan + cut-list written.
Remaining, needs subagents (blocked until 21:30 reset):
1. **W4 android sweep** — the one unreviewed unit (Rust FFI `ffi.rs`/`python.rs`, `attest_android.py`, `android/`).
2. **Plan-review agent** — architect/reviewer pass over Group A–D above.
3. **Execute** — fix workflow (one agent per fix, worktree-isolated), after owner decisions 1–4.
