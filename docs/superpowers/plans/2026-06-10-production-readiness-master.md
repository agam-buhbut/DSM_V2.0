# DSM V2.0 Production-Readiness — Master Plan

> **For agentic workers:** This is the master roadmap. Each phase has (or will get)
> its own detailed TDD plan in this directory; execute those with
> superpowers:subagent-driven-development or superpowers:executing-plans.
> Detailed phase plans are authored just-in-time, at the start of each phase,
> against the then-current tree.

**Goal:** Take DSM V2.0 from its current state (strong crypto core, NOT
production-ready per `PRODUCTION_REVIEW.md`) to a public, MIT-licensed
GitHub release that a stranger can install and run with an extraordinarily
simple setup path.

**Architecture:** Six sequential phases ordered security → reliability →
anonymity → TPM → release engineering → coverage/hygiene. Every phase ends
with the full local gate (black → isort → ruff → pylint → pyright → pytest;
rustfmt → clippy → cargo test → cargo audit) and an owner review checkpoint.
Findings inventory and severities live in `PRODUCTION_REVIEW.md` (repo root);
this plan references findings by their IDs/sections rather than restating them.

**Tech Stack:** Python 3.11+ asyncio, Rust (PyO3/maturin `tuncore`),
`cryptography`, `dnspython`, nftables, systemd; new in Phase 3: `tss-esapi`
(approved 2026-06-10); CI: GitHub Actions; distribution: GitHub Releases +
install script.

---

## Owner Decisions (recorded 2026-06-10 — do not re-litigate)

| Decision | Choice |
|---|---|
| Production target | Public open-source release; **MIT** license; setup must be *extraordinarily simple* |
| Threat model | Passive observer + active on-path + **compromised server**; stolen-device not a v1 adversary |
| Hardware attestation | **TPM 2.0 required for v1** — key-residency scope (key generated and resident in TPM, signs in-TPM; no PCR policy, no quotes in v1) |
| Active-traffic shaping (H8) | **Adaptive envelope**: real packets smoothed into a slowly-varying rate envelope, chaff fills to the envelope |
| Distribution | **GitHub Releases + install script** (no PyPI) |
| Git | Claude never commits; owner reviews and commits manually |
| File ops approved | Delete `refactor-plan-python.md` + `refactor-plan-rust.md`; rename `README.txt`→`README.md`, `deploy/GUIDE.txt`→`deploy/GUIDE.md` |
| New dependency approved | Rust crate `tss-esapi` (Phase 3 only) |

**Defaults adopted (flag if you disagree, owner):**
- Sealed-blob migration: writer emits versioned v1, reader accepts legacy v0 —
  no migration tooling (no production install base exists).
- Server lifecycle: sequential re-accept loop; single *active* session at a
  time is preserved (matches README non-goals).
- IPv6 server endpoint: rejected at config load until a real AF_INET6
  transport exists (post-v1).
- nameConstraints: drop the broken `permitted;dirName` clause from the CA
  cnf; DSM runtime continues NOT evaluating nameConstraints (documented as a
  third-party-trust bound only).
- Throughput: no hard target; establish a measured baseline (criterion +
  iperf3-in-netns) and document it.
- Boot/handshake fingerprint (M-ANON): documented as accepted v1 risk in the
  threat-model section; masking pre-key traffic is post-v1 research.

## Follow-up gaps surfaced during implementation
- **Sysctl crash-recovery GAP (from Phase-1.9):** `dsm cleanup` (ExecStopPost)
  restores IPv6 per-interface state precisely (Task 1.4 persists it to
  `/run/dsm/ipv6_state.json`), but `net.ipv4.ip_forward`, `rp_filter`, and
  `send_redirects`/`accept_redirects` originals live ONLY in-memory in
  `SysctlOverride._original` (`dsm/core/sysctl.py`). After a SIGKILL/OOM that
  bypasses the in-process unwind, cleanup can only set safe boot-defaults
  (`ip_forward=0`, `disable_ipv6=0`), not the operator's true prior values.
  **Fix (future task):** persist the sysctl originals to `/run/dsm/` at apply
  time (mirror Task 1.4's IPv6 state file) so cleanup can restore them exactly.
  Low severity — safe defaults == fresh boot, and clean stops restore precisely.

## Resolved owner items (2026-06-10, second round)
- LICENSE copyright line: **"Copyright (c) 2026 DSM contributors"** (MIT).
- Phase-0 existing-test edits APPROVED as deliberate consequences of fixes:
  (a) the four pre-v1 layout-lock tests in `passphrase_store.rs` update to
  the v1 blob format; (b) `tests/test_netaudit.py` `EXPECTED_EVENT_NAMES`
  gains `"soft_attest_acknowledged"`; (c) the three `tests/test_cli.py`
  config fixtures gain `chmod 0600`.
- Execution style: subagent-driven (fresh implementer per task, diff review
  between tasks, full gate at phase end).

---

## Process rules (apply to every phase)

1. TDD: failing test → minimal fix → green; tests live in `tests/`
   (new files; existing test files are NEVER edited without explicit owner
   approval — each phase plan lists any such request as a FLAG).
2. No commits, ever. Each task ends with a "Report" step; the owner commits.
3. Gate order after each task batch: `black` → `isort` → `ruff` → `pylint` →
   `pyright` → `pytest`; Rust: `rustfmt` → `clippy -D warnings` →
   `cargo test` → `cargo audit`.
4. No new dependencies beyond the approved ledger above without a fresh ask.
5. Security-sensitive changes get a security re-review pass before the phase
   gate is declared met.

---

## Phase 0 — Security blockers ✅ COMPLETE (2026-06-11, uncommitted)

Detailed plan: `2026-06-10-phase0-security-blockers.md` (this directory).
All 8 items implemented TDD-first, each with spec + quality/security review.
Exit gate met: Python 353 passed / 0 failed; Rust 114 passed / 0 failed
(release); black/isort/ruff clean; pyright strict 0 errors; pylint 10.00/10;
cargo clippy -D warnings + fmt clean. Awaiting owner commit.

| # | Item | Where |
|---|---|---|
| 0.1 | C1: translate Rust `RuntimeError` → `HandshakeError`; malformed unauthenticated msg1 must not kill the daemon | `dsm/crypto/handshake.py:350`, server/client retry loops |
| 0.2 | DNS proxy answers any source (open resolver/reflector): restrict to in-tunnel peers | `dsm/net/dns_proxy.py:307` |
| 0.3 | `LockedKey32` page-granular munlock unlocks other live keys: page refcount registry | `rust/tuncore/src/secure_memory.rs:151` |
| 0.4 | Sealed-blob format: add magic+version+Argon2id params header; read legacy | `rust/tuncore/src/passphrase_store.rs` |
| 0.5 | Soft-attest gate: refuse start unless `allow_soft_attest=true`; loud warning + netaudit event when allowed (full TPM in Phase 3) | `dsm/core/config.py`, attest selection site, `Cargo.toml` |
| 0.6 | Permission/ownership-check `config.toml` at load (it sets the trust anchor) | `dsm/core/config.py:406` + `path_security` |
| 0.7 | Core-dump backstop: `LimitCORE=0` + `PR_SET_DUMPABLE=0` in `harden_process()` | `deploy/dsm.service`, hardening module |
| 0.8 | netaudit `handshake_end` leaks cert-auth detail under `--debug-net`: emit class only | `dsm/server.py:246` |

**Gate:** every item fixed with a regression test; full Python+Rust gates
green; security re-review of the diffs clean.

## Phase 1 — Reliability & data-path correctness ✅ COMPLETE (2026-06-11, uncommitted)

Detailed plan: `2026-06-11-phase1-reliability.md`. All 13 items (1.1–1.13)
implemented TDD-first, each spec + quality/security reviewed; reviews caught
real second-order bugs (TCP shutdown deadlock in 1.6, resolv.conf OSError-race
in 1.5, an unimplementable re-accept design in 1.8 — all fixed). Exit gate met:
Python 425 passed / 0 failed; Rust 114 passed / 0 failed (release);
black/isort/ruff clean; pyright strict 0; pylint 10.00; clippy -D warnings +
fmt clean. Awaiting owner commit. (Item table below kept for reference.)


| # | Item | Where |
|---|---|---|
| 1.1 | Rekey lost-ACK recovery: cached ACK re-encrypted under old-epoch key / ACK exempted from epoch check | `dsm/rekey.py:240` |
| 1.2 | Responder-rotation wedge: add+call `abort_responder_rotation()` on ACK-send timeout (Rust API addition — internal) | `dsm/rekey.py:301`, `tuncore` |
| 1.3 | Server-mode `configure()`: skip client full-tunnel policy route (table 100 / not-fwmark rule) | `dsm/net/tunnel.py:240` |
| 1.4 | IPv6 restore on partial configure failure + restore global `disable_ipv6` | `dsm/net/tunnel.py:314,244` |
| 1.5 | resolv.conf: managed-marker detection + persistent backup in `/var/lib/dsm`, crash-safe restore | `dsm/net/resolv_conf.py:93` |
| 1.6 | TCP framing: buffer partial-frame state across `recv()` calls (no cancellable `wait_for` mid-frame) | `dsm/session.py:682`, `dsm/net/transport/tcp.py` |
| 1.7 | PMTU: clamp shaper size-class ceiling when auto_mtu lowers the path | `dsm/session.py:790`, shaper |
| 1.8 | Lifecycle: nonzero exit codes on all failure paths; signal handlers installed before pre-handshake kill switch; server sequential re-accept loop | `dsm/__main__.py:136`, `dsm/client.py:320`, `dsm/server.py:445` |
| 1.9 | systemd: `ExecStopPost` full cleanup (incl. `dsm_killswitch_pre`), `StartLimitIntervalSec` → `[Unit]`, document `CAP_IPC_LOCK` | `deploy/dsm.service` |
| 1.10 | DNS robustness: IP-literal-only DoH/DoT providers; NXDOMAIN vs SERVFAIL + negative cache; `_cache_heap` bound; TTL clamp | `dsm/net/dns.py:508,445,391` |
| 1.11 | Config/CLI UX mediums: friendly load errors, typed-TOML errors, argparse passphrase-flag clobber, `key_file` absolute, `atomic_write` write-return check, `enroll --csr-out` ordering, `padding_min` crash, IPv6 `server_ip` rejection, TUN-MTU default vs 1360 budget. **NOTE (from Phase-0 Task 6 review):** `dsm/core/config.py:load()` now raises typed `ConfigError` (insecure perms / not-found) but the three `load()` call sites in `dsm/__main__.py` (~123, 173, 260) catch nothing → raw traceback. Wrap them to `print(stderr) + sys.exit(2)` as part of this item (ties into 1.8 nonzero-exit work). | `dsm/core/config.py`, `dsm/__main__.py`, `dsm/core/atomic_io.py`, shaper |
| 1.12 | `config.example.toml` boots as shipped and documents every field | `config.example.toml` |

**Gate:** two-netns end-to-end soak: server forwards (`ip route get` proof),
IPv6/resolv.conf survive partial-configure and SIGKILL, TCP survives
segmented paths, rekey survives a dropped ACK, server survives client blips,
daemon exit codes drive systemd restart correctly.

## Phase 2 — Anonymity: adaptive envelope ✅ COMPLETE (2026-06-12, uncommitted)

Detailed plan: `2026-06-11-phase2-adaptive-shaping.md`. All 7 tasks (2.1–2.6,
2.8) done TDD-first with traffic-anonymity/security review. Owner raised the
latency budget to 1s; old additive-Poisson model removed; README rewritten to
claim exactly what holds (documented residuals: sustained volume visible, boot
fingerprint accepted, TCP caveat). Exit gate met: Python 478 passed / 0 failed;
Rust 114 / 0; lints/types clean; pylint 10.00. Awaiting owner commit.
**Phase-3 env note:** this host has BOTH `swtpm` + a real `/dev/tpm0`/`tpmrm0`,
`libtss2-esys.so`, and `tss-esapi` 7.7.0 in the cargo cache — TPM work is fully
testable here.


| # | Item |
|---|---|
| 2.1 | Design note (architecture review before code): envelope estimator (slow EMA + hysteresis), real-packet pacing into the envelope, chaff fill-to-envelope, configurable latency budget |
| 2.2 | Implement in `dsm/traffic/shaper.py`/`scheduler.py`; fix EMA ceiling-snap (`shaper.py:336`); make `burst_smoothing_delay()` real |
| 2.3 | Size-class selection decoupled from real-traffic EMA (`shaper.py:292`) |
| 2.4 | Seeded statistical tests: wire-rate variance bounded under burst; onset not step-detectable at second granularity |
| 2.5 | Docs: README threat-model section rewritten to claim exactly what holds (incl. boot-fingerprint accepted risk, 1pps idle floor, TCP caveat) |
| 2.6 | FLAG (existing-test edits need approval): `test_symmetric_shaping.py` is tautological; `test_shaper.py` assumptions change with the envelope |

**Gate:** statistical test suite green and deterministic; documented claims
match measured behavior on a netns capture.

## Phase 3 — TPM 2.0 attestation (key residency)

| # | Item |
|---|---|
| 3.1 | Add `tss-esapi` (approved); `tpm-attest` backend: ECDSA P-256 key created+resident in TPM (persistent handle), sign in-TPM, pubkey export for cert binding — implements the existing `device_attest` trait |
| 3.2 | Backend selection: config `attest_backend = "tpm" \| "soft"`; soft requires `allow_soft_attest=true` (Phase 0 gate) and becomes a non-default Cargo feature; release wheels build TPM-default |
| 3.3 | Enrollment flow: `dsm enroll` provisions/validates the TPM key; clear errors when no TPM/insufficient perms (`/dev/tpmrm0` access, `tss` group) |
| 3.4 | Tests: swtpm-backed integration (local + CI service container); soft-backend tests unchanged behind feature |
| 3.5 | Docs: GUIDE TPM provisioning section; troubleshooting (ownership, lockout) |

**Gate:** end-to-end handshake with TPM-resident keys on swtpm in CI; soft
backend impossible to enable silently.

## Phase 4 — CI, release engineering, docs, simple setup

| # | Item |
|---|---|
| 4.1 | Fix CI install step (wheel build → `--find-links` install); all gates actually run incl. `DSM_REQUIRE_TUNCORE=1`; rustfmt/clippy/cargo-test/cargo-audit (prebuilt) + pip-audit; SHA-pinned actions; `permissions:` block; 3.13 in matrix; `requirements.lock --generate-hashes` exercised in CI; maturin pin; `rust-version` MSRV. Owner makes CI a required check on `main`. **NOTE (Phase-1.2 learning):** Rust inline `#[cfg(test)]` tests that reference PyO3 wrapper types (`Py*`) fail to link the crate's test binary under the `extension-module` feature (libpython symbols suppressed) — breaking `cargo test` crate-wide. Either keep such behavior covered by Python FFI tests (current approach), or for CI add the libpython link (`pyo3` `auto-initialize` dev-dep or rustflags `-l python3.x`) so `cargo test` can exercise wrapper-level Rust tests. Decide in Phase 4. |
| 4.2 | Release pipeline: tagged builds → manylinux wheels → GitHub Release; `install.sh` (download wheel, create venv/pipx, verify checksum) |
| 4.3 | `dsm init` quickstart wizard (brainstorm first — the "extraordinarily simple" deliverable): guided CA+enroll+config+CRL+systemd setup for server and client |
| 4.4 | `deploy/openssl-ca.cnf`: fix nameConstraints (drop `permitted;dirName`, mask-form excluded IPs); kill dead `[crl_ext]` |
| 4.5 | GUIDE: initial-CRL provisioning step; crash-cleanup incl. `dsm_killswitch_pre`; stale-constant sweep (rekey 8s/9, test counts, CN 12-hex, jitter 1-100, log strings, SystemCallFilter status, CAP_IPC_LOCK, phantom confirm-prompt) |
| 4.6 | Legal/release files: `LICENSE` (MIT — copyright holder pending), `SECURITY.md`, `CHANGELOG.md`, license metadata in `pyproject.toml` + `Cargo.toml`; delete `refactor-plan-*.md` (approved); rename `README.txt`→`README.md`, `deploy/GUIDE.txt`→`deploy/GUIDE.md` (approved) with proper Markdown formatting; `.gitignore` gaps |

**Gate:** clean-VM walkthrough: a stranger goes from the GitHub release page
to a working two-box tunnel using only the README, in minutes, no Rust
toolchain required.

## Phase 5 — Test coverage, performance baseline, hygiene sweep

| # | Item |
|---|---|
| 5.1 | New tests: SPKI pin gate (`verify_pin`/`verify_pin_on_ssl_object`), `client.py`/`server.py` entrypoints, `forwarding.py`, mutual-init rekey tie-break, KeyStore wrong-passphrase |
| 5.2 | FLAG bundle (existing-test edits, owner approval per file): netaudit order-dependence, `TestServerWaitsIndefinitelyForFirstMsg1` bound, PKI fixtures missing EKU/SKI/AKI, tuncore suites error-vs-skip, slow Argon2id profile, direct `/tmp` writes |
| 5.3 | Performance baseline: criterion benches for tuncore seal/open; iperf3 two-netns throughput script; document figures; THEN decide the two perf mediums (`wait_for` overhead, per-packet `epoll_ctl`) by measurement only |
| 5.4 | Low/info sweep per `PRODUCTION_REVIEW.md` §6: fix mechanical items (`raise from`, thiserror, dead code, TTL clamp leftovers); record the rest in an accepted-risk ledger appended to `PRODUCTION_REVIEW.md` |
| 5.5 | Final full gate + fresh mini-review (security + code-review agents) of the cumulative diff |

**Gate:** all 176 findings either fixed (with test) or explicitly
accepted-with-rationale; suite green; lints/types/audits clean; baseline
documented.
