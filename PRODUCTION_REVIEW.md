# DSM V2.0 — Production-Readiness Synthesis

*Synthesis of a 14-dimension line-by-line review. Read-only; findings are drawn from the dimension data and three editor spot-verifications (`deploy/dsm.service`, `deploy/openssl-ca.cnf`, repo-root file inventory).*

## 1. Executive Summary

**Verdict: NOT production-ready.** The cryptographic foundation is genuinely strong, but the product is gated by reliability/OS-integration defects, a dead CI pipeline, a broken operator bootstrap, an overstated anonymity claim, and one unauthenticated remote-DoS edge in the crypto glue.
**Headline risks:** (1) a malformed unauthenticated `msg1` crashes the server daemon (untranslated Rust `RuntimeError`); (2) the network data path is broken for server forwarding and corrupts host IPv6/`resolv.conf` on partial-configure or crash; (3) every daemon failure path exits 0, so the kill switch comes down and traffic flows unprotected with no operator signal; (4) the DNS proxy is an off-tunnel open resolver/reflector; (5) the central traffic-analysis-resistance claim does not hold (real traffic is never smoothed into cover); (6) CI has never run a single gate and operators cannot even bootstrap a CA.
**Genuinely strong:** the Rust Noise/session core (airtight nonce uniqueness, forward secrecy, role-bound rotation, correct replay window, advisory-free deps), the fail-closed cert/CRL/Argon2id crypto posture, DNS SPKI-pin-before-payload and leak-safe client ordering, and disciplined app-sec (single atomic-write path, validated list-form subprocess, bounded network-fed state).

## 2. Subsystem Scorecard

| Subsystem | Grade | One-line rationale |
|---|---|---|
| Rust crypto core (Noise / session / AEAD) | A | No blockers; nonce uniqueness, FS, role-bound rotation, replay window all rigorous; deps advisory-free. |
| Crypto (Python layer) | B- | Mature fail-closed posture, but one **critical** remote-DoS blocker from untranslated Rust errors. |
| Rust FFI / identity / secure memory | C+ | Well-engineered, yet three structural blockers: page-granular munlock voids swap protection, no blob version byte, extractable soft-attest default. |
| Protocol & session orchestration | C+ | Hardened parsing and loop supervision undercut by two reachable rekey availability bugs that defeat documented recovery. |
| Network data path / OS integration | D+ | Four high OS-integration defects: server route loop, permanent IPv6 disable, TCP framing desync, PMTU oversize. |
| DNS stack | C+ | Strong pinning/leak-ordering, but crash destroys `resolv.conf`, open-resolver exposure, NXDOMAIN/cache defects. |
| Traffic anonymity / shaper | C | Real adaptive Poisson chaff, but the core indistinguishability claim is overstated; boot fingerprint. |
| App lifecycle / config / logging | C- | Three lifecycle blockers (exit-0, late signal handlers, no re-accept) plus config UX/example drift. |
| Tests (unit + integration) | B- | Real end-to-end suite passing, but zero coverage on the SPKI pin gate, client/server, and mutual-init; CI guard inert. |
| Docs / deploy assets | C | Excellent prose, but operator path broken at two load-bearing points and no LICENSE. |
| Packaging / CI | D+ | Local gates pass, but CI has never been green; unit-file restart/cleanup bugs. |
| Performance | B | Disciplined GIL-free hot path, no correctness blockers, but no measured baseline exists. |
| AppSec | B | Disciplined input/file handling; config-perm asymmetry and no core-dump backstop. |

## 3. Critical Findings

### C1 — Untranslated Rust `RuntimeError` from Noise parsing crashes the daemon (unauthenticated remote DoS)
- **File:** `/home/earl/Documents/prog/DSM_V2.0/dsm/crypto/handshake.py:350` (and the `NoiseTransport.decrypt` sites)
- **Dimensions:** crypto-python (confirmed)
- **What + why:** `read_message_1/2/3` and `NoiseTransport.decrypt` surface Rust errors as PyO3 `RuntimeError`. `handshake.py` never translates these, and `server.py`/`client.py` catch only `HandshakeError`/`CertAuthError` subclasses. A malformed UDP `msg1` (wrong size or low-order ephemeral, rejected in Rust) raises `RuntimeError` that escapes the retry loop and `asyncio.run`, terminating the server. No source pinning exists before `msg1`, so the input is fully unauthenticated.
- **Fix:** Wrap each Noise read/decrypt call in `handshake.py` in `try/except` and `raise HandshakeError(...) from e` on `RuntimeError`, so malformed peer input fails as a typed, handled error.

## 4. High Findings

### H1/H2 — Rekey recovery is self-defeating (two reachable availability bugs)
- **Files:** `/home/earl/.../dsm/rekey.py:240` and `:301`
- **Dimensions:** protocol-session (both confirmed)
- **What + why:** (a) A re-sent cached `REKEY_ACK` is stamped with the **new** epoch_id, but a retransmitted INIT means the initiator is still at the **old** epoch, so it drops the ACK; the documented lost-ACK recovery never succeeds and the initiator tears the session down (~72s). (b) An ACK-send timeout between `prepare_rotation_responder` and `apply` leaves Rust-side `pending_responder_rotation` set with no abort path, permanently wedging all future responder rekeys (most reachable on the backpressured TCP path).
- **Fix:** Exempt `REKEY_ACK` from the receiver epoch_id check (it self-validates via its epoch field + AEAD) and re-encrypt the cached ACK under the old send key while duplicate INITs arrive; add `abort_responder_rotation()` and call it on the timeout/early-return path.

### H3 — Server reuses the client full-tunnel policy route, looping forwarded traffic into the TUN
- **File:** `/home/earl/.../dsm/net/tunnel.py:240`
- **Dimensions:** network-datapath (confirmed)
- **What + why:** `configure()` unconditionally adds `default dev TUN table 100` plus `ip rule not fwmark 0x1 table 100`; `server.py` calls the same `configure()`. Forwarded client packets match `not fwmark 0x1 → table 100 → dev mtun0`, routing back into the TUN instead of out the WAN; MASQUERADE never fires. Server internet-forwarding is broken.
- **Fix:** Add a server-mode flag to `configure()` that skips the table-100 default route and the not-fwmark rule, or connmark-restore forwarded packets to the main table. Verify with `ip route get 8.8.8.8 iif mtun0 from 10.8.0.2` on a real server.

### H4 — Partial `configure()` failure leaves host IPv6 globally disabled and unrestored
- **File:** `/home/earl/.../dsm/net/tunnel.py:314`
- **Dimensions:** network-datapath (confirmed)
- **What + why:** `configure()` saves IPv6 state then runs `disable_ipv6=1` mid-sequence; if a later command fails it raises with `_configured` still False. `deconfigure()` guards restore behind `_configured`, so IPv6 stays disabled; the next run captures the now-disabled baseline and overwrites the state file — permanently breaking IPv6 across restarts.
- **Fix:** Track IPv6 mutation with a separate flag set right after `_save_ipv6_state()`, and restore whenever that flag is set, independent of full-configure success.

### H5 — Crash+restart permanently destroys the original `resolv.conf` (self-capture clobber)
- **File:** `/home/earl/.../dsm/net/resolv_conf.py:93`
- **Dimensions:** dns-stack (confirmed)
- **What + why:** `apply()` captures the current `/etc/resolv.conf` as the "original" with no managed-by-dsm marker check. After SIGKILL/crash (restore never ran), the next start captures dsm's own payload (`nameserver 10.8.0.1`) as the original; clean teardown then "restores" the dead nameserver. No persistent backup exists.
- **Fix:** If captured contents start with the managed-by-dsm marker, treat as no-original; persist the real original to `/var/lib/dsm/resolv.conf.orig` via `atomic_write` and prefer it on restore.

### H6 — TCP recv framing desyncs when the 0.1s timeout cancels a partial frame read
- **File:** `/home/earl/.../dsm/session.py:682`
- **Dimensions:** network-datapath (confirmed)
- **What + why:** `recv_loop` wraps the stateful `transport.recv()` (`readexactly` prefix then payload) in `wait_for(..., 0.1)`. If the timeout fires after the 4-byte prefix is consumed but before the payload arrives (>100ms inter-segment gap — exactly the degraded path TCP fallback targets), the length is lost; the next read treats payload bytes as a new prefix, causing permanent desync and a session-killing `ValueError`.
- **Fix:** Buffer partial-frame state inside `TCPTransport` across calls, or drive idle ticks from a separate task instead of a short cancellable timeout on the framed read.

### H7 — Padded/chaff packets exceed PMTU on constrained paths; auto_mtu never caps the size class
- **File:** `/home/earl/.../dsm/session.py:790`
- **Dimensions:** network-datapath (confirmed)
- **What + why:** `auto_mtu_loop` lowers only the inner TUN MTU. The shaper still pads outer packets to the static 1400 size class, so on a sub-1428 PMTU path with DF set, 1400-class packets are dropped with EMSGSIZE and only logged — never resized. The GUIDE's own `pmtu=1300` example loses ~6% of real traffic plus chaff.
- **Fix:** When auto_mtu lowers the path, also clamp the shaper's size-class ceiling to fit (path_mtu − IP/UDP), or resize outer packets to the discovered PMTU before `sendto`.

### H8 — Chaff is purely additive; real-traffic volume and burst onset are not hidden
- **File:** `/home/earl/.../dsm/traffic/shaper.py:16`
- **Dimensions:** traffic-anonymity (confirmed)
- **What + why:** Chaff fills idle time at an EMA rate, but real packets are enqueued immediately (1-100ms jitter only) and the scheduler drains all ready packets per poll with no rate cap; `burst_smoothing_delay()` is a permanent no-op. A browsing burst (hundreds of pps) passes through unshaped, far above the ~1pps floor. The docstring/README claim of "no observable boundary between active and idle" holds only for the chaff process in isolation, not the real+chaff wire total.
- **Fix:** Either feed real packets through a constant/cover rate limiter so wire rate is independent of real volume, or remove the indistinguishability claim and document that only the idle baseline is masked. (Owner decision — see §10.)

### H9/H10/H11 — Daemon lifecycle defeats fail-closed protection
- **Files:** `/home/earl/.../dsm/__main__.py:136`, `/home/earl/.../dsm/client.py:320`, `/home/earl/.../dsm/server.py:445`
- **Dimensions:** app-ux (all confirmed)
- **What + why:** (a) `run_client`/`run_server` return `None` on every error path and after normal teardown, so `main()` exits 0; with `Restart=on-failure` the VPN never auto-recovers, the kill switch is removed, and traffic flows unprotected with `systemctl status` showing a clean exit. (b) The client installs signal handlers only after the handshake (`client.py:320`), but the pre-handshake kill switch is applied at `:129`; a SIGTERM during connect kills the process without unwinding, orphaning the nftables rules and taking the host offline. (c) The server has no re-accept loop — after any successful session ends (dead-peer timeout, roam, SESSION_CLOSE) it falls off the end and exits, so one client blip permanently downs the service.
- **Fix:** Return an int exit status (nonzero for all error paths) and `sys.exit()` it; create the shutdown Event and call `setup_signal_handlers()` at the top of the client `AsyncExitStack` before the pre-killswitch; wrap the server session in an outer accept loop (or document single-session and switch the unit to `Restart=always` with nonzero codes).

### H12 — `deploy/openssl-ca.cnf` nameConstraints fails OpenSSL parsing — root-CA bootstrap broken
- **File:** `/home/earl/.../deploy/openssl-ca.cnf:90`
- **Dimensions:** docs (confirmed; editor re-verified line 90 uses `DirName:` and CIDR `IP:0.0.0.0/0`)
- **What + why:** GUIDE §2b's `openssl req -x509` fails with `unsupported option: name=DirName` (OpenSSL requires lowercase `dirName:`) and IP name constraints require mask form (`0.0.0.0/0.0.0.0`, `::/::`), not CIDR. No root cert is produced; every operator is blocked at the first CA step, so nothing downstream is reachable.
- **Fix:** Use the verified-working syntax (`permitted;dirName:...`, `excluded;IP:0.0.0.0/0.0.0.0`, `excluded;IP:::/::`), or drop the permitted clause (see M-DOCS group — `CN=dsm` subtree matching would reject every DSM leaf and DSM's runtime never evaluates nameConstraints anyway).

### H13 — CI has never been green: all 15 runs fail at the pip dependency-install step
- **File:** `/home/earl/.../.github/workflows/ci.yml:39`
- **Dimensions:** packaging-ci (confirmed)
- **What + why:** Every workflow run (15/15, 2026-04-25 → 2026-06-10) failed in ~4s at the install step on both matrix jobs; every downstream gate (black/isort/ruff/pylint/pyright, rustfmt/clippy, cargo-audit, pip-audit, both test suites, packaging smoke) is skipped. The entire CI protection has never executed. A latent second break (`pip install --no-index` cannot resolve `cryptography`) waits behind it.
- **Fix:** Pull the failing step log, fix the install (build wheel first, then `pip install --find-links dist "dsm[dev]"`), and make CI a required status check on `main`.

## 5. High-Adjacent / Medium Findings (grouped by theme)

**Rust key-memory & format (4 medium + supporting low/info — rust-identity, rust-noise).** Page-granular non-refcounted `munlock` in `LockedKey32::drop` (`secure_memory.rs:151`) silently unlocks pages holding other live keys, voiding the swap-protection guarantee the whole layer rests on; sealed-blob format has no version byte (`passphrase_store.rs:7`), freezing Argon2id params before any production blob exists; the GIL is held through multi-second Argon2id in the store methods (`lib.rs:111`), freezing the event loop; `IdentityKeyPair` is silently usable after `zeroize()` with an all-zero key (`identity.rs:85`); and `rotation_packets` caps at 2^48 while the nonce counter is u32 (`session_keys.rs:30`). *These four mediums plus C1 are the crypto-layer must-fixes.*

**DNS robustness & exposure (4 medium — dns-stack).** Proxy answers any off-tunnel source (`dns_proxy.py:307`, open resolver/reflector); hostname-form DoH/DoT providers dead-loop through the TUN (`dns.py:508`); NXDOMAIN is conflated with provider failure causing all-provider fan-out, ERROR spam and SERVFAIL-to-client (`dns.py:445`); `_cache_heap` grows unboundedly on long-running servers (`dns.py:391`).

**Residual traffic-analysis leaks (4 medium — traffic-anonymity).** Rate EMA snaps to ceiling on bursts (post-burst chaff tail, `shaper.py:336`); chaff size classes mirror the real-traffic EMA, leaking the coarse app profile in the aggregate histogram (`shaper.py:292`); handshake boot emits an uncovered fixed-1400B frame sequence — a DSM establishment fingerprint (`handshake.py:76`); `padding_min` in (1400,1500] passes config validation but crashes `TrafficShaper.__init__` (`shaper.py:176`).

**Config & UX hardening (7 medium — app-ux, appsec).** `config.toml` itself is never permission/ownership-checked though it controls the trust anchor and `crl_strict` (`config.py:406`, appsec); config-load errors surface as raw tracebacks (`__main__.py:123`); wrong-typed TOML values raise cryptic `TypeError` (`config.py:151`); passphrase flags before a subcommand are silently dropped (argparse dest clobbering, `__main__.py:94`); `key_file` is the only path not required absolute (`config.py:172`); `atomic_write` ignores the `os.write` return value, risking a silently truncated rename target (`atomic_io.py:39`); `enroll --csr-out` persists keys before validating the CSR path, stranding the operator on write failure (`__main__.py:206`).

**`config.example.toml` ships unusable (3 medium + 1 low — app-ux).** As copied it refuses to start (`crl_strict=true` default with `crl_file` commented out and the knob undocumented; plus an all-zeros `ca_root_sha256` placeholder); documents 0640 allowlist perms the code rejects; re-sets `jitter_ms_max=50`, silently reverting the M-ANON-4 bump to 100; and omits `debug_dns`/`debug_net`/`auto_mtu`/`pmtu_check_interval_s`.

**systemd / deploy lifecycle (4 medium — network-datapath, packaging-ci, appsec).** No `ExecStopPost` cleanup (SIGKILL/OOM leaves kill switch + `resolv.conf` + sysctls + ip rule unrestored — *editor-confirmed absent*); `StartLimitIntervalSec` is in `[Service]` and silently ignored, removing the crash-loop guard (*editor-confirmed line 131*); no `LimitCORE=0`/`CoredumpFilter` backstop, so a crash after a swallowed `harden_process()` failure can persist key material; dev-soft-attest is the default Cargo feature shipped in release wheels.

**Network secondary defects (3 medium — network-datapath).** Global `net.ipv6.conf.all.disable_ipv6=1` is set but never restored (`tunnel.py:244`); IPv6 `server_ip` passes validation but the AF_INET-only transport cannot use it (`config.py:141`); default TUN MTU 1400 exceeds the single-outer inner budget 1360, forcing fragmentation of full packets (`config.py:37`).

**Test-coverage gaps (8 medium — tests-unit, tests-integration).** Zero tests for the SPKI pin gate `verify_pin`/`verify_pin_on_ssl_object` (`tests/test_dns_pinning.py`, confirmed); no tests at all for `client.py`, `server.py`, `forwarding.py`; the mutual-init rekey tie-break is untested despite `test_rekey_mutual_init.py`'s name; `test_symmetric_shaping` is tautological (passes with server shaping deleted); `test_netaudit.py` is order-dependent (reproduced failure); KeyStore wrong-passphrase path untested; the `TestServerWaitsIndefinitelyForFirstMsg1` regression test cannot detect its own regression (sleeps 1.5s vs a 5-18s bound); test PKI fixtures omit production's critical EKU/nameConstraints/SKI/AKI; CI never sets `DSM_REQUIRE_TUNCORE=1`, so conftest's silent-skip guard is inert in the only lane it protects; several tuncore-dependent suites error instead of skipping without the extension.

**Docs drift (10 medium — docs).** GUIDE never provisions the initial CRL though `crl_strict=true` makes it mandatory (confirmed); crash-cleanup omits the `dsm_killswitch_pre` table, leaving a crashed-mid-handshake host offline (confirmed); the `CN=dsm` DirName constraint would reject every DSM leaf and DSM's runtime never evaluates nameConstraints; README rekey constants stale (5s/3 vs 8s/9); test counts stale (253/103 vs 335 collected); CN derivation documented as 8-hex vs the code's 12-hex `SHA-256(pub‖role)`; GUIDE claims a confirm passphrase prompt that does not exist; stale hardening status (GUIDE/README say SystemCallFilter is commented out — *editor-confirmed it ships active at line 173*); GUIDE capability list omits `CAP_IPC_LOCK` (which the unit calls panic-critical); no `SECURITY.md`/disclosure path.

**Performance scaffolding (2 medium — performance).** Per-packet `asyncio.wait_for` adds ~17µs across the two loops (`session.py:671`); `TunDevice.read` does `add_reader`/`remove_reader` (2 `epoll_ctl`) per packet (`tunnel.py:343`). No correctness impact; both have measurement plans, and **no benchmark/baseline exists** to validate any throughput claim.

**AppSec leak via audit stream (1 medium — appsec, app-ux).** `--debug-net` emits `handshake_end` with `error=<class>`/`message=str(e)` into journald, re-exposing the cert-auth detail the human WARNING log deliberately hides to block allowlist/CRL enumeration (`server.py:246`).

**Packaging supply-chain (3 medium — packaging-ci).** `requirements.lock` has no `--generate-hashes` and is never exercised by CI (deployed combo never tested); dev toolchain unpinned and hand-duplicated between `pyproject` and `ci.yml` (already drifted); `--no-index` wheel install cannot resolve `cryptography`.

## 6. Low / Info (one line per theme, with counts)

- **Crypto-python hardening (4: low/info):** enroll skips the CA-root pin; non-tty stdin passphrase leaves unwipeable copies; EC curves not pinned at verify; `DSM_PASSPHRASE_FILE` read failure falls through to weaker sources.
- **Rust-noise/identity hygiene (10: low/info):** mlock-failure panic per handshake; non-AEAD early return timing on absent prev-epoch; unauthenticated handshake trailer (documented covert channel); String errors instead of `thiserror`; munlock-before-zeroize ordering; Argon2 working memory freed unscrubbed; dev-soft-attest default; dead `PyAesKey`/`compute_hmac` FFI surface; panicking `Signer::sign`; 512 MiB alloc can abort on low-RAM hosts.
- **Protocol-session fragility (5: low/info):** dead FSM `on_enter`/`on_exit` "safety net"; unguarded teardown re-transition in `finally`; unbounded rekey-INIT resend; stale `RekeyState` docstring; lazy reassembly eviction.
- **Network-datapath polish (5: low/info):** nft retry can leave both kill-switch tables; unhandled `TimeoutExpired`; missing `raise ... from e`; ip-rule delete omits priority; fixed well-known fwmark.
- **DNS polish (6: low/info):** TTL clamp bug (MAX_TTL dead); no query/response binding; coalescing-leader `InvalidStateError` on cancel; `set_exception` log spam; no TC/TCP-53 truncation; DoH UA fingerprint, response-padding dependency, `trust-ad`, aliased cache list.
- **Traffic-anonymity polish (5: low/info):** chaff capped to one/poll; always-on 1pps floor signature; rekey/SESSION_CLOSE bypass jitter; dead `_recent_wire_times` deque.
- **App-ux polish (8: low/info):** validation warnings before logging configured; dead `config_dir` field; backoff jitter is ±25% not the documented ±50%; netaudit event list/help drift; file-perm TOCTOU; `KeyboardInterrupt` raw traceback; root-logger formatting gap.
- **Tests hygiene (10: low/info):** slow Argon2id tests (~17s, ~95s enroll); wall-clock-coupled async tests; dead code in `test_auto_mtu`; broad `assertRaises(Exception)`; direct `/tmp` writes; weak no-thrash assertions; TCP probe-bind race; swallowed loop exceptions; self-referential CLI test; doc-only stale comments (`derive_default_cn`, `cert.py` SHA-256→SHA-384, `test_fragmenter`).
- **Docs/release hygiene (12: low/info):** no LICENSE (legally all-rights-reserved); README jitter 1-50 vs 1-100; wrong expected log strings; stale "3 retries"; stale `§7` cross-ref; two fully-executed refactor plans shipping in root; dead `[crl_ext]`; cnf comment nits (`&gt;=`); `§0b` missing `dig`/`nc`/`tcpdump`; CRL mislabeled "optional"; `.txt` docs / no CHANGELOG.
- **Packaging-ci hygiene (9: low/info):** Actions on mutable tags / deprecated Node 20; no `permissions:` block; Python 3.13 (production interpreter) untested; `.gitignore` gaps; global `reportMissingImports=false`; `maturin>=1.0` floor; no `rust-version` MSRV; cargo-audit built from source per matrix job; root-by-design and no pyproject license metadata (accepted-risk notes).
- **Performance scale taxes (7: low/info):** per-packet byte copies, getrandom syscalls, getattr lookup, hot-loop imports, reassembly O(n) scan, per-datagram send lock, double-AEAD on forgery (a deliberate security property).
- **AppSec defense-in-depth (4: low/info):** subprocesses resolved via PATH; iface regex permits `.`/`..`; `DSM_PASSPHRASE` lingers in `/proc/PID/environ`; root for full lifetime.

## 7. Refuted Claims

No dimension formally refuted another reviewer's finding — the input `refuted_claims` set is empty and no finding carries `verified: refuted`. The 14 dimensions are mutually consistent; one apparent tension (docs says `SystemCallFilter` ships active; app-ux/commit log call it gated) reconciled cleanly on inspection — a broad `@system-service` filter **is** shipped (`dsm.service:173-174`), while only `RestrictNamespaces` and a tighter allowlist remain gated.

What the review **did** refute were several of the **codebase's own documented claims** (recorded to keep the record honest):
- GUIDE/README state `SystemCallFilter` is "deliberately commented out" — refuted; the unit ships it active (editor-verified).
- Cargo comment "Replaced by tpm-attest for production builds" — refuted; `tpm-attest` is a non-compiling placeholder, so release wheels necessarily ship the extractable soft backend.
- README "cross-checked against the current codebase" — refuted by multiple stale constants (rekey 5s/3, test counts, jitter, CN derivation).
- README "Open-source" — refuted; no LICENSE file and no `[project].license` (editor-verified absent), so the code is legally all-rights-reserved.
- The shaper docstring / README "no observable boundary between user active and user idle" — refuted by the additive-chaff analysis (H8); the property holds only for the idle baseline, not active volume.

## 8. Coverage Statement

- **Inventory swept:** 104 / 104 files, line-by-line across all 14 dimensions; `missed_then_swept` is empty (nothing was found unreviewed on a second pass).
- **Editor verifications (this synthesis):** directly inspected `/home/earl/.../deploy/dsm.service` (hardening directives, StartLimit placement, absent ExecStopPost/LimitCORE), `/home/earl/.../deploy/openssl-ca.cnf` (nameConstraints syntax), and a repo-root inventory confirming no `LICENSE`/`COPYING`/`SECURITY` files, no `rust/tuncore/benches`, and both `refactor-plan-*.md` present. All confirmed the underlying findings.
- **Test execution evidence (from dimensions):** full Python suite run twice on system Python 3.13 — 333 passed, 2 skipped, 9 subtests, 0 failures (~225-244s); local lint/type/audit gates all clean (black/isort/ruff, pylint 10.00/10, pyright strict 0, cargo-audit + pip-audit clean). GitHub CI itself has never executed a gate (H13).

## 9. Draft Production Roadmap (skeleton — gate criteria only; to be planned with the owner)

**Phase 0 — Security blockers (must clear first).**
Gate: C1 closed and regression-tested; `LockedKey32` swap-protection actually holds; sealed-blob versioning landed before any production blob is written; soft-attest backend gated or logged loudly at runtime; `config.toml` perms enforced at load; DNS proxy restricted to in-tunnel sources. Exit gate: every critical + security-class high/medium has a fix and a test.

**Phase 1 — Reliability & data-path correctness.**
Gate: server forwarding verified on a real host (`ip route get` from a client source); IPv6 and `resolv.conf` survive partial-configure failure **and** SIGKILL/crash (ExecStopPost + persistent backup); TCP path stable on segmented links; PMTU respected end-to-end; rekey recovers from a single lost ACK and can never wedge; daemon exits nonzero, auto-restarts, re-accepts, and never strips the kill switch on failure.

**Phase 2 — Anonymity claim reconciliation.**
Gate: an owner decision (see §10) is implemented — either real-into-cover shaping makes wire rate independent of real volume, or the docstring/README claims are scoped down to "idle baseline only"; boot-handshake fingerprint either masked or explicitly documented as accepted.

**Phase 3 — CI / release engineering.**
Gate: CI green and a required status check on `main`; production install path (lockfile with hashes + wheel) exercised in CI; `openssl-ca.cnf` fixed and the GUIDE bootstrap (incl. initial CRL) walks end-to-end on a clean box; blob-version migration path in place; criterion + iperf3 baseline established and a throughput figure documented or accepted.

**Phase 4 — UX, docs, polish, legal.**
Gate: LICENSE + SECURITY.md present; `config.example.toml` boots as-shipped; all documented constants/log strings/CN format reconciled with code; stale refactor plans removed; low/info hygiene cleared or explicitly deferred with rationale.

## 10. Open Questions for the Owner

1. **Deployment model:** is single-client-per-server-process permanent, or must the server multiplex / re-accept across sessions? (Drives the H11 fix shape and the `Restart=` policy.)
2. **Anonymity commitment:** what is the real threat-model promise for *active-period* traffic analysis — implement real-into-cover shaping, or formally scope the claim to idle-baseline masking? (Drives H8 and Phase 2.)
3. **Install base:** has any production instance written sealed key blobs yet? (Determines the urgency and migration window for the blob version byte.)
4. **TPM attestation:** when does `tpm-attest` land, and until then is shipping the extractable soft backend acceptable with a loud runtime warning, or must release wheels be gated now?
5. **Target hardware / throughput:** what pps / Mbit/s must a single core sustain? (Determines whether the asyncio scaffolding cost is worth restructuring or just documenting.)
6. **IPv6 scope:** is an IPv6 server endpoint / transport in scope, or should it be rejected in config until supported?
7. **Name constraints:** should DSM evaluate `nameConstraints` at runtime, or are they purely third-party-trust bounds? (Affects both `cert.py` and the CA cnf rewrite.)
8. **License choice:** MIT / Apache-2.0 / GPL-3.0? (Blocks any public release, packaging, or third-party pentest.)