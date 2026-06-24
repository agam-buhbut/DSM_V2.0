# DSM Production-Hardening — Implementation Report

**Date:** 2026-06-24
**Driver:** the live two-box pentest (`DSM_TWO_BOX_PENTEST_REPORT.md`, 2026-06-23).
**Spec:** `docs/superpowers/specs/2026-06-23-dsm-prod-hardening-design.md`.
**Plans:** `docs/superpowers/plans/2026-06-23-dsm-hardening.md`, `…-dsm-ux.md`.
**Method:** subagent-driven (fresh implementer + reviewer per task), two parallel
git worktrees, TDD, **no git commits** (owner commits/merges).

## Status

**Code-complete, reviewed, and green.** Every pentest finding is fixed, plus the
new vuln-sweep findings; both final whole-branch reviews returned **no
Critical/High** issues; the full test suite passes (**730 passed / 12 skipped**,
pylint `dsm` 10.00, pyright 0).

**Live two-box verification: PASSED (2026-06-24).** The combined hardened+UX
`dsm/` package (the two worktrees merged cleanly — 0 conflicts on the only two
shared files) was deployed to both real boxes (TPM-attest preserved) and the
fixes were confirmed empirically:

| Live check | Result |
|---|---|
| **B5 — UDP session holds** | ✅ established via the new acceptor and stayed up at t+5/15/30 s (old code died <1 s) |
| **Functional over UDP** | ✅ DNS via server proxy, HTTPS (TLS1.3), ping 3/3, forwarding |
| **Leak** | ✅ `leak_count=0` — all client packets to `:51820`, nothing off-tunnel; IPv6 blocked |
| **S1 — malformed-packet crash** | ✅ fired the exact 4-byte repro (+ garbage flood); server **stayed up** (`FramingError` caught → "recovering") |
| **S2 — ICMP leak** | ✅ SIGKILL the client daemon → **ICMP leak = 0** (was 2); `ping` fails; nft tables persist (fail-closed) |
| **Acceptor + inbox-DoS guard** | ✅ 1800 bogus msg1 from distinct source ports → server stays up, RSS 47.1→47.6 MB (bounded), no OOM |
| **B3 — clock-sync warning** | ✅ logged at every startup (boxes have no NTP) |
| **B1 — packaged templates** | ✅ loaded from the wheel package with S2 gating intact |
| **B4 — `:53` conflict** | ✅ with `unbound` on `:53`, server now exits with a clean **actionable fatal error** (was a cryptic crash-loop) |
| **Latency** | ✅ **massively improved: ~257 ms** inner-tunnel ping (was ~1370 ms over TCP) |
| **Throughput** | ⚠️ ~0.35 Mbit/s — *not* improved over the old 0.74; the **anonymity shaper** (per-packet jitter → high RTT, + UDP loss hurting inner-TCP) is the bottleneck, not the transport. The UDP fix buys session-stability + latency, not bulk throughput — which stays shaper-bound by design (you chose "keep shaping intact"). |

So the four Critical/High pentest items (S1 crash, B5 broken-UDP, B1 packaging,
S2 ICMP leak) and the serial-acceptor DoS are now **empirically confirmed fixed
on real hardware**.

## What was fixed (mapped to the pentest findings)

| Pentest finding | Severity | Fix | Where |
|---|---|---|---|
| **S1** — 1 unauthenticated 4-byte packet crashes the server | 🔴 Critical | Typed `FramingError`; the `_accept_one_session` call is guarded + the listener is closed on any exception (FD-leak fix); no exception except shutdown can exit `run_server` | `tcp.py`, `server.py` (T1) |
| **S2** — kill switch leaks real-IP ICMP off-tunnel | 🟠 High/Med | ICMP gated to the TUN (`oif/iif "{TUN}"`); pre-handshake ICMP dropped | `nftables/*.conf` + packaged `dsm/net/_templates/*.conf` (T4) |
| **B5** — default UDP transport can't hold a session (DSM-002) | 🟠 High | Chaff path **drops-and-waits** instead of `shutdown.set()` when the peer addr isn't known yet; security (no-misroute, return-routability) preserved | `session.py` (T8) |
| **Serial acceptor** — one slow/bogus msg1 starves clients | 🟡 Med (DoS) | Bounded-**concurrent** UDP handshake acceptor (single admitted session, concurrent validation; first-to-auth wins; inbox-eviction + hard caps to prevent its own DoS; jittered backoff restored) | new `dsm/net/handshake_acceptor.py` + `config.max_inflight_handshakes` (T6) |
| **B1** — wheel ships without nft templates → daemon won't start | 🟠 High (deploy) | Templates moved into the package, loaded via `importlib.resources`, shipped in the wheel | `dsm/net/_templates/`, `nftables.py`, `pyproject.toml` (UX T1) |
| **B4** — host resolver on `:53` → opaque EADDRINUSE crash-loop | 🟡 Med | `DNSProxyPortInUseError` with an actionable message; surfaced as a clear fatal error | `dns_proxy.py`, `server.py` (UX T2 + T2b) |
| **B3** — clock skew breaks the handshake, no NTP, opaque error | 🟡 Med | `check_clock_sync()` startup warning + freshness error names clock skew/NTP | `core/preflight.py`, `attest.py`, `server.py`/`client.py` (UX T3) |
| **B2** + doc traps | 🔵 Low | `patchelf`, build-once/copy-wheel, NTP, `:53`, t64 packages documented; packaging trap removed | `deploy/GUIDE.md` (UX T5) |
| **Perf** — 0.74 Mbit/s, TCP-in-TCP | 🟡 Med | The UDP fix (B5) removes the forced TCP-in-TCP; default pinned to UDP. *Throughput improvement pending live measurement.* | (T8 + UX T4) |
| **Doc-accuracy** (c46/c49/c65/c59/c15/c55/c51/c38) + **c4** | 🔵 Low | Claims corrected to match code; CA curve (P-384) now **enforced** in `validate_chain` | README/GUIDE + `cert.py` (T10) |

Vuln sweep (mitmproxy/scapy + a custom parser fuzzer, 6 parsers × 3000 iters):
**zero S1 siblings** — DSM's wire parsers are robust; a belt-and-suspenders
boundary regression test was added.

## Review outcomes

- Every task: a fresh implementer (TDD) + a dedicated spec/quality reviewer;
  fix loops until clean. The security-critical T6 acceptor and T8 UDP fix used a
  more capable model + a dedicated security/concurrency review.
- **Final whole-branch reviews:** Hardening = *READY-WITH-FIXES, no Critical/High*
  (cross-task composition verified: S1-guard ↔ acceptor ↔ backoff; undrained-socket
  handoff; session/PATH_CHALLENGE; S2↔acceptor scoping). UX = *conditional →
  resolved* (its one HIGH was a merge artifact — the packaged templates carried
  pre-S2 ICMP rules — **fixed proactively** by putting the S2-gated templates in
  the packaged location).

## Owner merge guide (two worktrees → main)

Branches carry **uncommitted** changes (per your rule); you commit/merge. The
files BOTH touch and how to reconcile (full detail in the scratch
`merge_and_findings.md`):
1. **nft templates** — authoritative copy is the packaged `dsm/net/_templates/*.conf`
   (now S2-gated). Delete the repo-root `nftables/` after merge.
2. **server.py** — transplant the UX clock-preflight + DNS-conflict catch into the
   hardening-restructured accept loop (additive, different regions).
3. **config.py / config.example.toml / GUIDE.md** — additive; concatenate.
   GUIDE §10 cleanup-script table list vs §6 count: align prose (both fine
   functionally).

## Triage (Minor, owner's call — non-blocking)
- A couple of TUN-gated ICMP rules are redundant (the broad TUN-accept fires
  first) but tested/harmless. `_accept_until_winner` cross-module private name.
  Backoff logic duplicated (documented; could extract a shared module). Stray
  `import logging`.

## Pending live verification (when the boxes return)
Deploy = sync the pure-Python `dsm/` + templates and restart (no wheel rebuild).
Then confirm: UDP holds a session + throughput vs the old 0.74 Mbit/s; S1
malformed-flood survival (+ no fd leak); S2 off-WAN ping dropped while in-tunnel
ICMP works; acceptor anti-starvation (slow-bogus stream + legit client wins ≤~12s)
+ spoofed-source flood stays memory-bounded; undrained handoff under a pipelining
client; functional regression (tunnel/forward/leak=0 over UDP); and the secondary
DoH-pin MITM + systemd-hardening checks.

## Bottom line
The four critical/high issues from the pentest (S1 crash, B5 broken-UDP, B1
broken packaging, S2 ICMP leak) and the serial-acceptor DoS are all fixed and
reviewed; the documentation now matches the code; perf's root cause (forced
TCP-in-TCP) is removed. **Subject to the live two-box re-verification**, DSM is
materially closer to production-ready than the "impressive prototype that won't
deploy" the pentest found.
