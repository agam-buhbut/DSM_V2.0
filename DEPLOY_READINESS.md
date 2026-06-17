# DSM v2.0 — Live-Deploy & Pentest Readiness

> Prepared 2026-06-17 for an imminent two-box live deployment + pentest.
> Companion to `PENTEST.md` (the pentest plan, now corrected) and
> `PRODUCTION_REVIEW.md` (the prior full review that drove Phases 0–5).

## Bottom line

The crypto/protocol engine was already proven over real sockets (637-test
suite). This pass attacked the **untested OS-integration + first-bring-up
surface** — the part that had never run on real hardware. Two real deploy
blockers were found by actually executing the bring-up path and are fixed and
verified; the GUIDE/example deploy traps are fixed; `PENTEST.md` is corrected so
its commands actually run. **9 lower findings remain for owner review** (none
block a first connection; 3 are pentest-relevant HIGHs).

---

## Empirically verified this session (actually executed, not just read)

Run root-free with a `dev-soft-attest` build against a throwaway CA in `/tmp`:

| Step | Result |
|---|---|
| **CA bootstrap** — `openssl req -x509` w/ `deploy/openssl-ca.cnf` (OpenSSL 3.5.6) | ✅ self-signs; nameConstraints parse (prior H12 breakage confirmed fixed) |
| **Initial CRL** — `openssl ca -gencrl` | ✅ produces a valid CRL |
| **Enrollment round-trip** — `dsm enroll --csr-out` → `openssl ca` sign → `dsm enroll --import` | ✅ after the cert-PEM fix below |
| **Config perm gate** — 0644 `config.toml` | ✅ rejected ("chmod 600") — GUIDE's `sudo tee` trap confirmed |
| **CRL-strict gate** — `crl_strict=true` + no `crl_file` | ✅ refuses to start — confirmed |
| **nft fail-closed** — server start without CAP_NET_ADMIN | ✅ now a clean "refusing to start (fail-closed)" exit, not a traceback |

---

## Fixes applied this session (all gate-green: black/isort/ruff, pylint 10.00, pyright 0)

### Code (verified)
1. **Cert import rejected GUIDE-produced certs** — `dsm/crypto/cert.py`. `openssl ca`
   without `-notext` prepends a text preamble; `from_pem_or_der` sniffed with
   `startswith(b"-----BEGIN")` and mis-routed it to the DER parser →
   `dsm enroll --import` failed on a clean box. Now sniffs for the PEM marker
   anywhere. **Deploy blocker.** Test: `tests/test_cert_pem_preamble.py`.
2. **Server crashed when one session's host-setup failed** — `dsm/server.py` (lc-1).
   `_run_one_session` (TUN/DNS-proxy/sysctl) ran with no guard in the re-accept
   loop; any setup error downed the daemon for *all* future clients. Now caught,
   logged, FSM reset to IDLE (`_drive_fsm_to_idle`), loop continues.
   Test: `tests/test_server_session_recovery.py`.
3. **Clean fail-closed on missing/unresolvable nft** — `dsm/server.py`,
   `dsm/client.py`. Broadened the fail-closed catch to `OSError` so an absent
   `nft` (FileNotFoundError) yields the actionable "refusing to start" exit
   instead of a raw traceback (verified live).
4. **PATH determinism for privileged tools** — `deploy/dsm.service`. Pinned
   `Environment="PATH=/usr/sbin:/usr/bin:/sbin:/bin"` so `nft`/`ip`/`sysctl`
   resolve regardless of host PATH (os-1's primary fix; covers non-merged-usr
   hosts where `/sbin` is off systemd's default PATH).
5. **`auto_mtu` silent no-op** — `dsm/core/config.py` (os-3). `auto_mtu` needs
   `pmtu_discover` to read kernel PMTU; without it the feature was inert and
   silent. Now warns at validation.

### Docs (deploy blockers)
6. **`deploy/GUIDE.md`** — config writes switched to `install -m 0600` (0644 was
   rejected, cfg-3); explicit initial-CRL generation + distribution step (ca-2);
   `-notext` on signing; cert filename/path bridging fixed (ca-3); §8 smoke-test
   sets `crl_strict=false` for the lab (cfg-1).
7. **`config.example.toml`** — "will NOT boot as-shipped" header; `crl_strict=false`
   documented dev escape-hatch with the production tradeoff spelled out (cfg-2);
   64-zero `ca_root_sha256` placeholder (rejected at CA-load).
8. **`PENTEST.md`** — 10 corrections (ph-1..ph-10): T07 missing `nfq.run()`;
   scapy UDP-checksum clears; netns harness `allow_soft_attest`/`crl_strict`;
   correct nft table names (`dsm_killswitch_pre`, `dsm_dns_leak`); roaming
   timeout 5s; `tcprewrite` before `tcpreplay`; port/outer-pad fact fixes; tools.

---

## Residual findings — for owner review (NOT changed this session)

None block a first **connection**. Severity is from the audit's adversarial verify.

| Sev | Pentest | ID | Finding & recommended fix |
|---|---|---|---|
| HIGH | ✓ | os-2 | **Server DNS proxy reachable off-tunnel** via source-IP spoofing (app-layer source filter is spoofable on a shared LAN; weak-host model + `rp_filter=2`). *Note:* not reachable in the port-forward+NAT scenario (only `:51820` is forwarded). Fix: server nft input rule `iifname != "<tun>" udp/tcp dport 53 drop`, or `SO_BINDTODEVICE(tun)` on the proxy socket. Left unimplemented to avoid socket/nft plumbing risk right before deploy. |
| HIGH | ✓ | dos-1/2 | **Serial handshake acceptor** — one slow/bogus `msg1` stalls new clients ~18–30s; the nft meter caps floods but not a single slow handshake. This is the **owner-deferred #5**; design at `docs/superpowers/plans/2026-06-16-concurrent-handshake-acceptor.md`. `PENTEST.md` T10 measures it. |
| MED | – | os-4 | Default `mtu=1400` + DF off + PMTUD off can black-hole on a sub-1468 NAT path ("connects, ping works, pages hang"). Partially mitigated by the existing `mtu>1400` warning + the new os-3 warning. Consider defaulting `pmtu_discover=true` (+`auto_mtu=true`) for cellular clients. |
| MED | ✓ | cfg-5 | `config.toml` owner-check can fail if the example is copied as a non-root user then run under sudo. Operator hygiene (`chown root:root`). |
| LOW | – | os-5 | Server MASQUERADE fails **open** (warn only) while kill-switch/rate-limiter fail closed. By design (tunnel still forms; no egress) — consider a louder error. |
| LOW | ✓ | ca-4 | `copy_extensions = copy` lets a CSR carry an unrequested SAN. Mitigated by the GUIDE's "verify the cert before signing" step. |
| LOW | – | ca-5 | Stale comment: `cert.py` says CA signs SHA-256; `openssl-ca.cnf` uses SHA-384. Comment-only. |
| LOW | – | lc-3 | Server applies nft rate-limiter + tcp_timestamps sysctl just before signal handlers (small unwind-window analog of the client #7 fix). |

**Also deferred (owner approval needed):** an `nft_binary()` absolute-path
resolver was implemented + verified, then **reverted** because it changes the
`nft` argv that 5 existing tests assert (`["nft", ...]`), and modifying tests is
a standing no-go without approval. The dsm.service PATH pin (#4) covers the same
risk for real deploys. Re-apply + update those 5 assertions on request.

---

## Pre-deploy checklist (owner)

- [ ] Install `nftables`, `iproute2` on both boxes (`nft --version`, `ip link`).
- [ ] Bootstrap CA per GUIDE §2 (now includes the initial CRL step).
- [ ] Enroll server then client; `config.toml` ends up mode **0600** (GUIDE now
      uses `install -m 0600`).
- [ ] Decide CRL: production keep `crl_strict=true` + provision `crl_file`;
      lab/loopback may set `crl_strict=false` (documented).
- [ ] **Run GUIDE §8 single-host loopback smoke test first** — it exercises the
      real TUN + nft + routing on one box before the two-box run.
- [ ] Pentest box: install `tcpdump python3-scapy python3-netfilterqueue
      hping3 tcpreplay` (per corrected `PENTEST.md` §5).

## Build / test notes

- Full gate: black, isort, ruff clean; **pylint dsm 10.00/10**; **pyright 0
  errors**; **pytest 647 passed / 12 skipped / 19 subtests, 0 failed**.
- Validation used a `dev-soft-attest` build in `/tmp/dsm-soft-venv` (no TPM in
  this environment); production is the default `tpm-attest` build. All changes
  are pure-Python / config and backend-independent.
