# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- A malformed or truncated TCP frame from an unauthenticated peer (oversized
  length prefix, zero-length frame, or EOF mid-frame) no longer crashes the
  server: the accept loop logs it and keeps serving, and the attempt's
  listener is closed so bad frames cannot leak sockets.
- The kill switch accepts ICMP only on the tunnel interface, so the host no
  longer sends or answers ICMP from its real address on the WAN. The one
  exception, in both the full and the pre-handshake rulesets, is inbound
  "fragmentation needed", which path-MTU discovery needs.
- UDP handshakes are validated concurrently (`max_inflight_handshakes`,
  default 8, each attempt capped at 12 s), so one stalled bogus handshake
  can no longer starve a legitimate client.
- The CA certificate must have a P-384 key.
- The cryptography dependency moves to 50.x (`>=50.0.0,<51`), which fixes
  CVE-2026-69247, CVE-2026-69248 and CVE-2026-69249. DSM does not use the
  affected APIs, but older versions failed the dependency audit.

### Fixed
- UDP sessions no longer end within ~50 ms of the handshake: a send before
  the server knows the client's address is dropped instead of shutting the
  session down.
- A wheel-only install can start: the nftables templates ship inside the
  `dsm` package.
- A DNS-proxy bind conflict on :53 (another resolver already listening) is
  a fatal startup error with an actionable message instead of a retry loop.
- `dsm init --install-unit` prints instructions instead of raising when
  `deploy/dsm.service` is not available.
- If the TCP listen port cannot be opened when the server starts (for
  example it is already in use), the server exits with a one-line error.
  Other accept errors are retried after the usual backoff.
- CI no longer tries to install the nonexistent `types-dnspython` package.

### Added
- `server_ip` may be a DNS hostname (e.g. DDNS for a home server); the
  client resolves it once, before the kill switch goes up. The deploy guide
  has a new section on running over the internet.
- A startup warning when the system clock is not NTP-synchronized, and a
  clock-skew hint on handshake freshness errors.
- A wire-parser fuzz harness (`tests/fuzz/fuzz_parsers.py`) and parser
  boundary tests.

### Documentation
- Corrected the default CN format (12 hex characters, bound to the role),
  the server's nftables tables, the DNS-leak drill, the handshake retry
  budget, and the `server_ip` and `allowed_cns_file` requirements.
- Documented build and runtime packages (patchelf, t64 TSS2 names), NTP,
  and installing a prebuilt wheel on a constrained client.
- The README Quickstart states that no release has been published yet.

## [0.1.0] - 2026-06-12

First public release. Pre-1.0: wire / sealed-blob / config formats may still
evolve, so this carries no SemVer-stability promise yet.

Work taking DSM from an internal state to a public, MIT-licensed release.

### Security
- Hardened the crypto glue and unauthenticated-input handling on the server
  data path.
- Closed network-integration gaps: kill-switch / fail-closed behavior on daemon
  failure paths, DNS proxy no longer acting as an open resolver, and safer
  restoration of host `resolv.conf`, IPv6, and sysctl state.
- Added project legal/disclosure files: `LICENSE` (MIT), `SECURITY.md`
  vulnerability-disclosure policy, and this changelog.

### Reliability / data-path correctness
- Fixed server-side forwarding and the broken data path; corrected
  partial-configure and crash-cleanup handling so the host is not left in a
  corrupted networking state.
- Made failure paths exit non-zero so operators get a clear signal instead of a
  silently-dropped kill switch.

### Traffic shaping / anonymity
- Reworked traffic shaping toward an adaptive-envelope model: real packets are
  smoothed into a slowly varying rate envelope with chaff filling to the
  envelope, replacing the previous static-rate approach.
- Scoped the anonymity claims to match the implemented behavior and documented
  the known accepted v1 risks (boot/handshake fingerprint, active-period
  traffic-analysis caveat).

### Hardware attestation
- TPM 2.0 key-residency attestation implemented and shipped as the production
  DEFAULT backend (the `tpm-attest` Cargo feature): the ECDSA P-256 attest key
  is generated in, never leaves, and signs inside the TPM, and the operator
  passphrase is bound as the in-TPM key's authorization value. The extractable
  software backend (`dev-soft-attest`) is retained for dev/CI/eval only.

### Tooling / release engineering
- Fixed the `deploy/openssl-ca.cnf` CA bootstrap so the offline CA config parses
  under OpenSSL (`nameConstraints` corrected; dead `[crl_ext]` removed).
- CI and packaging work toward a reproducible install path and GitHub Releases
  distribution.

[Unreleased]: https://github.com/agam-buhbut/DSM_V2.0/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/agam-buhbut/DSM_V2.0/releases/tag/v0.1.0
