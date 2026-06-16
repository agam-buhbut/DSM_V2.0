# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

_Nothing yet._

## [0.1.0] - 2026-06-12

First public release. Pre-1.0: wire / sealed-blob / config formats may still
evolve, so this carries **no SemVer-stability promise** yet.

Production-readiness work taking DSM from its strong-crypto-core internal state
toward a public, MIT-licensed release. High-level summary:

### Security
- Hardened the crypto glue and unauthenticated-input handling on the server
  data path (malformed handshake messages no longer crash the daemon).
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
