# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- A lost key-change reply (REKEY_ACK) no longer breaks the session: the
  side that answers keeps its old keys until the other side uses the new
  ones (at most 75 s), so a resent request can still be answered.
- A lost key-change request is now resent after 1.5 s and 2.5 s, then every
  8 s (10 resends), counted from when it really goes out.
- **Breaking:** traffic shaping now uses fixed rate steps ("tiers") instead
  of the adaptive envelope. Packets leave at a steady rate that only moves
  between a few set speeds. Your real packets take free places and fake
  packets (chaff) fill the rest. Apart from fake busy periods (below), the
  rate goes up only when real packets have waited too long, and it comes
  down slowly, a few minutes per step.
  Fake busy periods ("decoys") climb and come down like real use, and each
  session picks, and now and then changes, its own secret timing values.
  The timing and size decisions now run in the Rust core (`tuncore`), and
  the size list lives there too. So `dsm.core.protocol`, and every module
  that uses it, no longer loads without the built extension.
- The default `mtu` is now 1360 (was 1400). One DSM packet carries at most
  1360 bytes, so at 1400 every full-size packet was split in two, which
  halved top speed. Configs that set `mtu = 1400` keep the old behavior.
- A second DSM on a UDP port that is already in use now fails at start with
  a clear error. Before, both could share the port and each got only some
  of the packets, so sessions broke with no error.
- A queued packet now takes the next free place, with no random extra wait.
- The send loop no longer wakes up early when a packet is queued, so send
  times do not drift toward your real traffic.
- The resent key-change reply and the server's address check now take
  normal free places instead of going straight out.
- Control messages (key changes and address checks) wait in their own small
  queue that is sent before any data. A full data queue can no longer hold
  them up for seconds or drop them, which could break a key change.
- More cover traffic by default: about 3 GB a day per direction when
  connected all day with decoys on, about 6 GB with some real use.
  `config.example.toml` lists the costs.
- The first tier must be fast enough for the latency budget:
  `shaper_tiers_pps[0]` must be above 4.25 divided by the budget in seconds
  (above 8.5 packets per second at the default 500 ms). DSM refuses a
  slower first tier at startup, because it would let light traffic change
  the send times.
- Before dropping to idle, the rate waits at tier 1 (`shaper_linger_s`,
  5 to 30 minutes by default). If the link is still in use when that wait
  ends, the rate stays at tier 1 instead of dropping to idle.

### Removed
- **Breaking:** the six `envelope_*` config keys. Use `shaper_tiers_pps`,
  `shaper_latency_budget_ms`, `shaper_decoy_interval_s` and
  `shaper_linger_s` instead. A config that still has an `envelope_*` key
  stops at startup with a message that names the new keys.
- **Breaking:** `jitter_ms_min` and `jitter_ms_max`. A config that still has
  them stops at startup with a clear message.
- The send loop's mode without the tier shaper, so the send loop cannot
  send unshaped traffic by mistake.

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
- DNS names in logs are now shown as `qname-tag=` and 16 hex characters of
  a keyed hash (HMAC-SHA256) under a random key made at each start. They
  used to be a plain SHA-256 prefix (`qname-sha256=`), which anyone with a
  list of popular sites could reverse. The same name keeps its tag while
  DSM runs and gets a new tag after a restart.

### Fixed
- `dns_providers` or a pin value written as a single string instead of a
  list is now a clear config error, not a confusing error about single
  letters.
- `dns_provider_pins` written as a plain value (a string or list) instead
  of a `[dns_provider_pins]` section is now a clear config error naming the
  key, not a crash at server start.
- A client whose set `listen_port` is already in use now exits with one
  clear error line instead of a Python traceback.
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
- If the UDP listen port cannot be bound when the server starts (for
  example another program already holds it), the server exits with a
  one-line error and status 1 instead of a Python traceback.
- A setting written below the `[dns_provider_pins]` header was read as a
  pin and silently ignored. Every `dns_provider_pins` name must now be
  listed in `dns_providers`; otherwise DSM stops at startup with a message
  that names the entries and says how to fix them.
- CI no longer tries to install the nonexistent `types-dnspython` package.
- Warnings that can fire once per packet (a full send or receive queue, a
  failed send, an unexpected error in the send loop, a UDP socket error) no
  longer flood the log: each is logged once, then at most once every 10
  seconds with a count.
- A huge number in `shaper_tiers_pps` or `shaper_linger_s` stops startup
  with the usual one-line config error naming the key, not a traceback.

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

## [0.1.0] - not released yet

Planned as the first public release; it has not been tagged or published.
Pre-1.0: wire / sealed-blob / config formats may still evolve, so this
carries no SemVer-stability promise yet.

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
- Reworked traffic shaping toward an adaptive-envelope model: real packets
  were smoothed into a slowly changing rate, with chaff filling up to it,
  replacing the earlier fixed-rate approach. The tier shaper has since
  replaced this model (see Unreleased).
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
