# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- A lost key-change reply (REKEY_ACK) no longer breaks the session: the
  side that answers keeps its old keys until the other side uses the new
  ones (at most 110 s), so a resent request can still be answered.
- A lost key-change request is now resent after 1.5 s and 2.5 s, then every
  8 s (10 resends), counted from when it really goes out.
- **Breaking:** traffic shaping now uses fixed rate steps ("tiers") instead
  of the adaptive envelope. Packets leave at a steady rate that only moves
  between a few set speeds. Your real packets take free places and fake
  packets (chaff) fill the rest. Apart from fake busy periods (below), the
  rate goes up when real packets have waited too long or have filled nearly
  all of a tier for a few seconds, and it comes down slowly, a few minutes
  per step.
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
- **Breaking:** DSM no longer reads `/opt/mtun/hosts.txt` (fixed
  name-to-address answers on the server). It had no owner or mode check,
  and an IPv6 line made the answer fail. To block names, use the DNS
  blocklist (below).

### Security
- **Behavior change:** the client no longer fails open. Before, every end
  of a session the user did not ask for (a failed handshake, 60 s without
  packets from the server, the server closing the session, a TCP reset, a
  key change that gave up, an error in a data loop) removed the kill
  switch and exited, so all traffic went out in the clear; someone on the
  network could cause that by dropping packets for a minute. Now the
  client swaps back to the start-up kill switch in one nft step and
  reconnects by itself (1 s, doubling to 30 s, no limit). The kill switch
  comes down on Ctrl-C (a run by hand), `systemctl stop` or
  `sudo dsm cleanup`. A `systemctl stop` sent while DSM waits to restart
  (after a crash or a signal sent straight to it) leaves it up: run
  `sudo dsm cleanup`. A crash leaves it up, and the next start replaces it
  in one step. Setup errors at the first start (passphrase, keys, cert, a
  UDP port in use, a read-only resolv.conf) still remove it and exit 1;
  under `dsm-client.service` a UDP port in use keeps it and retries.
  Server cert and CN errors in the handshake now keep the block and retry,
  because someone on the network can send them. Once a handshake with it
  works, the address found for a server name is saved in
  `/run/dsm/server-endpoint.json`; a later start whose lookup is blocked
  (for example by a kill switch a crash left up) uses it instead of
  exiting.
- Handshake hardening on the server (no wire change):
  - A new UDP sender must open with a full 1400-byte handshake frame.
    Anything else is dropped before it can take a handshake slot.
  - Failed handshakes no longer pause the server. Before, after 3 failures
    in a row it stopped reading all handshake packets for about 1.5-6 s
    for every new sender, so a few junk packets could stall real clients.
  - One address may run at most 2 handshakes at once and start 3 at once,
    then 1 every 4 s; all addresses together may start 8 at once, then 4 a
    second. Refused UDP packets get no answer; refused TCP connections are
    closed at once. The log says why (an INFO line), without the address, at
    most once per 10 s per reason. A wrong-size packet logs nothing at INFO
    (DEBUG only).
  - TCP: the server keeps one listener open while handshakes run and checks
    connections side by side, with the same limits and the same 12 s cutoff
    per attempt as UDP. Before, one silent connection held the port for up
    to 30-48 s and every other client was refused.
- A malformed or truncated TCP frame from an unauthenticated peer (oversized
  length prefix, zero-length frame, or EOF mid-frame) no longer crashes the
  server: only that connection is closed and the server keeps serving.
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
- The client's new UDP socket after a key change no longer sets
  `SO_REUSEADDR`. Before, another program on the same machine, even
  without special rights, could bind the same port and get the server's
  packets instead of DSM.

### Fixed
- A client that resends its first handshake message, because the server's
  reply was lost or slow, no longer makes the server drop the attempt. The
  server skips the copy and goes on waiting for the client's next message.
- A client whose third handshake message is slow no longer fails when the
  server sends its second message again: the client skips the copy and
  goes on waiting for the server's last handshake message.
- The server now also ignores a repeated copy of the client's third
  handshake message while it waits for the next frame. Before, if the
  client's next message was lost or late, the client resent the third
  message first and the server failed the attempt on that copy.
- The client no longer loses the server's packets after each key change.
  It moves to a new port then, and the server keeps sending to the old one
  until the new one passes its address check. The old port closed after
  0.25 s, which was too short on slower links; it now stays open 5 s.
- A download that slows down to the speed it gets (as TCP does) no longer
  stays at a low tier for its whole length. Its packets never waited long
  enough to step the rate up: in a live test a 50 MB download stayed at
  about 1.8 Mbit/s. Now, when real packets fill nearly all of a tier for 1
  to 3 seconds (and over at least 200 free places, so 3 to 5 seconds at
  tier 1), the rate climbs one tier, the same way a decoy aimed one tier
  up climbs. The rate also steps down when your use would fit the lower
  tier with room to spare, so steady use that fits a lower tier does not
  stay at the top. A full-tier step comes a few seconds after the step
  before it, so decoys now pause between steps the same way, now and then:
  one climb no longer gives itself away by such a pause. Known limit: the
  decoys' pauses only roughly match real ramp-up times, so many climbs
  from one user might still be told apart by statistics.
- On a host with strict reverse-path filtering, the client no longer cuts
  itself off from its own local network: ARP requests from the router (or a
  DSM server on the same network) were dropped, so incoming traffic stopped
  for tens of seconds whenever an ARP entry expired. Local-network routes now
  stay out of the tunnel, as with WireGuard; the kill switch still blocks
  that traffic.
- The client now works on hosts with strict reverse-path filtering
  (`rp_filter=1`, common on hardened systems). Before, the handshake
  worked but no replies came back.
- `dns_providers` or a pin value written as a single string instead of a
  list is now a clear config error, not a confusing error about single
  letters.
- `dns_provider_pins` written as a plain value (a string or list) instead
  of a `[dns_provider_pins]` section is now a clear config error naming the
  key, not a crash at server start.
- A client whose set `listen_port` is already in use now exits with one
  clear error line instead of a Python traceback.
- The client no longer crashes when /etc/resolv.conf is a mount point (in
  containers and `ip netns exec`): it writes the file in place, or exits
  with one clear error line if it cannot write it at all.
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
- `deploy/dsm-client.service`, a systemd unit for clients (`--mode client`,
  `Restart=always`). It removes the kill switch only for `systemctl stop`;
  `systemctl restart dsm-client`, a signal sent straight to DSM and a
  shutdown or reboot keep it up (new flag `--stop-keeps-block`, which the
  unit passes).
  `install.sh --systemd --client` and `dsm init client --install-unit`
  install it; before, every install path put the server unit on a client,
  where it could not start.
- Server DNS blocklist, on by default (`dns_blocklist`). The server answers
  "no such name" (NXDOMAIN, which devices remember for 5 minutes) for every
  name on the lists in `/opt/mtun/dns/block/*.txt` and every name under
  a listed name, for every query type. Names in `/opt/mtun/dns/allow.txt`, and
  `@@||name^` lines, are never blocked. Lists may be hosts files (any
  address in front of a name blocks it), one name per line, or `||name^`
  lines. DSM checks the folder every 5 minutes. If any one file is refused,
  it skips the whole new load, keeps the lists it has and logs one warning;
  it logs only counts and file paths, never names. DSM never downloads:
  `deploy/dsm-blocklist-update.sh` and a daily timer fetch the URLs in
  `/opt/mtun/dns/sources.txt`, and `install.sh --systemd` installs them and
  fetches the default list (StevenBlack/hosts) once. With the blocklist on,
  `use-application-dns.net` always gets "no such name", even if it is on the
  allowlist; that tells Firefox not to switch to its own encrypted DNS. A
  config that sets `dns_blocklist` does not load in an older DSM.
- Slow-link auto cap. Each end now tells the other, about once a second,
  how many packets arrived. An end that loses 5% or more of what it sends
  for two seconds in a row, at tier 2 or higher, lowers its top tier one
  step (never below tier 1) and tries the higher step again after 5
  minutes, waiting longer (up to an hour) while the loss comes back. The
  gap between reports is random, 0.5 to 1.5 s (1 s on average), so there
  is no fixed 1 s beat that a watcher could use to pick them out. Junk
  that reaches an end (packets that fail to decrypt, are too short or are
  replays, that overflow the receive queue, or that the client's source
  filter drops) does not count as loss: packets missing in a stretch
  between two reports in which junk came in are reported as arrived, so a
  junk flood cannot force the cap down. On by default;
  `shaper_auto_cap = false` turns it off at either end. Mixed
  versions keep working: an older end drops the new report quietly, and a
  newer end facing an older one never caps. A config that sets
  `shaper_auto_cap` does not load in an older DSM.
- A warning, at most every 10 minutes, when the link still loses packets
  after auto cap has already dropped to tier 1, where it cannot go lower.
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
