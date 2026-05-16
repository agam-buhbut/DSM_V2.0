DSM_V2.0

Open-source, security and anonymity focused VPN for Linux. Single client-server tunnel with traffic analysis resistance.

GOAL
Provide a highly secure, anonymity-preserving VPN tunnel resistant to ISP surveillance, DPI, traffic analysis, and active adversaries.

NON-GOALS
- Multiple endpoints
- Server hopping
- Geographic location switching
- Large-scale multi-user infrastructure

ARCHITECTURE

Flow:
Client -> Client-Owned Server -> Destination

Components:
- Client: initiates handshake, encrypts traffic, generates chaff
- Server: completes handshake, decrypts and forwards traffic

State Model:
- Session-based finite state machine (6 states)
- IDLE -> CONNECTING -> HANDSHAKING -> ESTABLISHED -> REKEYING -> TEARDOWN -> IDLE

Concurrency:
- Python asyncio (single-threaded async I/O)
- Concurrent recv_loop + tun_send_loop + liveness_loop via asyncio.gather
  (client also runs auto_mtu_loop alongside the others)

NETWORKING

Transport:
- UDP (default)
- TCP (fallback, with 4-byte big-endian length-prefix framing; all frames
  padded to the max size class so the length prefix is constant on the wire)

Connection:
- Single client per server instance (server binds one socket and, for TCP,
  accepts a single connection; for UDP the server locks onto the first
  authenticated peer address)
- Session-based with graceful shutdown (SESSION_CLOSE packet)

Reliability:
- Handshake retransmission with exponential backoff (3 attempts, 1s/2s/4s)
- Bootstrap ephemeral-DH retransmit on lost response (retransmits msg3 +
  bootstrap_init as a pair until timeout)
- Rekey ACK retransmit on loss: if REKEY_ACK does not arrive within
  REKEY_ACK_TIMEOUT=5s, the initiator retransmits the same REKEY_INIT up
  to MAX_REKEY_RETRIES=3 times before giving up. Responder caches the
  last ACK payload so duplicate INITs replay the ACK without re-rotating.
- No application-level retransmission for data packets (relies on inner protocol or TCP)

Fragmentation:
- FRAGMENT packet type (0x07) defined
- Receive-side reassembly implemented (capacity-bounded, 5-second timeout,
  max 16 fragments per ID) and wired into the data path
- Send-side fragmenter implemented: packets larger than the on-wire inner
  budget (max size class minus outer/tag/inner headers ≈ 1360 B) are
  split into up to 16 FRAGMENT inner packets, each chunk sized to fit a
  single padded outer packet

Path MTU:
- Configurable TUN MTU (default 1400, bounds 576-1500)
- Optional kernel-level Path MTU Discovery on the UDP socket
  (IP_PMTUDISC_DO) — sets DF bit, records ICMP "frag needed"
- Client logs the kernel-discovered path MTU on session start and warns
  if the configured tun MTU exceeds the usable inner budget
- Optional `auto_mtu` adapter (client only): a background loop polls
  the kernel-discovered path MTU every `pmtu_check_interval_s` (default
  30 s) and adjusts the TUN MTU. Lower-on-drop is immediate; raise back
  toward `mtu` requires 3 stable observations (hysteresis-gated) so a
  transient PMTU bump can't cause flap. Recommended for cellular /
  roaming clients.

CRYPTOGRAPHY


Key Exchange:
- Noise XX pattern (X25519 + AES-256-GCM + SHA-256)
- Prologue-tagged: "DSM\x00\x01\x00\x01"
- Handshake messages padded to 1400 bytes (constant size)
- Each peer carries a CA-signed device cert (X.509, ECDSA P-256 leaf
  signed by an internal P-384 CA) inside the Noise XX msg2/msg3 payload
- The cert binds the device's hardware-bound ECDSA signing pubkey AND
  the device's X25519 Noise static (via custom critical extension
  id-dsm-noiseStaticBinding 1.3.6.1.4.1.99999.1.1)
- Per-handshake binding signature over the Noise handshake hash +
  remote_static + role, signed by the attest key — replay-resistant
- Server enforces a CN allowlist (one CN per line in allowed_cns_file);
  client checks the server cert's CN against expected_server_cn
- Optional CRL distributed via walked-USB on the offline-CA cadence

Key Rotation:
- Every 5000 packets or 600 seconds (configurable)
- Ephemeral X25519 DH per rotation
- HKDF-SHA256 key derivation with direction-specific labels and epoch in info
- 5-second grace period for in-flight packets from previous epoch
- Rate-limited to one rotation per 60 seconds

Encryption:
- AES-256-GCM (AEAD) with sequence number as AAD

Nonce Strategy:
- Structured 96-bit nonce: epoch(32) || counter(32) || random(32)
- Counter provides uniqueness guarantee within an epoch
- Random component prevents predictability
- Epoch separation prevents cross-rotation collisions
- Counter is poisoned on exhaustion (returns None permanently) to prevent
  nonce reuse if a session is somehow continued past 2^32 packets

Replay Protection:
- 128-bit sliding window bitmap (separate window per epoch during grace)
- Check-before-decrypt, update-after-authentication

Key Storage:
- Identity (X25519 Noise static) AND attest key (ECDSA P-256, soft
  backend) both encrypted at rest with Argon2id + XChaCha20-Poly1305
- Argon2id parameters: 512 MiB memory, 4 iterations, 2 parallelism
- Memory locked (mlock) during use
- Single-pass zeroization via Rust zeroize crate on drop
- Core dumps disabled at startup (setrlimit RLIMIT_CORE)
- Atomic file writes with 0600 permissions (tmpfile -> fchmod -> fsync -> rename)
- TPM 2.0 backend for the attest key is on the punch list (Phase 1
  step 5); when shipped, the on-disk attest blob is replaced by a TPM
  persistent handle.

ANONYMITY AND TRAFFIC RESISTANCE

Padding:
- 11 size classes: 128, 256, 384, 512, 640, 768, 896, 1024, 1152, 1280, 1400 bytes
- Inner padding fills the AEAD envelope to the target class boundary so no
  unauthenticated outer padding remains on the wire
- TCP frames padded to max size class (1400) for constant wire size

Chaff:
- Adaptive chaff generation mirroring real traffic patterns
- Active mode: rate tracks real traffic (0.5x-1.5x multiplier, resampled
  every 1-3s)
- Idle mode: burst patterns mimicking browsing (exponential inter-burst gaps)
- Size distribution mirrors observed real traffic via exponential moving
  average; chaff size occasionally perturbed ±1 class to decorrelate

Timing:
- Configurable jitter (default 1-50ms) on all outgoing packets
- Send scheduler with priority queue and randomized delays

Leak Prevention:
- nftables kill switch blocks all non-VPN traffic
- mDNS (5353) and LLMNR (5355) blocked to prevent LAN enumeration
- DNS (53, 853) on non-TUN interfaces blocked except to server IP
- VPN sockets marked with SO_MARK=0x1 so the ip-rule skips the TUN table
  and avoids routing loops

DNS:
- Resolution module implemented (DoH, DoT, static hosts file, caching)
- Server-side DNS interception wired into the data path (UDP:53 intercept,
  async resolution, encrypted response back to client)

THREAT MODEL

Adversaries:
- ISP surveillance
- DPI systems
- Active MITM attackers
- State-level adversaries
- Hostile/unsecured WiFi networks

Assumptions:
- Network is hostile
- Server is trusted (operator-owned)
- Client device is physically secure

Out of Scope:
- Physical access to client/server
- Compromised dependencies or libraries
- Anonymity from the server operator (server sees client IP)

IMPLEMENTATION

Languages:
- Python (protocol, networking, traffic shaping, session management)
- Rust via PyO3 (cryptographic primitives, key management, memory protection)

Rust crate (tuncore):
- AES-256-GCM encrypt/decrypt
- X25519 key exchange
- Noise XX handshake (via snow crate, with fixed-size attest payload)
- HKDF-SHA256 key derivation
- Argon2id password hashing
- Nonce generation with structured uniqueness and exhaustion poisoning
- Replay window (128-bit bitmap)
- Secure memory (mlock, zeroize, core dump disable)
- Identity + attest key storage (XChaCha20-Poly1305)
- ECDSA P-256 device-attestation soft backend (dev/CI only)

Dependencies:
- Python: cryptography (X.509 cert + CRL parsing), dnspython (server
  DNS proxy wire-format parsing). DoH transport is a hand-rolled
  asyncio TLS + HTTP/1.1 path so the SPKI pin can be checked on the
  live SSL object BEFORE the qname crosses the wire — no httpx.
- Rust: snow, aes-gcm, hkdf, sha2, x25519-dalek, zeroize, argon2,
  chacha20poly1305, hmac, subtle, libc, rand/rand_core, serde, pyo3,
  plus rcgen (gated on the soft-attest path for in-Rust CSR
  generation) and p256 (optional, gated on `dev-soft-attest` Cargo
  feature — the default).

CONFIGURATION

Format: TOML
Path: /opt/mtun/config.toml

Parameters:
- mode: client | server
- server_ip: literal IPv4/IPv6 address ONLY (hostnames are rejected;
  the kill-switch nftables rules cannot resolve names. Run
  `dig +short <host> | head -1` and put the resulting IP here)
- server_port, listen_port
- key_file: path to Argon2id-wrapped X25519 Noise static key
- cert_file: path to the device's CA-signed leaf cert (PEM or DER)
- ca_root_file: path to the pinned CA root cert (PEM)
- attest_key_file: path to Argon2id-wrapped ECDSA P-256 attest key
- crl_file: optional path to the CA's CRL (PEM or DER)
- expected_server_cn: client only; subject CN we accept on the server cert
- allowed_cns_file: server only; one allowed client subject CN per line,
  root-owned, mode 0o600 (any group/world bit causes startup to refuse
  to load the file)
- transport: udp | tcp (default: udp)
- dns_providers: DoH/DoT URLs (server mode)
- dns_provider_pins: SPKI SHA-256 pins per provider (server mode, required)
- tun_name: TUN device name (default: mtun0)
- mtu: TUN interface MTU in bytes (default: 1400, bounds 576-1500)
- pmtu_discover: enable kernel PMTUD on UDP socket (default: false).
  Required for `auto_mtu` to do anything — the kernel only tracks per-
  path MTU when this is on.
- auto_mtu: client-side adaptive TUN-MTU loop (default: false). Lower
  on PMTU drop; raise back toward `mtu` after 3 stable observations.
  Recommended for cellular / roaming clients.
- pmtu_check_interval_s: how often the auto_mtu loop polls the kernel
  PMTU, seconds (default: 30, bounds (0, 3600]).
- log_level: debug | info | warning | error (default: info — operational
  lines like "server forwarding subsystem active", "MASQUERADE for
  mtun0 applied", "tunnel established", "client connected" only appear
  at info or below. Use "debug" for protocol-level packet tracing.)
- padding_min, padding_max: padding range (default: 128-1400)
- jitter_ms_min, jitter_ms_max: jitter range in ms (default: 1-50)
- rotation_packets, rotation_seconds: key rotation thresholds (default: 5000/600)
- debug_dns: log plaintext DNS queries (default: false, logs are redacted)
- debug_net: emit structured JSON events on the `dsm.netaudit` logger
  (handshake start/end, nft apply/remove, TUN configure/deconfigure,
  rekey, liveness, shutdown, auto_mtu_change). Default: false. May
  also be enabled per-run via the `--debug-net` CLI flag.

OPERATOR GUIDE

The full step-by-step operator walkthrough — prerequisites, build,
offline-CA bootstrap, per-device enrollment, run, verification, common
operator tasks (rotation/revocation/CRL refresh), single-host smoke
test, two-box demo across two real ISPs, symptom-keyed debugging,
uninstall, file-placement reference, and CLI reference — lives in:

    deploy/GUIDE.txt

Every command in that guide is copy-paste-runnable and was cross-
checked against the current codebase. Companion config files in the
same directory:

    deploy/openssl-ca.cnf  — OpenSSL config used by the offline CA
    deploy/dsm.service     — systemd unit for the daemon

LOGGING

Default: log_level = "info". This shows operational lifecycle lines
(listening, handshake complete, connected, configured, MASQUERADE for
<iface> applied, sysctl changes, shutting down) without per-packet
noise. Recommended for both initial deployment and steady-state
operation.

- log_level = "debug" for protocol-level tracing (every packet class,
  every retry, every key derivation step). Verbose; use during
  bring-up or to diagnose specific protocol bugs.
- log_level = "warning" or "error" if you only want exceptional
  events. NOTE: at warning, you will not see "tunnel established",
  "MASQUERADE applied", or other normal-operation lines, which makes
  diagnosing "is the new code running?" much harder.

TESTING

- 253 Python tests (unittest, discovered by pytest)
- 103 Rust tests (cargo test --features dev-soft-attest)
- Covers: protocol serialization, FSM transitions, config validation
  (including auto_mtu/pmtu_check_interval bounds), replay window, nonce
  generation (including exhaustion), key rotation, AES-GCM, identity +
  attest-key storage (Argon2id + XChaCha20), Noise XX handshake (with
  fixed-size attest payload), X.509 cert parse + chain validation,
  noiseStaticBinding extension validation, attest-payload build/verify,
  CN allowlist + CRL, device enrollment (CSR build + signed-cert import
  with binding/SPKI/chain checks), post-handshake DH bootstrap, full
  end-to-end handshake over UDP and TCP with cert policy, full data path
  (TUN -> fragment -> encrypt -> wire -> decrypt -> reassemble -> TUN)
  round-trip, rekey with duplicate-INIT idempotency and retry-on-timeout
  scheduler, handshake retry under simulated cellular outage,
  auto_mtu adapter (lower/raise/floor/ceiling/oscillation/shutdown),
  netaudit JSON event stream + schema lock, DNS proxy coalescing and
  semaphore bounds, IPv6 state save/restore, CLI subcommands, PMTU
  sockopt plumbing.

Run:
   $ python3 -m pytest tests/ -q
   $ cd rust/tuncore && cargo test --features dev-soft-attest


ROADMAP

The current build (Phase 1 + Phase 2A) ships single-client, single-server,
Linux-only with cert-based auth (CA-signed device certs binding the
hardware ECDSA attest key to the X25519 Noise static via a custom
critical X.509 extension). Live items on the punch list:

- Phase 1 step 5 — TPM 2.0 attest backend (`tpm-attest` Cargo feature
  via tss-esapi). Parked until TPM hardware is available for empirical
  testing; the soft attest backend is the default and works end-to-end.
- Phase 2B — real-network demo on two physical Linux boxes across two
  ISPs (home Wi-Fi server + cellular client). Procedure in
  deploy/GUIDE.txt §9; once the strace-audit step there closes,
  RestrictNamespaces and SystemCallFilter land in deploy/dsm.service.
- Phase 3 — Android client (Kotlin VpnService + JNI to the Rust crate,
  with hardware-bound signing via Android Keystore/StrongBox). The
  protocol state machine is lifted into Rust as part of this phase so
  there is one implementation across Linux + Android.
- Phase 4 — third-party pentest: threat model authoring, hardening
  checklist execution, telemetry build toggle, engagement coordination.

Explicit non-goals (reaffirmed):
- Multiple clients per server / multi-tenant infrastructure — out of
  scope by design (NON-GOALS at top of file).
- Server hopping / relay chains / geographic load balancing — out of
  scope; the threat model assumes a single client-owned server.
