# DSM_V2.0

Open-source, security and anonymity focused VPN for Linux. Single client-server tunnel with traffic analysis resistance.

## Quickstart

> **Supported target:** Debian 12+ / Ubuntu 22.04+ / x86_64 with a **TPM 2.0**.
> Other distros: build from source (see `deploy/GUIDE.md` §1). No PyPI — DSM is
> distributed via signed GitHub Releases.

```sh
# 1. Install (downloads + minisign-verifies the wheel, apt-installs the TPM
#    runtime libs, creates /opt/dsm/venv, symlinks `dsm`, installs the unit).
#    TODO(owner): replace <OWNER/REPO> with the real repo before release.
curl -fsSL https://github.com/<OWNER/REPO>/releases/download/v0.1.0/install.sh | sudo sh

# 2. Go from zero to running (orchestrates config + CA-pin + enroll + TPM + unit).
sudo dsm init server      # or, on the client box:  sudo dsm init client
#   ...prompts for IP/port/paths/CA-root/passphrase; pauses for the offline-CA
#   signing step; resume with:  sudo dsm init server --resume

# 3. Start it.
sudo systemctl enable --now dsm
```

**Evaluation without a TPM:** a clearly-named `+soft` evaluation wheel is also
published. Install it with `install.sh --eval`. It provides **no hardware
binding** — it is for evaluation only and must never be deployed in production.

## Goal

Provide a highly secure, anonymity-preserving VPN tunnel resistant to ISP surveillance, DPI, traffic analysis, and active adversaries.

## Non-Goals

- Multiple endpoints
- Server hopping
- Geographic location switching
- Large-scale multi-user infrastructure

## Architecture

**Flow:**

```
Client -> Client-Owned Server -> Destination
```

**Components:**

- Client: initiates handshake, encrypts traffic, generates chaff
- Server: completes handshake, decrypts and forwards traffic

**State Model:**

- Session-based finite state machine (6 states)
- `IDLE -> CONNECTING -> HANDSHAKING -> ESTABLISHED -> REKEYING -> TEARDOWN -> IDLE`

**Concurrency:**

- Python asyncio (single-threaded async I/O)
- Concurrent recv_loop + tun_send_loop + liveness_loop via asyncio.gather
  (client also runs auto_mtu_loop alongside the others)

## Networking

**Transport:**

- UDP (default)
- TCP (fallback, with 4-byte big-endian length-prefix framing; all frames
  padded to the max size class so the length prefix is constant on the wire)

  IMPORTANT — TCP is "obfuscation only against simple DPI", not against
  passive traffic analysis. The TCP handshake (SYN / SYN-ACK / ACK),
  teardown (FIN / RST), and connection-establishment fingerprint
  remain visible to a passive on-path adversary regardless of DSM's
  inner padding/timing defenses. TLS-fronting (wrapping the wire in
  a TLS connection that mimics a common origin) would close this gap
  but is intentionally out of scope. Use UDP for the strongest
  anonymity properties this codebase provides; reach for TCP only
  when a network strictly blocks UDP or NAT-symmetric routing makes
  UDP unusable.

**Connection:**

- Single client per server instance (server binds one socket and, for TCP,
  accepts a single connection; for UDP the server locks onto the first
  authenticated peer address)
- Session-based with graceful shutdown (SESSION_CLOSE packet)

**Reliability:**

- Handshake retransmission with exponential backoff (3 attempts, 1s/2s/4s)
- Bootstrap ephemeral-DH retransmit on lost response (retransmits msg3 +
  bootstrap_init as a pair until timeout)
- Rekey ACK retransmit on loss: if REKEY_ACK does not arrive within
  REKEY_ACK_TIMEOUT=5s, the initiator retransmits the same REKEY_INIT up
  to MAX_REKEY_RETRIES=3 times before giving up. Responder caches the
  last ACK payload so duplicate INITs replay the ACK without re-rotating.
- No application-level retransmission for data packets (relies on inner protocol or TCP)

**Fragmentation:**

- FRAGMENT packet type (0x07) defined
- Receive-side reassembly implemented (capacity-bounded, 5-second timeout,
  max 16 fragments per ID) and wired into the data path
- Send-side fragmenter implemented: packets larger than the on-wire inner
  budget (max size class minus outer/tag/inner headers ≈ 1360 B) are
  split into up to 16 FRAGMENT inner packets, each chunk sized to fit a
  single padded outer packet

**Path MTU:**

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

## Cryptography

**Key Exchange:**

- Noise XX pattern (X25519 + AES-256-GCM + SHA-256)
- Prologue-tagged: `"DSM\x00\x01\x00\x01"`
- Handshake messages padded to 1400 bytes (constant size)
- Each peer carries a CA-signed device cert (X.509, ECDSA P-256 leaf
  signed by an internal P-384 CA) inside the Noise XX msg2/msg3 payload
- The cert binds the device's ECDSA attestation signing pubkey AND
  the device's X25519 Noise static (via custom critical extension
  id-dsm-noiseStaticBinding 1.3.6.1.4.1.99999.1.1)
- ATTESTATION: the default build uses the TPM 2.0 backend
  (`tpm-attest`). The ECDSA P-256 attest key is generated in, never
  leaves, and signs inside a TPM 2.0 — it is non-extractable even by code
  running as root, and the on-disk attest_key_file holds only a TPM-bound
  blob (useless on any other TPM). This is KEY RESIDENCY: it proves the
  signing key lives in this device's TPM. It is NOT PCR-policy sealing and
  NOT remote attestation / TPM quotes (those remain future work), so a
  valid binding does not by itself attest a measured-boot state. The
  SOFTWARE backend (`dev-soft-attest`) remains available as a dev/test
  build ONLY — its key is Argon2id-wrapped on disk but EXTRACTABLE from
  process memory, so treat its binding as a software credential, not a
  hardware root of trust. Android hardware binding (Keystore/StrongBox)
  is planned (Phase 3).
- Per-handshake binding signature over the Noise handshake hash +
  remote_static + role, signed by the attest key — replay-resistant
- Server enforces a CN allowlist (one CN per line in allowed_cns_file);
  client checks the server cert's CN against expected_server_cn
- Optional CRL distributed via walked-USB on the offline-CA cadence

**Key Rotation:**

- Every 5000 packets or 600 seconds (configurable)
- Ephemeral X25519 DH per rotation
- HKDF-SHA256 key derivation with direction-specific labels and epoch in info
- 5-second grace period for in-flight packets from previous epoch
- Rate-limited to one rotation per 60 seconds

**Encryption:**

- AES-256-GCM (AEAD) with sequence number as AAD

**Nonce Strategy:**

- Structured 96-bit nonce: epoch(32) || counter(32) || random(32)
- Counter provides uniqueness guarantee within an epoch
- Random component prevents predictability
- Epoch separation prevents cross-rotation collisions
- Counter is poisoned on exhaustion (returns None permanently) to prevent
  nonce reuse if a session is somehow continued past 2^32 packets

**Replay Protection:**

- 128-bit sliding window bitmap (separate window per epoch during grace)
- Check-before-decrypt, update-after-authentication

**Key Storage:**

- Identity key (X25519 Noise static): encrypted at rest with Argon2id +
  XChaCha20-Poly1305, mlock'd during use, single-pass zeroized on drop.
- Attest key (ECDSA P-256), DEFAULT tpm-attest backend: generated inside
  and non-extractable from a TPM 2.0; signs in-TPM (TPM2_Sign). The
  on-disk attest_key_file is a versioned, TPM-bound DSMT context blob
  (marshalled TPMT_PUBLIC + the TPM-encrypted TPM2B_PRIVATE) that loads
  ONLY on the TPM that created it — there is no extractable private
  scalar and no attest-key passphrase. The dev/test soft backend instead
  Argon2id-wraps a software attest key on disk (extractable).
- Argon2id parameters: 512 MiB memory, 4 iterations, 2 parallelism
- Memory locked (mlock) during use
- Single-pass zeroization via Rust zeroize crate on drop
- Core dumps disabled at startup (setrlimit RLIMIT_CORE)
- Atomic file writes with 0600 permissions (tmpfile -> fchmod -> fsync -> rename)

## Anonymity and Traffic Resistance

**Padding:**

- 11 size classes: 128, 256, 384, 512, 640, 768, 896, 1024, 1152, 1280, 1400 bytes
- Inner padding fills the AEAD envelope to the target class boundary so no
  unauthenticated outer padding remains on the wire
- TCP frames padded to max size class (1400) for constant wire size

**Chaff and adaptive-envelope shaping:**

- The wire packet rate (real + chaff) is paced to a slowly-varying
  ENVELOPE — a target packets/sec that the scheduler emits exactly,
  regardless of instantaneous real-traffic volume. Real packets are
  queued and released at the envelope rate; chaff fills the gap when
  real traffic is below the envelope.
- Burst onset is SMEARED: when real traffic arrives the envelope rises
  slowly (bounded ×2 per second), so a passive observer sees a gradual
  rate increase over seconds rather than a step at the moment real
  traffic starts. Short-term volume is hidden within the latency budget.
- Per-packet latency budget (default 1000 ms): a real packet is never
  delayed longer than the budget waiting for the envelope to rise.
  Latency-sensitive deployments (VoIP, gaming) can lower
  envelope_latency_budget_ms to trade onset-hiding for responsiveness.
- Idle cover: a low, per-session-randomized chaff floor (default
  0.5–2.0 pps, drawn once at session start) keeps cover traffic flowing
  when idle. Idle overhead ≈ 0.5–2 kB/s.
- Chaff sizes are drawn from a FIXED published size-class prior
  (SIZE_CLASS_WEIGHTS), NOT the live real-traffic distribution. So the
  aggregate (real + chaff) wire-size histogram trends toward a
  fleet-wide constant rather than revealing the user's application
  profile. A per-chaff-packet ±1-class perturbation further decorrelates.

  DOCUMENTED RESIDUALS (what is NOT hidden — be explicit):
  - SUSTAINED high-volume traffic (e.g. a bulk download) IS visible on
    the wire: the budget override raises the envelope to match within
    ~1 s, so a long steady-state flow at high rate is observable.
    Only the onset (the transition from idle to active) is smeared;
    steady-state volume is not hidden by this model.
  - The idle floor is a detectable steady baseline: the PRESENCE of a
    low-rate (~0.5–2 pps) chaff stream is visible even though the exact
    rate is randomized per session.
  - The envelope paces PACKETS, not bytes. Residual byte-rate signal is
    bounded by the shared fixed-prior chaff sizes but not eliminated.
  - BOOT / HANDSHAKE FINGERPRINT (accepted v1 risk): the Noise XX
    handshake emits a fixed-size pre-key frame sequence before session
    keys exist. This window is NOT covered by the envelope. A passive
    observer can fingerprint DSM session establishment from this
    recognizable fixed-1400-byte exchange. Masking pre-key traffic is
    post-v1 research; it is documented here as an accepted v1 risk.
  - TCP transport: see IMPORTANT note in NETWORKING above. TCP is
    obfuscation-only against simple DPI; the SYN/FIN/RST connection
    fingerprint remains visible regardless of inner padding or timing.
    Use UDP for the strongest anonymity properties.

**Timing:**

- Configurable jitter (default 1-100ms) on all outgoing packets
- Send scheduler with priority queue and randomized delays
- Envelope knobs (envelope_latency_budget_ms, envelope_rise_per_s,
  envelope_fall_half_life_s, envelope_ceiling_pps,
  envelope_idle_floor_min_pps, envelope_idle_floor_max_pps) are
  documented with bandwidth/latency tradeoffs in config.example.toml

**Leak Prevention:**

- nftables kill switch blocks all non-VPN traffic
- mDNS (5353) and LLMNR (5355) blocked to prevent LAN enumeration
- DNS (53, 853) on non-TUN interfaces blocked except to server IP
- VPN sockets marked with SO_MARK=0x1 so the ip-rule skips the TUN table
  and avoids routing loops

**DNS:**

- Resolution module implemented (DoH, DoT, static hosts file, caching)
- Server-side DNS interception wired into the data path (UDP:53 intercept,
  async resolution, encrypted response back to client)

## Threat Model

**Adversaries:**

- ISP surveillance
- DPI systems
- Active MITM attackers
- State-level adversaries
- Hostile/unsecured WiFi networks

**Assumptions:**

- Network is hostile
- Server is trusted (operator-owned)
- Client device is physically secure

**Out of Scope:**

- Physical access to client/server
- Compromised dependencies or libraries
- Anonymity from the server operator (server sees client IP)

**Accepted v1 Risks (documented, not fixed in this release):**

- BOOT / HANDSHAKE FINGERPRINT: the Noise XX establishment exchange
  emits a recognizable fixed-1400-byte pre-key frame sequence before
  any session keys exist. This window is outside the adaptive-envelope
  shaper (the envelope governs post-key data traffic only). A passive
  on-path observer can detect and fingerprint DSM session establishment
  from this sequence. Masking pre-key traffic is post-v1 research.
  (The attest key signs once per connection-establishment, not per
  packet; the TPM sign adds tens of ms of setup latency. In a MIXED
  soft/TPM fleet that latency could distinguish backends, but v1
  MANDATES the TPM backend for ALL production devices — the soft
  backend is dev/test only — so there is no soft-vs-TPM timing
  distinction in production.)
- SUSTAINED VOLUME: the envelope hides burst ONSET and short-term
  volume within the configurable latency budget (default 1 s). A
  sustained high-rate transfer that exceeds the budget for long enough
  drives the envelope to match the real rate within ~1 s, making the
  steady-state wire rate visible. Volume over many seconds is not
  hidden; only the transition is smeared.
- TCP TRANSPORT: see IMPORTANT note in NETWORKING above. TCP is
  obfuscation-only against simple DPI; connection establishment and
  teardown patterns are visible. Use UDP for the strongest anonymity
  properties.
- PACKET-RATE (not byte-rate) ENVELOPE: the shaper paces packets/sec.
  Residual byte-rate signal is bounded by the fixed-prior chaff sizes
  but not eliminated; a bytes/sec envelope is post-v1 work.
- ATTEST KEY RESIDENCY (scope): the default tpm-attest backend keeps the
  ECDSA attest key non-extractable in a TPM 2.0 (see CRYPTOGRAPHY above),
  which defeats disk/memory key theft. It proves key residency only — it
  does NOT bind the key to a measured-boot state (no PCR policy) and does
  NOT do remote attestation / quotes; those are future work. The optional
  soft-attest dev/test build has NO hardware binding and its key is
  extractable — never deploy it.

## Implementation

**Languages:**

- Python (protocol, networking, traffic shaping, session management)
- Rust via PyO3 (cryptographic primitives, key management, memory protection)

**Rust crate (tuncore):**

- AES-256-GCM encrypt/decrypt
- X25519 key exchange
- Noise XX handshake (via snow crate, with fixed-size attest payload)
- HKDF-SHA256 key derivation
- Argon2id password hashing
- Nonce generation with structured uniqueness and exhaustion poisoning
- Replay window (128-bit bitmap)
- Secure memory (mlock, zeroize, core dump disable)
- Identity + attest key storage (XChaCha20-Poly1305)
- ECDSA P-256 device attestation: TPM 2.0 key-residency backend
  (default, via tss-esapi — generate/sign/store/zeroize in-TPM, DSMT
  context blob) and a software backend (dev/CI only, extractable)

**Dependencies:**

- Python: cryptography (X.509 cert + CRL parsing), dnspython (server
  DNS proxy wire-format parsing). DoH transport is a hand-rolled
  asyncio TLS + HTTP/1.1 path so the SPKI pin can be checked on the
  live SSL object BEFORE the qname crosses the wire — no httpx.
- Rust: snow, aes-gcm, hkdf, sha2, x25519-dalek, zeroize, argon2,
  chacha20poly1305, hmac, subtle, libc, rand/rand_core, serde, pyo3,
  plus tss-esapi (gated on `tpm-attest`, the default — links the system
  tss2-esys via pkg-config; tss-esapi-sys ships pregenerated
  x86_64-linux bindings so no libclang/bindgen), rcgen (gated on the
  soft-attest path for in-Rust CSR generation), and p256 (used by both
  backends — for the in-Rust soft CSR and for SPKI/signature DER
  encoding of the in-TPM public key).

## Configuration

**Format:** TOML

**Path:** `/opt/mtun/config.toml`

**Parameters:**

- mode: client | server
- server_ip: literal IPv4/IPv6 address ONLY (hostnames are rejected;
  the kill-switch nftables rules cannot resolve names. Run
  `dig +short <host> | head -1` and put the resulting IP here)
- server_port, listen_port
- key_file: path to Argon2id-wrapped X25519 Noise static key
- cert_file: path to the device's CA-signed leaf cert (PEM or DER)
- ca_root_file: path to the pinned CA root cert (PEM)
- ca_root_sha256: REQUIRED. 64-hex SHA-256 of ca_root_file. The daemon
  refuses to start if unset, and rejects a ca_root_file whose hash does
  not match — pinning the trust anchor so a swapped on-disk CA PEM is
  fatal at startup, not silently trusted. Compute with:
  `sha256sum <ca_root_file> | cut -d' ' -f1`
- attest_key_file: path to the attest-key artifact. On the default
  tpm-attest build this is a TPM-bound DSMT context blob (no extractable
  key, no passphrase); on the dev-soft-attest build it is an
  Argon2id-wrapped ECDSA P-256 software key.
- attest_tpm_tcti: tpm-attest only; optional TSS2 TCTI string selecting
  the TPM (e.g. "device:/dev/tpmrm0"). Unset = auto-resolve via the
  TCTI / TPM2TOOLS_TCTI env vars, then /dev/tpmrm0. Ignored by the soft
  backend.
- crl_file: optional path to the CA's CRL (PEM or DER)
- crl_strict: bool (default: true). When true (the default), refuse
  to start if crl_file is absent OR the loaded CRL is past its
  next_update. When false, absent or stale CRL surfaces only as a
  WARNING and revoked certs are accepted (intended for lab/dev only).
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
- jitter_ms_min, jitter_ms_max: jitter range in ms (default: 1-100,
  bumped from 1-50 under M-ANON-4 to give the per-packet reorder
  window better coverage at modern line rates). VoIP / gaming /
  remote-shell deployments that need sub-100 ms RTT can drop
  jitter_ms_max to 50 or lower. High-bandwidth deployments can raise
  to 1000.
- rotation_packets, rotation_seconds: key rotation thresholds (default: 5000/600)
- debug_dns: log plaintext DNS queries (default: false, logs are redacted)
- debug_net: emit structured JSON events on the `dsm.netaudit` logger
  (handshake start/end, nft apply/remove, TUN configure/deconfigure,
  rekey, liveness, shutdown, auto_mtu_change, crl_missing, crl_stale).
  Default: false. May also be enabled per-run via the `--debug-net`
  CLI flag.

## Operator Guide

The full step-by-step operator walkthrough — prerequisites, build,
offline-CA bootstrap, per-device enrollment, run, verification, common
operator tasks (rotation/revocation/CRL refresh), single-host smoke
test, two-box demo across two real ISPs, symptom-keyed debugging,
uninstall, file-placement reference, and CLI reference — lives in:

    deploy/GUIDE.md

Every command in that guide is copy-paste-runnable and was cross-
checked against the current codebase. Companion config files in the
same directory:

    deploy/openssl-ca.cnf  — OpenSSL config used by the offline CA
    deploy/dsm.service     — systemd unit for the daemon

## Logging

Default: `log_level = "info"`. This shows operational lifecycle lines
(listening, handshake complete, connected, configured, MASQUERADE for
`<iface>` applied, sysctl changes, shutting down) without per-packet
noise. Recommended for both initial deployment and steady-state
operation.

- `log_level = "debug"` for protocol-level tracing (every packet class,
  every retry, every key derivation step). Verbose; use during
  bring-up or to diagnose specific protocol bugs.
- `log_level = "warning"` or `"error"` if you only want exceptional
  events. NOTE: at warning, you will not see "tunnel established",
  "MASQUERADE applied", or other normal-operation lines, which makes
  diagnosing "is the new code running?" much harder.

## Testing

- Python tests (unittest, discovered by pytest); the full suite runs
  against a soft wheel, with TPM-only tests under a tpm wheel
- Rust tests in two mutually-exclusive feature lanes: the soft lane
  (`cargo test --no-default-features --features dev-soft-attest`) and the
  swtpm-driven TPM lane (`cargo test --no-default-features --features
  tpm-attest --test tpm_swtpm --test dsmt_format`)
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
  sockopt plumbing. The TPM lane additionally covers (under swtpm):
  in-TPM generate/sign/zeroize, independent p256 signature verification,
  the residency-critical TPMA_OBJECT bitmask, cross-TPM blob rejection
  (a blob from one TPM fails to load on another), the DSMT
  serialize/parse format with tampered-header rejection, the backend-
  aware AttestStore passphrase sourcing, the enroll-time TPM preflight,
  and the in-TPM-signed CSR assembly.

**Run:**

```sh
# Soft lane (the broad gate; needs a soft wheel):
$ python3 -m pytest tests/ -q
$ cd rust/tuncore && \
      cargo test --no-default-features --features dev-soft-attest
# TPM lane (needs swtpm + libtss2-dev + libtss2-tcti-swtpm0):
$ cd rust/tuncore && cargo test --no-default-features \
      --features tpm-attest --test tpm_swtpm --test dsmt_format \
      -- --test-threads=1
```

## Roadmap

The current build (Phase 1 + Phase 2A + Phase 3 TPM) ships single-client,
single-server, Linux-only with cert-based auth (CA-signed device certs
binding the ECDSA attest key to the X25519 Noise static via a custom
critical X.509 extension).

- TPM 2.0 attestation (key residency): IMPLEMENTED — the default backend
  (`tpm-attest` Cargo feature, via tss-esapi). The ECDSA P-256 attest key
  is generated in and non-extractable from the TPM and signs in-TPM; the
  on-disk artifact is a TPM-bound DSMT context blob. This delivers key
  residency only: it does NOT add PCR-policy sealing and does NOT do
  remote attestation / TPM quotes (both remain future work). The
  extractable software backend (`dev-soft-attest`) is retained as a
  dev/test build.

Live items on the punch list:

- Future TPM hardening — bind the attest key to a PCR policy (measured
  boot) and add remote attestation (TPM quotes) so a peer can verify the
  key is TPM-resident, not just that the signature validates. Today's
  backend proves residency locally but emits no quote.
- Phase 2B — real-network demo on two physical Linux boxes across two
  ISPs (home Wi-Fi server + cellular client). Procedure in
  deploy/GUIDE.md §9; once the strace-audit step there closes,
  RestrictNamespaces and SystemCallFilter land in deploy/dsm.service.
- Android client (Kotlin VpnService + JNI to the Rust crate, with
  hardware-bound signing via Android Keystore/StrongBox). The protocol
  state machine is lifted into Rust as part of this work so there is one
  implementation across Linux + Android.
- Third-party pentest: threat model authoring, hardening checklist
  execution, telemetry build toggle, engagement coordination.

**Explicit non-goals (reaffirmed):**

- Multiple clients per server / multi-tenant infrastructure — out of
  scope by design (NON-GOALS at top of file).
- Server hopping / relay chains / geographic load balancing — out of
  scope; the threat model assumes a single client-owned server.
