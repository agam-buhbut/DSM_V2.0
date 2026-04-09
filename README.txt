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
Client -> Optional Relay(s) -> Client-Owned Server -> Destination

Components:
- Client: initiates handshake, encrypts traffic, generates chaff
- Relay (optional): forwards opaque packets without decryption
- Server: completes handshake, decrypts and forwards traffic

State Model:
- Session-based finite state machine (6 states)
- IDLE -> CONNECTING -> HANDSHAKING -> ESTABLISHED -> REKEYING -> TEARDOWN -> IDLE

Concurrency:
- Python asyncio (single-threaded async I/O)
- Concurrent recv_loop + tun_send_loop via asyncio.gather

NETWORKING

Transport:
- UDP (default)
- TCP (fallback, with length-prefix framing)

Connection:
- Single client per server instance
- Session-based with graceful shutdown (SESSION_CLOSE packet)

Reliability:
- Handshake retransmission with exponential backoff (3 retries, 1s/2s/4s)
- No application-level retransmission for data packets (relies on inner protocol or TCP)

Fragmentation:
- Packet type defined but not yet implemented

CRYPTOGRAPHY

Key Exchange:
- Noise XX pattern (X25519 + AES-256-GCM + SHA-256)
- Prologue-tagged: "DSM\x00\x01\x00\x01"
- Handshake messages padded to 1400 bytes (constant size)
- Trust-on-first-use (TOFU) server key pinning with HMAC-SHA256 integrity

Key Rotation:
- Every 5000 packets or 600 seconds (configurable)
- Ephemeral X25519 DH per rotation
- HKDF-SHA256 key derivation with direction-specific labels
- 5-second grace period for in-flight packets from previous epoch
- Rate-limited to one rotation per 60 seconds

Encryption:
- AES-256-GCM (AEAD) with sequence number as AAD

Nonce Strategy:
- Structured 96-bit nonce: epoch(32) || counter(32) || random(32)
- Counter provides uniqueness guarantee within epoch
- Random component prevents predictability
- Epoch separation prevents cross-rotation collisions

Replay Protection:
- 128-bit sliding window bitmap
- Check-before-decrypt, update-after-authentication

Key Storage:
- Identity keys encrypted at rest with Argon2id + XChaCha20-Poly1305
- Argon2id parameters: 512 MiB memory, 4 iterations, 2 parallelism
- Memory locked (mlock) during use
- Single-pass zeroization via Rust zeroize crate on drop
- Core dumps disabled at startup (setrlimit RLIMIT_CORE)
- Atomic file writes with 0600 permissions

ANONYMITY AND TRAFFIC RESISTANCE

Padding:
- 11 size classes: 128, 256, 384, 512, 640, 768, 896, 1024, 1152, 1280, 1400 bytes
- Inner padding fills encrypted envelope to size class boundary
- TCP frames padded to max size class (1400) for constant wire size

Chaff:
- Adaptive chaff generation mirroring real traffic patterns
- Active mode: rate tracks real traffic (0.5x-1.5x, resampled every 1-3s)
- Idle mode: burst patterns mimicking browsing (exponential inter-burst gaps)
- Size distribution mirrors observed real traffic via exponential moving average

Timing:
- Configurable jitter (default 1-50ms) on all outgoing packets
- Send scheduler with priority queue and randomized delays

Leak Prevention:
- nftables kill switch blocks all non-VPN traffic
- mDNS and LLMNR blocked to prevent LAN enumeration
- DNS on non-TUN interfaces blocked except to server IP

DNS:
- Resolution module implemented (DoH, DoT, static hosts file, caching)
- Not yet wired into the data path (TODO)

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
- Noise XX handshake (via snow crate)
- HKDF-SHA256 key derivation
- Argon2id password hashing
- Nonce generation with structured uniqueness
- Replay window (128-bit bitmap)
- Secure memory (mlock, zeroize, core dump disable)
- Identity key storage (XChaCha20-Poly1305)

Dependencies:
- Python: httpx (DNS-over-HTTPS)
- Rust: snow, aes-gcm, hkdf, sha2, x25519-dalek, zeroize, argon2, chacha20poly1305, pyo3

CONFIGURATION

Format: TOML
Path: /opt/mtun/config.toml

Parameters:
- mode: client | server | relay
- server_ip, server_port, listen_port
- key_file: path to encrypted identity key
- transport: udp | tcp (default: udp)
- relay_addresses: list of relay IPs:ports
- dns_providers: DoH/DoT URLs (server mode)
- tun_name: TUN device name (default: mtun0)
- log_level: debug | info | warning | error (default: warning)
- padding_min, padding_max: padding range (default: 128-1400)
- jitter_ms_min, jitter_ms_max: jitter range in ms (default: 1-50)
- rotation_packets, rotation_seconds: key rotation thresholds (default: 5000/600)

SETUP

File Placement:
- Config: /opt/mtun/config.toml
- Identity key: /opt/mtun/identity.enc (generated on first run)
- Known hosts: /opt/mtun/known_hosts.json (TOFU, client only)

Dependencies:
- Python 3.11+
- Rust toolchain (for building tuncore)
- nftables
- TUN/TAP kernel support

Build:
- cd rust/tuncore && maturin develop --release

LOGGING

Development:
- log_level = "debug" for full verbose logging

Production:
- log_level = "warning" (default) for errors and warnings only

TESTING

- 55 Python unit tests (unittest)
- 49 Rust unit tests (cargo test)
- Covers: protocol serialization, FSM transitions, config validation,
  replay window, nonce generation, key rotation, AES-GCM, identity storage,
  Noise XX handshake
