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
  step 8); when shipped, the on-disk attest blob is replaced by a TPM
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
- Python: httpx (DoH client), cryptography (X.509 cert + CRL), dnspython
  (server DNS proxy)
- Rust: snow, aes-gcm, hkdf, sha2, x25519-dalek, zeroize, argon2,
  chacha20poly1305, pyo3, plus p256 (optional, gated on `dev-soft-attest`
  Cargo feature — the default).

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
  mode 0o600 / 0o640
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
  lines like "ip_forward enabled", "MASQUERADE applied", "tunnel
  established", "client connected" only appear at info or below.
  Use "debug" for protocol-level packet tracing.)
- padding_min, padding_max: padding range (default: 128-1400)
- jitter_ms_min, jitter_ms_max: jitter range in ms (default: 1-50)
- rotation_packets, rotation_seconds: key rotation thresholds (default: 5000/600)
- debug_dns: log plaintext DNS queries (default: false, logs are redacted)
- debug_net: emit structured JSON events on the `dsm.netaudit` logger
  (handshake start/end, nft apply/remove, TUN configure/deconfigure,
  rekey, liveness, shutdown, auto_mtu_change). Default: false. May
  also be enabled per-run via the `--debug-net` CLI flag.

OPERATOR GUIDE

  This section is a complete, copy-paste-friendly walkthrough: from a
  blank Linux box to a working single-host loopback tunnel, plus a
  debugging section keyed to the failure modes you will actually hit.

  Companion docs:
  - deploy/SMOKE_TEST.md     — single-host loopback sanity check (what
                               this section covers in shorter form).
  - deploy/CA_RUNBOOK.md     — offline CA bootstrap + per-device
                               enrollment workflow on the air-gapped
                               laptop. You walk through this once
                               before any host can run dsm.
  - deploy/two_box_runbook.md — Phase 2 demo procedure across two real
                               ISPs (server on home Wi-Fi + client on
                               cellular hotspot). Includes the strace
                               audit that gates the deferred systemd
                               hardening flags.

0. PREREQUISITES (both hosts)

   Hardware/OS:
   - Linux kernel 5.x+ with TUN driver (modprobe tun)
   - Ethernet or WiFi connectivity; the server must have a public IP or
     at least a port the client can reach (by default UDP 51820)

   Privileges: the process needs CAP_NET_ADMIN + CAP_SYS_ADMIN +
   CAP_NET_BIND_SERVICE to create the TUN device, install nftables rules,
   set SO_MARK, write sysctls, and bind UDP/53 on the TUN address.
   Running as root is the simplest route. The shipped systemd unit
   (deploy/dsm.service) runs as `User=root` with a tightened
   `CapabilityBoundingSet` plus a conservative hardening subset
   (MemoryDenyWriteExecute, LockPersonality, ProtectKernelModules,
   ProtectControlGroups, RestrictAddressFamilies, RestrictRealtime,
   PrivateTmp, ProcSubset=pid, etc.). Two flags — `RestrictNamespaces`
   and `SystemCallFilter` — are intentionally left as TODOs in the unit
   pending an empirical strace audit (see deploy/two_box_runbook.md §7);
   running `sudo systemd-analyze security dsm` after install reports a
   ~5.5 MEDIUM score, target < 3.0 once the audit closes.

0a. Install system packages

   Debian / Ubuntu:
   $ sudo apt update
   $ sudo apt install -y \
         build-essential pkg-config \
         python3 python3-venv python3-pip python3-dev \
         nftables iproute2 curl ca-certificates git
0b. Install Rust (if you don't already have it)

   The official rustup installer is the easiest path — no root needed,
   installs into ~/.cargo:
   $ curl --proto '=https' --tlsv1.3 -sSf https://sh.rustup.rs | sh -s -- -y
   $ source "$HOME/.cargo/env"       # add cargo to PATH in this shell
   $ rustc --version                 # e.g. rustc 1.82.0 (stable)

   On distros that package rustc >= 1.74, `sudo apt install rustc cargo`
   works too — but the maturin toolchain expects a recent cargo, so
   rustup is more reliable.

0c. Pre-flight check

   $ python3 --version          # 3.11 or newer
   $ gcc --version              # any recent gcc
   $ rustc --version            # stable channel
   $ sudo nft --version              # nftables
   $ ls /dev/net/tun            # TUN node present
   $ ip link                    # iproute2 working


1. BUILD (both hosts, inside the repo)

   All commands below are run from the top-level repo directory.

   IMPORTANT — read this before running anything in section 1.

   The dsm process needs CAP_NET_ADMIN + CAP_SYS_ADMIN so it must be
   invoked with `sudo`. Under sudo, Python's interpreter is the system
   one at /usr/bin/python3 — NOT a venv, NOT --user installs. Every
   Python dependency dsm imports (tuncore, httpx, dnspython,
   cryptography) MUST be visible to /usr/bin/python3.

   This walkthrough installs everything into the system Python. Do
   NOT use a venv. Do NOT use `pip install --user`. If you have
   already created a venv from an earlier attempt and installed
   things there, scrap it now:

   $ rm -rf .venv

   Then proceed.

1a. Build the tuncore wheel

   maturin produces a Python wheel containing the compiled Rust
   extension. Building requires a venv (a maturin quirk), but we'll
   only USE the venv to build — the wheel itself is then installed
   into the system Python. The venv is throwaway.

   $ python3 -m venv /tmp/dsm-build-venv
   $ /tmp/dsm-build-venv/bin/pip install --upgrade pip maturin

   $ cd rust/tuncore
   $ /tmp/dsm-build-venv/bin/maturin build --release
   $ ls target/wheels/                        # confirm a .whl appeared
   $ cd ../..

   You can `rm -rf /tmp/dsm-build-venv` at the end of section 1 — it's
   no longer needed once the wheel is installed system-wide.

1b. Install everything into the system Python

   $ sudo /usr/bin/python3 -m pip install --break-system-packages \
         "$(ls $PWD/rust/tuncore/target/wheels/dsm_tuncore-*.whl | tail -1)" \
         httpx dnspython cryptography

   `--break-system-packages` is required on distros with PEP 668
   protection (Debian 12+, Ubuntu 23.10+, Fedora 38+). It's the
   correct flag here: we're knowingly installing into the system
   Python because root needs to see these packages.

1c. Verify the install

   Run this EXACT command — it confirms root's Python sees every
   import dsm needs:

   $ sudo /usr/bin/python3 -c \
         "import tuncore, dns, httpx, cryptography; print('all 4 imports ok')"

   You must see "all 4 imports ok" before continuing. If any import
   fails:

   - "No module named 'tuncore'" — the wheel install in 1b failed
     silently. Re-run 1b and check the pip output for errors.
   - "No module named 'dns'" — dnspython didn't install. Re-run 1b.
   - "No module named 'httpx'" or "'cryptography'" — same fix.

1d. Optional: run the test suite

   $ sudo /usr/bin/python3 -m pip install --break-system-packages \
         pytest pytest-asyncio
   $ python3 -m pytest tests/ -q              # ~250 tests should pass
   $ cd rust/tuncore && PYO3_PYTHON=/usr/bin/python3 cargo test --release \
         --features dev-soft-attest
                                              # ~70 tests should pass.
                                              # PYO3_PYTHON is required on
                                              # Debian/Ubuntu where only
                                              # /usr/bin/python3 exists (pyo3
                                              # otherwise looks for /usr/bin/python).
                                              # `dev-soft-attest` is the
                                              # default feature; explicit
                                              # here so the intent is clear.
   $ cd ../..

   The tests don't need root, so plain `python3` here is fine.

   If pytest reports `ModuleNotFoundError: tuncore`, your user-level
   Python and root's Python are different versions. The dsm CLI uses
   root's Python regardless, so as long as 1c printed "all 4 imports
   ok" you can continue — test-suite runs are optional.


2. SERVER SETUP

2a. Choose a DNS upstream and fetch its SPKI SHA-256 pin

   The server resolves clients' DNS queries via DoH (HTTPS) or DoT
   (TLS). DSM does not ship a default pin — the operator MUST supply
   one so stale hardcoded pins cannot degrade to unpinned traffic. The
   pin is the SHA-256 of the provider's SubjectPublicKeyInfo, as
   64-character lowercase hex.

   Fetch the current pin for a DoH provider — the one-liner below
   grabs Cloudflare's pin. Swap the host for your chosen provider:

   $ HOST=1.1.1.1 PORT=443
   $ openssl s_client -connect "$HOST:$PORT" -servername "$HOST" \
         < /dev/null 2>/dev/null \
       | openssl x509 -pubkey -noout \
       | openssl pkey -pubin -outform DER \
       | openssl dgst -sha256 -binary \
       | xxd -p -c 64

   The output is a single 64-char hex string. Copy it — you will
   paste it into config.toml below.

   Notes:
   - Pins expire when the provider rotates its cert (Cloudflare, for
     example, rotates roughly yearly). Plan to re-fetch and re-deploy.
   - For DoT, replace port 443 with 853 in the command above.
   - You can pin MULTIPLE keys per provider (current + backup/next);
     DSM accepts a list and succeeds if any one matches.

2b. Write the server config file

   Pick your server's public IP and a UDP port (default 51820). Drop
   the pin from 2a into the config below. The cert/CA/attest paths
   below assume the offline-CA runbook (deploy/CA_RUNBOOK.md) has
   already been walked at least once to produce dsm_ca_root.pem; the
   device.crt + attest.key + identity.key files are produced in step
   2c via `dsm enroll`.

   $ sudo mkdir -p /opt/mtun
   $ sudo tee /opt/mtun/config.toml >/dev/null <<'EOF'
   mode               = "server"
   server_ip          = "10.0.0.5"         # this host's public IP
   server_port        = 51820
   listen_port        = 51820
   key_file           = "/opt/mtun/identity.key"
   cert_file          = "/opt/mtun/device.crt"
   ca_root_file       = "/opt/mtun/dsm_ca_root.pem"
   attest_key_file    = "/opt/mtun/attest.key"
   # crl_file         = "/opt/mtun/dsm_ca.crl"   # optional, recommended

   # Server-only: one allowed client subject CN per line.
   allowed_cns_file   = "/opt/mtun/allowed_cns.txt"

   transport          = "udp"              # "tcp" also supported
   mtu                = 1400
   pmtu_discover      = false              # set true for WAN deployment
   log_level          = "info"

   # DoH upstream for client DNS queries tunneled through the server.
   dns_providers = ["https://1.1.1.1/dns-query"]

   [dns_provider_pins]
   # Paste the 64-char hex SHA-256 SPKI pin from step 2a here.
   # Multiple pins allowed; put current cert first, backup/next second.
   "https://1.1.1.1/dns-query" = [
       "REPLACE_WITH_64_CHAR_HEX_SPKI_SHA256_PIN",
   ]
   EOF

   Sanity check — verify the file actually parses as TOML before you
   try to start dsm. A single missing quote will produce a confusing
   stack trace later; catching it here is one command:

   $ python3 -c "import tomllib; tomllib.load(open('/opt/mtun/config.toml','rb')); print('ok')"

   Expected output: a single line "ok". If you instead see something
   like:

       tomllib.TOMLDecodeError: Expected newline or end of document
       after a statement (at line N, column M)

   then the file has a TOML syntax error at line N, col M. The most
   common causes (try them in order):

   (1) Missing quotes around a STRING value. TOML is strict about
       what's a string vs a number/bool:

       Must be "double-quoted":
         mode, transport, log_level         e.g. "server" "udp" "info"
         server_ip, key_file                e.g. "10.0.0.5" "/opt/..."
         cert_file, ca_root_file,
         attest_key_file, crl_file,
         expected_server_cn,
         allowed_cns_file                   e.g. "/opt/mtun/..."

       Bare (no quotes):
         server_port, listen_port, mtu      bare integers
         padding_*, jitter_*, rotation_*    bare integers
         pmtu_discover, debug_dns           bare true / false

       Concrete example: writing `server_ip = 10.0.0.5` (no quotes)
       trips at column 17 because tomllib parses `10.0` as a float
       and chokes on the second `.`. Fix in place with sed:
         $ sudo sed -i 's|^server_ip = .*|server_ip = "10.0.0.5"|' \
               /opt/mtun/config.toml

   (2) Smart quotes (curly quotes) from a copy-paste. If you pasted
       from a chat app or rendered web page, the file may contain
       " or " (Unicode) instead of ASCII ". Diagnose:
         $ cat -An /opt/mtun/config.toml | head -10
       Curly quotes show up as multi-byte sequences like M-bM-^@M-^\.
       Re-type the offending line by hand.

   (3) Wrong comment marker. TOML comments are `#` only — `;` or
       `//` make the rest of the line part of the preceding value
       and trigger the same error.

   (4) Inspect the exact line tomllib complained about, with all
       whitespace and non-printables visible:
         $ sed -n '<N>p' /opt/mtun/config.toml | cat -An

   Re-run the `python3 -c "import tomllib..."` check after every edit;
   only proceed once it prints `ok`.

2c. First-run: enroll the server (interactive, one time)

   The CA root file (dsm_ca_root.pem) must already be in place per
   deploy/CA_RUNBOOK.md §2. Then run enroll on the server:

   $ sudo python3 -m dsm --config /opt/mtun/config.toml \
         enroll --csr-out /tmp/dsm-csr-server.der --role server
   # Prompted for the new passphrase (twice). Identity + attest keys
   # are written to /opt/mtun/identity.key and /opt/mtun/attest.key
   # (mode 0o600), and a CSR is dropped at /tmp/dsm-csr-server.der.

   Walk the CSR to the offline CA laptop (CA_RUNBOOK.md §3b), have
   the operator sign it with the dsm_server_leaf profile, walk the
   resulting cert back, then:

   $ sudo python3 -m dsm --config /opt/mtun/config.toml \
         enroll --import /tmp/dsm-cert-server.pem
   # Verifies chain + binding + attest pubkey, then writes
   # /opt/mtun/device.crt (mode 0o600).

   Populate /opt/mtun/allowed_cns.txt with the CNs of every client
   you intend to authorize (mode 0o600, root-owned). One CN per line;
   `# comments` allowed.

2d. Store the passphrase for non-interactive restarts

   Pick ONE of:

   (i) File on disk (0600, read once at startup):
       $ echo 'my-strong-passphrase' | sudo install -m 0600 /dev/stdin /etc/dsm/passphrase
       Start with:
           sudo python3 -m dsm --mode server \
               --passphrase-env-file /etc/dsm/passphrase

   (ii) systemd LoadCredential (preferred):
        Edit deploy/dsm.service so the ExecStart is:
            ExecStart=/usr/bin/python3 -m dsm --mode server \
                --passphrase-env-file=${CREDENTIALS_DIRECTORY}/passphrase
        Then:
            $ sudo install -m 0400 -o root -g root \
                  /etc/dsm/passphrase /etc/dsm/passphrase
            $ sudo systemctl daemon-reload
            $ sudo systemctl enable --now dsm

   (iii) Environment variable (CI/testing only — visible in /proc/*/environ):
        DSM_PASSPHRASE='...' sudo -E python3 -m dsm --mode server


3. CLIENT SETUP

   Mirror step 2 on the client host with mode="client":

   $ sudo mkdir -p /opt/mtun
   $ sudo tee /opt/mtun/config.toml >/dev/null <<'EOF'
   mode               = "client"
   server_ip          = "10.0.0.5"      # the server's public IP (step 2)
   server_port        = 51820
   listen_port        = 0               # ephemeral client port
   key_file           = "/opt/mtun/identity.key"
   cert_file          = "/opt/mtun/device.crt"
   ca_root_file       = "/opt/mtun/dsm_ca_root.pem"
   attest_key_file    = "/opt/mtun/attest.key"
   # crl_file         = "/opt/mtun/dsm_ca.crl"   # optional

   # Subject CN we will accept on the server cert (from CA_RUNBOOK).
   expected_server_cn = "dsm-XXXXXXXX-server"

   transport          = "udp"
   mtu                = 1400
   pmtu_discover      = true            # client benefits more from PMTUD
   # Cellular path MTU drifts on handover (Wi-Fi <-> LTE/5G). The
   # auto_mtu loop tracks the kernel-discovered PMTU and adjusts the
   # TUN MTU on the fly. Safe default for cellular; harmless on stable
   # wired links (no PMTU drift -> no adaptation).
   auto_mtu           = true
   log_level          = "info"
   EOF

   Sanity check — same TOML-parse verification as on the server:

   $ python3 -c "import tomllib; tomllib.load(open('/opt/mtun/config.toml','rb')); print('ok')"

   Must print "ok". If it raises a TOMLDecodeError, see the four
   numbered fix recipes under "Sanity check" in step 2b — they apply
   identically to the client config.

   Enroll the client (CA_RUNBOOK.md §3 again, mirror of step 2c):

   $ sudo python3 -m dsm --config /opt/mtun/config.toml \
         enroll --csr-out /tmp/dsm-csr-client.der --role client
   # Prompted for a passphrase. Note the printed CN — record it; the
   # operator adds it to the server's allowed_cns_file.

   Walk the CSR to the CA, have it signed with the dsm_client_leaf
   profile, walk the cert back, then:

   $ sudo python3 -m dsm --config /opt/mtun/config.toml \
         enroll --import /tmp/dsm-cert-client.pem


4. AUTHORIZATION

   On the server, append the client's CN (printed by `dsm enroll
   --csr-out`) to the allowlist:

   $ echo 'dsm-XXXXXXXX-client' \
         | sudo install -m 0600 -o root -g root /dev/stdin /tmp/cn \
         && sudo cat /tmp/cn >> /opt/mtun/allowed_cns.txt \
         && sudo chmod 0600 /opt/mtun/allowed_cns.txt \
         && sudo rm /tmp/cn

   Restart the server. Future restarts re-read the file at startup;
   live SIGHUP reload is on the Phase 2 punch list.

   To revoke a client: remove its CN from allowed_cns_file (and
   issue a CRL update via CA_RUNBOOK.md §5 if the cert may surface
   elsewhere).


5. RUN BOTH SIDES

   Server:
   $ sudo systemctl start dsm
   # or
   $ sudo python3 -m dsm --mode server --passphrase-env-file /etc/dsm/passphrase

   Client:
   $ sudo python3 -m dsm --mode client --passphrase-env-file /etc/dsm/passphrase

   Expected client log (log_level = info):
     ... handshake complete (client) — server_cn=dsm-XXXXXXXX-server
     ... TUN mtun0 configured: 10.8.0.2/24 mtu=1400
     ... tunnel established
     ... kernel path MTU = 1500 (usable inner 1432)
     ... auto_mtu: lowered tun mtu 1400 -> 1232 (kernel pmtu=1300)
                                                   ↑ only when auto_mtu=true
                                                     AND the path needs it
                                                     (typical on cellular)

   Expected server log:
     ... CN allowlist loaded (N entries)
     ... server listening on port 51820 (udp)
     ... handshake complete (server) — client_cn=dsm-XXXXXXXX-client
     ... client connected (noise_static=<first16hex>)


6. VERIFICATION

   From the client (second terminal, while the VPN is running):

   TUN and routing:
   $ ip link show mtun0             # state UP, mtu from config
   $ ip addr show mtun0             # 10.8.0.2/24 (client) or 10.8.0.1/24 (server)
   $ ip rule                        # expect "not from all fwmark 0x1 lookup 100"
   $ ip route show table 100        # default via mtun0

   Kill switch:
   $ sudo nft list ruleset | grep -A3 'table inet dsm'

   DNS (goes through the tunnel, resolved on server via DoH/DoT):
   $ dig @10.8.0.1 example.com +short

   Leak test — open one terminal with tcpdump on the physical interface:
   $ sudo tcpdump -ni eth0 'port not 51820 and not arp and not ip6'
   In another, send some traffic:
   $ curl -s https://example.com > /dev/null
   # tcpdump should show ZERO packets during the curl. Anything on the
   # wire that is not port 51820 is a leak.

   IPv6 disabled during session:
   $ sysctl net.ipv6.conf.all.disable_ipv6     # expect 1
   $ cat /run/dsm/ipv6_state.json              # per-iface snapshot

   Graceful shutdown (Ctrl-C or systemctl stop):
   # Expect in the peer's log within ~1 second:
     ... shutdown set (SESSION_CLOSE received)
   # On both hosts:
   $ ip link show mtun0                  # "does not exist"
   $ sudo nft list ruleset | grep dsm    # no output
   $ cat /etc/resolv.conf | head -2      # restored to pre-VPN nameserver
   $ sysctl net.ipv6.conf.all.disable_ipv6  # 0 (restored from state file)


7. COMMON OPERATOR TASKS

7a. Re-pin a new server cert on the client

    No client-side action when the server rotates within the same CA:
    the client trusts any cert that chains to dsm_ca_root.pem and
    matches expected_server_cn. If you change expected_server_cn,
    update /opt/mtun/config.toml and restart the client.

7b. Revoke a client

    On the server: remove the client's CN from /opt/mtun/allowed_cns.txt
    and restart. Optionally issue a CRL update via deploy/CA_RUNBOOK.md
    §5 so any other server in the fleet refuses the cert too.

7c. Rotate the server identity

    On the server:
    $ sudo systemctl stop dsm
    $ sudo rm /opt/mtun/identity.key /opt/mtun/attest.key /opt/mtun/device.crt
    $ sudo python3 -m dsm --config /opt/mtun/config.toml \
          enroll --csr-out /tmp/dsm-csr-server.der --role server
    # Walk CSR to CA, sign, walk back:
    $ sudo python3 -m dsm --config /opt/mtun/config.toml \
          enroll --import /tmp/dsm-cert-server.pem
    $ sudo systemctl start dsm
    # Clients keep working as long as expected_server_cn still matches
    # (deterministic CN derivation produces a new CN per Noise pubkey;
    # if the CN changed, push the new value to every client).

7d. Change MTU live

    Stop both sides, edit `mtu` in config.toml, restart. The TUN device
    is torn down and rebuilt on startup.

7e. Change transport (UDP <-> TCP)

    Same as MTU: change config on both sides, restart. Cert auth is
    transport-independent — the same enrollment works for either.


8. DEBUGGING

   The log_level = "debug" setting turns on per-packet-class log lines;
   turn it on while reproducing a bug, then off.

   PROBLEM: "handshake recv timed out after 3 attempts" / "handshake failed: ..."
     - Server actually down, or port blocked. Test plain UDP reachability:
         $ nc -u -v <server-ip> 51820     # then type and press enter
     - Server is up but bound to the wrong interface. On the server:
         $ sudo ss -ulnp | grep 51820
     - Firewall between you and the server dropping DF packets (less
       likely with default pmtu_discover=false).
     - On cellular: the link was down when the handshake started. Each
       retry adds 5 s of timeout + (1, 2, 4) s of backoff — total budget
       ~22 s. A longer outage exceeds the budget; restart the client
       once the link is back up.

   PROBLEM: "client CN not in allowlist"
     - Expected on first connect; see step 4. The client's CN must be
       on a line of /opt/mtun/allowed_cns.txt on the server (mode 0o600).
     - The CN you added to the file does not match the cert the client
       actually presents. Ask the client operator for the CN that
       `dsm enroll --csr-out` printed, and compare exactly.

   PROBLEM: "server CN check failed: server CN ... does not match expected ..."
     - The client's expected_server_cn does not match the cert the
       server presents. Either correct the client's config, or roll
       the server back if the CN changed unexpectedly (which would
       imply an unauthorized re-enrollment).

   PROBLEM: "server cert auth failed: cert chain ..."
     - The pinned ca_root_file does not match the CA that issued
       the server's cert. Cross-check
       `sha256sum /opt/mtun/dsm_ca_root.pem` against the value the
       CA operator recorded in the safe (CA_RUNBOOK.md §1).

   PROBLEM: "process hardening partially failed"
     - Informational, not fatal. The service started, but core-dump
       disabling or prctl(PR_SET_DUMPABLE) didn't stick. Usually one of:
       (a) SELinux/AppArmor blocking; (b) systemd unit's
       `CapabilityBoundingSet` is too tight (we ship NET_ADMIN +
       SYS_ADMIN + NET_BIND_SERVICE only — if a future change needs
       another cap, add it to deploy/dsm.service and restart);
       (c) running outside systemd without the right caps.

   PROBLEM: Tunnel is up but `curl` through it is very slow or hangs
     - Path MTU issue. Check the startup log for:
         "configured tun mtu=1400 exceeds usable inner NNN"
       Lower the `mtu` in config on both sides until the warning is gone.
     - Or: enable pmtu_discover=true and check the logged kernel PMTU.
     - Chaff + jitter adds latency by design. Turn padding_max down and
       jitter_ms_max to 5 for a less-anonymized-but-faster test.

   PROBLEM: "rekey giving up after 3 retries — tearing down"
     - REKEY_ACK never got back to the initiator. Check peer log for
       "rekey completed as responder" — if missing, the server never
       processed the INIT (network drop). If present, the ACK was dropped
       in the reverse direction.
     - Session tears down on purpose. Client/server both return to IDLE
       and exit; restart to re-handshake.

   PROBLEM: "DNS resolve failed for qname-sha256=<redacted>"
     - Server's upstream DoH/DoT provider failed or pin mismatch.
       Temporarily set debug_dns = true and rerun to see the plaintext
       qname in logs — then disable.
     - Check the SPKI pin against the provider's live cert:
         $ openssl s_client -connect 1.1.1.1:443 -servername 1.1.1.1 \
             < /dev/null 2>/dev/null \
             | openssl x509 -pubkey -noout \
             | openssl pkey -pubin -outform DER \
             | openssl dgst -sha256 -binary \
             | xxd -p -c 64

   PROBLEM: "DNS proxy listening on 10.8.0.1:53" but client can't resolve
     - Client's resolv.conf wasn't updated, or the kill-switch is
       dropping the query. Check:
         $ cat /etc/resolv.conf
         $ sudo nft list ruleset
     - Firewall on the server is blocking the local DNS-proxy bind.

   PROBLEM: Host IPv6 stuck off after a crashed client
     - /run/dsm/ipv6_state.json persists across crashes; next normal
       `dsm` start reads it and restores. If it's missing:
         $ for iface in $(ls /sys/class/net); do
               sudo sysctl -w net.ipv6.conf.$iface.disable_ipv6=0
           done
         $ sudo sysctl -w net.ipv6.conf.all.disable_ipv6=0

   PROBLEM: nftables rules stuck after a crashed client
     - No crash-recovery is shipped; clean up manually:
         $ sudo nft delete table inet dsm
       and restart the client.

   PROBLEM: ImportError / ModuleNotFoundError: No module named '<X>'
     - X = tuncore: the Rust wheel never landed in /usr/bin/python3.
       Re-run step 1b — confirm pip output reports
       "Successfully installed dsm-tuncore-0.1.0".
     - X = dns / httpx / cryptography: dnspython / httpx / cryptography
       isn't installed for root's Python. They get installed together
       in step 1b. Re-run that command.
     - Did you create a venv and install there instead? `sudo python3`
       can't see venv packages — see section 1's IMPORTANT note.
       Run step 1c verification; if any import fails, redo 1b.

   PROBLEM: TypeError or AttributeError mentioning a tuncore object
     (e.g. "a bytes-like object is required, not 'list'")
     - Almost certainly a stale wheel: you rebuilt the Rust source but
       didn't reinstall the wheel into the system Python. Rebuild and
       re-install:
         $ cd rust/tuncore
         $ /tmp/dsm-build-venv/bin/maturin build --release
         $ sudo /usr/bin/python3 -m pip install --break-system-packages \
               --force-reinstall \
               "$(ls $PWD/target/wheels/dsm_tuncore-*.whl | tail -1)"


9. UNINSTALL

   $ sudo systemctl disable --now dsm
   $ sudo rm -rf /opt/mtun /etc/dsm /run/dsm
   $ sudo pip uninstall dsm-tuncore              # if pip-installed
   $ sudo rm /etc/systemd/system/dsm.service
   $ sudo systemctl daemon-reload

   Manual firewall/TUN reset (paranoid):
   $ sudo nft delete table inet dsm 2>/dev/null
   $ sudo ip link delete mtun0 2>/dev/null
   $ sudo ip rule delete priority 10 2>/dev/null
   $ sudo ip route flush table 100 2>/dev/null
   $ for iface in $(ls /sys/class/net); do
         sudo sysctl -w net.ipv6.conf.$iface.disable_ipv6=0 2>/dev/null
     done


FILE PLACEMENT REFERENCE

   /opt/mtun/config.toml                 # main config (both modes)
   /opt/mtun/identity.key                # X25519 Noise static (Argon2id)
   /opt/mtun/attest.key                  # ECDSA P-256 attest key (Argon2id)
   /opt/mtun/device.crt                  # CA-signed leaf cert (mode 0o600)
   /opt/mtun/dsm_ca_root.pem             # pinned CA root cert
   /opt/mtun/dsm_ca.crl                  # optional CRL (walked-USB cadence)
   /opt/mtun/allowed_cns.txt             # server only: one CN per line
   /etc/dsm/passphrase                   # non-interactive passphrase (0600)
   /run/dsm/ipv6_state.json              # per-iface IPv6 state snapshot
   /etc/systemd/system/dsm.service       # (optional) systemd unit

CLI REFERENCE

   python -m dsm --mode {client,server}          Run the VPN
   python -m dsm --config PATH                   Override config file path
   python -m dsm --passphrase-fd N               Read passphrase from FD N
   python -m dsm --passphrase-env-file PATH      Read passphrase from file
   python -m dsm --debug-net                     Emit JSON audit events
                                                 on the dsm.netaudit logger
   python -m dsm enroll --csr-out PATH           Provision keys + emit CSR
   python -m dsm enroll --import CERT_PATH       Verify + persist signed cert
   python -m dsm enroll --cn CN [--role …]       Override CN / role suffix
   python -m dsm show-pubkey                     Print local identity pubkey


LOGGING

Default: log_level = "info". This shows operational lifecycle lines
(listening, connected, authorized, configured, MASQUERADE applied,
sysctl changes, shutting down) without per-packet noise. Recommended
for both initial deployment and steady-state operation.

- log_level = "debug" for protocol-level tracing (every packet class,
  every retry, every key derivation step). Verbose; use during
  bring-up or to diagnose specific protocol bugs.
- log_level = "warning" or "error" if you only want exceptional
  events. NOTE: at warning, you will not see "tunnel established",
  "MASQUERADE applied", or other normal-operation lines, which makes
  diagnosing "is the new code running?" much harder.

TESTING

- 253 Python tests (unittest, discovered by pytest)
- 70 Rust tests (cargo test --features dev-soft-attest)
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

- Phase 1 step 8 — TPM 2.0 attest backend (`tpm-attest` Cargo feature
  via tss-esapi). Parked until TPM hardware is available for empirical
  testing; the soft attest backend is the default and works end-to-end.
- Phase 2B — real-network demo on two physical Linux boxes across two
  ISPs (home Wi-Fi server + cellular client). Procedure in
  deploy/two_box_runbook.md; once the strace-audit step there closes,
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