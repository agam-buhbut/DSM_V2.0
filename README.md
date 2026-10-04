# DSM_V2.0

DSM is an open-source VPN for Linux that puts security and anonymity first.
It runs a single tunnel between one client and one server. It also resists
traffic analysis: working out what you do from the size and timing of your
packets.

## Quickstart

> **Supported systems:** Debian 12+ or Ubuntu 22.04+ on x86_64, with a TPM 2.0
> (a security chip in the computer). On other distributions, build from
> source (see `deploy/GUIDE.md` §1). DSM is not on PyPI; it is distributed
> through signed GitHub Releases.

> **No release has been published yet.** There is no `v0.1.0` tag or GitHub
> Release. `install.sh` still has a placeholder minisign public key (the key
> that checks the download's signature). So step 1 below does not work yet.
> Until the first signed release, build and install from source
> (`deploy/GUIDE.md` §1), then go on with steps 2 and 3.

Setup has three steps: install, set up, start. Setting up writes the config,
pins your CA (certificate authority) root and enrolls this device. Enrolling
means your offline CA signs the device's certificate request.

```sh
# 1. Install (downloads + minisign-verifies the wheel, apt-installs the TPM
#    runtime libs, creates /opt/dsm/venv, symlinks `dsm`). Add `--systemd`
#    to also install the dsm.service unit.
curl -fsSL https://github.com/agam-buhbut/DSM_V2.0/releases/download/v0.1.0/install.sh | sudo sh -s -- --systemd

# 2. Provision config + CA-pin + enroll (orchestrates config + TPM preflight +
#    CSR emit). Pass the required flags up front; only the key passphrase is
#    prompted. Server example (client: use `client` + --expected-server-cn and
#    drop --dns-provider/--dns-pin):
sudo dsm init server \
    --server-ip <IP> --server-port <PORT> --ca-root <ca-root.pem> \
    --dns-provider <DoH-URL> --dns-pin <SPKI-SHA256>
#   ...this writes a CSR and pauses for the offline-CA signing step. Walk the
#   CSR to the CA, sign it, then resume with the returned cert:
sudo dsm init server --resume --signed-cert <signed.crt>

# 3. Start it.
sudo systemctl enable --now dsm
```

**Trying DSM without a TPM:** releases will also carry a clearly named
`+soft` evaluation wheel (a Python install package), installed with
`install.sh --eval`. Flags can go in any order, for example
`-s -- --eval --systemd`. This wheel has **no hardware binding**: its key is
not held in a TPM. It is for evaluation only. Never deploy it in production.

## Goal

A VPN tunnel that stands up to:

- ISP surveillance
- DPI (deep packet inspection: tools that look into traffic to classify or
  block it)
- traffic analysis
- active attackers on the network path

## Non-Goals

- Multiple endpoints
- Server hopping
- Switching between geographic locations
- Large setups with many users

## Architecture

### Flow

```
Client -> Client-Owned Server -> Destination
```

Your client sends traffic through a server you own, and the server passes it
on to where it is going.

### Components

The client starts the handshake (the first exchange, which sets up the keys)
and encrypts your traffic. The server finishes the handshake, decrypts the
traffic and forwards it. Both ends add chaff (fake packets) to what they
send.

### State Model

A session is a state machine with six states:
`IDLE -> CONNECTING -> HANDSHAKING -> ESTABLISHED -> REKEYING -> TEARDOWN -> IDLE`

### Concurrency

DSM runs on a single thread with Python's asyncio. Three loops run side by
side under `asyncio.gather`: `recv_loop`, `tun_send_loop` and
`liveness_loop`. The client adds a fourth, `auto_mtu_loop`.

## Networking

### Transport

- UDP (the default).
- TCP (a fallback). Each frame starts with a 4-byte big-endian length prefix.
  Every frame is padded to the largest size class, so the length prefix is
  always the same on the wire.

  TCP only hides DSM from simple DPI. It does not stop passive traffic
  analysis. Someone watching the path still sees the TCP handshake
  (SYN / SYN-ACK / ACK), the teardown (FIN / RST) and the fingerprint of how
  the connection is set up. DSM's own padding and timing inside the tunnel
  do not change that. TLS-fronting (hiding the tunnel inside
  ordinary-looking TLS traffic) would close this gap, but it is out of
  scope. Use UDP for the best anonymity DSM offers. Use TCP only when a
  network blocks UDP, or when a symmetric NAT (a strict kind of router
  address sharing) makes UDP unusable.

### Connection

Each server instance serves one client. The server opens a single socket.
Over TCP it accepts one connection. Over UDP it locks onto the first peer
address that passes authentication. A session ends cleanly with a
SESSION_CLOSE packet.

### Reliability

- The handshake is retried with growing waits (exponential backoff):
  3 attempts, waiting 1 s, 2 s, then 4 s.
- After the Noise messages comes a bootstrap ephemeral-DH exchange (a
  one-time key exchange). If its reply is lost, msg3 and bootstrap_init are
  resent together, as a pair, until a timeout.
- Key-change retries: if the REKEY_ACK (the reply that confirms a key
  change) does not arrive within REKEY_ACK_TIMEOUT=8s, the side that started
  the change resends the same REKEY_INIT. It does this up to
  MAX_REKEY_RETRIES=9 times, then gives up. The total retry window
  (8s × 9 = 72s) is longer than the 60s rekey rate limit on purpose. That
  gives a responder that is still inside its own rate-limit window time to
  accept a later resend. The responder keeps the last ACK payload, so a
  duplicate INIT gets the same ACK again without a second key change.
- DSM does not resend lost data packets. It relies on the protocol inside
  the tunnel, or on TCP.

### Fragmentation

- There is a FRAGMENT packet type (0x07).
- The receiver puts fragments back together (reassembly), as part of the
  data path. It holds a limited number of partial packets, drops a partial
  packet after 5 seconds, and accepts at most 16 fragments per ID.
- The sender splits any packet that is too big for one padded wire packet.
  The limit is the largest size class minus the outer header, the tag and
  the inner header: about 1360 B. Such a packet is split into up to 16
  FRAGMENT packets, each sized to fit one padded outer packet.

### Path MTU

The MTU is the largest packet a link can carry.

- The TUN MTU can be set: default 1400, allowed 576-1500.
- Optional: the kernel's Path MTU Discovery on the UDP socket
  (IP_PMTUDISC_DO). It sets the DF (don't fragment) bit and records ICMP
  "frag needed" replies.
- At session start the client logs the path MTU the kernel found. It warns
  if the configured TUN MTU is bigger than the usable inner budget (the room
  left for data inside one packet).
- Optional `auto_mtu` (client only): a background loop reads the kernel's
  path MTU every `pmtu_check_interval_s` (default 30 s) and adjusts the TUN
  MTU. It lowers the MTU at once when the path MTU drops. It raises it back
  toward `mtu` only after 3 steady readings in a row, so a short bump cannot
  make it flip back and forth. Recommended for cellular and roaming clients.

## Cryptography

### Key Exchange

- The handshake uses the Noise XX pattern (X25519 + AES-256-GCM + SHA-256).
- Its prologue (a fixed tag that both sides mix into the handshake) is
  `"DSM\x00\x01\x00\x01"`.
- Every handshake message is padded to 1400 bytes, so they all have the
  same size.
- Each side sends a CA-signed device certificate inside the Noise XX
  msg2/msg3 payload. It is an X.509 certificate: an ECDSA P-256 leaf signed
  by an internal P-384 CA.
- The certificate ties together two keys of the device: its ECDSA
  attestation signing public key and its X25519 Noise static key. It does
  this with a custom critical extension, id-dsm-noiseStaticBinding
  (1.3.6.1.4.1.99999.1.1).
- Attestation: the default build uses the TPM 2.0 backend (`tpm-attest`).
  The ECDSA P-256 attest key is created inside a TPM 2.0, signs inside it
  and never leaves it. Not even code running as root can copy it out. The
  `attest_key_file` on disk holds only a blob tied to that TPM, useless on
  any other TPM. This is key residency: it proves the signing key lives in
  this device's TPM. It is not PCR-policy sealing, and it is not remote
  attestation or TPM quotes; those are future work. So a valid binding does
  not, by itself, vouch for a measured boot state (a record of what the
  device booted). The software backend (`dev-soft-attest`) stays available
  as a dev and test build only. Its key is Argon2id-wrapped on disk, but it
  can be copied out of process memory. So treat its binding as a software
  credential, not a hardware root of trust. Hardware binding on Android
  (Keystore/StrongBox) is planned (Phase 3).
- In each handshake the attest key signs a binding over the Noise handshake
  hash, remote_static and the role. So the signature cannot be reused in
  another handshake.
- The server accepts only the client CNs (certificate names) listed in
  `allowed_cns_file`, one per line. The client checks the server
  certificate's CN against `expected_server_cn`.
- An optional CRL (certificate revocation list) is carried from the offline
  CA by USB stick, on the CA's regular schedule.

### Key Rotation

- Keys change every 5000 packets or 600 seconds (both can be set).
- Each change runs a fresh ephemeral X25519 DH (a one-time key exchange).
- New keys come from HKDF-SHA256, with a different label for each direction
  and the epoch (the key generation number) in the info field.
- Packets still in flight under the old keys are accepted for 5 more
  seconds (the grace period).
- At most one key change per 60 seconds.

### Encryption

Packets are encrypted with AES-256-GCM, an AEAD (encryption that also detects
tampering). The sequence number is the AAD: it is sent unencrypted, but any
change to it is detected.

### Nonce Strategy

A nonce is a number that must never repeat under the same key.

- DSM uses a structured 96-bit nonce: epoch(32) || counter(32) || random(32).
- The counter makes each nonce unique within an epoch.
- The random part makes nonces hard to predict.
- The epoch part keeps nonces from different key changes apart.
- When the counter runs out, it is poisoned: it returns None from then on.
  So even a session that somehow ran past 2^32 packets cannot reuse a nonce.

### Replay Protection

A 128-bit sliding window (a bitmap of recently seen packet numbers) catches
replayed packets. During the grace period, each epoch has its own window. The
window is checked before decryption and updated only after the packet passes
authentication.

### Key Storage

- The identity key (the X25519 Noise static key) is encrypted on disk with
  Argon2id + XChaCha20-Poly1305.
- The attest key (ECDSA P-256) is stored the way its backend requires (see
  Key Exchange). On `tpm-attest` the file on disk is a versioned, TPM-bound
  DSMT context blob that loads only on the TPM that made it. The operator
  passphrase is the key's authorization value inside the TPM, so signing
  needs both the TPM and the passphrase. A forgotten passphrase means
  enrolling again. On `dev-soft-attest` the key is sealed on disk with
  Argon2id under the same passphrase.
- Argon2id settings: 512 MiB of memory, 4 iterations, parallelism 2.
- Keys are locked in memory (mlock) while in use, so they are not swapped to
  disk.
- Keys are wiped in a single pass when they are dropped, using the Rust
  zeroize crate.
- Core dumps are turned off at startup (setrlimit RLIMIT_CORE).
- Files are written atomically (all or nothing), with 0600 permissions
  (tmpfile -> fchmod -> fsync -> rename).

## Anonymity and Traffic Resistance

### Padding

- With the default settings, every packet is padded to one of 11 sizes
  (size classes): 128, 256, 384, 512, 640, 768, 896, 1024, 1152, 1280 or
  1400 bytes. `padding_min` and `padding_max` can narrow this list, and
  `auto_mtu` drops sizes that are too big for the path. A real packet too
  big for every size left is sent at its exact size.
- The padding sits inside the encryption: it fills the encrypted part up to
  the size class. So no unauthenticated padding is left on the wire.
- In TCP mode every frame is padded to the largest class (1400), so all
  frames have the same size on the wire.
- Real and fake packets draw their size from the same fixed, published mix
  (`SIZE_CLASS_WEIGHTS`), never from your live traffic. Every DSM user has
  the same mix. So the sizes on the wire tend to look the same for everyone,
  instead of showing which apps you use. Small and mixed-size traffic
  follows the mix closely, because a small packet almost never needs a
  bigger size than the one drawn.

### How DSM hides your traffic

Someone watching your connection cannot read what you send. But they can
still count your packets and time them. DSM makes those counts and times
say as little as possible.

**Steady steps.** Packets leave at a steady pace. The pace only changes in
a few fixed steps, called tiers. By default the tiers are 10, 50, 200 and
800 packets per second, and the lowest one is the idle pace. Your real
packets take free places in this flow, and fake packets (called chaff) fill
the rest. A real packet takes the next free place; DSM adds no other wait.
At every tier, real packets wait in a queue until a free place comes. The
queue holds up to 512 packets; when it is full, the oldest packet is
dropped. That can happen at any tier, for example when a big burst comes in
before the pace has stepped up. Control messages, such as the reply that
confirms a key change or the check the server sends when your address
changes, also take normal free places. They wait in their own small queue
that goes first, so a full queue of data never holds them up or drops them.
Only the goodbye message at shutdown goes straight out.

**Going up and coming down.** Apart from decoys (below), DSM moves up a
tier only when your real packets have waited too long: by default, a
random point between 0.25 and 0.5 seconds. Now and then it jumps two tiers
at once. It comes down slowly. After every change it does not come down
for about 1 to 5 minutes (it can still go up). Then it steps down only if,
over the last 5 to 15 seconds, you used less than about half of what the
lower tier can carry. So coming down from the top takes several minutes
per tier. Before it drops back to idle, it stays one step up for a while
longer: 5 to 30 minutes by default. When that time is up, it checks your
use again. If you are still using the link, it stays one step up, and the
next drop to idle waits again.

**Fake busy periods.** Now and then DSM pretends to be busy. These "decoys"
climb the way a real page load does. Each one picks a tier to reach: the
top tier between half and four fifths of the time (each session picks how
often), otherwise a lower one. It climbs there one step at a time, through
exactly the same steps as real use. Then it stays busy for a while and
comes down slowly, just like real use. So a watcher cannot tell which
short busy periods were real. A decoy's busy stretch lasts 1 to 6 minutes
on average, so a much longer busy period is almost surely real. By default
a decoy comes about every 2 hours on average (each session picks its own
average, between 1 and 4 hours).

**Secret numbers.** Every session secretly picks its own timing values:
how fast each tier really is (within 20% of the set value), how uneven the
gaps between packets are, how often it jumps two tiers, how long it waits
before coming down, how it judges your use, how often decoys come and how
often they go to the top. It picks new values every 10 to 40 minutes. So
reading this code does not tell a watcher the numbers your session uses.

**Sizes.** Real and fake packets are padded to sizes from the same fixed
list (128 to 1400 bytes), using the same fixed mix in which smaller sizes
are more common. A real packet is bumped up to the next size that fits it.
A fake packet's size is moved one step up or down now and then. Your past
packets never change the mix. (Older versions picked real sizes from a
running average of your own traffic. Within tens of packets, most real
packets ended up at one size, your most common one, which gave it away.
That is gone.)

**What it costs** (per direction; padding only, not counting your real
traffic):

| Situation | Cost |
|---|---|
| Connected all day, no use, decoys on | about 3 GB a day |
| Connected all day, about 20 bursts of real use | about 6 GB a day |
| Each decoy | about 0.2 GB (the climb, the busy stretch, the slow step-down and the wait before idle) |
| After using the top tier | the top tier for 1 to 5 minutes, then a few minutes per lower tier, then 5 to 30 minutes at tier 1 (about 0.15 GB) |
| Top speed | about 3.6 to 5.4 Mbit/s at the default `mtu = 1400`: one DSM packet carries at most 1360 bytes, so each full-size packet is split in two. Up to about 7 to 10 Mbit/s with `mtu` at 1360 (less for a smaller `mtu`) |
| When a burst starts | about 0.5 to 1.5 seconds of extra wait while the pace steps up |

**What it hides** from someone watching the link between you and your
server:

- how fast you really send: they only see which tier you are on;
- short bursts that fit in the current tier;
- when you stop: the slow step-down and the wait before idle blur it by
  minutes;
- whether a short busy period was real: decoys look the same.

**What it does not hide:**

- that you use DSM at all;
- roughly how much you send: a watcher sees which tier you are on, and a
  long download keeps the rate up for as long as it runs;
- the packet counter at the start of every packet. It is not encrypted, and
  it links your traffic across port changes. (A fix is planned.)
- anything from someone who watches both your link and your server's own
  internet traffic. Your real busy periods line up with what your server
  sends out, so they can filter out decoys and the wait before idle. With
  one user per server, all of the server's outgoing traffic is you;
- when your device is off;
- the start of a connection: the handshake (the first exchange that sets up
  the keys) has a fixed, recognizable pattern before any cover traffic runs.
  Hiding it is left to research after v1;
- in TCP mode, the TCP connection itself (its setup and teardown);
- the exact amount of data: the tiers pace packets, not bytes, and big real
  packets (for example during a large download) push more packets into the
  largest size, because padding can only make a packet bigger.

The tiers, the wait limit, decoys and the wait before idle are set in
`config.example.toml`, which also lists the costs. Both ends ship the same
defaults, and each end shapes only what it sends.

### Timing

- DSM adds no random wait of its own: a queued packet takes the next free
  place in the flow. Queued control messages leave first, then queued data,
  each oldest first.
- The old per-packet wait settings, `jitter_ms_min` and `jitter_ms_max`,
  were removed. A config that still has them stops at startup with a clear
  message.
- The tier shaper settings and what they cost are explained in
  `config.example.toml`.

### Leak Prevention

- An nftables kill switch blocks all traffic that does not go through the
  VPN.
- mDNS (5353) and LLMNR (5355) are blocked, so they cannot be used to map
  the local network.
- DNS (53/udp+tcp) and DoT/DoQ (853; DNS over TLS or QUIC) are always
  blocked on interfaces other than the TUN. There is no exception for the
  server IP for cleartext DNS or DoT. The "except to the server IP"
  exception applies only to HTTPS/DoH and DoH3 (443/tcp+udp; DNS over
  HTTPS). So the encrypted tunnel itself can reach the server, while every
  other DoH destination is dropped.
- VPN sockets are marked with SO_MARK=0x1, so the ip rule skips the TUN
  routing table for them. This avoids routing loops.
- Name lookups run on the server. A DNS proxy listens on UDP port 53 on the
  server's TUN address. It resolves each query asynchronously (DoH, DoT, a
  static hosts file, caching) and sends the answer back to the client inside
  the tunnel.

## Threat Model

### Attackers

- ISP surveillance
- DPI systems
- Active MITM (man-in-the-middle) attackers
- State-level attackers
- Hostile or open Wi-Fi networks

### Assumptions

- The network is hostile.
- The server is trusted: you own and run it. It is where the tunnel ends, so
  it sees the client's source IP and the decrypted traffic. DSM does not
  promise to keep that traffic secret from the server operator. Some things
  still hold against a misbehaving server, thanks to the CA-signed device
  certificate and the attestation binding. It cannot forge a client's device
  identity, swap in a different Noise static key, or pivot to (move on to
  attack) other enrolled devices. Peer authentication and the session keys,
  agreed end to end, stay sound. SECURITY.md states the same split.
- The client device is physically secure.

### Out of Scope

- Physical access to the client or server
- Compromised dependencies or libraries
- Anonymity from the server operator (the server sees the client's IP)

**Accepted v1 risks.** The traffic-analysis limits listed under "What it
does not hide" (in "How DSM hides your traffic" above) are known and
accepted for v1, not fixed. One more limit: the default `tpm-attest`
backend only proves that the ECDSA attest key lives in this device's TPM 2.0
chip and cannot be copied out. That stops theft of the key from disk or
memory, but it does not tie the key to a measured boot state (no PCR policy)
and does no remote attestation or TPM quotes. The `dev-soft-attest` build
has no hardware binding, and its key can be copied out of memory: never
deploy it.

## Implementation

Python handles the protocol, networking and session management, and builds
the padded real and fake packets. Rust (the `tuncore` crate, loaded through
PyO3) does the cryptography, key management and memory protection, and
decides when packets leave and how big they are.

### Rust crate (tuncore)

- AES-256-GCM encrypt/decrypt
- X25519 key exchange
- Noise XX handshake (through the snow crate, with a fixed-size attest
  payload)
- HKDF-SHA256 key derivation
- Argon2id password hashing
- Nonce creation: unique by design, and poisoned when the counter runs out
- Replay window (128-bit bitmap)
- Tier shaper: when packets leave, packet sizes, decoys and the
  per-session secret timing values (`src/shaper.rs`)
- Secure memory (mlock, zeroize, core dumps off)
- Identity + attest key storage (XChaCha20-Poly1305)
- ECDSA P-256 device attestation, with two backends. The default is the
  TPM 2.0 key-residency backend, through tss-esapi: the key is generated,
  signs, is stored and is wiped inside the TPM, with a DSMT context blob on
  disk. The software backend is for dev and CI only, and its key can be
  copied out.

### Dependencies

- Python: cryptography (reads X.509 certificates and CRLs) and dnspython
  (reads DNS messages in the server's DNS proxy). DoH runs over DSM's own
  asyncio TLS + HTTP/1.1 code, not httpx. That way the SPKI pin (a hash of
  the provider's public key) is checked on the live SSL connection before
  the query name crosses the wire.
- Rust: snow, aes-gcm, hkdf, sha2, x25519-dalek, zeroize, argon2,
  chacha20poly1305, hmac, subtle, libc, rand/rand_core, serde, pyo3. Also:
  - tss-esapi, only with `tpm-attest` (the default). It links the system's
    tss2-esys through pkg-config. tss-esapi-sys ships ready-made
    x86_64-linux bindings, so no libclang or bindgen is needed.
  - rcgen, only on the soft-attest path, to build CSRs in Rust.
  - p256, used by both backends: for the soft CSR in Rust, and for the SPKI
    and signature DER encoding of the in-TPM public key.

## Configuration

The config file is TOML, at `/opt/mtun/config.toml`.

### Parameters

- mode: client | server
- server_ip: a literal IPv4 address, or a DNS hostname (for example a DDNS
  name for a home server). The client looks the hostname up once at
  startup, before the kill switch is installed. That one lookup is sent in
  the clear; use a literal address to avoid it. IPv6 is rejected (the
  transport is AF_INET-only, that is, IPv4 only).
- server_port, listen_port
- key_file: path to the Argon2id-wrapped X25519 Noise static key
- cert_file: path to the device's CA-signed leaf certificate (PEM or DER)
- ca_root_file: path to the pinned CA root certificate (PEM)
- ca_root_sha256: **required.** The 64-hex SHA-256 of ca_root_file. The
  daemon refuses to start if it is not set, and rejects a ca_root_file whose
  hash does not match. This pins the trust anchor: a swapped CA PEM on disk
  stops startup instead of being trusted without notice. Compute it with:
  `sha256sum <ca_root_file> | cut -d' ' -f1`
- attest_key_file: path to the attest-key file. On the default tpm-attest
  build it is a TPM-bound DSMT context blob, with no key that can be copied
  out. The operator passphrase is the in-TPM key's authorization value, so
  signing needs both this TPM and the passphrase. On the dev-soft-attest
  build it is an Argon2id-sealed ECDSA P-256 software key under the same
  passphrase.
- attest_tpm_tcti: tpm-attest only. An optional TSS2 TCTI string that picks
  the TPM (for example "device:/dev/tpmrm0"). If it is not set, DSM uses the
  TCTI or TPM2TOOLS_TCTI environment variable, then /dev/tpmrm0. The soft
  backend ignores it.
- crl_file: optional path to the CA's CRL (PEM or DER)
- crl_strict: bool (default: true). When true, DSM refuses to start if
  crl_file is missing or the loaded CRL is past its next_update. When false,
  a missing or stale CRL only logs a WARNING, and revoked certificates are
  accepted (meant for lab and dev use only).
- expected_server_cn: client only; the subject CN accepted on the server
  certificate
- allowed_cns_file: server only; one allowed client subject CN per line. The
  file must have no group or world access bits and must be owned by the
  daemon's uid. Otherwise startup refuses to load it.
- max_inflight_handshakes: server only; how many handshake attempts the UDP
  acceptor checks at the same time (default: 8, allowed 1-4096, warns above
  1024). One stalled attempt cannot block a real client.
- transport: udp | tcp (default: udp)
- dns_providers: DoH/DoT URLs (server mode)
- dns_provider_pins: SPKI SHA-256 pins for each provider (server mode,
  required). Every name in it must also be listed in dns_providers. TOML
  reads every line below the `[dns_provider_pins]` header as part of this
  table, so keep it last in config.toml and put all other settings above
  it. A setting below it stops startup with a message that names it.
- tun_name: TUN device name (default: mtun0)
- mtu: TUN interface MTU in bytes (default: 1400, allowed 576-1500)
- pmtu_discover: turn on kernel PMTUD (path MTU discovery) on the UDP socket
  (default: false). `auto_mtu` needs it, because the kernel only tracks each
  path's MTU when this is on.
- auto_mtu: client-side loop that adjusts the TUN MTU (default: false). It
  lowers the MTU when the path MTU drops, and raises it back toward `mtu`
  after 3 steady readings. Recommended for cellular and roaming clients.
- pmtu_check_interval_s: how often the auto_mtu loop reads the kernel's path
  MTU, in seconds (default: 30, allowed (0, 3600]).
- log_level: debug | info | warning | error (default: info). See Logging
  below.
- padding_min, padding_max: padding range (default: 128-1400). A narrow
  range leaves fewer sizes, and a real packet too big for every size left
  is sent at its exact size (see Padding above).
- shaper_tiers_pps: the tier rates in packets per second, lowest first
  (default: [10, 50, 200, 800]; 2 to 8 entries, each 1 to 5000, each higher
  than the one before). The first one is the idle rate. It must be above
  4.25 divided by the latency budget in seconds: above 8.5 with the default
  budget of 500 ms. Otherwise DSM refuses the config at startup, because a
  slower first tier would let light traffic change the send times.
- shaper_latency_budget_ms: how long a real packet may wait before the rate
  steps up (default: 500; 10 to 5000). Lower means less waiting, but steps
  that are easier to see.
- shaper_decoy_interval_s: average seconds between decoys (default: 7200;
  0 turns decoys off, otherwise 300 to 86400).
- shaper_linger_s: how long to stay at tier 1 before going idle, as
  [min, max] seconds (default: [300, 1800]; [0, 0] turns it off, otherwise
  0 < min <= max <= 7200).
- An old `envelope_*` key stops startup with a message that names these
  four keys.
- The removed `jitter_ms_min` and `jitter_ms_max` keys also stop startup,
  with a message that says to remove them.
- rotation_packets, rotation_seconds: when keys change, by packet count or
  by seconds (default: 5000/600)
- debug_dns: log DNS queries in plain text (default: false). Otherwise the
  logs show `qname-tag=` and 16 hex characters in place of each name: a
  keyed hash with a random key made at each start, so the same name keeps
  its tag while DSM runs and gets a new one after a restart.
- debug_net: write structured JSON events to the `dsm.netaudit` logger
  (handshake start/end, nft apply/remove, TUN configure/deconfigure, rekey,
  liveness, shutdown, auto_mtu_change, crl_missing, crl_stale). Default:
  false. It can also be turned on for a single run with the `--debug-net`
  CLI flag.

## Operator Guide

`deploy/GUIDE.md` walks an operator through setup, from prerequisites to
checking that it works. It also covers routine tasks and debugging by
symptom. The same directory holds `openssl-ca.cnf` (the OpenSSL config for
the offline CA) and `dsm.service` (the systemd unit).

## Logging

The default is `log_level = "info"`. It shows the main lifecycle lines
(listening, handshake complete, connected, configured, MASQUERADE for
`<iface>` applied, sysctl changes, shutting down) but nothing per packet.
Use it both when you first deploy and for everyday running.

- `log_level = "debug"` traces the protocol: every packet class, every
  retry, every key derivation step. It is verbose. Use it during bring-up or
  to chase a specific protocol bug.
- `log_level = "warning"` or `"error"` shows only problems. Note: at warning
  you will not see "tunnel established", "MASQUERADE applied" or other
  normal lines. That makes it much harder to tell whether the new code is
  running.

## Testing

- Python tests (unittest, discovered by pytest). The full suite runs
  against a soft wheel; the TPM-only tests run under a tpm wheel.
- Rust tests run in two feature lanes that cannot be combined: the soft lane
  (`cargo test --no-default-features --features dev-soft-attest`) and the
  TPM lane, driven by swtpm, a software TPM (`cargo test
  --no-default-features --features tpm-attest --test tpm_swtpm --test
  dsmt_format`).
- The tests cover protocol serialization and framing, state machine (FSM)
  transitions, config validation, replay window and nonce handling, key
  rotation, key storage, Noise XX with the attest payload, X.509
  chain/binding/CRL/CN policy, enrollment, the full TUN-to-TUN data path
  over UDP and TCP, rekey retry, auto_mtu, the netaudit event schema, the
  DNS proxy, and the tier shaper. For the tier shaper there are seeded Rust
  tests, including the check that traffic fitting the current tier leaves
  send times unchanged, plus Python tests of the wrapper, the config rules
  and the send loop. The TPM lane adds in-TPM generate/sign/zeroize, the
  residency-critical object attributes, cross-TPM blob rejection, and the
  DSMT format.
- The Python test suite needs the built `tuncore` extension. The size list
  lives in Rust, so `dsm.core.protocol`, and every module that uses it,
  fails to import without it.

### Run

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

The current build (Phase 1 + Phase 2A + Phase 3 TPM) is single-client,
single-server and Linux-only. It uses certificate-based authentication:
CA-signed device certificates tie the ECDSA attest key to the X25519 Noise
static key through a custom critical X.509 extension.

Open items:

- More TPM hardening: tie the attest key to a PCR policy (measured boot)
  and add remote attestation (TPM quotes). Then a peer can check that the
  key really lives in a TPM, not just that the signature is valid. Today's
  backend proves residency locally but produces no quote.
- Header protection: encrypt the packet counter and key epoch at the start
  of every packet, which are sent in the clear today. This changes the wire
  format.
- Phase 2B: a real-network demo on two physical Linux machines across two
  ISPs (a server on home Wi-Fi, a client on cellular). The steps are in
  `deploy/GUIDE.md` §9. Once the strace audit step there is done,
  RestrictNamespaces and SystemCallFilter will be added to
  `deploy/dsm.service`.
- An Android client (Kotlin VpnService + JNI to the Rust crate, with
  hardware-bound signing through Android Keystore/StrongBox). As part of
  this work the protocol state machine moves into Rust, so Linux and Android
  share one implementation.
- A third-party pentest: writing the threat model, running the hardening
  checklist, a telemetry build toggle, and coordinating the engagement.
