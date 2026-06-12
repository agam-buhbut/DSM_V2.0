# DSM VPN — Operator Guide

This is the single source of truth for deploying, running, verifying, and
troubleshooting DSM. Every command is copy-paste-runnable. If you have a
fresh Linux box and the repo checked out, working through sections 0 → 7
end-to-end gives you a live tunnel. The later sections (8 single-host
smoke test, 9 two-box demo, 10 debugging, 11 uninstall) are reference
material you reach when you need them.

Architecture in one sentence:  one client connects to one operator-owned
server over UDP (default) or TCP. Both ends authenticate with X.509
device certs signed by your offline CA; the cert binds the device's
ECDSA attestation signing key AND the device's X25519 Noise static
via a custom critical extension, so a stolen cert OR a stolen Noise key
alone is useless.

ATTESTATION (the default is now hardware-bound):  the default build uses
the TPM 2.0 attestation backend (the tpm-attest Cargo feature). The ECDSA
P-256 attest key is GENERATED INSIDE the TPM, never leaves it, and SIGNS
inside it — it is non-extractable even by code running as root. The on-disk
attest_key_file holds only a TPM-bound DSMT context blob (a sealed handle,
useless on any other TPM), not the key itself. This is KEY RESIDENCY: it
proves the signing key lives in this device's TPM. It is NOT a PCR-policy
seal and NOT remote attestation / TPM quotes — those remain future work, so
do not treat a valid binding as proof of a measured-boot state. Prerequisite:
the host needs a TPM 2.0 (see §0e). The dev/test SOFTWARE backend is still
available as the `dev-soft-attest` build (see §1, "soft wheel"); its key is
Argon2id-wrapped on disk and EXTRACTABLE from process memory, so use it for
testing only — never treat its binding as a hardware root of trust.

Hardware binding on Android (Keystore/StrongBox) remains planned (Phase 3).

Companion files in this directory:

- `deploy/openssl-ca.cnf` — OpenSSL config used by the offline CA in §3.
  UNCHANGED by the TPM backend: the CSR and leaf cert have identical
  structure (same P-256 SPKI algorithm, same critical noiseStaticBinding
  extension) whether the key is soft or TPM-resident.
- `deploy/dsm.service` — systemd unit shipped with the repo.

Top-level `README.md` covers everything ABOVE the operator layer: protocol
state machine, cryptographic primitives, anonymity properties, threat
model, configuration parameter list. Read it once when you want to
understand WHY the operator steps below look the way they do.

## Table of Contents

  0.  Prerequisites
  1.  Build (every host that will run dsm)
  2.  CA bootstrap (one time, on the air-gapped laptop)
  3.  Per-device enrollment (server first, then each client)
  4.  Authorization (add client CN to the server's allowlist)
  5.  Run both sides
  6.  Verification
  7.  Common operator tasks
  8.  Single-host loopback smoke test
  9.  Two-box demo across two real ISPs
  10. Debugging by symptom
  11. Uninstall
  12. File placement reference
  13. CLI reference

## 0. Prerequisites

### 0a. Hardware / OS (every host)

- Linux kernel 5.x or newer with TUN/TAP support:

  ```sh
  $ sudo modprobe tun && ls /dev/net/tun
  ```

- Network reachability: server must have an IP the client can reach
  directly (public IPv4/IPv6 or a routable port-forward). Cellular
  clients work outbound-only.
- The dsm process needs CAP_NET_ADMIN + CAP_NET_BIND_SERVICE
  (TUN create, nftables apply, sysctl writes, bind UDP/53 on the
  TUN address). The shipped systemd unit (deploy/dsm.service)
  drops everything else from CapabilityBoundingSet and runs as
  User=root. If you invoke dsm without systemd, use `sudo`.

### 0b. Install system packages (Debian / Ubuntu)

```sh
$ sudo apt update
$ sudo apt install -y \
      build-essential pkg-config \
      python3 python3-venv python3-pip python3-dev \
      nftables iproute2 curl ca-certificates git xxd
```

### 0c. Install the Rust toolchain (if you don't already have it)

The official rustup installer is the easiest path — no root, installs
into ~/.cargo:

```sh
$ curl --proto '=https' --tlsv1.3 -sSf https://sh.rustup.rs | sh -s -- -y
$ source "$HOME/.cargo/env"
$ rustc --version                 # e.g. rustc 1.82.0 (stable)
```

On distros that package rustc >= 1.74 you can `sudo apt install rustc
cargo` instead — but maturin expects a recent cargo, so rustup is
more reliable.

### 0d. Pre-flight check

```sh
$ python3 --version       # 3.11 or newer
$ gcc --version           # any recent gcc
$ rustc --version         # stable channel
$ sudo nft --version      # nftables
$ ls /dev/net/tun         # TUN node present
$ ip link                 # iproute2 working
```

### 0e. TPM 2.0 prerequisites (DEFAULT attest backend — required)

The default build (the tpm-attest Cargo feature) keeps the device
attestation key INSIDE a TPM 2.0. Every host that runs dsm — or runs
`dsm enroll` — therefore needs a working TPM 2.0 and its userspace
stack. (Only the dev-soft-attest test build skips this — see §1.)

- A TPM 2.0 with the in-kernel resource manager exposed:

  ```sh
  $ ls -l /dev/tpmrm0          # expect: crw-rw---- root tss (mode 0660)
  ```

  If you only have /dev/tpm0 (no resource manager), load the kernel
  module or upgrade the kernel — dsm targets /dev/tpmrm0 by default.
  Firmware TPMs (fTPM/PTT) and discrete TPM chips both work.

- The TSS2 runtime libraries (Esys + the device TCTI):

  ```sh
  $ sudo apt install -y libtss2-esys-3.0.2-0 libtss2-tcti-device0
  ```

  (On some releases these are pulled in by `tpm2-tools`. The build host
  additionally needs `libtss2-dev` for headers + pkg-config — that is a
  BUILD dependency, added in §1 below, not a runtime one.)

- Group access. /dev/tpmrm0 is owned tss:tss mode 0660. The shipped
  deploy/dsm.service runs as root and also sets SupplementaryGroups=tss,
  so the daemon can open the TPM. When you run `dsm enroll` BY HAND, run
  it as a user that is either root or in the `tss` group:

  ```sh
  $ sudo usermod -aG tss "$USER"   # then log out / back in
  ```

  or simply prefix the enroll commands in §3 with `sudo` (the guide
  already does).

- Optional inspection tooling (not required by dsm):

  ```sh
  $ sudo apt install -y tpm2-tools   # tpm2_getcap, tpm2_pcrread, …
  ```

- swtpm (the software TPM emulator) is CI-ONLY: it backs the hermetic
  test suite. Production hosts must use a real TPM 2.0; do NOT point a
  production deployment at swtpm.

Sanity check the TPM is reachable before enrolling:

```sh
$ tpm2_getrandom --hex 8         # prints 16 hex chars if the TPM works
```

(`dsm enroll` runs its own preflight and fails with an actionable
message if the TPM or the tss group is missing.)

## 1. Build

The dsm process runs under `sudo` (CAP_NET_ADMIN + CAP_NET_BIND_SERVICE),
which means Python's interpreter is the system one at /usr/bin/python3 —
NOT a venv, NOT a --user install. Every Python module dsm imports
(tuncore, dns, cryptography) MUST be visible to /usr/bin/python3.

If you previously created a .venv under the repo from an earlier
attempt, delete it now so you don't get confused later:

```sh
$ rm -rf .venv
```

All commands below are from the top-level repo directory.

### 1a. Build the dsm wheel (ONE wheel: dsm package + tuncore extension)

maturin, run FROM THE REPO ROOT, produces a single Python wheel that
contains BOTH the compiled Rust extension (tuncore) AND the pure-
Python `dsm` package. Run it from the repo root (NOT from
rust/tuncore) — the root pyproject.toml's [tool.maturin] manifest-path
points maturin at rust/tuncore/Cargo.toml and bundles the `dsm`
package alongside the extension. Building requires a venv (maturin
quirk) — we throw it away once the wheel is built.

The DEFAULT build links the TPM 2.0 backend (tpm-attest), which needs
the TSS2 development headers + pkg-config at BUILD time:

```sh
$ sudo apt install -y libtss2-dev      # tss2-esys headers + pkg-config
# (tss-esapi-sys ships pregenerated x86_64-linux bindings, so no
#  libclang / bindgen is needed — only this dev package.)
```

DEV/TEST ONLY — the soft wheel:  to build the extractable SOFTWARE
attest backend for local testing (no TPM, no libtss2-dev), pass
`--no-default-features --features dev-soft-attest` to the maturin build
commands below. The result imports identically but its attest key is
NOT hardware-bound — never deploy it. The rest of this section assumes
the default (TPM) wheel.

```sh
$ python3 -m venv /tmp/dsm-build-venv
$ /tmp/dsm-build-venv/bin/pip install --upgrade pip maturin

$ /tmp/dsm-build-venv/bin/maturin build --release
# maturin writes the wheel under the Cargo target dir, i.e.
# rust/tuncore/target/wheels/ (NOT <repo>/target/wheels/):
$ ls rust/tuncore/target/wheels/            # confirm dsm-0.1.0-*.whl appeared
```

The wheel is named dsm-0.1.0-`<pytag>`-`<platform>`.whl. Confirm it
bundles both halves (and does NOT ship the test suite):

```sh
$ unzip -l rust/tuncore/target/wheels/dsm-0.1.0-*.whl \
      | grep -E 'dsm/__main__|tuncore.*\.so'
# expect both a dsm/__main__.py line and a tuncore/...so line
```

You can `rm -rf /tmp/dsm-build-venv` at the end of section 1.

### 1b. Install the wheel into the system Python (pins runtime deps)

Installing the dsm wheel ALSO installs its runtime dependencies at the
versions pinned in pyproject.toml ([project].dependencies:
cryptography>=46.0.7,<49 and dnspython>=2.6,<3.0). Do NOT install
`dnspython cryptography` unpinned by hand — let the wheel's metadata
pin them so a surprise major release can't be pulled in:

```sh
$ sudo /usr/bin/python3 -m pip install --break-system-packages \
      "$(ls $PWD/rust/tuncore/target/wheels/dsm-0.1.0-*.whl | tail -1)"
```

--break-system-packages is required on PEP-668 distros (Debian 12+,
Ubuntu 23.10+, Fedora 38+). It's the right flag here: we're
knowingly installing into the system Python because root needs to
see these packages.

For a fully reproducible, exactly-pinned install (recommended for
production), the repo ships requirements.lock (a uv-compiled pin set:
cryptography==48.0.0, dnspython==2.8.0, plus their transitive deps).
Pre-install those exact versions, then add the wheel without letting
pip re-resolve the transitive set:

```sh
$ sudo /usr/bin/python3 -m pip install --break-system-packages \
      -r requirements.lock
$ sudo /usr/bin/python3 -m pip install --break-system-packages \
      --no-deps "$(ls $PWD/rust/tuncore/target/wheels/dsm-0.1.0-*.whl | tail -1)"
```

Installing the wheel puts BOTH `import dsm` and `import tuncore` on
/usr/bin/python3's path, so `python3 -m dsm` resolves from any working
directory — including under systemd (cwd=/), which is why
deploy/dsm.service needs no WorkingDirectory= or PYTHONPATH=.

NOTE: dsm has NO httpx dependency. The DoH client is a hand-rolled
asyncio TLS + HTTP/1.1 path so the SPKI pin is checked on the live
SSL object before the qname crosses the wire.

### 1c. Verify the install

Run this EXACT command FROM A DIRECTORY THAT IS NOT THE REPO (e.g.
/tmp) — running from the repo root would let cwd-on-sys.path mask a
bad install. It confirms root's Python sees every import dsm needs,
including the `dsm` package itself out of the installed wheel:

```sh
$ cd /tmp && sudo /usr/bin/python3 -c \
      "import dsm, tuncore, dns, cryptography; print('all 4 imports ok')"
```

You must see "all 4 imports ok" before continuing. If any import
fails:

- "No module named 'dsm'" — wheel install in 1b failed, or you built
  only the old extension-only wheel. Rebuild from the REPO ROOT (1a)
  and re-run 1b.
- "No module named 'tuncore'" — wheel install in 1b failed silently.
  Re-run 1b and read pip's output.
- "No module named 'dns'" — dnspython didn't install.
- "No module named 'cryptography'" — same fix as above.

### 1d. Optional: run the test suite

The two attest backends are mutually exclusive at compile time, so the
soft and TPM test lanes use different Cargo invocations. The full
Python suite runs against a SOFT wheel (so the soft-attest tests are
exercised); the TPM lane is separate.

Soft lane (no TPM needed — the broad gate):

```sh
$ sudo /usr/bin/python3 -m pip install --break-system-packages \
      pytest pytest-asyncio
$ python3 -m pytest tests/ -q                # full Python suite
  # NB: this needs the SOFT wheel installed (ATTEST_BACKEND_IS_SOFTWARE
  # = True). If you installed the default TPM wheel, the TPM-only tests
  # run and the soft-only tests self-skip; rebuild the soft wheel
  # (§1a, --no-default-features --features dev-soft-attest) to run them.
$ cd rust/tuncore && PYO3_PYTHON=/usr/bin/python3 \
      cargo test --release --no-default-features --features dev-soft-attest
                                             # soft Rust tests. NOTE:
                                             # --no-default-features is
                                             # REQUIRED now that the
                                             # default is tpm-attest —
                                             # without it both backends
                                             # are on and the build fails
                                             # the exactly-one-backend
                                             # compile_error guard.
                                             # PYO3_PYTHON is needed on
                                             # Debian/Ubuntu where only
                                             # /usr/bin/python3 exists
                                             # (pyo3 otherwise probes
                                             # /usr/bin/python).
$ cd ../..
```

TPM lane (swtpm-driven; needs swtpm + libtss2-dev + libtss2-tcti-swtpm0):

```sh
$ cd rust/tuncore && PYO3_PYTHON=/usr/bin/python3 \
      cargo test --release --no-default-features --features tpm-attest \
          --test tpm_swtpm --test dsmt_format -- --test-threads=1
  # swtpm spins up per test; --test-threads=1 keeps the per-test TCP
  # ports + TPM transient slots from colliding. The real /dev/tpmrm0 is
  # never touched. The TPM-only Python tests then run against a TPM
  # wheel: pytest tests/test_tpm_attest_store.py tests/test_tpm_enroll_csr.py
$ cd ../..
```

## 2. CA Bootstrap (one-time, on the air-gapped laptop)

Trust model summary:

The CA private key NEVER leaves the air-gapped laptop. Devices walk
CSRs to the laptop on a wiped USB stick; the laptop signs the CSR;
you walk the signed cert back. The CA root cert (public) is copied to
every dsm host once. Network compromise of any dsm host does NOT
let an attacker mint new certs. Theft of a device's keys does NOT
enable impersonation: the daemon refuses to start without the matching
cert AND the CSR-signing flow requires live access to the attest key.

Out of scope: physical compromise of the CA laptop; supply-chain
compromise of the OS image installed on the CA laptop; side-channel
attacks against the CA private key during signing.

Required kit (per the two-box demo's hardware ledger):

- **Stick A** — CA storage. Encrypted (LUKS). Holds dsm_ca.key + the CA
  database + a copy of openssl-ca.cnf. Lives in your safe.
  Mounted RW only when signing, on the CA laptop only.
- **Stick B** — Transport. Wiped (`shred -v`) between every walk. Carries
  CSRs in, signed certs out. Never mounted anywhere except
  the CA laptop and the device being enrolled.
- **CA laptop** — Dedicated machine. Boot a wiped Tails or Debian live ISO,
  or a thin install with the wifi card physically removed.
  Disk encryption required. NEVER plugged in to a network
  after initial OS install.

Production best practice (NOT required for a demo): a third USB stick
with a redundant CA-storage backup, off-site (safe deposit box). If
Stick A dies and there's no backup, the entire fleet must be reissued
under a new CA.

Custom OID used by DSM:

```
id-dsm-noiseStaticBinding ::= 1.3.6.1.4.1.99999.1.1
```

An OCTET STRING (32 bytes) carrying the device's X25519 Noise static
pubkey. MUST be marked critical on every issued leaf cert. The dsm
runtime refuses to load a cert where this extension is missing,
non-critical, or the wrong length. The OID lives in the IETF
"experimental" arc — renumber under your registered Private Enterprise
Number before any production fleet deployment.

### 2a. Create the CA directory structure (on the laptop)

```sh
$ mkdir -p ca/{certs,crl,newcerts,private}
$ cd ca
$ chmod 700 private
$ touch index.txt
$ echo 1000 > serial
$ echo 1000 > crlnumber

# Copy the openssl config from the repo onto the laptop, into ca/.
# The file is deploy/openssl-ca.cnf in this repo.
```

### 2b. Generate the CA private key (P-384) and self-sign the root cert

```sh
$ openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 \
      -out private/dsm_ca.key
$ chmod 600 private/dsm_ca.key

$ openssl req -config openssl-ca.cnf \
      -x509 -new -key private/dsm_ca.key \
      -days 3650 \
      -out dsm_ca_root.pem
```

### 2c. Record the root cert fingerprint in your physical safe

```sh
$ openssl x509 -in dsm_ca_root.pem -noout -fingerprint -sha256
$ sha256sum dsm_ca_root.pem
```

Print BOTH outputs and store the printout in the safe.

The bare 64-hex SHA-256 of the FILE (second command) is also the
REQUIRED `ca_root_sha256` config value (see §2e and §3a). The daemon
refuses to start unless config.toml sets `ca_root_sha256` and it
matches the on-disk dsm_ca_root.pem — this pins the trust anchor so a
swapped CA PEM is rejected. Capture it in config-ready form now:

```sh
$ sha256sum dsm_ca_root.pem | cut -d' ' -f1
# -> 64 hex chars; this goes verbatim into ca_root_sha256 = "<hex>"
```

### 2d. Snapshot the CA directory onto your encrypted USB sticks

Make AT LEAST two redundant copies on separate USB sticks. Store at
least one off-site (safe deposit box). Wipe and re-snapshot whenever
you sign a new CSR or generate a new CRL — the ca/index.txt and
ca/serial files must stay in sync with what was issued.

The CA private key NEVER leaves these USBs. To sign a CSR, mount the
USB RW, sign, unmount, return to safe.

### 2e. Distribute the root cert to every dsm host (via Stick B)

On Stick B, place a copy of dsm_ca_root.pem (public, safe to walk).
On each dsm host:

```sh
$ sudo install -m 0600 -o root -g root /mnt/transport/dsm_ca_root.pem \
      /opt/mtun/dsm_ca_root.pem
$ sha256sum /opt/mtun/dsm_ca_root.pem | cut -d' ' -f1
      # cross-check this 64-hex value vs the safe printout (§2c),
      # then paste it into config.toml as ca_root_sha256 (§3a).
```

The CA root cert is a public document, but dsm's path-security check
refuses to load any file (even certs) that has group/world bits, so
install it 0o600. Substitution of dsm_ca_root.pem changes the trust
anchor — defense-in-depth is appropriate, and the REQUIRED
`ca_root_sha256` config pin makes the swap fatal at startup rather
than silently trusting the new anchor.

Re-wipe Stick B (`shred -v`) before reusing it.

## 3. Per-Device Enrollment

Order matters. Enroll the SERVER first so its CN exists by the time you
configure clients (clients pin the server's CN via `expected_server_cn`).

### 3a. Server: write /opt/mtun/config.toml

Pick the server's public IP and a UDP port (default 51820). Stash
the DoH provider's SPKI pin (see 3a.1 below).

```sh
$ sudo mkdir -p /opt/mtun
$ sudo tee /opt/mtun/config.toml >/dev/null <<'EOF'
mode               = "server"
server_ip          = "10.0.0.5"         # THIS host's public IP (literal)
server_port        = 51820
listen_port        = 51820

key_file           = "/opt/mtun/identity.key"
cert_file          = "/opt/mtun/device.crt"
ca_root_file       = "/opt/mtun/dsm_ca_root.pem"
# REQUIRED: 64-hex SHA-256 of ca_root_file (§2c / §2e). The daemon refuses
# to start without it and rejects a swapped CA PEM. Compute with:
#   sha256sum /opt/mtun/dsm_ca_root.pem | cut -d' ' -f1
ca_root_sha256     = "REPLACE_WITH_64_HEX_SHA256_OF_dsm_ca_root.pem"
attest_key_file    = "/opt/mtun/attest.key"
crl_file           = "/opt/mtun/dsm_ca.crl"   # required by default (crl_strict=true)
# crl_strict       = true                     # default. Set false ONLY for
                                              # lab/dev with no CA workflow.

# Server-only: one allowed client subject CN per line, mode 0o600.
allowed_cns_file   = "/opt/mtun/allowed_cns.txt"

transport          = "udp"              # "tcp" also supported
mtu                = 1400
pmtu_discover      = false              # set true on real-WAN deploys
log_level          = "info"

# DoH upstream for client DNS queries tunneled through the server.
dns_providers      = ["https://1.1.1.1/dns-query"]

[dns_provider_pins]
# Paste the 64-char hex SHA-256 SPKI pin from step 3a.1 here. You
# may pin multiple keys per provider (current + backup/next) — dsm
# accepts a list and succeeds if any one matches.
"https://1.1.1.1/dns-query" = [
    "REPLACE_WITH_64_CHAR_HEX_SPKI_SHA256_PIN",
]
EOF
```

Validate the TOML before continuing — a missing quote produces a
confusing stack trace later:

```sh
$ python3 -c "import tomllib; tomllib.load(open('/opt/mtun/config.toml','rb')); print('ok')"
```

Must print "ok". If you instead see TOMLDecodeError, see §10's TOML
triage list for fixes.

### 3a.1 Fetch the DoH provider's SPKI pin

dsm does not ship a default pin — the operator MUST supply one so
stale hardcoded pins cannot degrade to unpinned traffic. The pin is
the SHA-256 of the provider's SubjectPublicKeyInfo, as a 64-character
lowercase hex string.

```sh
$ HOST=1.1.1.1 PORT=443
$ openssl s_client -connect "$HOST:$PORT" -servername "$HOST" \
        < /dev/null 2>/dev/null \
    | openssl x509 -pubkey -noout \
    | openssl pkey -pubin -outform DER \
    | openssl dgst -sha256 -binary \
    | xxd -p -c 64
```

Output is a single 64-char hex line. Paste it into
/opt/mtun/config.toml's dns_provider_pins section.

For DoT, swap port 443 → 853 in the command above.

Pins expire when the provider rotates its cert (Cloudflare rotates
roughly yearly). Plan to re-fetch and re-deploy on a cadence.

### 3b. Server: generate keys + emit CSR

```sh
$ sudo python3 -m dsm --config /opt/mtun/config.toml \
      enroll --csr-out /tmp/dsm-csr-server.der --role server
```

On the default TPM backend this runs a TPM preflight first (it fails
with an actionable message if /dev/tpmrm0 is missing or you are not in
the `tss` group — see §0e), then PROVISIONS the attest key INSIDE the
TPM. The CSR is signed by the TPM (the signing scalar never leaves it).

You will be prompted for a NEW passphrase (twice). The passphrase is
load-bearing for BOTH stored keys:

- the identity key (X25519 Noise static) is wrapped under it with
  Argon2id (512 MiB / 4 iterations / 2 parallelism) + XChaCha20-Poly1305
  at rest; and
- on the TPM backend the SAME passphrase is bound as the attest key's
  TPM authorization value, so signing requires TPM residency AND the
  passphrase (two factors). An attacker who steals the disk blob and has
  TPM access still cannot sign without the passphrase, and the TPM's
  dictionary-attack lockout rate-limits guessing.

(On the dev-soft-attest build the same single passphrase wraps both
stores.) A FORGOTTEN passphrase makes the attest key unusable on the TPM
backend too — you must RE-ENROLL (see the recovery note below).

The command writes:

```
/opt/mtun/identity.key   mode 0o600  (Argon2id-wrapped X25519)
/opt/mtun/attest.key     mode 0o600  (TPM-bound DSMT context blob —
                                      NOT a key; see the backup note)
/tmp/dsm-csr-server.der  the CSR
```

And prints:

```
cn = dsm-<8 hex>-server
noise_static_pub = <hex>
```

Record both in your device inventory.

BACKUP / RECOVERY of attest.key on TPM:  attest.key is a TPM-BOUND
blob, not the key. It loads ONLY on the exact TPM that created it, so:

- The blob's key requires the operator enroll passphrase as its TPM
  authorization value. You do NOT back up a SEPARATE attest-key
  passphrase — it is the SAME enroll passphrase that wraps the identity
  key — but you DO still need that passphrase to use the attest key. A
  forgotten passphrase ⇒ the attest key is unusable ⇒ re-enroll.
- Backing up the blob file guards only against losing the FILE (e.g.
  a wiped /opt/mtun). Restore it and the key works again, as long as
  the SAME TPM is intact AND you know the passphrase.
- If the TPM itself is cleared, replaced, or fails, the blob is dead
  and the key is UNRECOVERABLE — you must RE-ENROLL (new attest key,
  new CSR, new signed cert; see §7g). The blob is worthless to a
  thief who steals only the disk (no TPM, no passphrase), which is the
  point.

### 3c. Server: walk CSR to CA, sign, walk cert back

Walk /tmp/dsm-csr-server.der to the CA laptop on freshly-wiped
Stick B. On the laptop:

```sh
$ cd ca

# 1. Inspect the CSR (THIS IS THE CRITICAL REVIEW STEP)
$ openssl req -in /mnt/transport/dsm-csr-server.der \
      -inform DER -text -noout -verify
# Verify by eye:
#   * Subject CN matches an approved inventory entry
#   * "1.3.6.1.4.1.99999.1.1: critical" is present
#   * "Certificate request self-signature verify OK" appears
#   * Subject Public Key is prime256v1 (256-bit ECDSA)
# If ANY check fails, REJECT. Wipe Stick B. Investigate.

# 2. Sign with the server profile
$ openssl ca -config openssl-ca.cnf -extensions dsm_server_leaf \
      -in /mnt/transport/dsm-csr-server.der -inform DER \
      -out certs/<hostname>.pem -batch

# 3. Copy the signed cert back to Stick B (the cert ONLY — never
#    walk the CA private key or index.txt anywhere)
$ cp certs/<hostname>.pem /mnt/transport/

# 4. Eject Stick B, eject Stick A, return both to the safe.
```

### 3d. Server: import the signed cert

```sh
$ sudo python3 -m dsm --config /opt/mtun/config.toml \
      enroll --import /tmp/dsm-cert-server.pem
```

dsm verifies:

- chain to /opt/mtun/dsm_ca_root.pem
- id-dsm-noiseStaticBinding extension matches the loaded Noise
  static pubkey
- cert subject pubkey SPKI matches the loaded attest key SPKI
- cert is within its validity window

On success, writes /opt/mtun/device.crt (mode 0o600) and prints
cn / serial / not_after.

### 3e. Server: stash the passphrase for non-interactive restarts

Pick ONE source:

(i) Plain file (0600, read once at startup):

```sh
$ echo 'my-strong-passphrase' \
      | sudo install -m 0600 /dev/stdin /etc/dsm/passphrase
```

Then start with:

```sh
sudo python3 -m dsm --mode server \
    --passphrase-env-file /etc/dsm/passphrase
```

(ii) systemd LoadCredential (preferred for production):

The shipped deploy/dsm.service already does this:

```
LoadCredential=passphrase:/etc/dsm/passphrase
ExecStart=/opt/dsm/venv/bin/dsm --mode server \
    --passphrase-env-file=${CREDENTIALS_DIRECTORY}/passphrase
```

systemd materializes a per-process copy at
$CREDENTIALS_DIRECTORY/passphrase (mode 0400, root-owned, in
tmpfs). Install the source file:

```sh
$ echo 'my-strong-passphrase' | \
    sudo install -m 0600 /dev/stdin /etc/dsm/passphrase
$ sudo cp deploy/dsm.service /etc/systemd/system/dsm.service
$ sudo systemctl daemon-reload
$ sudo systemctl enable --now dsm
```

(iii) Environment variable (CI / one-shot test only — visible in
/proc/$pid/environ):

```sh
DSM_PASSPHRASE='...' sudo -E python3 -m dsm --mode server
```

### 3f. Client: mirror 3a – 3e

On the client host, mirror the server steps with:

```toml
mode               = "client"
server_ip          = "<the server's public IP>"
server_port        = 51820
listen_port        = 0                          # ephemeral
expected_server_cn = "<server CN from §3b>"
auto_mtu           = true                       # cellular benefit
pmtu_discover      = true                       # required by auto_mtu
```

Then:

```sh
$ sudo python3 -m dsm --config /opt/mtun/config.toml \
      enroll --csr-out /tmp/dsm-csr-client.der --role client
```

Walk to CA, sign with `-extensions dsm_client_leaf` (NOT
dsm_server_leaf), walk back, then:

```sh
$ sudo python3 -m dsm --config /opt/mtun/config.toml \
      enroll --import /tmp/dsm-cert-client.pem
```

Stash passphrase as in 3e.

Record the client's CN — you need it for §4.

## 4. Authorization

The server refuses every cert whose subject CN is not in the allowlist,
even if the cert chains to the pinned CA. This gives you per-device
revocation that survives lazy CRL refresh.

On the SERVER:

```sh
$ sudo touch /opt/mtun/allowed_cns.txt
$ sudo chown root:root /opt/mtun/allowed_cns.txt
$ sudo chmod 0600 /opt/mtun/allowed_cns.txt

# Append the client's CN (from §3f). One CN per line. '#' comments allowed.
$ echo 'dsm-XXXXXXXX-client' | \
      sudo tee -a /opt/mtun/allowed_cns.txt >/dev/null
```

Restart the server after editing — the allowlist is read once at startup.
Live SIGHUP reload is on the Phase-2 punch list. To REVOKE: remove the
CN from the file, restart, and optionally issue a CRL update (§7e).

## 5. Run Both Sides

Server:

```sh
$ sudo systemctl start dsm                   # if you installed the unit
# or
$ sudo python3 -m dsm --mode server \
      --passphrase-env-file /etc/dsm/passphrase
```

Client:

```sh
$ sudo python3 -m dsm --mode client \
      --passphrase-env-file /etc/dsm/passphrase
```

Expected client log lines (log_level = "info"), in order, within ~5 s:

```
... handshake complete (client) — server_cn=dsm-XXXXXXXX-server
... TUN mtun0 configured: 10.8.0.2/24 mtu=1400
... tunnel established
... kernel path MTU = 1500 (usable inner 1432)
... auto_mtu: lowered tun mtu 1400 -> 1232 (kernel pmtu=1300)
                                               ↑ only when
                                                 auto_mtu=true AND the
                                                 path actually needs it
                                                 (typical on cellular)
```

Expected server log lines:

```
... CN allowlist loaded (1 entries)
... server listening on UDP port 51820
... handshake complete (server) — client_cn=dsm-XXXXXXXX-client
... client connected (noise_static=<first 16 hex>)
```

## 6. Verification

From the client (second terminal, while the VPN is running):

TUN + routing:

```sh
$ ip link show mtun0          # state UP, mtu from config
$ ip addr show mtun0          # client: 10.8.0.2/24 (server: 10.8.0.1/24)
$ ip rule                     # expect "10: not from all fwmark 0x1 lookup 100"
$ ip route show table 100     # expect "default dev mtun0"
```

Kill switch (4 tables on the server, 2 on the client):

```sh
$ sudo nft list tables | grep '^table inet dsm_'
# Server-side, expect:
#   table inet dsm_killswitch        (default-drop output/input + ICMP rate-limit)
#   table inet dsm_dns_leak          (DNS/DoT/DoH/mDNS/LLMNR blocked off-tunnel)
#   table inet dsm_server_ratelimit  (per-source-IP handshake limiter)
#   table inet dsm_server_nat        (MASQUERADE for decrypted client traffic)
# Client-side, expect dsm_killswitch + dsm_dns_leak only.
```

DNS goes through the tunnel and resolves on the server via DoH:

```sh
$ dig @10.8.0.1 example.com +short
```

Leak test:

```sh
# In terminal 1 (replace eth0 with your physical iface):
$ sudo tcpdump -ni eth0 'port not 51820 and not arp and not ip6'
# In terminal 2:
$ curl -s https://example.com > /dev/null
# tcpdump output during the curl must be EMPTY. Anything on the wire
# that is not port 51820 is a leak.
```

IPv6 disabled during the session:

```sh
$ sysctl net.ipv6.conf.all.disable_ipv6      # expect 1
$ cat /run/dsm/ipv6_state.json               # per-iface snapshot
```

Graceful shutdown (Ctrl-C or `systemctl stop`):

```sh
# Within ~1 second, the peer logs:
#   client side: ... dsm.client: shutting down
#   server side: ... dsm.server: server shutting down
# SESSION_CLOSE is received silently (it sets the shutdown event);
# the visible log line comes from the teardown path that follows.
$ ip link show mtun0                           # "Device does not exist"
$ sudo nft list tables | grep '^table inet dsm_'   # no output
$ cat /etc/resolv.conf | head -2               # restored to pre-VPN
$ sysctl net.ipv6.conf.all.disable_ipv6        # 0 (restored)
```

## 7. Common Operator Tasks

### 7a. Re-pin a new server cert on the client (same CA)

No client-side action is needed when the server rotates within the
same CA AND the server's CN does not change. The client trusts any
cert that chains to dsm_ca_root.pem and matches expected_server_cn.

If the server's CN DOES change (it will any time the server's Noise
static rotates — see §7c), push the new value to every client's
/opt/mtun/config.toml `expected_server_cn` and restart them.

### 7b. Revoke a client

On the server:

```sh
$ sudo sed -i '/^dsm-XXXXXXXX-client$/d' /opt/mtun/allowed_cns.txt
$ sudo systemctl restart dsm
```

Optionally issue a CRL update (§7e) so other servers in the fleet
refuse the cert too.

### 7c. Rotate the server identity

Fresh enrollment generates a new Noise static, so the CN derivation
`dsm-<sha256(noise_static)[:4 hex]>-server` ALWAYS produces a new
CN. Plan accordingly.

```sh
$ sudo systemctl stop dsm
$ sudo rm /opt/mtun/identity.key /opt/mtun/attest.key /opt/mtun/device.crt
$ sudo python3 -m dsm --config /opt/mtun/config.toml \
      enroll --csr-out /tmp/dsm-csr-server.der --role server
# Note the printed CN. Walk CSR to CA, sign with dsm_server_leaf,
# walk back:
$ sudo python3 -m dsm --config /opt/mtun/config.toml \
      enroll --import /tmp/dsm-cert-server.pem
$ sudo systemctl start dsm
```

Push the new CN to every client's `expected_server_cn` before the
client reconnects, otherwise it will refuse the cert with
"server CN check failed".

### 7d. Change MTU live, or change transport (UDP <-> TCP)

Stop both sides, edit /opt/mtun/config.toml, restart. The TUN device
is rebuilt on startup; cert auth is transport-independent.

### 7e. Refresh the CRL (and revoke a cert)

On the CA laptop:

```sh
$ cd ca

# If revoking a cert:
$ openssl ca -config openssl-ca.cnf \
      -revoke newcerts/<serial>.pem -crl_reason <reason>
# Valid reasons (RFC 5280):
#   keyCompromise, affiliationChanged, superseded,
#   cessationOfOperation, certificateHold, removeFromCRL
# DO NOT USE cACompromise — it would invalidate the entire fleet.

# Always (revocation or just freshness refresh):
$ openssl ca -config openssl-ca.cnf -gencrl -out crl/dsm_ca.crl
```

The CRL number auto-increments in ca/crlnumber. Walk crl/dsm_ca.crl
via fresh transport USB to every server (and to clients that have a
CRL configured). Place at /opt/mtun/dsm_ca.crl. Restart the daemon
to pick it up (no SIGHUP reload yet).

Default validity:

- Leaf cert  : 1 year   (default_days = 365 in openssl-ca.cnf)
- CRL        : 31 days  (default_crl_days = 31)

dsm FAILS CLOSED when crl_file is absent or the CRL is past its
next_update timestamp (crl_strict defaults to true, audit H-CRYPT-3
flip). To allow startup without a CRL (lab/dev only — accepts
revoked certs silently), set `crl_strict = false` in config.toml.

### 7f. Disaster recovery — CA private key lost

1. Bootstrap a new CA per §2.
2. Walk the new root cert to every dsm host (§2e).
3. Re-enroll every device per §3.

### 7g. Disaster recovery — device identity / attest key compromise, or a lost/cleared TPM

1. Revoke the cert per §7e immediately.
2. Remove identity.key / attest.key from the affected device by hand.
   (On the TPM backend, also clear the in-TPM key — a TPM clear, or
   just re-enrolling, overwrites the deterministic attest key.)
3. Re-enroll per §3 with a fresh keypair.
4. The old cert remains in the CRL until expiry.

TPM cleared / replaced / failed (no compromise):  the attest.key DSMT
blob only loads on the TPM that made it, so a cleared or swapped TPM
makes the existing attest key unrecoverable even if attest.key is
intact. Re-enroll per §3 (new attest key in the new TPM → new CSR →
new signed cert) and revoke the old cert per §7e.

## 8. Single-Host Loopback Smoke Test

Bring a client/server pair up on ONE Linux host (or one host + one VM)
as a sanity check before crossing real ISPs. Confirms the code builds,
certs validate, kill switch arms, data path round-trips, and shutdown
leaves no residue.

### 8a. Prerequisites

Both "sides" need everything in §0 and §1. If you're using two
network namespaces on one host, build once and inject the wheel into
each namespace's root filesystem (or just run them in the same
namespace; the test still works).

### 8b. Configure the server side (§3a–§3e shorthand)

```sh
$ sudo mkdir -p /opt/mtun
$ sudo tee /opt/mtun/config.toml <<'EOF'
mode = "server"
server_ip = "127.0.0.1"
server_port = 51820
listen_port = 51820
key_file = "/opt/mtun/identity.key"
cert_file = "/opt/mtun/device.crt"
ca_root_file = "/opt/mtun/dsm_ca_root.pem"
ca_root_sha256 = "REPLACE_WITH_64_HEX_SHA256_OF_dsm_ca_root.pem"  # REQUIRED (§2c)
attest_key_file = "/opt/mtun/attest.key"
allowed_cns_file = "/opt/mtun/allowed_cns.txt"
transport = "udp"
dns_providers = ["https://1.1.1.1/dns-query"]
[dns_provider_pins]
"https://1.1.1.1/dns-query" = ["<64-hex SPKI SHA-256>"]
EOF
```

Place /opt/mtun/dsm_ca_root.pem per §2e. Cross-check its SHA-256
against the safe printout, and set ca_root_sha256 to that 64-hex
value (`sha256sum /opt/mtun/dsm_ca_root.pem | cut -d' ' -f1`) — the
daemon refuses to start without it.

### 8c. Enroll the server (§3b–§3d)

```sh
$ sudo python3 -m dsm --config /opt/mtun/config.toml \
      enroll --csr-out /tmp/dsm-csr-server.der --role server
# Walk to CA, sign with dsm_server_leaf, walk back, then:
$ sudo python3 -m dsm --config /opt/mtun/config.toml \
      enroll --import /tmp/dsm-cert-server.pem
```

Stash the passphrase per §3e. Create the empty allowlist:

```sh
$ sudo install -m 0600 -o root -g root /dev/null /opt/mtun/allowed_cns.txt
```

### 8d. Configure + enroll the client side

Mirror §3f with `mode = "client"`, `server_ip = "127.0.0.1"`, and
`expected_server_cn = "<server CN from 8c>"`. Run the same enroll
sequence with `--role client` and the dsm_client_leaf profile on
the CA.

### 8e. Add the client's CN to the server allowlist (§4)

```sh
$ echo 'dsm-XXXXXXXX-client' \
      | sudo tee -a /opt/mtun/allowed_cns.txt >/dev/null
```

(You haven't started the server yet — it refuses to start when the
allowlist is empty. Adding the CN now lets §8f succeed.)

### 8f. Start both sides (§5)

Expected client log: see §5.
Expected server log: see §5.

### 8g. Verify everything (§6)

Run every command in §6. Pass criterion: every check produces its
expected output AND graceful shutdown leaves NO residue.

### 8h. Failure drills

8h.1 — Server crash (SIGKILL mid-session)

```sh
$ sudo pkill -9 -f 'dsm --mode server'
# On the client, watch the log for ~60 s. The client should detect
# a dead peer after DEAD_PEER_TIMEOUT (60 s) and tear down the
# tunnel automatically.
```

8h.2 — Client crash

```sh
$ sudo pkill -9 -f 'dsm --mode client'
# Expected host state on the client side after crash:
#   - mtun0 is gone (kernel reaps the TUN when the owning fd closes)
#   - nftables rules ARE STILL PRESENT (no crash-recovery yet)
#   - resolv.conf still points at 10.8.0.1; the pre-VPN contents
#     were captured only in process memory and are lost
#   - /run/dsm/ipv6_state.json remains (next clean dsm start restores)
# Manual cleanup:
$ for t in dsm_killswitch dsm_dns_leak dsm_server_ratelimit dsm_server_nat; do
      sudo nft delete table inet "$t" 2>/dev/null
  done
$ sudo $EDITOR /etc/resolv.conf            # restore pre-VPN nameserver by hand
$ for iface in $(ls /sys/class/net); do
      sudo sysctl -w "net.ipv6.conf.$iface.disable_ipv6=0" 2>/dev/null
  done
$ sudo sysctl -w net.ipv6.conf.all.disable_ipv6=0
$ sudo rm -f /run/dsm/ipv6_state.json
```

## 9. Two-Box Demo Across Two Real ISPs

End-to-end procedure for the Phase 2 demo: server on home Wi-Fi (router
port-forwarded) and client on a cellular hotspot, running DSM over UDP
across two real ISPs. First time the codebase is exercised against real
kernel TUN, real `nft -f -`, real PMTU, and a real shutdown.

### 9a. Topology

```
       ┌────────────────────────┐                       ┌─────────────────────────┐
       │   Cellular hotspot     │                       │   Home ISP (cable/fiber)│
       │   (carrier-grade NAT)  │                       │   public IP A.B.C.D     │
       └─────────┬──────────────┘                       └────────────┬────────────┘
                 │                                                   │
                 │ UDP/51820 outbound                                │ Router port-forward
                 │ (cellular CGN allows reply-                       │ UDP/51820 → 192.168.x.y
                 │  to-source-port)                                  │
                 ▼                                                   ▼
        ┌─────────────────────┐  Internet  UDP/51820  ┌────────────────────────────┐
        │ CLIENT box (Linux)  │ ─────────────────────▶│ SERVER box (Linux)         │
        │  • cert-auth        │ ◀──────────────────── │  • cert-auth + CN allowlist│
        │  • TUN mtun0        │                       │  • TUN mtun0 + DNS proxy   │
        │  • auto_mtu = true  │                       │  • IP forwarding + MASQ    │
        └─────────────────────┘                       └────────────────────────────┘
```

STUN/ICE for double-NAT is EXPLICITLY out of scope. If both ends are
behind NAT with no port-forward, this demo will not work.

### 9b. Pre-flight: verify the server's reachability

On the server box (BEFORE starting dsm):

```sh
$ curl -s https://ifconfig.co              # what's our public IP?
$ nc -u -l 51820                           # spin up a UDP listener
# From a friend / a phone tether elsewhere:
$   nc -u -v <server-public-ip> 51820      # type something, press enter
# If the listener prints it, the port-forward is good.
```

If the public IP is private (10/8, 172.16/12, 192.168/16) you're
behind carrier-grade NAT on the home side and a port-forward won't
help. Find a different "home" with a real ISP-routable IP, or fall
back to §8 single-host loopback.

### 9c. Per-host setup

Work §0–§4 on both boxes. Use auto_mtu = true on the client (cellular
PMTU drifts on Wi-Fi <-> LTE handovers). Recommended config snippet:

```toml
# Server side (stable home Wi-Fi):
mtu = 1400
pmtu_discover = false
auto_mtu = false                     # static MTU is fine
# Client side (cellular):
mtu = 1400
pmtu_discover = true                 # REQUIRED for auto_mtu
auto_mtu = true                      # adapts to PMTU drops
```

### 9d. First connect: see §5 expected logs

If the client's `auto_mtu` line shows it lowering, that's the adapter
catching cellular's smaller path MTU.

### 9e. Acceptance test sequence

Seven Phase-2 acceptance criteria as runnable commands. Run on the
CLIENT unless noted. Capture results.

9e.1 — 30-minute session

```sh
$ for i in $(seq 1 30); do
      curl -sS -o /dev/null -w "[%{time_total}s] %{http_code} via %{remote_ip}\n" \
          https://www.cloudflare.com/cdn-cgi/trace
      sleep 60
  done | tee /tmp/dsm-30min.log
```

PASS: 30 lines, all HTTP 200, remote_ip matches the server's
public IP (or its CDN edge), no curl timeouts.

9e.2 — Server-IP attribution

```sh
$ curl -s https://www.cloudflare.com/cdn-cgi/trace | grep ^ip=
```

PASS: shows the SERVER's public IP (or its CDN edge), NOT the
cellular operator's IP.

9e.3 — DNS leak

```sh
$ dig @8.8.8.8 example.com +time=3 +tries=1 || echo PASS-direct-timed-out
$ dig @10.8.0.1 example.com +short
```

PASS: direct query times out (kill switch); @10.8.0.1 returns A records.

9e.4 — IPv6 leak

```sh
$ curl -6 -m 5 https://ifconfig.co || echo "PASS-ipv6-blocked"
```

PASS: connection times out. If it returns a v6 address, capture
`sysctl net.ipv6.conf.all.disable_ipv6` to triage.

9e.5 — Kill-switch SIGSTOP test

```sh
# Terminal 1: hold a curl through the tunnel.
( while :; do curl -sS https://ifconfig.co || break; sleep 1; done; \
  echo egress-stopped-at-$(date +%T) ) &
LOOP_PID=$!

# Terminal 2: find the dsm pid and STOP it.
DSM_PID=$(pidof python3 | tr ' ' '\n' | head -1)
sudo kill -STOP "$DSM_PID"

# While dsm is STOPped, no traffic should egress (kill switch
# remains installed). The curl loop should hit a failure and break
# within 5–10 s.
sleep 10
sudo kill -CONT "$DSM_PID"
sleep 30
curl -sS -m 5 https://ifconfig.co              # should work again after reconnect
```

PASS: traffic stops during STOP; resumes after CONT + reconnect.

9e.6 — Systemd hardening score (on the SERVER under systemd)

```sh
$ sudo systemd-analyze security dsm
```

PASS: top-line score ≤ 5.5 (MEDIUM) with the conservative subset
shipped today. Target < 3.0 once the strace audit (§9f)
unblocks SystemCallFilter + RestrictNamespaces.

9e.7 — Auto-MTU adaptation

```sh
$ sudo journalctl -u dsm | grep -E "auto_mtu|kernel path MTU"
```

PASS: at least one "auto_mtu: lowered tun mtu N -> M (kernel
pmtu=K)" line on the cellular client.

### 9f. Strace audit (gates the deferred systemd hardening flags)

Two flags in deploy/dsm.service are deliberately commented out:

```
RestrictNamespaces=true
SystemCallFilter=...
```

They can break TUN ioctl / netlink in subtle ways depending on the
kernel build. Enable empirically:

```sh
# 1. Stop dsm.
$ sudo systemctl stop dsm

# 2. Run dsm under strace through one full handshake + ~30 s of
#    real traffic. DO THIS WITH THE CELLULAR CLIENT CONNECTING
#    FROM ITS REAL ISP, not a loopback — some syscalls (e.g. PMTU
#    sockopts) only fire on real paths.
$ sudo strace -f -e trace=%file,%network,%process \
      -o /tmp/dsm-strace.log \
      timeout 60 python3 -m dsm --mode server \
      --passphrase-env-file /etc/dsm/passphrase

# 3. Pull the unique syscall names actually used.
$ awk -F'(' '/^[0-9]+ +[a-z_]+\(/ {print $1}' /tmp/dsm-strace.log \
      | awk '{print $NF}' | sort -u > /tmp/dsm-syscalls.txt
$ wc -l /tmp/dsm-syscalls.txt
$ cat /tmp/dsm-syscalls.txt
```

Convert /tmp/dsm-syscalls.txt into a SystemCallFilter= allowlist in
deploy/dsm.service. Then enable RestrictNamespaces empirically:
restart, re-run §9e. If dsm fails to open /dev/net/tun or netlink,
drop the flag with a comment in the unit.

### 9g. What to capture and ship back from each demo run

- journalctl -u dsm  (server + client, full session)
- sudo nft list ruleset           (after established)
- ip rule + ip route show table 100   (both boxes)
- The Cloudflare trace output from §9e.2
- sudo systemd-analyze security dsm
- /tmp/dsm-strace.log and /tmp/dsm-syscalls.txt from §9f
- With --debug-net enabled: the JSON event stream from
  `sudo journalctl -u dsm -o cat | grep dsm.netaudit > /tmp/demo.jsonl`

## 10. Debugging by Symptom

`log_level = "debug"` turns on per-packet-class log lines — useful while
reproducing a bug. Switch back to "info" for steady state.

`--debug-net` (or `debug_net = true` in config) emits one structured
JSON event per state transition on the `dsm.netaudit` logger
(handshake_start, handshake_end, nft_apply/_remove, tun_configure/
_deconfigure, rekey_epoch, liveness_fire, shutdown_signal,
auto_mtu_change, crl_missing/stale). Capture with:

```sh
$ sudo journalctl -u dsm -o cat | grep dsm.netaudit > /tmp/audit.jsonl
```

### TOML triage: `python3 -c "import tomllib; ..."` raised TOMLDecodeError

(1) Missing quotes around a STRING value:

```
Must be quoted   — mode, transport, log_level, server_ip,
                   key_file, cert_file, ca_root_file,
                   attest_key_file, crl_file,
                   expected_server_cn, allowed_cns_file,
                   tun_name
Bare (no quotes) — server_port, listen_port, mtu, padding_*,
                   jitter_*, rotation_*, pmtu_discover,
                   pmtu_check_interval_s, debug_dns, debug_net,
                   auto_mtu, crl_strict
```

Concrete: `server_ip = 10.0.0.5` trips at col 17 because tomllib
parses 10.0 as a float and chokes on the second dot. Fix:

```sh
$ sudo sed -i 's|^server_ip = .*|server_ip = "10.0.0.5"|' \
      /opt/mtun/config.toml
```

(2) Smart quotes (curly “…” from a chat / web paste). Diagnose:

```sh
$ cat -An /opt/mtun/config.toml | head -10
```

Curly quotes appear as multi-byte sequences (M-bM-^@M-^\). Retype
the offending line by hand.

(3) Wrong comment marker. TOML uses `#` only — `;` or `//` make the
remainder of the line part of the preceding value.

(4) Inspect the exact line with all whitespace visible:

```sh
$ sed -n '<N>p' /opt/mtun/config.toml | cat -An
```

Re-run the tomllib check after every edit; proceed only when it
prints "ok".

### "handshake recv timed out after 3 attempts" / "handshake failed: ..."

- Server actually down, or port blocked. Test plain UDP reachability:

  ```sh
  $ nc -u -v <server-ip> 51820       # type, press enter
  ```

- Server is up but bound to the wrong interface. On the server:

  ```sh
  $ sudo ss -ulnp | grep 51820
  ```

- Firewall between you and the server dropping DF packets (less
  likely with default pmtu_discover=false).
- On cellular: the link was down when the handshake started. Each
  retry adds 5 s of timeout + (1, 2, 4) s of backoff — total budget
  ~22 s. A longer outage exceeds the budget; restart the client once
  the link is back up.

### Server log shows "handshake rejected (CNNotAllowedError): client CN '...' not in allowlist"

Expected on first connect — see §4. The client's CN must be on a line
of /opt/mtun/allowed_cns.txt (mode 0o600). If you DID add a line and
still see this, the line doesn't match the cert the client actually
presents — compare exactly against the CN the client's `dsm enroll
--csr-out` printed.

### Client log: "server CN check failed: server CN ... does not match expected ..."

The client's expected_server_cn does not match the cert the server
presents. Either correct the client's config, or roll the server back
if the CN changed unexpectedly (implies unauthorized re-enrollment).

### "server cert auth failed: ..." or "client cert auth failed: ..."

- "chain ..." → the pinned ca_root_file does not match the CA that
  issued this side's cert. Cross-check
  `sha256sum /opt/mtun/dsm_ca_root.pem` against the value recorded in
  your safe (§2c).
- "binding ..." → the cert's noiseStaticBinding extension does not
  match the local Noise static. The cert was issued for a different
  identity. Re-enroll.
- "expired" → cert is past its validity window. Re-enroll (§7c for
  server, §3 again for client).

### "process hardening partially failed"

Informational, not fatal. The service started, but core-dump disabling
or prctl(PR_SET_DUMPABLE) didn't stick. Usually one of:

(a) SELinux/AppArmor blocking;
(b) systemd unit's CapabilityBoundingSet is too tight — we ship
    CAP_NET_ADMIN + CAP_NET_BIND_SERVICE only. If a future change
    needs another cap, add it to deploy/dsm.service and restart.
(c) Running outside systemd without the right caps. Use sudo.

### Tunnel up but `curl` through it is very slow or hangs

- Path MTU issue. Check the startup log for:
  `"configured tun mtu=1400 exceeds usable inner NNN"`
  Lower `mtu` in both configs until the warning is gone, OR set
  `auto_mtu = true` + `pmtu_discover = true` on the client.
- Chaff + jitter adds latency by design. For a faster-but-less-
  anonymized smoke test, lower padding_max and jitter_ms_max to 5.

### "rekey giving up after 3 retries — tearing down"

REKEY_ACK never reached the initiator. Check the peer log for
"rekey completed as responder" — if missing, the server never
processed the INIT (network drop). If present, the ACK was dropped in
the reverse direction. Session tears down on purpose; restart to
re-handshake.

### "DNS resolve failed for qname-sha256=<hex>"

Server's upstream DoH/DoT provider failed or pin mismatch.
Temporarily set `debug_dns = true` to log the plaintext qname (then
flip it off). Re-check the SPKI pin against the provider's live cert
(§3a.1).

### "DNS proxy listening on 10.8.0.1:53" but client can't resolve

- Client's resolv.conf wasn't updated, or the client-side kill switch
  is dropping the query. Check:

  ```sh
  $ cat /etc/resolv.conf
  $ sudo nft list tables | grep '^table inet dsm_'
  ```

- Server's local firewall blocks the DNS-proxy bind. Allow UDP 53 on
  10.8.0.1 (the TUN address).

### Host IPv6 stuck off after a crashed client

/run/dsm/ipv6_state.json persists across crashes; the next clean
`dsm` start reads it and restores. If the file is gone:

```sh
$ for iface in $(ls /sys/class/net); do
      sudo sysctl -w "net.ipv6.conf.$iface.disable_ipv6=0"
  done
$ sudo sysctl -w net.ipv6.conf.all.disable_ipv6=0
```

### nftables rules stuck after a crashed client

No crash-recovery is shipped; clean up manually:

```sh
$ for t in dsm_killswitch dsm_dns_leak dsm_server_ratelimit dsm_server_nat; do
      sudo nft delete table inet "$t" 2>/dev/null
  done
```

### ImportError / ModuleNotFoundError: No module named '\<X>'

- X = dsm      → the dsm wheel never landed in /usr/bin/python3, or you
  built the old extension-only wheel. Rebuild from the REPO ROOT (§1a)
  and re-run §1b; confirm pip output reports "Successfully installed
  dsm-0.1.0".
- X = tuncore  → wheel never landed in /usr/bin/python3. Re-run §1b
  and confirm pip output reports "Successfully installed dsm-0.1.0"
  (the tuncore extension ships inside the dsm wheel).
- X = dns      → dnspython missing. Re-run §1b.
- X = cryptography → same fix.
- Did you create a venv and install there instead? `sudo python3`
  can't see venv packages. Re-run §1c verification; if any import
  fails, redo §1b.

### TypeError or AttributeError mentioning a tuncore object

(e.g. "a bytes-like object is required, not 'list'")

Almost certainly a stale wheel: you rebuilt the Rust source but
didn't reinstall the wheel. Rebuild FROM THE REPO ROOT and
force-reinstall:

```sh
$ /tmp/dsm-build-venv/bin/maturin build --release
$ sudo /usr/bin/python3 -m pip install --break-system-packages \
      --force-reinstall \
      "$(ls $PWD/rust/tuncore/target/wheels/dsm-0.1.0-*.whl | tail -1)"
```

## 11. Uninstall

```sh
$ sudo systemctl disable --now dsm
$ sudo rm -rf /opt/mtun /etc/dsm /run/dsm
$ sudo /usr/bin/python3 -m pip uninstall --break-system-packages dsm   # if pip-installed
$ sudo rm /etc/systemd/system/dsm.service
$ sudo systemctl daemon-reload
```

Paranoid firewall / TUN reset (in case dsm wasn't shut down cleanly):

```sh
$ for t in dsm_killswitch dsm_dns_leak dsm_server_ratelimit dsm_server_nat; do
      sudo nft delete table inet "$t" 2>/dev/null
  done
$ sudo ip link delete mtun0 2>/dev/null
$ sudo ip rule delete priority 10 2>/dev/null
$ sudo ip route flush table 100 2>/dev/null
$ for iface in $(ls /sys/class/net); do
      sudo sysctl -w "net.ipv6.conf.$iface.disable_ipv6=0" 2>/dev/null
  done
```

## 12. File Placement Reference

```
/opt/mtun/config.toml                 # main config (both modes)
/opt/mtun/identity.key                # X25519 Noise static (Argon2id)
/opt/mtun/attest.key                  # TPM-bound DSMT context blob (default
                                      # tpm-attest) / Argon2id-wrapped ECDSA
                                      # P-256 key (dev-soft-attest build)
/opt/mtun/device.crt                  # CA-signed leaf cert (mode 0o600)
/opt/mtun/dsm_ca_root.pem             # pinned CA root cert (mode 0o600)
/opt/mtun/dsm_ca.crl                  # optional CRL (walked-USB cadence)
/opt/mtun/allowed_cns.txt             # server only: one CN per line (0o600)
/etc/dsm/passphrase                   # non-interactive passphrase source (0o600)
/run/dsm/ipv6_state.json              # per-iface IPv6 state snapshot
/etc/systemd/system/dsm.service       # (optional) systemd unit
```

## 13. CLI Reference

```
python3 -m dsm --mode {client,server}            Run the VPN
python3 -m dsm --config PATH                     Override config file path
python3 -m dsm --debug-net                       Emit JSON audit events on
                                                 the dsm.netaudit logger
python3 -m dsm --passphrase-fd N                 Read passphrase from FD N
python3 -m dsm --passphrase-env-file PATH        Read passphrase from a
                                                 0600-mode file at PATH

python3 -m dsm enroll --csr-out PATH             Provision identity +
                                                 attest key, write a CSR
python3 -m dsm enroll --import CERT_PATH         Verify + persist a
                                                 CA-signed cert
python3 -m dsm enroll --cn CN [--role ROLE]      Override the derived CN
                                                 (default: dsm-<8 hex>-<role>)
python3 -m dsm enroll --role {client,server}     Set the role suffix when
                                                 --cn is not given

python3 -m dsm show-pubkey                       Print the local identity's
                                                 Noise static pubkey (hex)
```
