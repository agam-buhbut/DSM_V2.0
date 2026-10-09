# DSM VPN — Operator Guide

Deployment, operation, verification, and troubleshooting for DSM.
Sections 0 through 7 taken in order bring up a live tunnel on a fresh
Linux box; 8 onward are reference.

Architecture in one sentence:  one client connects to one operator-owned
server over UDP (default) or TCP. Both ends authenticate with X.509
device certs signed by your offline CA; the cert binds the device's
ECDSA attestation signing key AND the device's X25519 Noise static
via a custom critical extension, so a stolen cert OR a stolen Noise key
alone is useless.

ATTESTATION: the default build (tpm-attest) generates the ECDSA P-256
attest key inside a TPM 2.0, where it signs and from which it never
leaves; attest_key_file holds only a TPM-bound DSMT blob. This is key
residency, not PCR sealing and not remote attestation — a valid binding
is not proof of measured boot. The host needs a TPM 2.0 (§0e). The
dev-soft-attest build's key is extractable from process memory; test
only.

Hardware binding on Android (Keystore/StrongBox) remains planned (Phase 3).

Companion files in this directory:

- `deploy/openssl-ca.cnf` — OpenSSL config used by the offline CA in §3.
  UNCHANGED by the TPM backend: the CSR and leaf cert have identical
  structure (same P-256 SPKI algorithm, same critical noiseStaticBinding
  extension) whether the key is soft or TPM-resident.
- `deploy/dsm.service` — the server's systemd unit.
- `deploy/dsm-client.service` — the client's systemd unit (§3f). Never put
  `dsm.service` on a client.
- `deploy/dsm-blocklist-update.sh`, `.service`, `.timer` — the daily DNS
  block list download for the server (§7h).

Protocol, crypto, anonymity properties, threat model, and the full config
reference are in the top-level `README.md`.

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
  10. Running over the internet (remote client)
  11. Debugging by symptom
  12. Uninstall
  13. File placement reference
  14. CLI reference

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
      patchelf \
      nftables iproute2 curl ca-certificates git xxd
```

`patchelf` is required by maturin when building the default (TPM) wheel on a
plain Debian/Ubuntu host: a bare `maturin build --release` detects the linked
`libtss2` shared libraries and runs an auditwheel-style RPATH-rewrite repair
step, which calls `patchelf`. Without `patchelf` installed, the build fails at
that repair stage.

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
  $ sudo apt install -y libtss2-esys-3.0.2-0t64 libtss2-tcti-device0t64
  ```

  (On Debian 13 "trixie" and Ubuntu 24.04+ the packages use the `t64`
  suffix: `libtss2-esys-3.0.2-0t64` and `libtss2-tcti-device0t64`. On
  older releases they may be named `libtss2-esys-3.0.2-0` and
  `libtss2-tcti-device0` — try both if the `t64` names have no apt
  candidate.
  On some releases these are pulled in by `tpm2-tools`. The build host
  additionally needs `libtss2-dev` for headers + pkg-config — that is a
  BUILD dependency, added in §1 below, not a runtime one.)

- Group access. /dev/tpmrm0 is owned tss:tss mode 0660. The shipped
  deploy/dsm.service runs as root and also sets SupplementaryGroups=tss,
  so the daemon can open the TPM. When you run `dsm enroll` BY HAND, run
  it as a user that is either root or in the `tss` group:

  ```sh
  $ sudo usermod -aG tss "$USER"   # then log out / back in
  ```

  or prefix the enroll commands in §3 with `sudo` (the guide
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

### 0f. Clock synchronization (NTP) — both client and server

DSM handshakes include a freshness timestamp. If the two peers' clocks
differ by more than ~5 minutes, the handshake fails with a freshness
rejection error that names clock skew. The daemon also logs a WARNING at
startup when the system clock is not NTP-synchronized.

Ensure NTP is running on BOTH the client and the server BEFORE starting dsm:

```sh
$ sudo timedatectl set-ntp true
$ timedatectl status | grep -E 'synchronized|NTP'
# expect: "NTP service: active" and "System clock synchronized: yes"
```

## 1. Build

The dsm process runs under `sudo` (CAP_NET_ADMIN + CAP_NET_BIND_SERVICE),
which means Python's interpreter is the system one at /usr/bin/python3 —
not a venv and not a --user install. Every Python module dsm imports
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

Soft wheel (dev/test): pass `--no-default-features --features
dev-soft-attest` to the maturin commands below to build the software
attest backend (no TPM, no libtss2-dev). It imports identically but is
not hardware-bound. The rest of this section assumes the default TPM
wheel.

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

The wheel also ships the nftables ruleset templates inside the `dsm`
package (`dsm/net/_templates/`). No manual copy of `nftables/*.conf`
into site-packages is needed — a plain `pip install <wheel>` is
sufficient for the daemon to start.

You can `rm -rf /tmp/dsm-build-venv` at the end of section 1.

### 1a.1 Constrained client: build once, copy the wheel

A constrained client (small disk, no Rust toolchain, no `libtss2-dev`)
does not need to build locally. Build the wheel ONCE on a capable host
of the SAME distro, arch, and Python MINOR version, copy the `.whl` to
the client, then `pip install` it there.

On the BUILD host:

```sh
# Build as above (§1a), then copy the wheel to the client:
$ scp rust/tuncore/target/wheels/dsm-0.1.0-*.whl user@client:/tmp/
```

On the CLIENT (after copying the wheel):

```sh
# Install only the runtime packages — no Rust toolchain, no libtss2-dev:
$ sudo apt install -y \
      python3 python3-pip \
      libtss2-esys-3.0.2-0t64 libtss2-tcti-device0t64 \
      nftables iproute2
# python3-pip: Debian's ensurepip is disabled; install python3-pip via apt.
# libtss2-*t64: the t64-suffixed names are correct on Debian 13+ / Ubuntu 24.04+.
# On older releases use libtss2-esys-3.0.2-0 and libtss2-tcti-device0 instead.

$ sudo /usr/bin/python3 -m pip install --break-system-packages \
      /tmp/dsm-0.1.0-*.whl
```

Important caveats:
- The wheel MUST be built on the SAME distro + arch + Python minor version
  as the client. A wheel built on Debian 12 (Python 3.11, amd64) will
  NOT install cleanly on Ubuntu 22.04 (Python 3.10) or on arm64.
- A wheel built with the plain `maturin build --release` command above has
  its `libtss2` libraries vendored in (RPATH-rewritten) by maturin's repair
  step. The client still needs the runtime TSS2 packages above regardless,
  because the TCTI device driver (`libtss2-tcti-device0t64`) opens
  `/dev/tpmrm0` at runtime and is not vendored.
- `python3-pip` must be installed on the client via `apt` — Debian's
  system Python intentionally omits `ensurepip`, so `python3 -m pip`
  fails without the apt-installed pip.

### 1b. Install the wheel into the system Python (pins runtime deps)

Installing the dsm wheel ALSO installs its runtime dependencies at the
versions pinned in pyproject.toml ([project].dependencies:
cryptography>=50.0.0,<51 and dnspython>=2.6,<3.0). Do NOT install
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
cryptography==50.0.2, dnspython==2.8.0, plus their transitive deps).
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

Run this command from a directory outside the repo (e.g.
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

### 2c. Generate the initial (empty) CRL

The daemon ships fail-closed: `crl_strict` defaults to true, so every dsm
host REFUSES to start unless a `crl_file` is present and current (see §3a,
§7e). You must therefore produce a CRL now — even on a fresh CA with an
empty `index.txt`, before any cert has been revoked — and distribute it
alongside the root cert in §2f.

```sh
$ openssl ca -config openssl-ca.cnf -gencrl -out crl/dsm_ca.crl
```

This writes an empty but valid CRL whose `next_update` is `default_crl_days`
(31) out. Re-run this command (and re-walk the CRL) before it expires, and
whenever you revoke a cert (§7e).

### 2d. Record the root cert fingerprint in your physical safe

```sh
$ openssl x509 -in dsm_ca_root.pem -noout -fingerprint -sha256
$ sha256sum dsm_ca_root.pem
```

Print BOTH outputs and store the printout in the safe.

The bare 64-hex SHA-256 of the FILE (second command) is also the
REQUIRED `ca_root_sha256` config value (see §2f and §3a). The daemon
refuses to start unless config.toml sets `ca_root_sha256` and it
matches the on-disk dsm_ca_root.pem — this pins the trust anchor so a
swapped CA PEM is rejected. Capture it in config-ready form now:

```sh
$ sha256sum dsm_ca_root.pem | cut -d' ' -f1
# -> 64 hex chars; this goes verbatim into ca_root_sha256 = "<hex>"
```

### 2e. Snapshot the CA directory onto your encrypted USB sticks

Make AT LEAST two redundant copies on separate USB sticks. Store at
least one off-site (safe deposit box). Wipe and re-snapshot whenever
you sign a new CSR or generate a new CRL — the ca/index.txt and
ca/serial files must stay in sync with what was issued.

The CA private key NEVER leaves these USBs. To sign a CSR, mount the
USB RW, sign, unmount, return to safe.

### 2f. Distribute the root cert + CRL to every dsm host (via Stick B)

On Stick B, place a copy of BOTH dsm_ca_root.pem and the initial CRL
crl/dsm_ca.crl from §2c (both public, safe to walk). On each dsm host:

```sh
$ sudo install -m 0600 -o root -g root /mnt/transport/dsm_ca_root.pem \
      /opt/mtun/dsm_ca_root.pem
$ sudo install -m 0600 -o root -g root /mnt/transport/dsm_ca.crl \
      /opt/mtun/dsm_ca.crl
$ sha256sum /opt/mtun/dsm_ca_root.pem | cut -d' ' -f1
      # cross-check this 64-hex value vs the safe printout (§2d),
      # then paste it into config.toml as ca_root_sha256 (§3a).
```

The CA root cert is a public document, but dsm's path-security check
refuses to load any file (even certs) that has group/world bits, so
install it 0o600. Substitution of dsm_ca_root.pem changes the trust
anchor — defense-in-depth is appropriate, and the REQUIRED
`ca_root_sha256` config pin makes the swap fatal at startup rather
than silently trusting the new anchor.

The CRL goes to /opt/mtun/dsm_ca.crl (the `crl_file` path in §3a). Because
`crl_strict` defaults true, the daemon will not start without it. Refresh
it on the CRL cadence (§7e).

Re-wipe Stick B (`shred -v`) before reusing it.

## 3. Per-Device Enrollment

Order matters. Enroll the SERVER first so its CN exists by the time you
configure clients (clients pin the server's CN via `expected_server_cn`).

### 3a. Server: write /opt/mtun/config.toml

Pick the server's public IP and a UDP port (default 51820). Stash
the DoH provider's SPKI pin (see 3a.1 below).

```sh
$ sudo mkdir -p /opt/mtun
# install -m 0600 writes the file mode 0600 directly. A plain `sudo tee`
# would create it mode 0644 under root's umask, and the daemon's
# path-security check REFUSES to load a config with any group/world bits
# ("refusing to load config with insecure permissions ... chmod 600").
$ sudo install -m 0600 /dev/stdin /opt/mtun/config.toml <<'EOF'
mode               = "server"
server_ip          = "10.0.0.5"         # THIS host's public IP (literal)
server_port        = 51820
listen_port        = 51820

key_file           = "/opt/mtun/identity.key"
cert_file          = "/opt/mtun/device.crt"
ca_root_file       = "/opt/mtun/dsm_ca_root.pem"
# REQUIRED: 64-hex SHA-256 of ca_root_file (§2d / §2f). The daemon refuses
# to start without it and rejects a swapped CA PEM. Compute with:
#   sha256sum /opt/mtun/dsm_ca_root.pem | cut -d' ' -f1
ca_root_sha256     = "REPLACE_WITH_64_HEX_SHA256_OF_dsm_ca_root.pem"
attest_key_file    = "/opt/mtun/attest.key"
crl_file           = "/opt/mtun/dsm_ca.crl"   # required by default (crl_strict=true);
                                              # provision the initial CRL per §2c
                                              # and distribute it per §2f BEFORE
                                              # first start, else the daemon refuses
                                              # to boot ("crl_file configured but
                                              # missing").
# crl_strict       = true                     # default. Set false ONLY for
                                              # lab/dev with no CA workflow.

# Server-only: one allowed client subject CN per line, mode 0o600.
allowed_cns_file   = "/opt/mtun/allowed_cns.txt"

transport          = "udp"              # UDP recommended; use "tcp" only as fallback on
                                        # networks that block/mangle UDP (TCP-in-TCP
                                        # causes throughput collapse on TCP traffic)
mtu                = 1360
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

Keep `[dns_provider_pins]` as the last section of config.toml. TOML reads
every line below that header as a pin, so a setting added below it stops
dsm at startup (`dns_provider_pins has entries that are not in
dns_providers: ...`). Put new settings above the header.

Validate the TOML before continuing — a missing quote produces a
confusing stack trace later:

```sh
$ python3 -c "import tomllib; tomllib.load(open('/opt/mtun/config.toml','rb')); print('ok')"
```

Must print "ok". If you instead see TOMLDecodeError, see §11's TOML
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
cn = dsm-<12 hex>-server
noise_static_pub = <hex>
```

Record both in your device inventory.

BACKUP / RECOVERY of attest.key on TPM:  attest.key is a TPM-bound blob,
not a key, and loads only on the TPM that created it. Backing it up
protects against losing the file, nothing else — restoring it works only
if that TPM is intact and you still have the enroll passphrase. If the
TPM is cleared, replaced, or fails, or the passphrase is forgotten, the
key is unrecoverable and you must re-enroll (§7g). A thief with only the
disk gets nothing, which is the point.

### 3c. Server: walk CSR to CA, sign, walk cert back

Walk /tmp/dsm-csr-server.der to the CA laptop on freshly-wiped
Stick B. On the laptop:

```sh
$ cd ca

# 1. Inspect the CSR — this is the review step that gates issuance
$ openssl req -in /mnt/transport/dsm-csr-server.der \
      -inform DER -text -noout -verify
# Verify by eye:
#   * Subject CN matches an approved inventory entry
#   * "1.3.6.1.4.1.99999.1.1: critical" is present
#   * "Certificate request self-signature verify OK" appears
#   * Subject Public Key is prime256v1 (256-bit ECDSA)
# If ANY check fails, REJECT. Wipe Stick B. Investigate.

# 2. Sign with the server profile. -notext keeps the emitted file pure PEM
#    (without it openssl prepends a human-readable text dump before the
#    -----BEGIN CERTIFICATE----- block). The output name matches the import
#    path used in §3d so the two steps line up.
$ openssl ca -config openssl-ca.cnf -extensions dsm_server_leaf -notext \
      -in /mnt/transport/dsm-csr-server.der -inform DER \
      -out certs/dsm-cert-server.pem -batch

# 3. Copy the signed cert back to Stick B (the cert ONLY — never
#    walk the CA private key or index.txt anywhere)
$ cp certs/dsm-cert-server.pem /mnt/transport/

# 4. Eject Stick B, eject Stick A, return both to the safe.
```

### 3d. Server: import the signed cert

Walk Stick B back to the server and copy the signed cert off it to the
import path BEFORE importing (this is the cross-machine bridge — §3c wrote
the cert on the CA laptop's Stick B, not on the server):

```sh
$ sudo cp /mnt/transport/dsm-cert-server.pem /tmp/dsm-cert-server.pem
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
# Type the passphrase at the prompt; do NOT pass it as a literal on the
# command line (it would be saved in your shell history). read -s hides it.
$ read -rs DSM_PP
$ printf '%s' "$DSM_PP" | sudo install -m 0600 /dev/stdin /etc/dsm/passphrase
$ unset DSM_PP
```

Then start with:

```sh
sudo python3 -m dsm --mode server \
    --passphrase-env-file /etc/dsm/passphrase
```

(ii) systemd LoadCredential (preferred for production):

This is the server's unit. A client uses `deploy/dsm-client.service`
instead (§3f): `dsm.service` runs DSM as a server.

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
# Same rule: never echo a literal passphrase (it lands in shell history).
$ read -rs DSM_PP
$ printf '%s' "$DSM_PP" | sudo install -m 0600 /dev/stdin /etc/dsm/passphrase
$ unset DSM_PP
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

Walk to CA, sign exactly as in §3c but with `-extensions dsm_client_leaf`
(NOT dsm_server_leaf) and `-out certs/dsm-cert-client.pem` (keep `-notext`),
copy it to Stick B, walk back, then bridge it off the stick and import:

```sh
$ sudo cp /mnt/transport/dsm-cert-client.pem /tmp/dsm-cert-client.pem
$ sudo python3 -m dsm --config /opt/mtun/config.toml \
      enroll --import /tmp/dsm-cert-client.pem
```

Stash the passphrase as in 3e (i) or (ii). For (ii) a client uses its own
unit, never `deploy/dsm.service` (that one runs DSM as a server):

```sh
$ sudo cp deploy/dsm-client.service /etc/systemd/system/dsm-client.service
$ sudo systemctl daemon-reload
$ sudo systemctl enable dsm-client
```

Do not start it yet: the server must know this client first (§4), and
you start the client in §5. A client that cannot reach a server blocks all
traffic, SSH too, and keeps trying.

`sudo dsm init client --install-unit` and `install.sh --systemd --client`
install the same unit. Unlike the server's, the client unit takes the kill
switch down only after a stop you ask for (`systemctl stop`); see §7i.

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
Connected clients keep their kill switch up during the restart and connect
again by themselves. Live SIGHUP reload is on the Phase-2 punch list. To
REVOKE: remove the CN from the file, restart, and optionally issue a CRL
update (§7e).

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
$ sudo systemctl start dsm-client            # if you installed the client unit (§3f)
# or
$ sudo python3 -m dsm --mode client \
      --passphrase-env-file /etc/dsm/passphrase
```

Expected client log lines (log_level = "info"), in order, within ~5 s:

```
... handshake complete (client) — server_cn=dsm-XXXXXXXX-server
... TUN mtun0 configured: 10.8.0.2/24 mtu=1360
... tunnel established
... kernel path MTU = 1500 (usable inner 1432)
... auto_mtu: lowered tun mtu 1360 -> 1232 (kernel pmtu=1300)
                                               ↑ only when
                                                 auto_mtu=true AND the
                                                 path actually needs it
                                                 (typical on cellular)
```

If the server cannot be reached, the client does not exit. It keeps all
traffic blocked, logs `no tunnel: all traffic is blocked until DSM connects
again; ...` and keeps trying (§7i).

Expected server log lines:

```
... CN allowlist loaded (1 entries)
... server listening on UDP port 51820
... DNS blocklist loaded: 72,525 names to block, 0 allowed (files read: 1, lines skipped: 13)
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

nftables tables (2 on the server, 2 on the client):

```sh
$ sudo nft list tables | grep '^table inet dsm_'
# Server-side, expect:
#   table inet dsm_server_ratelimit  (per-source-IP handshake limiter)
#   table inet dsm_server_nat        (MASQUERADE for decrypted client traffic)
# Client-side, while the tunnel is up, expect:
#   table inet dsm_killswitch        (default-drop output/input + ICMP rate-limit)
#   table inet dsm_dns_leak          (DNS/DoT/DoH/mDNS/LLMNR blocked off-tunnel)
# Client-side, while it connects or reconnects, expect only:
#   table inet dsm_killswitch_pre    (only loopback, DHCP and the server)
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

Graceful shutdown of the client (Ctrl-C, or `sudo systemctl stop dsm-client`):

```sh
# Within ~1 second the server logs: ... dsm.server: server shutting down
# (SESSION_CLOSE is received silently; the visible line comes from the
# teardown that follows). On the client:
$ ip link show mtun0                           # "Device does not exist"
$ sudo nft list tables | grep '^table inet dsm_'   # no output
$ cat /etc/resolv.conf | head -2               # restored to pre-VPN
$ sysctl net.ipv6.conf.all.disable_ipv6        # 0 (restored)
```

Stopping the server is not a stop of the client. The client logs
`dsm.client: shutting down` for the session, then `no tunnel: all traffic
is blocked until DSM connects again; ...`, keeps `table inet
dsm_killswitch_pre` up and connects again by itself when the server is
back (§7i).

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
`dsm-<sha256(noise_static ‖ role)[:6 bytes / 12 hex]>-server` ALWAYS produces
a new CN. Plan accordingly.

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

UDP (`transport = "udp"`) is the recommended default. It avoids the
TCP-in-TCP throughput collapse that TCP transport causes when the
tunneled traffic is itself TCP. Switch to `transport = "tcp"` only as a
fallback on networks that block or aggressively mangle UDP (e.g.,
restrictive firewalls, some mobile carriers).

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
2. Walk the new root cert + CRL to every dsm host (§2f).
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

### 7h. DNS blocklist (server)

The server answers "no such name" (NXDOMAIN) for every name on your block
lists and every name under a listed name, for every kind of query. Devices
remember that answer for 5 minutes. It is on by default
(`dns_blocklist = true`).

The files, all owned by root, mode 0600 (folders 0700), no links:

```
/opt/mtun/dns/sources.txt      # list URLs, one per line (you edit this)
/opt/mtun/dns/block/*.txt      # the block lists; fetched-*.txt come from sources.txt
/opt/mtun/dns/allow.txt        # names that are never blocked (you edit this)
```

Only `block/` files that end in `.txt` and do not start with a dot are read.
A list can hold hosts lines (`0.0.0.0 ads.example.com`), one name per line,
or `||ads.example.com^` lines. `@@||name^` lines count as allowed names.
Lines that start with `#` or `!` are comments. Rules to know:

- A hosts line blocks its names whatever address is in front of them. DSM
  never answers with that address. So an old hosts file of fixed answers,
  copied into `block/`, blocks its names; it does not redirect them. DSM no
  longer reads such a file by itself.
- A list can block a shared suffix such as `co.uk`, and with it every name
  under it. Only bare one-word names such as `localhost` are refused. Read a
  list before you add it.
- Other AdGuard rules (wildcards, `$` options, regular expressions) and
  lines longer than 4096 bytes are skipped, and counted in the log line
  below.
- Limits: 64 MiB per file and 2,000,000 names in all (counted before
  duplicates are dropped).
- `allow.txt` takes the same line forms; every name in it is allowed.
- One refused file stops the whole new load, not only that file (see §11).

An allowed name also covers the names under it, and it wins over the block
lists. One name is the exception: `use-application-dns.net` always gets "no
such name", even if it is on `allow.txt` or on an `@@||name^` line.

DSM never downloads anything. `dsm-blocklist-update` downloads every URL in
`sources.txt` into `block/` once a day (a systemd timer, at a random time in
the hour after midnight). Only `https://` URLs are used. A list over
64 MiB is refused while it is written. When a download fails, the copy from
before stays. When `sources.txt` is missing, the script writes one with the
default list: StevenBlack's unified ads and malware hosts list, about 72,000
names (`https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts`).
That list merges others that keep their own licences, some only for
non-commercial use. DSM only ships its address; to use another list, replace
that line in `sources.txt` (see "Everyday tasks"). `install.sh --systemd`
sets all this up and downloads once; if that first download fails, it only
warns, and the timer tries again the next day. From a source checkout, set it
up by hand:

```sh
$ sudo install -m 0755 deploy/dsm-blocklist-update.sh /usr/local/sbin/dsm-blocklist-update
$ sudo install -m 0644 deploy/dsm-blocklist-update.service deploy/dsm-blocklist-update.timer /etc/systemd/system/
$ sudo systemctl daemon-reload
$ sudo systemctl enable --now dsm-blocklist-update.timer
$ sudo install -d -m 0700 /opt/mtun/dns     # the unit needs this folder
$ sudo systemctl start dsm-blocklist-update # first download, now
```

The download runs inside the unit's sandbox, never as plain root. If your
config is not in /opt/mtun, change /opt/mtun in the `.service` file (the
comment at its top lists the lines) and in the `install -d` command.

dsm looks at the folder every 5 minutes and loads the lists again, in the
background, when a file changed. You never need to restart dsm. Log lines
(the first comes when a load ends, so it can show a moment after start; both
need `log_level = "info"`, the default):

```
... DNS blocklist loaded: 72,525 names to block, 0 allowed (files read: 1, lines skipped: 13)
... DNS blocklist: queries blocked in the last hour: 1,234
```

The second line comes once an hour, only if something was blocked. Logs show
counts, and file paths in a warning. They never show the names.

Everyday tasks:

- Add a list: add its `https://` URL to `sources.txt`, then
  `sudo systemctl start dsm-blocklist-update`.
- Stop using the default list: put a `#` in front of its line. The next
  download run deletes the file it made from that line. Do not delete
  `sources.txt`: a missing one is written again with the default.
- Use a list file of your own: `sudo install -m 0600 my-list.txt
  /opt/mtun/dns/block/`. The download job only touches `fetched-*.txt`.
- Never block a name: add it to `allow.txt` with
  `sudo sh -c 'umask 077; echo good.example.com >> /opt/mtun/dns/allow.txt'`.
  This adds the line at the end, and makes the file (mode 0600) if it is
  missing. If you allow a name under a blocked one (`x.ads.example.com` under
  `ads.example.com`), a device that got "no such name" for the blocked one
  may treat the allowed name as missing too, for up to 5 minutes (RFC 8020).
- Turn the blocklist off: `dns_blocklist = false` in config.toml, above the
  `[dns_provider_pins]` table, then restart dsm. This also turns off the
  `use-application-dns.net` answer below.

Limit: an app that uses its own encrypted DNS (DNS over HTTPS or over TLS)
through the tunnel skips the blocklist. DSM answers "no such name" for
`use-application-dns.net`, which tells Firefox not to switch to its own
encrypted DNS, but a Firefox set to always use it, and other apps, still
skip the list. Pi-hole has the same limit.

### 7i. Client: when the tunnel is down

The client's kill switch is up whenever DSM runs, also while there is no
tunnel. It comes down when you stop DSM. Two cases differ: a setup error at
the first try also removes it (DSM exits 1), and a `systemctl stop` sent
while DSM waits to restart (after a crash or a signal sent straight to it)
leaves it up; run `sudo dsm cleanup`.

- **The tunnel drops** (no packets from the server for 60 s, the server
  restarts or closes the session, a TCP reset, a key change that gives up,
  a handshake that fails). The client goes back to the start-up kill
  switch, `table inet dsm_killswitch_pre`, in one nft step. It lets
  through only loopback, DHCP and the server's IP and port. Then it
  connects again by itself: after 1 s, then 2, 4, 8, 16 and 30 s, then
  every 30 s, with no limit (plus the time each try takes). It logs this
  once per outage, and at most once a minute:

  ```
  no tunnel: all traffic is blocked until DSM connects again; it keeps trying. To get internet back without the VPN, stop DSM: Ctrl-C, or `sudo systemctl stop dsm-client`. If DSM is not running, run `sudo dsm cleanup`.
  ```

- **Getting internet back without the VPN:** stop DSM. Ctrl-C if you
  started it by hand, `sudo systemctl stop dsm-client` under systemd. Both
  take every DSM table down. If DSM is not running but its tables are
  still there (after a crash or `kill -9`, or a `systemctl stop` while
  DSM was waiting to restart after a crash or a signal sent straight to
  it), run `sudo dsm cleanup`. That command also sets `net.ipv4.ip_forward`
  to 0 and turns IPv6 back on, which can break Docker: if you use Docker,
  restart it after `dsm cleanup`.
- **Captive portals** (hotel, airport or train Wi-Fi with a login page):
  the login page cannot load while DSM runs. Stop DSM, log in, start DSM.
- **DSM crashes** (a Python error, exit 1): the kill switch stays up on
  purpose, and the log says so. The next start replaces the old tables in
  the same nft step, so the host is never open in between. Under
  `dsm-client.service`, systemd starts DSM again after 5 s. If it keeps
  failing, systemd gives up after 5 failed starts in 10 minutes. After
  crashes the block stays; after setup errors (below) it is already gone.
  Read `journalctl -u dsm-client`, then fix the problem or run
  `sudo dsm cleanup`. To start DSM again after systemd gave up, run
  `sudo systemctl reset-failed dsm-client`, then
  `sudo systemctl start dsm-client`.
- **Setup errors at the first start** (a wrong passphrase, keys or cert
  that do not match, a UDP `listen_port` in use, a read-only
  `/etc/resolv.conf`): DSM removes the kill switch and exits 1, as before:
  you are there, and nothing was protected yet. The same errors on a
  later reconnect keep the block, and DSM tries again.
- **Server cert or CN errors** (`server CN check failed`, `server cert
  auth failed`, `server cert revoked`) keep the block too: someone on the
  network can send them. If your config is wrong, stop DSM, fix it, start
  it again.
- **A DDNS server name:** DSM looks the name up once, at start, and keeps
  that address while it reconnects; no lookup goes out through the block.
  If the server's address changes during an outage, the client logs
  `server IP may have changed ...` after 5 failed tries: stop DSM, then
  start it. Once a handshake with a looked-up address works, DSM saves
  the name and that address in `/run/dsm/server-endpoint.json` (root only;
  gone at reboot; `dsm cleanup` leaves it). A run whose handshake never
  works leaves the file as it was. If a later start cannot look the name
  up, for example because a kill switch left by a crash blocks the lookup,
  DSM uses the saved address and logs `could not look up the server name;
  using the last address it had`. A lookup that works always wins, and
  its address replaces the saved one once a handshake with it works. With
  no saved address for that name, DSM exits with `could not resolve
  server endpoint`: run `sudo dsm cleanup`, then start DSM.
- **`systemctl restart dsm-client`** keeps the kill switch up: the old run
  leaves the start-up kill switch in place and the new start replaces it
  in one nft step, so the host is never open. The same goes for a signal
  sent straight to DSM (`kill`, `systemctl kill`): systemd starts DSM
  again and the block stays. A restart can also keep the old server
  address (the block can stop the name lookup, and then DSM uses the saved
  one): after the server's address changed, stop DSM and start it
  instead. Apart from `sudo dsm cleanup`, only `sudo systemctl stop
  dsm-client` and Ctrl-C on a run by hand take the kill switch down, with
  two exceptions: a setup error at the first try also removes it (DSM exits
  1), and a `systemctl stop` sent while DSM waits to restart (after a crash
  or a signal sent straight to it) leaves it up; run `sudo dsm cleanup`.

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
# install -m 0600 (NOT `tee`) so the config is mode 0600 — a 0644 config is
# rejected at startup ("refusing to load config with insecure permissions").
$ sudo install -m 0600 /dev/stdin /opt/mtun/config.toml <<'EOF'
mode = "server"
server_ip = "127.0.0.1"
server_port = 51820
listen_port = 51820
key_file = "/opt/mtun/identity.key"
cert_file = "/opt/mtun/device.crt"
ca_root_file = "/opt/mtun/dsm_ca_root.pem"
ca_root_sha256 = "REPLACE_WITH_64_HEX_SHA256_OF_dsm_ca_root.pem"  # REQUIRED (§2d)
attest_key_file = "/opt/mtun/attest.key"
allowed_cns_file = "/opt/mtun/allowed_cns.txt"
transport = "udp"
# crl_strict = false ONLY for this local sanity check, which has no CA CRL
# workflow. PRODUCTION MUST provision a CRL (§2c) and leave crl_strict at its
# fail-closed default of true (§3a, §7e).
crl_strict = false
dns_providers = ["https://1.1.1.1/dns-query"]
[dns_provider_pins]
"https://1.1.1.1/dns-query" = ["<64-hex SPKI SHA-256>"]
EOF
```

Place /opt/mtun/dsm_ca_root.pem per §2f. Cross-check its SHA-256
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

### 8g. Verify everything (§6)

Expected client and server logs are in §5. Run every command in §6.
Pass criterion: every check produces its
expected output AND graceful shutdown leaves NO residue.

### 8h. Failure drills

8h.1 — Server crash (SIGKILL mid-session)

```sh
$ sudo pkill -9 -f 'dsm --mode server'
# On the client, watch the log. After about 60-65 s (DEAD_PEER_TIMEOUT
# plus one 5 s check) the client logs "dead peer", then
# "no tunnel: all traffic is blocked until DSM connects again; ...".
$ sudo nft list tables | grep '^table inet dsm_'
# expect table inet dsm_killswitch_pre, and no dsm_killswitch or
# dsm_dns_leak. A server on the same host also leaves its dsm_server_*
# tables.
$ curl -m 5 https://example.com || echo "PASS-blocked"
# Start the server again: the client connects again by itself within
# about 30 s and logs "tunnel established".
```

PASS: the kill switch never comes down: traffic is blocked while the
server is gone and flows again after the reconnect.

8h.2 — Client crash

```sh
$ sudo pkill -9 -f 'dsm --mode client'
# Expected host state on the client side after crash:
#   - mtun0 is gone (kernel reaps the TUN when the owning fd closes)
#   - the kill switch tables are STILL PRESENT, on purpose: all traffic
#     stays blocked (fail closed). Starting DSM again replaces them.
#   - resolv.conf still points at 10.8.0.1; the pre-VPN contents
#     were captured only in process memory and are lost
#   - /run/dsm/ipv6_state.json remains (next clean dsm start restores)
# To get the host back without DSM:
$ sudo dsm cleanup
# Or by hand:
$ for t in dsm_killswitch_pre dsm_killswitch dsm_dns_leak dsm_server_ratelimit dsm_server_nat; do
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
mtu = 1360
pmtu_discover = false
auto_mtu = false                     # static MTU is fine
# Client side (cellular):
mtu = 1360
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
$ dig @10.8.0.1 example.com +short
```

PASS: @10.8.0.1 returns A records (query goes via TUN, resolved on server).
Real leak proof: the tcpdump step above shows no DNS packets exiting the WAN
interface except to server:port — no direct DNS to external resolvers.

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
deploy/dsm.service. Without the audit a too-tight filter will SIGSYS
the daemon mid-handshake.

Then enable RestrictNamespaces empirically: restart, re-run §9e. It
should not break dsm in the common case — dsm enters no namespaces at
runtime — but `ip(8)` attempts unshare()/setns() on some distros. After
enabling, check `journalctl -u dsm | grep -i 'permission denied'` and
exercise the kill-switch nftables apply path specifically. If dsm fails
to open /dev/net/tun or netlink, drop the flag with a comment in the
unit.

### 9g. What to capture and ship back from each demo run

- journalctl -u dsm  (server + client, full session)
- sudo nft list ruleset           (after established)
- ip rule + ip route show table 100   (both boxes)
- The Cloudflare trace output from §9e.2
- sudo systemd-analyze security dsm
- /tmp/dsm-strace.log and /tmp/dsm-syscalls.txt from §9f
- With --debug-net enabled: the JSON event stream from
  `sudo journalctl -u dsm -o cat | grep dsm.netaudit > /tmp/demo.jsonl`

## 10. Running Over the Internet (Remote Client)

The real-world deployment: the SERVER sits on your home network behind a
consumer router, and the CLIENT is somewhere else entirely — cellular
data, hotel/cafe Wi-Fi, any foreign network behind NAT. The server is
reachable by a stable dynamic-DNS name; the client dials that name.

Almost nothing new is required. The server already binds all interfaces
(0.0.0.0), NAT keepalives hold the router mapping open, and the client
adapts to small cellular MTUs by itself. You need exactly three things: a
router port-forward, a DDNS name, and three client config lines.

This is the minimal get-it-working recipe. For the full end-to-end
acceptance procedure (30-minute soak, leak drills, MTU-adaptation checks)
see §9.

### 10a. Server (home network): port-forward the router

The server binds `0.0.0.0:<listen_port>` already — NO server config change
is needed. You only have to expose that port through your home router.

1. Note the server's `listen_port` (default 51820) and its LAN IP:

   ```sh
   $ ip -4 addr show | grep -w inet        # e.g. 192.168.1.3
   ```

2. In the router's admin page, add a port-forward rule:

   ```
   WAN 51820/udp  →  192.168.1.3:51820     # <server-LAN-IP>:<listen_port>
   ```

   If you also plan to use the TCP fallback (§10d), add a second rule for
   `51820/tcp` to the same LAN IP.

(Optional: §9b shows a one-line `nc` UDP listener you can hit from a phone
to confirm the forward works before involving dsm.)

### 10b. Dynamic DNS: give the home IP a stable name

Home ISPs hand out a public IP that changes without warning. A free
dynamic-DNS provider (e.g. duckdns.org, no-ip.com) gives you a stable name
like `my-dsm.duckdns.org` that always tracks your current home IP.

- Register a name with the provider.
- Keep it pointed at your home IP: enable the provider's DDNS client in the
  router, OR run the provider's small updater script on the server.
- Confirm it resolves to your home's public IP (run at home):

  ```sh
  $ dig +short my-dsm.duckdns.org         # should equal: curl -s https://ifconfig.co
  ```

### 10c. Client: dial the DDNS name

In the CLIENT's /opt/mtun/config.toml, point `server_ip` at the DDNS name
and turn on the cellular-friendly MTU knobs:

```toml
server_ip     = "my-dsm.duckdns.org"   # DDNS hostname (resolved once at startup)
server_port   = 51820                  # = the server's forwarded listen_port
auto_mtu      = true                   # adapt TUN MTU to the path
pmtu_discover = true                   # required by auto_mtu
```

`server_ip` takes either the DDNS hostname or a literal IPv4. A literal
avoids the single startup hostname lookup (privacy-max — see §10f); the
hostname is the convenient choice for a home server on a changing IP.
`auto_mtu` + `pmtu_discover` matter on cellular, where the path MTU is
small and oversized packets are often silently black-holed — the client
tracks the kernel PMTU and lowers the TUN MTU to fit (the "auto_mtu:
lowered tun mtu ..." line in §5).

Data use: the tier shaper sends fake packets and padding the whole time
the tunnel is up, even when you are not using it. Connected all day with
decoys on, this extra traffic alone is about 3 GB a day in each direction.
Real use adds more of it: about 6 GB a day with about 20 bursts of use, on
top of your real traffic. The settings that control it are
`shaper_tiers_pps`, `shaper_latency_budget_ms`, `shaper_decoy_interval_s`,
`shaper_linger_s` and `shaper_auto_cap`; `config.example.toml` lists the
costs.

### 10d. UDP-blocked networks (some cellular / captive Wi-Fi)

A few networks block outbound UDP except on port 443. If the UDP handshake
never completes (the client logs "handshake recv timed out" — see §11),
switch BOTH ends to the TCP transport:

```toml
transport = "tcp"
```

and add the matching `51820/tcp` port-forward on the router (§10a). TCP
rides the same port number and survives more captive/proxy networks, at the
cost of some TCP-over-TCP overhead.

### 10e. Test from a phone (cellular, off your home Wi-Fi)

The point is reachability from a foreign network, so test from one:

1. On the client, **turn Wi-Fi off** and use cellular data — you must NOT be
   on the home LAN, or you would be testing the local path, not the internet
   path.
2. Bring the tunnel up (§5) and wait for `tunnel established`.
3. Confirm traffic exits via the SERVER, not the cellular carrier:

   ```sh
   $ curl -s https://ifconfig.me        # must print the SERVER's home public IP
   $ dig @10.8.0.1 example.com +short   # DNS resolves through the tunnel
   ```

   If `ifconfig.me` shows your home public IP and a browser loads pages, the
   remote path is live.

### 10f. Security / privacy note

With a DDNS hostname the client makes ONE cleartext DNS A-lookup at startup
(before the kill switch installs) to turn the name into an IP — that lookup
reveals the *hostname* to the local network. It is NOT a trust anchor: the
server is still authenticated by Noise + the cert/CN pin, so a spoofed or
poisoned DNS answer makes the handshake fail CLOSED rather than redirecting
you to an attacker. While the tunnel is down the client keeps that first
address and does not look the name up again (§7i). Set `server_ip` to a
literal IPv4 if you want to avoid even that single lookup.

## 11. Debugging by Symptom

`log_level = "debug"` turns on per-packet-class log lines — useful while
reproducing a bug. Switch back to "info" for steady state.

`--debug-net` (or `debug_net = true` in config) emits one structured
JSON event per state transition on the `dsm.netaudit` logger
(handshake_start, handshake_end, nft_apply/_remove, tun_configure/
_deconfigure, rekey_epoch, liveness_fire, shutdown_signal,
auto_mtu_change, auto_cap_change, crl_missing/stale). Capture with:

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
                   shaper_*, rotation_*, pmtu_discover,
                   pmtu_check_interval_s, max_inflight_handshakes,
                   debug_dns, debug_net, auto_mtu, crl_strict
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
  retry adds 5 s of timeout + (1, 2) s of backoff (3 attempts; the
  third raises without sleeping) — about 18 s per try. After a failed
  try the client keeps the kill switch up and tries again by itself
  (1 s, doubling to 30 s, no limit; §7i). You do not need to restart it.

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

The client keeps the kill switch up and keeps trying (someone on the
network could send a wrong cert). Stop it, fix the config, start it again.

### "server cert auth failed: ..." or "client cert auth failed: ..."

- "chain ..." → the pinned ca_root_file does not match the CA that
  issued this side's cert. Cross-check
  `sha256sum /opt/mtun/dsm_ca_root.pem` against the value recorded in
  your safe (§2d).
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
- The tier shaper adds wait by design. When a burst starts, packets
  wait about 0.5 to 1.5 seconds while the rate steps up (a download that
  paces itself to the speed it gets, as TCP does, needs about 2 to 5
  seconds per tier), and with the
  defaults the top tier caps speed at about 7 to 10 Mbit/s (less for a
  smaller `mtu`). One DSM packet carries at most 1360 bytes, so with `mtu`
  above 1360 each full-size packet is split in two and the cap halves to
  about 3.6 to 5.4 Mbit/s. For a faster smoke
  test that hides less, lower `shaper_latency_budget_ms` and raise
  `shaper_tiers_pps` in both configs. A lower budget needs a faster first
  tier: it must stay above 4.25 divided by the budget in seconds. On a
  slow link, lowering padding_max also cuts the padding bytes. Do that for
  a quick test only, because it hides much less: a real packet too big for
  the largest allowed size is sent at its exact size, which no fake packet
  ever has, and that size shows how big the packet really is.

### Tunnel stalls or drops during big downloads (slow link)

At the default top tier (800 packets/s) DSM sends up to about 11 Mbit/s in
each direction. On a slower link it floods the link: packets are lost, key
changes can be lost too, and the tunnel stalls or drops, mostly during big
downloads. DSM now lowers its own top tier when that happens. Look for
`auto cap:` lines in the log (`journalctl -u dsm | grep 'auto cap'`). A
line like this means it worked:
`auto cap: lost 12% at tier 3 (800/s); top tier now 2 (200/s), next try in 5 min`.
It tries the higher tier again after 5 minutes, and waits longer (up to an
hour) while the loss keeps coming back. A line
`auto cap: link too slow even for tier 1` comes only after auto cap has
already dropped to tier 1, and means the link cannot carry even tier 1:
set the tiers by hand as below.

Set the tiers by hand only when auto cap cannot help: in TCP mode, when the
other end runs an older DSM, when `shaper_auto_cap = false`, or when the
link is slower than tier 1 (about 0.7 Mbit/s). Then lower the top tier in
`shaper_tiers_pps` to about 50 packets/s per Mbit/s of the link's slower
direction, e.g. `[10, 50, 150, 200]` for 4 Mbit/s. Keep the list rising and
the first entry above 8.5. The end that sends over the slow direction needs
it; setting it in both configs is simplest. Restart the end you changed.

### Tunnel up but nothing comes back (hardened host)

On hosts with strict reverse-path filtering (`rp_filter=1`, often set in
`/etc/sysctl.d` on hardened systems), older clients finished the handshake
and then got no replies: the kernel threw the server's answers away. The
client now handles this by itself, the same way wg-quick does. While
connected it sets `net.ipv4.conf.all.src_valid_mark=1` and adds two small
chains (three rules) to the kill-switch table. They tag only the replies
from your DSM server (its IP and port). You do not need to loosen
`rp_filter`.

On a clean exit the client puts `src_valid_mark` back to the value it found
at start. It also saves the old value in `/run/dsm/src_valid_mark.orig`.
If the client crashes, run `sudo dsm cleanup`: it puts the saved value back
and then deletes the file. (The server's systemd unit runs `dsm cleanup`
on every stop. On a client nothing runs it after a crash, by hand or under
dsm-client.service, because it would take the kill switch down; run it
yourself when you want the host back without DSM.)
If a file from a crash is still there when the client starts, the client
keeps it and logs a warning. Run `sudo dsm cleanup` after that run to get
the value from before the crash back.

`src_valid_mark` is one setting for the whole machine, not just for DSM.
While DSM is connected, the kernel's address check also uses the marks
that other programs put on packets (other VPNs, policy-routing rules).
Packets with no mark are checked as before. If you start another VPN that
needs the setting on (wg-quick turns it on) while DSM is up, DSM turns it
back to the old value when it exits. Restart that VPN, or set
`src_valid_mark=1` again yourself.

To check while connected:

```sh
$ sysctl net.ipv4.conf.all.rp_filter net.ipv4.conf.all.src_valid_mark
$ sudo nft list chain inet dsm_killswitch mark_restore
```

If `src_valid_mark` stays 0, look in the client log for
`could not set net.ipv4.conf.all.src_valid_mark` (the service may lack
permission to write it).

### "rekey giving up after 9 retries — tearing down"

REKEY_ACK never reached the initiator. Check the peer log for
"rekey completed as responder" — if missing, the server never
processed the INIT (network drop). If present, the ACK was dropped in
the reverse direction. The session ends on purpose; a client keeps the
kill switch up and makes a new handshake by itself (§7i).

### "DNS resolve failed for qname-tag=<hex>"

Server's upstream DoH/DoT provider failed or pin mismatch.
Temporarily set `debug_dns = true` to log the plaintext qname (then
flip it off). Re-check the SPKI pin against the provider's live cert
(§3a.1).

`qname-tag=<hex>` stands for the DNS name: 16 hex characters of a keyed
hash, so a log reader cannot look the name up. The same name keeps the
same tag while dsm runs. The key is new at every restart, so a tag from
before a restart does not match tags after it. (Older versions logged
`qname-sha256=<hex>`, a plain hash.)

### Server log: "cannot listen on UDP port 51820: Address already in use; exiting"

The server could not open its listen port at startup, so it exits with
status 1. systemd starts it again after `RestartSec` (10 s in the unit
file) and gives up after 5 failed starts in 10 minutes. With
`transport = "tcp"` the same line says TCP. Another program holds the
port. Find it, then stop it or change `listen_port` (and `server_port` on
the clients):

```sh
$ sudo ss -ulnp | grep ':51820 '        # for TCP: sudo ss -tlnp
```

If the reason at the end of the line is "Permission denied" or "Operation
not permitted", the daemon is missing a privilege (the unit file runs it
as root with CAP_NET_ADMIN and CAP_NET_BIND_SERVICE). After you fix the
cause, clear the start limit and start again:

```sh
$ sudo systemctl reset-failed dsm
$ sudo systemctl start dsm
```

### "config: dns_provider_pins has entries that are not in dns_providers: ..."

The names after the colon sit in the `[dns_provider_pins]` table but are not
listed in `dns_providers`. Usually they are settings that were added below
the `[dns_provider_pins]` header: TOML reads every line under a header as
part of that table (`dsm init` writes the table last). Move those lines
above the header. If a name is meant as a pin, it must match a
`dns_providers` entry exactly: fix the spelling, add the provider to
`dns_providers`, or remove the pin. dsm exits with status 2 before it
starts anything.

### Server log: "DNS proxy cannot bind \<tun-ip\>:53 — another resolver … is already bound there"

A host resolver (`unbound`, `systemd-resolved`, or `dnsmasq`) is listening
on the TUN address or on `0.0.0.0:53`, which blocks the dsm DNS proxy from
binding port 53 on the TUN IP. The daemon now surfaces this as a specific
actionable error (rather than a bare `OSError`).

Remedies (pick one):

1. Stop the conflicting service before starting dsm:

   ```sh
   $ sudo systemctl stop unbound           # or: systemd-resolved / dnsmasq
   $ sudo systemctl disable unbound        # prevent it from restarting
   ```

2. If you need the host resolver for other purposes, change the TUN address
   in config.toml so it no longer conflicts with the resolver's bind address.

To identify which process holds :53:

```sh
$ sudo ss -ulnp | grep ':53 '
```

### "DNS proxy listening on 10.8.0.1:53" but client can't resolve

- Client's resolv.conf wasn't updated, or the client-side kill switch
  is dropping the query. Check:

  ```sh
  $ cat /etc/resolv.conf
  $ sudo nft list tables | grep '^table inet dsm_'
  ```

- Server's local firewall blocks the DNS-proxy bind. Allow UDP 53 on
  10.8.0.1 (the TUN address).

### Server log: "DNS blocklist not loaded: ... The lists already in use stay."

The message names the file and says why. Fix it as it says: `chmod 600`
for a file, `chmod 700` for a folder, owner root
(`sudo chown root:root <file>`), a real file in place of a link, or fewer or
smaller lists (64 MiB per file, 2,000,000 names in all). One bad file stops
the whole new load, so lists you added or changed since the last good load
wait until it is fixed. dsm loads the lists within 5 minutes after the file
changes; nothing else to do. Until then it keeps the lists it had (none if
this happened at start, so only `use-application-dns.net` is blocked). It
warns once per change, not every 5 minutes.

### Server log: "DNS blocklist is on but has no names to block"

There is no list in `/opt/mtun/dns/block/` yet, or the lists hold no usable
lines. Usually the download did not run or failed:

```sh
$ sudo systemctl status dsm-blocklist-update.timer
$ sudo journalctl -u dsm-blocklist-update.service -n 20
$ sudo systemctl start dsm-blocklist-update        # run it now
```

`could not download <url>` means that host was down or refused; an older
copy, if any, stays. If the unit fails at once with "Read-only file system",
`/opt/mtun/dns` does not exist yet: make it with
`sudo install -d -m 0700 /opt/mtun/dns`, then start the unit again. If you do
not want a blocklist, set `dns_blocklist = false` (§7h).

### A site or app breaks: is the blocklist stopping it?

On the client:

```sh
$ dig +noall +comments +authority <name>
```

`status: NXDOMAIN` with `dsm.invalid.` in the authority section means the
DSM blocklist answered. Add the name to `/opt/mtun/dns/allow.txt` on the
server (§7h). dsm picks it up within 5 minutes; the device may remember the
old answer for 5 more minutes.

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

That is on purpose: after a crash the kill switch stays up (fail closed,
§7i). Start DSM again (it replaces the old tables), or take them down:

```sh
$ sudo dsm cleanup
```

By hand:

```sh
$ for t in dsm_killswitch_pre dsm_killswitch dsm_dns_leak dsm_server_ratelimit dsm_server_nat; do
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

## 12. Uninstall

```sh
$ sudo systemctl disable --now dsm                          # server
$ sudo systemctl disable --now dsm-blocklist-update.timer   # server
$ sudo systemctl disable --now dsm-client                   # client
$ sudo rm -rf /opt/mtun /etc/dsm /run/dsm
$ sudo /usr/bin/python3 -m pip uninstall --break-system-packages dsm   # if pip-installed
$ sudo rm -f /etc/systemd/system/dsm.service /etc/systemd/system/dsm-client.service
$ sudo rm /etc/systemd/system/dsm-blocklist-update.service \
      /etc/systemd/system/dsm-blocklist-update.timer \
      /usr/local/sbin/dsm-blocklist-update
$ sudo systemctl daemon-reload
```

Paranoid firewall / TUN reset (in case dsm wasn't shut down cleanly):

```sh
$ for t in dsm_killswitch_pre dsm_killswitch dsm_dns_leak dsm_server_ratelimit dsm_server_nat; do
      sudo nft delete table inet "$t" 2>/dev/null
  done
$ sudo ip link delete mtun0 2>/dev/null
$ sudo ip rule delete priority 10 2>/dev/null
$ sudo ip route flush table 100 2>/dev/null
$ for iface in $(ls /sys/class/net); do
      sudo sysctl -w "net.ipv6.conf.$iface.disable_ipv6=0" 2>/dev/null
  done
```

## 13. File Placement Reference

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
/run/dsm/server-endpoint.json         # client: last address of server_ip's name
/opt/mtun/dns/sources.txt             # server: DNS block list URLs (0o600)
/opt/mtun/dns/block/*.txt             # server: DNS block lists (0o600)
/opt/mtun/dns/allow.txt               # server: names never blocked (0o600)
/usr/local/sbin/dsm-blocklist-update  # server: block list download script
/etc/systemd/system/dsm-blocklist-update.{service,timer}  # daily download
/etc/systemd/system/dsm.service       # (optional) server unit
/etc/systemd/system/dsm-client.service  # (optional) client unit
```

## 14. CLI Reference

```
python3 -m dsm --mode {client,server}            Run the VPN
python3 -m dsm --config PATH                     Override config file path
python3 -m dsm --debug-net                       Emit JSON audit events on
                                                 the dsm.netaudit logger
python3 -m dsm --passphrase-fd N                 Read passphrase from FD N
python3 -m dsm --passphrase-env-file PATH        Read passphrase from a
                                                 0600-mode file at PATH
python3 -m dsm --stop-keeps-block                Client: Ctrl-C or SIGTERM
                                                 leaves the start-up kill
                                                 switch up (dsm-client.service
                                                 passes it)

python3 -m dsm enroll --csr-out PATH             Provision identity +
                                                 attest key, write a CSR
python3 -m dsm enroll --import CERT_PATH         Verify + persist a
                                                 CA-signed cert
python3 -m dsm enroll --cn CN [--role ROLE]      Override the derived CN
                                                 (default: dsm-<12 hex>-<role>)
python3 -m dsm enroll --role {client,server}     Set the role suffix when
                                                 --cn is not given

python3 -m dsm show-pubkey                       Print the local identity's
                                                 Noise static pubkey (hex)

python3 -m dsm cleanup                           Remove every DSM table, rule
                                                 and setting (gets the host
                                                 back after a crash)
```
