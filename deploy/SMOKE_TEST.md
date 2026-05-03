# DSM VPN — Single-Host Loopback Smoke Test

A manual runbook for bringing a DSM client ↔ server pair up on a **single
Linux host** as a sanity check before crossing real ISPs. Two `dsm`
processes (one per network namespace, or one host + one VM on the same
LAN) run client and server against each other.

> **Doing the real two-box demo over different ISPs?** See
> [two_box_runbook.md](two_box_runbook.md) — that's the Phase 2 procedure.
> This file is the prerequisite sanity check you run first to confirm the
> code builds, certs validate, and the data path works under ideal
> conditions, before introducing real-network failure modes.

## 0. Prerequisites (both hosts)

- Linux kernel ≥ 5.x with TUN/TAP support (`modprobe tun`)
- Python 3.11+
- Rust stable toolchain (`rustup install stable`)
- `nftables` (`nft` binary on PATH)
- `CAP_NET_ADMIN` and `CAP_SYS_ADMIN` — easiest is root, otherwise see the
  systemd unit at `deploy/dsm.service` for capability setup
- Ports reachable server-to-client on UDP (or TCP) `listen_port` (default
  `51820`)

## 1. Build on both hosts

```sh
cd DSM_V2.0
python3 -m pip install --user maturin
cd rust/tuncore && maturin develop --release
# Verify:
python3 -c "import tuncore; print(tuncore.__name__, 'ok')"
```

## 2. Configure the server

```sh
sudo mkdir -p /opt/mtun
sudo tee /opt/mtun/config.toml <<'EOF'
mode = "server"
server_ip = "10.0.0.5"          # this host's public address
server_port = 51820              # port clients will connect to
listen_port = 51820
key_file = "/opt/mtun/identity.key"
cert_file = "/opt/mtun/device.crt"
ca_root_file = "/opt/mtun/dsm_ca_root.pem"
attest_key_file = "/opt/mtun/attest.key"
# crl_file = "/opt/mtun/dsm_ca.crl"   # optional
allowed_cns_file = "/opt/mtun/allowed_cns.txt"
transport = "udp"

# DoH provider + pinned SPKI SHA-256 (example — replace with your pin).
dns_providers = ["https://1.1.1.1/dns-query"]
[dns_provider_pins]
"https://1.1.1.1/dns-query" = ["<64-hex SPKI SHA-256>"]
EOF
```

Place the pinned CA root cert (per `deploy/CA_RUNBOOK.md`) at
`/opt/mtun/dsm_ca_root.pem`. Cross-check its SHA-256 against the value
recorded in your physical safe.

## 3. First-run: enroll the server

```sh
# Generate identity + attest key, emit a CSR.
sudo python3 -m dsm --config /opt/mtun/config.toml \
    enroll --csr-out /tmp/dsm-csr-server.der --role server
# Enter a strong passphrase twice. /opt/mtun/identity.key and
# /opt/mtun/attest.key are written (mode 0o600).

# Walk /tmp/dsm-csr-server.der to the offline CA on a wiped USB,
# sign with profile `dsm_server_leaf` (CA_RUNBOOK.md §3b), walk
# the resulting cert back, then import:
sudo python3 -m dsm --config /opt/mtun/config.toml \
    enroll --import /tmp/dsm-cert-server.pem
# Verifies chain + binding + attest pubkey, writes /opt/mtun/device.crt.

# Stash the passphrase for non-interactive restarts:
sudo install -m 0600 /dev/stdin /etc/dsm/passphrase <<<"<your-passphrase>"

# Create an empty allowlist; populated in step 5.
sudo install -m 0600 -o root -g root /dev/null /opt/mtun/allowed_cns.txt
```

## 4. Configure + enroll the client

On the client host, mirror step 2 with `mode = "client"`, the server's
public IP, and `expected_server_cn = "<server CN from step 3>"`. Then:

```sh
sudo python3 -m dsm --config /opt/mtun/config.toml \
    enroll --csr-out /tmp/dsm-csr-client.der --role client
# Note the printed CN — record it.

# Walk CSR to CA, sign with `dsm_client_leaf` profile, walk back:
sudo python3 -m dsm --config /opt/mtun/config.toml \
    enroll --import /tmp/dsm-cert-client.pem
```

## 5. Add the client CN to the server allowlist

On the **server**:

```sh
echo 'dsm-XXXXXXXX-client' | sudo tee -a /opt/mtun/allowed_cns.txt
sudo chmod 0600 /opt/mtun/allowed_cns.txt
sudo systemctl restart dsm
```

## 6. Start both sides in production mode

Server:
```sh
sudo systemctl start dsm  # uses deploy/dsm.service
# or: sudo python3 -m dsm --mode server \
#       --passphrase-env-file /etc/dsm/passphrase
```

Client:
```sh
sudo python3 -m dsm --mode client \
    --passphrase-env-file /etc/dsm/passphrase
```

Expect in the client log:
- `tunnel established`
- no errors in the next 30 s

And in the server log:
- `client authorized: <first 16 hex>`
- `client connected`

## 7. Verification

On the **client**, from a second terminal:

```sh
# TUN interface exists and is up
ip link show mtun0
ip addr show mtun0
# Routing is pointed at TUN for everything except VPN traffic
ip rule
ip route show table 100

# DNS resolver is the server's TUN address
cat /etc/resolv.conf | head -2

# nftables kill switch is live
sudo nft list ruleset | grep -A3 'table inet dsm'

# DNS through the tunnel
dig @10.8.0.1 example.com +short
# Expect: one or more A records. Upstream resolution went DoH on the server.

# Fetch through the tunnel; watch that nothing goes out the physical iface.
# In one terminal:
sudo tcpdump -ni <your-physical-iface> 'host not <server-ip> and port not 51820' &
# In another:
curl -s https://example.com/ > /dev/null
# tcpdump output should be EMPTY — no leaks. Ctrl-C tcpdump.

# IPv6 should be disabled on non-TUN interfaces during the session
sysctl net.ipv6.conf.all.disable_ipv6   # expect 1
```

## 8. Graceful shutdown

Stop the client (Ctrl-C or `systemctl stop`). Within ~1 second the server
log should show:

```
… dsm.session: … shutdown set (received SESSION_CLOSE)
```

On both hosts:
```sh
ip link show mtun0              # no such device
ip rule show priority 10        # rule removed
sudo nft list ruleset | grep dsm  # no output
cat /etc/resolv.conf | head -2  # restored to pre-VPN nameserver
sysctl net.ipv6.conf.all.disable_ipv6  # expect 0 (restored)
```

Zero leftover state.

## 9. Failure drills

### 9a. Server crash (SIGKILL mid-session)

```sh
# on server:
pidof python3 | xargs sudo kill -9
# on client: watch the log for 60 s
```

Expect: the client detects dead peer after `DEAD_PEER_TIMEOUT` (~60 s) and
tears down the tunnel automatically.

### 9b. Client crash

```sh
# on client:
pidof python3 | xargs sudo kill -9
```

Expected host state on the client:
- `mtun0` is gone (kernel removes the TUN when the owning fd is closed)
- **nftables rules are still present** — crash-recovery for the nft
  ruleset is not implemented yet
- `resolv.conf` is still pointed at `10.8.0.1`
- `/run/dsm/ipv6_state.json` remains (next `dsm` start restores IPv6)

To clean up manually after a client SIGKILL:
```sh
sudo nft delete table inet dsm
sudo cp /etc/resolv.conf.dsm-backup /etc/resolv.conf
sudo python3 -m dsm --mode client ...  # the next normal start restores IPv6
```

### 9c. Identity rotation

The cert-based model removes the client-side TOFU cache. Within the
same CA + same expected_server_cn, the server can rotate its identity
freely (re-enroll, re-import) and clients keep working. If the server
CN changes, push the new value to every client's
`expected_server_cn` and restart them. See README.txt §7c.

## 10. Verdict criteria

The smoke test passes iff every command in §7 produces the expected
output AND the shutdown drill in §8 leaves no residue. If any of those
fail, diagnose — the test exists to catch real regressions.
