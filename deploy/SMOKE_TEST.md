# DSM VPN — Operational Smoke Test

A manual runbook for bringing a DSM client ↔ server pair up on real hosts
and verifying it works end-to-end. Assumes two Linux boxes (or VMs): one
**server** (public IP) and one **client** (anywhere that can reach it).

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
key_file = "/opt/mtun/identity.enc"
transport = "udp"

# Strict by default. Flip to false for TOFU bootstrap on first connect.
strict_client_auth = true

# DoH provider + pinned SPKI SHA-256 (example — replace with your pin).
dns_providers = ["https://1.1.1.1/dns-query"]
[dns_provider_pins]
"https://1.1.1.1/dns-query" = ["<64-hex SPKI SHA-256>"]
EOF
```

## 3. First-run: generate server identity + passphrase

```sh
# Interactive prompt (one-time identity generation).
sudo python3 -m dsm --mode server
# Enter a strong passphrase twice. The server will START and wait for
# connections. Ctrl-C once the log line "server listening on port 51820"
# appears.

# Stash the passphrase for non-interactive restarts:
sudo install -m 0600 /dev/stdin /etc/dsm/passphrase <<<"<your-passphrase>"
```

The identity is now encrypted at `/opt/mtun/identity.enc`.

## 4. Configure + generate client identity

On the client host, mirror step 2 with `mode = "client"` and the server's
public IP. Then:

```sh
sudo python3 -m dsm --mode client
# Passphrase prompt (client has its own identity). Ctrl-C after
# "handshake failed: client not authorized" in the log — that's expected
# on the first run; proceed to step 5.
```

## 5. Authorize the client on the server

On the **client**, print its public key:

```sh
sudo python3 -m dsm show-pubkey \
    --passphrase-env-file /etc/dsm/passphrase
# Copy the 64-char hex output.
```

On the **server**, add it to the allowlist:

```sh
sudo python3 -m dsm authorize <client-hex-pubkey> \
    --passphrase-env-file /etc/dsm/passphrase
# Expected: "Authorized client <prefix>... (1 total)"
```

**Alternative: TOFU bootstrap.** Set `strict_client_auth = false` in the
server config before the first client connects. The first client to complete
the handshake is added automatically. Flip back to `true` immediately
after — otherwise any future client pubkey replaces the trust anchor.

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

If the server's identity is rotated, clients' known_hosts caches are
invalidated. On each client:

```sh
sudo python3 -m dsm reset-trust --yes
```

Next connection re-TOFUs the server key. If `strict_keys=true` (default),
the client MUST have a fresh known_hosts file before reconnecting.

## 10. Verdict criteria

The smoke test passes iff every command in §7 produces the expected
output AND the shutdown drill in §8 leaves no residue. If any of those
fail, diagnose — the test exists to catch real regressions.
