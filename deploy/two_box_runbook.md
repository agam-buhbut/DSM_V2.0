# DSM Two-Box Demo Runbook

End-to-end procedure for the Phase 2 demo: a server on home Wi-Fi (with a
router port-forward) and a client on a cellular hotspot, running
DSM-over-UDP across two real ISPs. This is the first time the codebase
is exercised against real kernel TUN, real `nft -f -`, real PMTU, and a
real shutdown — every prior integration test mocked one or more of those.

This runbook references three companion docs and assumes you've read them:

- [CA_RUNBOOK.md](CA_RUNBOOK.md) — offline CA setup + per-device enrollment
- [SMOKE_TEST.md](SMOKE_TEST.md) — single-host loopback sanity check
- [README.txt](../README.txt) — operator guide / config schema

---

## §0 Hardware ledger (your kit)

For the demo your minimum kit is **2 USB sticks + 2 Linux boxes + 1 air-gapped
laptop + 1 cellular hotspot**:

| Item | Purpose |
| ---- | ------- |
| **Stick A — CA storage** | Encrypted (LUKS); holds `dsm_ca.key`, the CA database, and a copy of `openssl-ca.cnf`. Lives in your safe. Mounts read-write only on the CA laptop and only when signing. |
| **Stick B — Transport** | Wiped (`shred -v`) between every walk. Carries CSRs in, signed certs out. Never mounted on anything except the CA laptop and the device being enrolled. |
| Server box | Linux on home Wi-Fi side. ISP-routable through a router port-forward. |
| Client box | Linux on cellular hotspot. Outbound only — no port-forward needed. |
| Air-gapped CA laptop | The Windows / live-OS machine. Boot a wiped Tails or Debian live ISO. WiFi physically disabled or removed. |
| Cellular hotspot | Provides the second ISP for the client. Phone tether or dedicated MiFi both work. |

**Production-only best practice (NOT required for this demo)**: a third
USB stick with a redundant CA storage backup, off-site. The CA root
private key is a single point of failure; if Stick A dies and you have
no backup, the entire fleet must be reissued under a new CA. For a demo
you can accept the risk; for shipping to your client, add the third
stick before go-live.

---

## §1 Topology

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

The server side is the "anchor" — it has the routable address. The
client is outbound-only. STUN/ICE for double-NAT is **explicitly out of
scope** for this demo; if both ends are behind NAT with no port-forward,
the demo will not work.

### Verify the server's reachability before going further

On the server box (BEFORE starting `dsm`):

```sh
# 1. What public IP do we look like?
curl -s https://ifconfig.co
# 2. Does the router forward UDP/51820 to us?
#    Open a simple UDP listener and have a friend / a phone tether
#    do `nc -u -v <public-ip> 51820` and type something. If the
#    listener prints what they typed, the forward is good.
nc -u -l 51820     # Ctrl-C when done
```

If the public IP is private (10/8, 172.16/12, 192.168/16) you're behind
carrier-grade NAT on the home side and a port-forward won't help — find
a different "home" with a real ISP-routable IP, or fall back to a
single-host loopback demo (see [SMOKE_TEST.md](SMOKE_TEST.md)).

---

## §2 Bootstrap the CA (one-time)

Walk [CA_RUNBOOK.md](CA_RUNBOOK.md) §1 on the air-gapped laptop. After
this step you have:

- `dsm_ca_root.pem` (public, can travel on Stick B alongside CSRs)
- a known-good SHA-256 fingerprint, printed and stored in your safe
- Stick A loaded with `ca/` directory, encrypted, in the safe

Walk the root cert to **both** the server and client boxes via Stick B
(re-wipe between each walk). Place at `/opt/mtun/dsm_ca_root.pem`,
mode `0o644`, owned by root. Cross-check the SHA-256 against the safe
copy on each box.

---

## §3 Per-host setup

Order: server first, then client. Doing it in this order means by the
time you bring the client up, the server's CN is known and you can put
it in the client's `expected_server_cn` config.

### §3a Server box

1. **Install** dsm per [README.txt](../README.txt) §1.

2. **Write the config** at `/opt/mtun/config.toml`. Start from the server
   block in `config.example.toml`. Critical fields:
   ```toml
   mode = "server"
   server_ip = "<server's public IP>"
   server_port = 51820
   listen_port = 51820
   key_file = "/opt/mtun/identity.key"
   cert_file = "/opt/mtun/device.crt"
   ca_root_file = "/opt/mtun/dsm_ca_root.pem"
   attest_key_file = "/opt/mtun/attest.key"
   allowed_cns_file = "/opt/mtun/allowed_cns.txt"
   transport = "udp"
   # Server is on stable home Wi-Fi — leave auto_mtu off; static
   # mtu = 1400 is correct for typical 1500-byte Ethernet uplinks.
   mtu = 1400
   pmtu_discover = false
   dns_providers = ["https://1.1.1.1/dns-query"]
   [dns_provider_pins]
   "https://1.1.1.1/dns-query" = ["<64-hex SPKI SHA-256>"]
   ```

3. **Enroll** per [CA_RUNBOOK.md](CA_RUNBOOK.md) §3:
   ```sh
   sudo python3 -m dsm --config /opt/mtun/config.toml \
       enroll --csr-out /tmp/dsm-csr-server.der --role server
   ```
   Record the printed CN (e.g. `dsm-a3f29c81-server`). Walk the CSR on
   Stick B to the CA laptop, sign with profile `dsm_server_leaf`, walk
   the cert back, then:
   ```sh
   sudo python3 -m dsm --config /opt/mtun/config.toml \
       enroll --import /tmp/dsm-cert-server.pem
   ```

4. **Empty allowlist** (populated in §3c after the client enrolls):
   ```sh
   sudo install -m 0600 -o root -g root /dev/null /opt/mtun/allowed_cns.txt
   ```

5. **Stash the passphrase** for non-interactive systemd starts:
   ```sh
   echo -n 'your-passphrase' | sudo install -m 0600 /dev/stdin /etc/dsm/passphrase
   ```

### §3b Client box

1. **Install** dsm per [README.txt](../README.txt) §1.

2. **Write the config**:
   ```toml
   mode = "client"
   server_ip = "<server's public IP>"
   server_port = 51820
   listen_port = 0
   key_file = "/opt/mtun/identity.key"
   cert_file = "/opt/mtun/device.crt"
   ca_root_file = "/opt/mtun/dsm_ca_root.pem"
   attest_key_file = "/opt/mtun/attest.key"
   expected_server_cn = "<server CN from §3a step 3>"
   transport = "udp"
   mtu = 1400
   # Cellular path MTU drifts on handover (Wi-Fi → LTE → 5G).
   # auto_mtu = true tracks PMTU drops and raises back hysteresis-gated.
   auto_mtu = true
   pmtu_discover = true
   ```

3. **Enroll**:
   ```sh
   sudo python3 -m dsm --config /opt/mtun/config.toml \
       enroll --csr-out /tmp/dsm-csr-client.der --role client
   ```
   Note the printed CN. Walk to CA, sign with `dsm_client_leaf`, walk
   back, import.

4. **Stash passphrase** as in §3a step 5.

### §3c Authorize the client on the server

On the **server**, add the client's CN to the allowlist:

```sh
echo 'dsm-XXXXXXXX-client' | sudo tee -a /opt/mtun/allowed_cns.txt
sudo chmod 0600 /opt/mtun/allowed_cns.txt
```

The current implementation reads the allowlist at startup; restart the
server after editing.

---

## §4 First connect

```sh
# Server
sudo systemctl start dsm     # or: sudo python3 -m dsm --mode server \
                             #         --passphrase-env-file /etc/dsm/passphrase

# Client
sudo python3 -m dsm --mode client \
    --passphrase-env-file /etc/dsm/passphrase
```

Expected client log lines (in order, within ~5 seconds):

```
... handshake complete (client) — server_cn=dsm-XXXXXXXX-server
... TUN mtun0 configured: 10.8.0.2/24 mtu=1400
... tunnel established
... kernel path MTU = 1392 (usable inner 1324)
... auto_mtu: lowered tun mtu 1400 -> 1324 (kernel pmtu=1392)    ← cellular
```

Expected server log lines:

```
... CN allowlist loaded (1 entries)
... server listening on port 51820 (udp)
... handshake complete (server) — client_cn=dsm-XXXXXXXX-client
... client connected (noise_static=<first16hex>)
```

If the client's `auto_mtu` line shows it lowering — that's the
adaptive loop catching cellular's smaller path MTU.

---

## §5 Acceptance test sequence

These are the seven Phase 2 acceptance criteria as runnable commands.
Run them in order on the **client** unless noted. Capture results.

### §5.1 — 30-minute browser session

```sh
# Open Firefox / Chromium pointed at any web property; let it run.
# Or scripted (no browser):
for i in $(seq 1 30); do
    curl -sS -o /dev/null -w "[%{time_total}s] %{http_code} via %{remote_ip}\n" \
        https://www.cloudflare.com/cdn-cgi/trace
    sleep 60
done | tee /tmp/dsm-30min.log
```

PASS: 30 lines, all HTTP 200, `remote_ip` matches the server's public
IP (or its CDN edge), no `curl: (x) ... timeout` lines.
FAIL: any disconnect → triage with §6.

### §5.2 — Server-IP attribution

```sh
curl -s https://www.cloudflare.com/cdn-cgi/trace | grep ^ip=
```

PASS: shows the **server's** public IP (or its CDN edge), NOT the
cellular operator's IP.
FAIL: shows your cellular IP → kill switch is broken or DNS is leaking.
Run §5.3 immediately.

### §5.3 — DNS leak

```sh
# Direct must time out (kill-switch nftables drop):
dig @8.8.8.8 example.com +time=3 +tries=1 || echo PASS-direct-timed-out

# Through the tunnel must succeed:
dig @10.8.0.1 example.com +short
```

PASS: direct query times out; `@10.8.0.1` returns A records.
FAIL: direct query returns a result → kill-switch DNS rules missing.

### §5.4 — IPv6 leak

```sh
# Should fail. If it succeeds, IPv6 is not being blocked.
curl -6 -m 5 https://ifconfig.co || echo "PASS-ipv6-blocked"
```

PASS: `curl: (28) Connection timed out` or similar.
FAIL: returns an IPv6 address → kernel `disable_ipv6` snapshot/restore
isn't holding through whatever just happened. Capture
`sysctl net.ipv6.conf.all.disable_ipv6` to confirm.

### §5.5 — Kill-switch SIGSTOP test

```sh
# In one terminal: hold a curl through the tunnel.
( while :; do curl -sS https://ifconfig.co || break; sleep 1; done; \
  echo egress-stopped-at-$(date +%T) ) &
LOOP_PID=$!

# Find the dsm pid and STOP it.
DSM_PID=$(pidof python3 | tr ' ' '\n' | head -1)
sudo kill -STOP "$DSM_PID"

# Wait 10s. The curl loop should hit the kill-switch and `break`.
sleep 10

# Resume.
sudo kill -CONT "$DSM_PID"

# The loop should NOT auto-resume — it broke on first failure. The
# session should however reconnect within ~30s. New traffic works:
sleep 30
curl -sS -m 5 https://ifconfig.co
```

PASS: while STOPped, no traffic egresses (the loop's `break` line is
in the log within 5-10s); after CONT + reconnect, traffic flows again.
FAIL: traffic continues during STOP → kill-switch is leaking.

### §5.6 — Systemd hardening score

On the **server** (or any host running dsm under systemd):

```sh
sudo systemd-analyze security dsm
```

PASS: top-line score < 4.0 (with the conservative subset shipped in
this Ship). After the strace audit step (§7), targeting < 3.0.

### §5.7 — Auto-MTU adaptation

```sh
sudo journalctl -u dsm | grep -E "auto_mtu|kernel path MTU"
```

PASS: at least one `auto_mtu: lowered tun mtu N -> M (kernel pmtu=K)`
line on the cellular client. Optionally a later `auto_mtu: raised tun
mtu` after a sustained better path. No flap (more than ~3 oscillations
in 5 minutes is suspicious).
FAIL: no `auto_mtu` lines on the cellular client AND
`pmtu_discover = true` in client config → `transport.get_path_mtu()` is
returning None. Kernel PMTU may not be enabled; see §6.

---

## §6 Triage by symptom

### Handshake never completes
- Server log shows nothing → router port-forward broken. Re-run the §1
  reachability check.
- Server log shows `client cert auth failed: ...` → CA mismatch on one
  side. SHA-256 the `dsm_ca_root.pem` on each box and the safe copy.
- Client log shows `server cert auth failed: ...` → server's cert was
  not signed by the CA the client is pinning, or the cert expired.
- `client CN not in allowlist` → §3c missed.

### Tunnel up but slow / hangs after seconds
- Path MTU. Check `journalctl -u dsm | grep mtu`. With `auto_mtu = true`
  the adapter should fix itself within `pmtu_check_interval_s` (default
  30 s). Without it, lower `mtu = 1400` to `mtu = 1280` and restart.

### `auto_mtu` never logs on the client
- `pmtu_discover = true` must be in the client config — without it, the
  kernel doesn't track per-path MTU and `IP_MTU` returns nothing.
- Cellular operator may strip ICMP frag-needed; PMTU stays at the link
  default. Workaround: lower `mtu` statically until packets stop
  fragmenting, or accept whatever `auto_mtu` does on the next handover.

### IPv6 leak under network change
- Capture `cat /run/dsm/ipv6_state.json` before and after a Wi-Fi → LTE
  handover. If keys differ (interfaces appeared / disappeared), the
  snapshot is stale — file an issue with both files attached.

### Kill-switch leaks during SIGSTOP
- `sudo nft list ruleset | grep -A4 'table inet dsm'` to verify the
  ruleset is still installed. STOP doesn't tear down nft tables; rules
  should persist while the process is frozen. If they're gone, something
  else removed them.

For deeper triage once Ship 2 lands, `--debug-net` will emit one JSON
event per state transition; capture with
`sudo journalctl -u dsm -o cat | grep dsm.netaudit > /tmp/demo.jsonl`.

---

## §7 Strace audit (gates the deferred systemd hardening flags)

The unit ships with a conservative hardening subset (see comments in
[deploy/dsm.service](dsm.service)). Two flags are deliberately left as
TODOs because they can break TUN/netlink in subtle ways:

- `RestrictNamespaces=true`
- `SystemCallFilter=...`

You enable them empirically by running this audit once on each box:

```sh
# 1. Stop the running daemon.
sudo systemctl stop dsm

# 2. Run dsm under strace through one full handshake + ~30 seconds of
#    real traffic. Do this with the cellular client connecting from
#    its real ISP, not a loopback test — some syscalls (e.g. PMTU
#    socket options) only fire on real paths.
sudo strace -f -e trace=%file,%network,%process -o /tmp/dsm-strace.log \
    timeout 60 python3 -m dsm --mode server \
    --passphrase-env-file /etc/dsm/passphrase

# 3. From the strace log, pull the unique syscall names actually used:
awk -F'(' '/^[0-9]+ +[a-z_]+\(/ {print $1}' /tmp/dsm-strace.log \
    | awk '{print $NF}' | sort -u > /tmp/dsm-syscalls.txt
wc -l /tmp/dsm-syscalls.txt
cat /tmp/dsm-syscalls.txt
```

Send `/tmp/dsm-syscalls.txt` to me. I produce a `SystemCallFilter=`
allowlist line and a hardened version of `dsm.service`. Then we test
`RestrictNamespaces=true` empirically: enable it, restart, run §5
acceptance tests; if `dsm` fails to open `/dev/net/tun` or netlink, we
drop it with a comment in the unit.

After the audit, expected `systemd-analyze security dsm` < 3.0.

---

## §8 What to capture and send back

For each demo run, archive:

- `journalctl -u dsm` from server and client (full session)
- `nft list ruleset` after the session is established
- `ip rule`, `ip route show table 100` from both
- The Cloudflare trace output from §5.2
- `systemd-analyze security dsm` output
- Any `/tmp/dsm-strace.log` or `/tmp/dsm-syscalls.txt` from §7

Ship 2 will add `--debug-net` JSON; once it's in, the JSON stream
becomes the primary artifact and the above grep-based capture becomes
the fallback for older deployments.
