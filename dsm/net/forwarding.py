"""Server-only IPv4 forwarding + NAT/MASQUERADE setup.

The server's data path is:
    client encrypted UDP -> server transport -> decrypt
                          -> server's TUN write (src=client_tun_ip, dst=internet)
                          -> *kernel forwards* (needs ip_forward=1)
                          -> *kernel SNATs* (MASQUERADE) onto the WAN interface
                          -> internet

Both pieces are off by default on Linux:
  * ``net.ipv4.ip_forward`` defaults to 0 (no forwarding).
  * Without MASQUERADE, replies are addressed to the client's TUN IP
    (10.8.0.2/24) which is not routable on the public internet.

This module owns enabling those two for the duration of the server
session, and reverting on teardown.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

log = logging.getLogger(__name__)

IP_FORWARD_PATH = Path("/proc/sys/net/ipv4/ip_forward")


def _sysctl_path(key: str) -> Path:
    return Path("/proc/sys") / key.replace(".", "/")


class IPForwardingManager:
    """Configure kernel for VPN forwarding and remember every value we touch.

    Beyond ``net.ipv4.ip_forward``, two sysctls cause subtle breakage when
    left at their defaults:

    * ``send_redirects=1`` — server sends ICMP Redirect Host to the client
      (e.g. "use 8.8.8.8 directly"), which makes the client bypass the
      tunnel entirely. Common symptom: ``ping`` through the tunnel fails
      with "Redirect Host (New nexthop: ...)".
    * ``rp_filter=1`` (strict) — drops packets whose reverse path doesn't
      match. With a TUN whose peer is on a different subnet than any
      physical interface, this can drop legitimate decrypted packets.
      Loose mode (``2``) is the right setting for asymmetric/VPN paths.
    """

    def __init__(self, tun_name: str | None = None) -> None:
        self._tun_name = tun_name
        self._original: dict[str, str] = {}

    def _set(self, key: str, value: str) -> None:
        path = _sysctl_path(key)
        try:
            current = path.read_text().strip()
            if current != value:
                path.write_text(f"{value}\n")
                self._original[key] = current
                log.info("sysctl %s: %s -> %s", key, current, value)
        except OSError as e:
            log.warning("could not set %s=%s: %s", key, value, e)

    def apply(self) -> None:
        self._set("net.ipv4.ip_forward", "1")
        # Stop the kernel from telling clients about "better" paths.
        self._set("net.ipv4.conf.all.send_redirects", "0")
        self._set("net.ipv4.conf.default.send_redirects", "0")
        # Loose reverse-path filtering for asymmetric tunnel paths.
        self._set("net.ipv4.conf.all.rp_filter", "2")
        if self._tun_name:
            self._set(f"net.ipv4.conf.{self._tun_name}.send_redirects", "0")
            self._set(f"net.ipv4.conf.{self._tun_name}.rp_filter", "2")
            self._set(f"net.ipv4.conf.{self._tun_name}.accept_local", "1")
        log.info("server forwarding subsystem active")

    def remove(self) -> None:
        for key, value in self._original.items():
            try:
                _sysctl_path(key).write_text(f"{value}\n")
                log.info("sysctl %s restored to %s", key, value)
            except OSError as e:
                log.warning("could not restore %s: %s", key, e)
        self._original.clear()


class MasqueradeManager:
    """Install a single inet/nat MASQUERADE rule so server-routed traffic
    leaves under the server's public IP.

    Uses its own nftables table (``dsm_server_nat``) so it cleans up
    independently of the rate-limiter or kill-switch tables.
    """

    TABLE = "dsm_server_nat"

    def __init__(self, tun_name: str) -> None:
        self._tun_name = tun_name
        self._applied = False

    def apply(self) -> None:
        # NAT runs on packets coming OUT of the box. The packet's input
        # interface is the TUN (where decrypted client traffic is
        # written); its output interface is whatever the kernel routes it
        # to (eth0/wlan0/etc.). We MASQUERADE everything that arrived via
        # the TUN — that gives us a clean SNAT to whichever WAN interface
        # the kernel picks.
        ruleset = f"""
table inet {self.TABLE} {{
    chain postrouting {{
        type nat hook postrouting priority 100; policy accept;
        iifname "{self._tun_name}" oifname != "{self._tun_name}" masquerade
    }}
}}
"""
        try:
            subprocess.run(
                ["nft", "-f", "-"],
                input=ruleset.encode(),
                check=True,
                capture_output=True,
                timeout=5,
            )
            self._applied = True
            log.info("MASQUERADE for %s applied", self._tun_name)
        except FileNotFoundError:
            log.warning("nft not installed; client traffic won't reach the internet")
        except subprocess.CalledProcessError as e:
            stderr = e.stderr.decode(errors="replace").strip()
            log.warning("MASQUERADE apply failed: %s", stderr)

    def remove(self) -> None:
        if not self._applied:
            return
        try:
            subprocess.run(
                ["nft", "delete", "table", "inet", self.TABLE],
                capture_output=True,
                timeout=5,
            )
            log.info("MASQUERADE removed")
        except (FileNotFoundError, subprocess.SubprocessError):
            pass
        self._applied = False
