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


class IPForwardingManager:
    """Toggles ``net.ipv4.ip_forward`` and remembers the original value."""

    def __init__(self) -> None:
        self._original: str | None = None

    def apply(self) -> None:
        try:
            self._original = IP_FORWARD_PATH.read_text().strip()
            if self._original != "1":
                IP_FORWARD_PATH.write_text("1\n")
            log.info("ip_forward enabled (was %s)", self._original)
        except OSError as e:
            log.warning("could not enable ip_forward: %s", e)
            self._original = None

    def remove(self) -> None:
        if self._original is None:
            return
        try:
            IP_FORWARD_PATH.write_text(f"{self._original}\n")
            log.info("ip_forward restored to %s", self._original)
        except OSError as e:
            log.warning("could not restore ip_forward: %s", e)
        self._original = None


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
