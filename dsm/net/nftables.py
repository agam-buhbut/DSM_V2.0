"""nftables kill switch, DNS leak prevention, and host-hardening helpers."""

from __future__ import annotations

import ipaddress
import logging
import re
import subprocess
from pathlib import Path

log = logging.getLogger(__name__)

TEMPLATE_PATH = Path(__file__).parent.parent.parent / "nftables" / "nftables.conf"
SERVER_TEMPLATE_PATH = Path(__file__).parent.parent.parent / "nftables" / "server.conf"
TCP_TIMESTAMPS_PATH = Path("/proc/sys/net/ipv4/tcp_timestamps")


def _apply_ruleset(rules: str, *, fatal: bool, log_label: str) -> bool:
    """Load a rendered nftables ruleset via ``nft -f -``.

    When ``fatal`` is true, a failure raises ``RuntimeError``; otherwise it
    logs at WARNING and returns False. Returns True on success.
    """
    try:
        subprocess.run(
            ["nft", "-f", "-"],
            input=rules.encode(),
            check=True,
            capture_output=True,
            timeout=5,
        )
        log.info("%s applied", log_label)
        return True
    except FileNotFoundError:
        if fatal:
            raise
        log.warning("nft not installed; skipping %s", log_label)
        return False
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.decode(errors="replace").strip()
        if fatal:
            raise RuntimeError(f"{log_label} apply failed: {stderr}")
        log.warning("%s apply failed: %s", log_label, stderr)
        return False


def _delete_tables(*table_names: str) -> None:
    """Best-effort delete of inet tables. Silently ignores missing tables."""
    for name in table_names:
        try:
            subprocess.run(
                ["nft", "delete", "table", "inet", name],
                capture_output=True,
                timeout=5,
            )
        except (FileNotFoundError, subprocess.SubprocessError):
            pass


class TcpTimestampsDisabler:
    """Disable ``net.ipv4.tcp_timestamps`` while the VPN is up.

    TCP timestamps leak per-host clock skew, enough to re-identify a host
    across sessions even through a VPN. Best-effort: hardened systems may
    deny the sysctl write.
    """

    def __init__(self) -> None:
        self._original: str | None = None

    def apply(self) -> None:
        try:
            self._original = TCP_TIMESTAMPS_PATH.read_text().strip()
            TCP_TIMESTAMPS_PATH.write_text("0\n")
            log.info("tcp_timestamps disabled (was %s)", self._original)
        except OSError as e:
            log.warning("could not disable tcp_timestamps: %s", e)
            self._original = None

    def remove(self) -> None:
        if self._original is None:
            return
        try:
            TCP_TIMESTAMPS_PATH.write_text(f"{self._original}\n")
            log.info("tcp_timestamps restored to %s", self._original)
        except OSError as e:
            log.warning("could not restore tcp_timestamps: %s", e)
        self._original = None


class NFTablesManager:
    """Apply and remove nftables kill switch rules."""

    def __init__(
        self,
        server_ip: str,
        server_port: int,
        tun_name: str = "mtun0",
    ) -> None:
        self._server_ip = server_ip
        self._server_port = server_port
        self._tun_name = tun_name

    def apply(self) -> None:
        from dsm.core import netaudit
        _apply_ruleset(self._render(), fatal=True, log_label="nftables kill switch")
        netaudit.emit(
            "nft_apply",
            tables=["dsm_killswitch", "dsm_dns_leak"],
            tun_name=self._tun_name,
            server_ip=self._server_ip,
            server_port=self._server_port,
        )

    def remove(self) -> None:
        from dsm.core import netaudit
        _delete_tables("dsm_killswitch", "dsm_dns_leak")
        log.info("nftables rules removed")
        netaudit.emit(
            "nft_remove",
            tables=["dsm_killswitch", "dsm_dns_leak"],
        )

    def _render(self) -> str:
        ipaddress.ip_address(self._server_ip)
        if not re.match(r'^[a-zA-Z0-9_-]{1,15}$', self._tun_name):
            raise ValueError(f"invalid tun_name: {self._tun_name!r}")
        template = TEMPLATE_PATH.read_text()
        return (
            template
            .replace("{SERVER_IP}", self._server_ip)
            .replace("{SERVER_PORT}", str(int(self._server_port)))
            .replace("{TUN_NAME}", self._tun_name)
        )


class ServerRateLimitManager:
    """Server-side handshake-flood rate limiter via nftables.

    Drops new connections on the listen port over 20/s (burst 40);
    established flows are unaffected. Best-effort.
    """

    def __init__(self, listen_port: int) -> None:
        if not (1 <= listen_port <= 65535):
            raise ValueError(f"invalid listen_port: {listen_port}")
        self._listen_port = listen_port
        self._applied = False

    def apply(self) -> None:
        from dsm.core import netaudit
        self._applied = _apply_ruleset(
            self._render(), fatal=False,
            log_label=f"server rate-limit (port {self._listen_port})",
        )
        if self._applied:
            netaudit.emit(
                "nft_apply",
                tables=["dsm_server_ratelimit"],
                listen_port=self._listen_port,
            )

    def remove(self) -> None:
        if not self._applied:
            return
        from dsm.core import netaudit
        _delete_tables("dsm_server_ratelimit")
        self._applied = False
        netaudit.emit("nft_remove", tables=["dsm_server_ratelimit"])

    def _render(self) -> str:
        return SERVER_TEMPLATE_PATH.read_text().replace(
            "{SERVER_PORT}", str(int(self._listen_port)),
        )
