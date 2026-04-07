"""nftables kill switch and DNS leak prevention manager."""

from __future__ import annotations

import ipaddress
import logging
import re
import subprocess
from pathlib import Path

log = logging.getLogger(__name__)

TEMPLATE_PATH = Path(__file__).parent.parent.parent / "nftables" / "nftables.conf"


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
        self._active = False

    def apply(self) -> None:
        """Apply kill switch and DNS leak prevention rules."""
        rules = self._render()
        try:
            subprocess.run(
                ["nft", "-f", "-"],
                input=rules.encode(),
                check=True,
                capture_output=True,
                timeout=5,
            )
            self._active = True
            log.info("nftables kill switch applied")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(
                f"nftables apply failed: {e.stderr.decode()}"
            )

    def remove(self) -> None:
        """Remove kill switch rules (best-effort)."""
        for table in ("dsm_killswitch", "dsm_dns_leak"):
            try:
                subprocess.run(
                    ["nft", "delete", "table", "inet", table],
                    capture_output=True,
                    timeout=5,
                )
            except Exception:
                pass
        self._active = False
        log.info("nftables rules removed")

    @property
    def is_active(self) -> bool:
        return self._active

    def _render(self) -> str:
        """Render nftables rules from template with substitutions."""
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
