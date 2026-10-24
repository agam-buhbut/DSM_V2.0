"""nftables kill switch, DNS leak prevention, and host-hardening helpers."""

from __future__ import annotations

import importlib.resources as _res
import ipaddress
import logging
import subprocess
from collections.abc import Sequence
from pathlib import Path

from dsm.core import netaudit
from dsm.core._validators import validate_tun_name
from dsm.net.ntp_opening import NtpOpening
from dsm.net.transport._fwmark import SO_MARK_VALUE as FWMARK

log = logging.getLogger(__name__)


def _load_template(name: str) -> str:
    return (_res.files("dsm.net._templates") / name).read_text(encoding="utf-8")


TCP_TIMESTAMPS_PATH = Path("/proc/sys/net/ipv4/tcp_timestamps")


def _ip_proto(server_ip: str) -> str:
    """Return the nftables IP-family matcher for ``server_ip``: ``ip6`` or ``ip``."""
    return "ip6" if ipaddress.ip_address(server_ip).version == 6 else "ip"


def _nft_set(addresses: Sequence[str]) -> str:
    """One address as itself, more as an anonymous nft set."""
    if len(addresses) == 1:
        return addresses[0]
    return "{ " + ", ".join(addresses) + " }"


def apply_ruleset(rules: str, *, log_label: str) -> None:
    """Load a rendered nftables ruleset via ``nft -f -``.

    Raises ``RuntimeError`` on ``nft`` failure and re-raises
    ``FileNotFoundError`` when ``nft`` is not installed.
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
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.decode(errors="replace").strip()
        raise RuntimeError(f"{log_label} apply failed: {stderr}")


def delete_tables(*table_names: str) -> None:
    """Best-effort delete of inet tables. Silently ignores missing tables."""
    for name in table_names:
        try:
            subprocess.run(  # pylint: disable=subprocess-run-check  # best-effort delete
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
            self._original = (
                TCP_TIMESTAMPS_PATH.read_text().strip()
            )  # pylint: disable=unspecified-encoding
            TCP_TIMESTAMPS_PATH.write_text(
                "0\n"
            )  # pylint: disable=unspecified-encoding
            log.info("tcp_timestamps disabled (was %s)", self._original)
        except OSError as e:
            log.warning("could not disable tcp_timestamps: %s", e)
            self._original = None

    def remove(self) -> None:
        if self._original is None:
            return
        try:
            TCP_TIMESTAMPS_PATH.write_text(
                f"{self._original}\n"
            )  # pylint: disable=unspecified-encoding
            log.info("tcp_timestamps restored to %s", self._original)
        except OSError as e:
            log.warning("could not restore tcp_timestamps: %s", e)
        self._original = None


class PreHandshakeKillSwitch:
    """The client's start-up kill switch, also up between sessions.

    Allows only:
      * loopback
      * DHCP (so a roaming client can keep its lease)
      * DSM's own marked sockets to the server's addresses and port (UDP
        and TCP), and only the replies to them
      * while DSM looks a server name up (``resolvers``): its own marked
        query, as root, to those resolvers on port 53, and the replies
      * while a date problem holds the start (``ntp``): the time daemon's
        NTP to the servers its config names by IPv4 address, and the replies
      * inbound ICMP "fragmentation needed", for path-MTU discovery
    Everything else is dropped by the chains' default policy.

    ``server_ips`` is one address, a list (the fresh answer for a server
    name and the address a handshake proved before), or None/empty for a
    name not looked up yet: then there are no server lines at all.

    Upgraded to the full :class:`NFTablesManager` ruleset (which also
    handles the TUN interface, DNS leak prevention, etc.) atomically by
    `NFTablesManager.apply()` once the TUN device is up.

    ``apply()`` also replaces every client kill-switch table in the same
    commit: at start that removes one a crashed run left, and when a session
    ends it swaps the full kill switch back to this table, so the host is
    never without one.
    """

    TABLE_NAME = "dsm_killswitch_pre"
    # The client's kill-switch tables: this one and NFTablesManager's two.
    CLIENT_TABLES = (TABLE_NAME, "dsm_killswitch", "dsm_dns_leak")

    def __init__(
        self,
        server_ips: str | Sequence[str] | None,
        server_port: int,
        *,
        resolvers: Sequence[str] = (),
        ntp: NtpOpening | None = None,
    ) -> None:
        ips = [server_ips] if isinstance(server_ips, str) else list(server_ips or ())
        for ip in ips:
            ipaddress.ip_address(ip)  # raises on bad input
        if len({_ip_proto(ip) for ip in ips}) > 1:
            raise ValueError("server addresses must all be IPv4 or all IPv6")
        for address in (*resolvers, *(ntp.servers if ntp is not None else ())):
            # These rules are written with `ip`: IPv4 only.
            ipaddress.IPv4Address(address)
        if not (1 <= server_port <= 65535):
            raise ValueError(f"invalid server_port: {server_port}")
        self._server_ips = ips
        self._server_port = server_port
        self._resolvers = list(resolvers)
        self._ntp = ntp
        self._applied = False

    def apply(self) -> None:
        apply_ruleset(
            self._ruleset(),
            log_label="pre-handshake kill switch",
        )
        self._applied = True
        netaudit.emit(
            "nft_apply",
            tables=[self.TABLE_NAME],
            server_ip=",".join(self._server_ips),
            server_port=self._server_port,
            phase="pre_handshake",
            lookup=bool(self._resolvers),
            ntp=self._ntp is not None,
        )

    def remove(self) -> None:
        """Tear down the pre-handshake table. Idempotent."""
        if not self._applied:
            return
        delete_tables(self.TABLE_NAME)
        self._applied = False
        netaudit.emit(
            "nft_remove",
            tables=[self.TABLE_NAME],
            phase="pre_handshake",
        )

    def _ruleset(self) -> str:
        # "add" then "delete" removes a table whether or not it exists, in the
        # same transaction as the new one (nft 1.0.6 on Debian 12 has no
        # "destroy").
        replace = "".join(
            f"add table inet {name}\ndelete table inet {name}\n"
            for name in self.CLIENT_TABLES
        )
        return replace + self._render()

    def _render(self) -> str:
        # A line tagged SERVER, LOOKUP or NTP stays only while that opening
        # is on; the tag itself is cut.
        keep = {
            "{SERVER}": bool(self._server_ips),
            "{LOOKUP}": bool(self._resolvers),
            "{NTP}": self._ntp is not None,
        }
        lines: list[str] = []
        for line in _load_template("pre_handshake.conf").splitlines(keepends=True):
            tag = next((t for t in keep if t in line), None)
            if tag is None:
                lines.append(line)
            elif keep[tag]:
                lines.append(line.replace(tag, ""))
        text = "".join(lines).replace("{FWMARK}", f"{int(FWMARK):#x}")
        if self._server_ips:
            text = (
                text.replace("{SERVER_IPS}", _nft_set(self._server_ips))
                .replace("{SERVER_PORT}", str(int(self._server_port)))
                .replace("{IP_PROTO}", _ip_proto(self._server_ips[0]))
            )
        if self._resolvers:
            text = text.replace("{RESOLVERS}", _nft_set(self._resolvers))
        if self._ntp is not None:
            text = text.replace("{NTP_UID}", str(int(self._ntp.uid))).replace(
                "{NTP_SERVERS}", _nft_set(self._ntp.servers)
            )
        return text


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
        """Install the full kill switch + DNS-leak tables.

        Bundles the pre-handshake table teardown in the SAME `nft -f`
        transaction so there's no atomicity gap between "pre table goes
        away" and "full table is in place" — nft processes the whole
        ruleset as one commit.
        """
        rules = (
            f"delete table inet {PreHandshakeKillSwitch.TABLE_NAME}\n" + self._render()
        )
        try:
            apply_ruleset(rules, log_label="nftables kill switch")
        except RuntimeError:
            # The pre-handshake table may not exist (e.g. operator wired
            # apply() manually without the pre-handshake step). Retry
            # without the delete.
            apply_ruleset(
                self._render(),
                log_label="nftables kill switch",
            )
        netaudit.emit(
            "nft_apply",
            tables=["dsm_killswitch", "dsm_dns_leak"],
            tun_name=self._tun_name,
            server_ip=self._server_ip,
            server_port=self._server_port,
            phase="full",
        )

    def remove(self) -> None:
        delete_tables("dsm_killswitch", "dsm_dns_leak")
        log.info("nftables rules removed")
        netaudit.emit(
            "nft_remove",
            tables=["dsm_killswitch", "dsm_dns_leak"],
        )

    def _render(self) -> str:
        # The default-drop policy on the chain handles the complementary
        # AF: if the server is IPv6, the killswitch's `ip6 daddr SERVER`
        # accept rule fires for legitimate VPN traffic, while IPv4 packets to
        # the same port hit the chain's `policy drop`. Same logic mirrored for
        # IPv4 servers.
        ip_proto = _ip_proto(self._server_ip)
        validate_tun_name(self._tun_name)
        template = _load_template("nftables.conf")
        return (
            template.replace("{SERVER_IP}", self._server_ip)
            .replace("{SERVER_PORT}", str(int(self._server_port)))
            .replace("{TUN_NAME}", self._tun_name)
            .replace("{IP_PROTO}", ip_proto)
            .replace("{FWMARK}", f"{int(FWMARK):#x}")
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
        # Fail closed: handshake rate-limiting is the server's first line of
        # defense against unauthenticated flood/DoS. If the ruleset cannot be
        # installed (no nft, permission failure), apply_ruleset raises so the
        # caller aborts startup rather than serving unprotected.
        apply_ruleset(
            self._render(),
            log_label=f"server rate-limit (port {self._listen_port})",
        )
        self._applied = True
        netaudit.emit(
            "nft_apply",
            tables=["dsm_server_ratelimit"],
            listen_port=self._listen_port,
        )

    def remove(self) -> None:
        if not self._applied:
            return
        delete_tables("dsm_server_ratelimit")
        self._applied = False
        netaudit.emit("nft_remove", tables=["dsm_server_ratelimit"])

    def _render(self) -> str:
        return _load_template("server.conf").replace(
            "{SERVER_PORT}",
            str(int(self._listen_port)),
        )
