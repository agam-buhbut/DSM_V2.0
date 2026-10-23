"""Server-only IPv4 forwarding, NAT and client isolation.

The server's data path is:
    client encrypted UDP -> server transport -> decrypt
                          -> server's TUN write (src=client_tun_ip, dst=internet)
                          -> *kernel forwards* (needs ip_forward=1)
                          -> *kernel SNATs* (MASQUERADE) onto the WAN interface
                          -> internet

Both pieces are off by default on Linux:
  * ``net.ipv4.ip_forward`` defaults to 0 (no forwarding).
  * Without MASQUERADE, replies are addressed to the client's TUN IP (each
    client's own address in 10.8.0.0/24), which is not routable on the
    public internet.

The NAT table also stops clients reaching each other through the TUN and
tags each client's flows (multi-client spec §3.2, §3.3). This module owns
all of it for the server's run, and reverts it on teardown.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
from collections.abc import Mapping

from dsm.core._validators import validate_tun_name
from dsm.core.sysctl import SysctlOverride
from dsm.net._addresses import SERVER_TUN_IP, TUN_PREFIX_LEN
from dsm.net.nftables import apply_ruleset, delete_tables

log = logging.getLogger(__name__)


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
        # Same interpolation hazard as MasqueradeManager: tun_name is spliced
        # into per-iface sysctl keys in apply(). Validate against the strict
        # DSM_TUN_NAME_RE so an attacker-controlled name cannot escape into
        # the sysctl path. None is allowed (those per-iface sysctls are
        # skipped) and is not validated.
        if tun_name is not None:
            validate_tun_name(tun_name)
        self._tun_name = tun_name
        self._sysctl = SysctlOverride()

    def apply(self) -> None:
        self._sysctl.set("net.ipv4.ip_forward", "1")
        # Stop the kernel from telling clients about "better" paths.
        self._sysctl.set("net.ipv4.conf.all.send_redirects", "0")
        self._sysctl.set("net.ipv4.conf.default.send_redirects", "0")
        # Belt-and-braces: also refuse to ACCEPT redirects from
        # the LAN side. nftables already drops them but a kernel that
        # honored a stale route table entry from before nft applied is
        # eliminated by this sysctl. Set on both `all` and `default` so
        # interfaces brought up after dsm started inherit the secure
        # default.
        self._sysctl.set("net.ipv4.conf.all.accept_redirects", "0")
        self._sysctl.set("net.ipv4.conf.default.accept_redirects", "0")
        self._sysctl.set("net.ipv4.conf.all.secure_redirects", "0")
        if self._tun_name:
            self._sysctl.set(f"net.ipv4.conf.{self._tun_name}.send_redirects", "0")
            self._sysctl.set(f"net.ipv4.conf.{self._tun_name}.accept_redirects", "0")
            self._sysctl.set(f"net.ipv4.conf.{self._tun_name}.rp_filter", "2")
            self._sysctl.set(f"net.ipv4.conf.{self._tun_name}.accept_local", "1")
        log.info("server forwarding subsystem active")

    def remove(self) -> None:
        self._sysctl.restore_all()


# The clients' tunnel network: a packet from it must come in on the TUN.
_CLIENTS_NET = ipaddress.IPv4Interface(f"{SERVER_TUN_IP}/{TUN_PREFIX_LEN}").network


def _flow_tag(cn: str) -> int:
    """The conntrack mark on ``cn``'s flows (multi-client spec §3.3): the
    first 4 bytes of SHA-256(CN), lowest bit set, so it is never 0, the mark
    of every flow nobody tagged."""
    return int.from_bytes(hashlib.sha256(cn.encode()).digest()[:4], "big") | 1


class MasqueradeManager:
    """Install the server's NAT table, ``dsm_server_nat``, in one atomic load:

    * MASQUERADE, so client traffic leaves under the server's public IP;
    * a forward chain that drops anything the kernel would forward from the
      TUN back into it, so clients cannot reach each other (spec §3.2);
    * per client, a flow tag: each new flow a client opens gets its CN's
      conntrack mark, and a forwarded packet to a client's address whose
      flow lacks that mark is dropped, so late replies to a former holder of
      the address never reach its new one (spec §3.3);
    * a prerouting drop of any packet with a tunnel source that did not come
      in on the TUN (roadmap 1.4), and a forward drop of packets into the
      TUN that belong to no flow (invalid or untracked), which the flow tags
      cannot see.

    Uses its own nftables table so it cleans up independently of the
    rate-limiter or kill-switch tables.
    """

    TABLE = "dsm_server_nat"

    def __init__(
        self, tun_name: str, *, clients: Mapping[str, str] | None = None
    ) -> None:
        validate_tun_name(tun_name)
        self._tun_name = tun_name
        # Tunnel address -> CN. The addresses go into the ruleset, so each
        # must be a plain IPv4 address (ValueError otherwise).
        self._clients = {
            str(ipaddress.IPv4Address(address)): cn
            for address, cn in (clients or {}).items()
        }
        self._applied = False

    @property
    def applied(self) -> bool:
        """Whether the table is loaded: True after an ``apply()`` that worked,
        until ``remove()``. ``apply()`` logs a failure and never raises, so
        the server reads this to stop when the load failed."""
        return self._applied

    def apply(self) -> None:
        tun = self._tun_name
        tags = "".join(
            f'        iifname "{tun}" ct state new ip saddr {address} '
            f"ct mark set {_flow_tag(cn):#010x}\n"
            f'        oifname "{tun}" ip daddr {address} '
            f"ct mark != {_flow_tag(cn):#010x} counter drop\n"
            for address, cn in sorted(self._clients.items())
        )
        # NAT runs on packets coming OUT of the box: everything that arrived
        # via the TUN and leaves elsewhere is SNATed to whichever WAN
        # interface the kernel picks. "add table" then "delete table" empties
        # a table a crashed run left behind, in the same atomic load: its old
        # flow tags would drop the replies of an address's new holder.
        ruleset = f"""add table inet {self.TABLE}
delete table inet {self.TABLE}
table inet {self.TABLE} {{
    chain prerouting {{
        type filter hook prerouting priority -150; policy accept;
        iifname != "{tun}" iifname != "lo" ip saddr {_CLIENTS_NET} counter drop
    }}
    chain postrouting {{
        type nat hook postrouting priority 100; policy accept;
        iifname "{tun}" oifname != "{tun}" masquerade
    }}
    chain forward {{
        type filter hook forward priority 0; policy accept;
        iifname "{tun}" oifname "{tun}" counter drop
        oifname "{tun}" ct state invalid,untracked counter drop
{tags}    }}
}}
"""
        try:
            apply_ruleset(ruleset, log_label=f"MASQUERADE for {self._tun_name}")
            self._applied = True
        except (RuntimeError, FileNotFoundError) as e:
            log.warning("MASQUERADE not applied; client traffic won't reach WAN: %s", e)

    def remove(self) -> None:
        if not self._applied:
            return
        delete_tables(self.TABLE)
        log.info("MASQUERADE removed")
        self._applied = False
