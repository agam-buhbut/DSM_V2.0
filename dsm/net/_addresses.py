"""The tunnel's address contract.

Wire v2 (spec §7.7): the last handshake frame, the bootstrap reply, tells
the client its tunnel address, the server's tunnel address (also the
client's DNS server) and the prefix length. The client takes them from
there and assumes none of them. The server gives each allowlisted CN the
address of its line (``dsm.net.session_slot.SessionTable``); it binds its own
TUN to ``SERVER_TUN_IP`` and its DNS proxy listens on ``SERVER_TUN_IP:53``.

Stdlib only: ``dsm cleanup`` imports this module through ``dsm.net.tunnel``
and must not need the Rust extension. Changing these values affects the
deployment guide and any nftables or captive-portal settings that name the
addresses.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import ClassVar

# The server's address inside the tunnel. Also the DNS-proxy bind IP and the
# DNS server the client is told to use.
SERVER_TUN_IP: str = "10.8.0.1"

# Consumers: dns_proxy.LocalDNSProxy (source-filter net) and
# tunnel.TunDevice.configure (netmask default).
TUN_PREFIX_LEN: int = 24

_PRIVATE_RANGES = tuple(
    ipaddress.IPv4Network(net)
    for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
# /31 and /32 leave no room for two hosts; wider than /16 would put a very
# large on-link route on the client's TUN.
_MIN_PREFIX = 16
_MAX_PREFIX = 30


def _check(
    client: ipaddress.IPv4Address, server: ipaddress.IPv4Address, prefix_len: int
) -> None:
    """The client's checks on a tunnel assignment (spec §7.7).

    Raises:
        ValueError: the assignment breaks one of them; the text says which.
    """
    if not _MIN_PREFIX <= prefix_len <= _MAX_PREFIX:
        raise ValueError(f"prefix length {prefix_len} is not between 16 and 30")
    if not any(client in net and server in net for net in _PRIVATE_RANGES):
        raise ValueError(f"{client} and {server} are not in one private range")
    network = ipaddress.IPv4Network((client, prefix_len), strict=False)
    if server not in network:
        raise ValueError(f"{server} is not in {network}")
    if client == server:
        raise ValueError(f"the client and the server both have {client}")
    for address in (client, server):
        if address in (network.network_address, network.broadcast_address):
            raise ValueError(f"{address} is not a host address of {network}")


@dataclass(frozen=True, slots=True)
class TunnelAssignment:
    """A client's place in the tunnel, as the bootstrap reply carries it.

    The constructor, ``to_bytes`` and ``from_bytes`` all run the client's
    checks, so a bad assignment can never be built or sent: the prefix is 16
    to 30; both addresses are in one private range and in one network of
    that prefix; neither is that network's network or broadcast address; and
    they differ. The server is authenticated by the time the client reads
    one, so the checks catch bugs and bad settings, not attacks.
    """

    client: ipaddress.IPv4Address
    server: ipaddress.IPv4Address
    prefix_len: int
    SIZE: ClassVar[int] = 9

    def __post_init__(self) -> None:
        _check(self.client, self.server, self.prefix_len)

    def to_bytes(self) -> bytes:
        """9 bytes: client (4, big-endian) ‖ server (4) ‖ prefix length (1)."""
        _check(self.client, self.server, self.prefix_len)
        return self.client.packed + self.server.packed + bytes([self.prefix_len])

    @classmethod
    def from_bytes(cls, data: bytes) -> TunnelAssignment:
        """Read the 9-byte field.

        Raises:
            ValueError: ``data`` is not 9 bytes, or a value fails a check.
        """
        if len(data) != cls.SIZE:
            raise ValueError(f"the field is {len(data)} bytes, not {cls.SIZE}")
        return cls(
            client=ipaddress.IPv4Address(data[0:4]),
            server=ipaddress.IPv4Address(data[4:8]),
            prefix_len=data[8],
        )


# server_handshake's tunnel when no admit_client hook gives one (tests);
# the first allowlist line's address.
SINGLE_CLIENT_TUNNEL: TunnelAssignment = TunnelAssignment(
    client=ipaddress.IPv4Address("10.8.0.2"),
    server=ipaddress.IPv4Address(SERVER_TUN_IP),
    prefix_len=TUN_PREFIX_LEN,
)
