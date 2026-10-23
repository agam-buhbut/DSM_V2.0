"""Where each packet goes when one server serves several clients
(multi-client spec §2.5, §2.9, §3.1, §3.2).

Nothing here opens a packet: only its session does, once.
"""

from __future__ import annotations

import enum
import ipaddress

# The shortest IPv4 header.
_IPV4_HEADER_LEN = 20


class Verdict(enum.Enum):
    """What :func:`check_from_client` says about a client's packet."""

    OK = enum.auto()
    NOT_IPV4 = enum.auto()
    WRONG_SOURCE = enum.auto()
    TO_ANOTHER_CLIENT = enum.auto()


def check_from_client(
    packet: bytes, own: bytes, server: bytes, network: ipaddress.IPv4Network
) -> Verdict:
    """Whether a packet a client sent may go to the TUN (spec §3.1).

    ``own`` and ``server`` are 4 raw address bytes: the client's tunnel
    address and the server's. The key that opened the packet decides which
    inner source it may carry, so no client can send as another (cryptokey
    routing). A destination inside ``network`` other than the server is
    another client, the network address or the broadcast address:
    client-to-client traffic is blocked (spec §3.2). Inner IPv6 is dropped;
    clients send none. Never raises.
    """
    if len(packet) < _IPV4_HEADER_LEN or packet[0] >> 4 != 4:
        return Verdict.NOT_IPV4
    if packet[12:16] != own:
        return Verdict.WRONG_SOURCE
    destination = packet[16:20]
    if destination != server and ipaddress.IPv4Address(destination) in network:
        return Verdict.TO_ANOTHER_CLIENT
    return Verdict.OK
