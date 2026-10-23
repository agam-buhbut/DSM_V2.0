"""dsm.net.session_router (multi-client spec §2.5, §2.9, §3.1, §3.2): the
inner checks, each session's UDP and TUN views, and the TUN router.
In-memory fakes; no sockets, no TUN device, no session keys."""

from __future__ import annotations

import ipaddress

import pytest

from dsm.net.session_router import Verdict, check_from_client

NETWORK = ipaddress.IPv4Network("10.8.0.0/24")
SERVER = ipaddress.IPv4Address("10.8.0.1")
OWN = ipaddress.IPv4Address("10.8.0.2").packed
IPV6 = bytes([0x60]) + bytes(15) + OWN + bytes(20)  # bytes 16-19: a client's address


def _ipv4(src: str, dst: str) -> bytes:
    """A 20-byte IPv4 header; the checks read only the version and the two
    addresses."""
    header = bytearray(20)
    header[0] = 0x45
    header[12:16] = ipaddress.IPv4Address(src).packed
    header[16:20] = ipaddress.IPv4Address(dst).packed
    return bytes(header)


@pytest.mark.parametrize(
    ("packet", "verdict"),
    [
        (IPV6, Verdict.NOT_IPV4),
        (b"", Verdict.NOT_IPV4),
        (_ipv4("10.8.0.2", "93.184.216.34")[:19], Verdict.NOT_IPV4),
        (_ipv4("10.8.0.3", "93.184.216.34"), Verdict.WRONG_SOURCE),
        (_ipv4("192.0.2.1", "93.184.216.34"), Verdict.WRONG_SOURCE),
        (_ipv4("10.8.0.2", "10.8.0.3"), Verdict.TO_ANOTHER_CLIENT),
        (_ipv4("10.8.0.2", "10.8.0.0"), Verdict.TO_ANOTHER_CLIENT),
        (_ipv4("10.8.0.2", "10.8.0.255"), Verdict.TO_ANOTHER_CLIENT),
        (_ipv4("10.8.0.2", "10.8.0.1"), Verdict.OK),  # the server: DNS, ping
        (_ipv4("10.8.0.2", "93.184.216.34") + b"payload", Verdict.OK),
        (_ipv4("10.8.0.2", "10.9.0.5"), Verdict.OK),  # outside the tunnel net
    ],
)
def test_check_from_client(packet: bytes, verdict: Verdict) -> None:
    assert check_from_client(packet, OWN, SERVER.packed, NETWORK) is verdict
