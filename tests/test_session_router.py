"""dsm.net.session_router (multi-client spec §2.5, §2.9, §3.1, §3.2): the
inner checks, each session's UDP and TUN views, and the TUN router.
In-memory fakes; no sockets, no TUN device, no session keys."""

from __future__ import annotations

import ipaddress

import pytest

from dsm.net.session_router import Verdict, _SessionUDPView, check_from_client
from dsm.net.session_slot import SESSION_QUEUE_PACKETS
from dsm.net.transport.udp import UDPTransport

NETWORK = ipaddress.IPv4Network("10.8.0.0/24")
SERVER = ipaddress.IPv4Address("10.8.0.1")
OWN = ipaddress.IPv4Address("10.8.0.2").packed
IPV6 = bytes([0x60]) + bytes(15) + OWN + bytes(20)  # bytes 16-19: a client's address
A_PEER = ("198.51.100.7", 40000)
NEW_PEER = ("203.0.113.5", 51000)


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


class _Socket:
    """The run's UDP socket: records sends, has its own drop count."""

    def __init__(self) -> None:
        self.sent: list[tuple[bytes, tuple[str, int]]] = []
        self.drops = 0
        self.closed = False

    async def send(self, data: bytes, addr: tuple[str, int]) -> None:
        self.sent.append((data, addr))

    def recv_drops(self) -> int:
        return self.drops

    def close(self) -> None:
        self.closed = True


async def test_the_view_gives_each_packet_with_its_real_sender() -> None:
    view = _SessionUDPView(_Socket(), lambda: 0)
    assert isinstance(view, UDPTransport)
    assert view.deliver(b"one", A_PEER)
    assert view.deliver(b"two", NEW_PEER)
    assert await view.recv() == (b"one", A_PEER)
    assert await view.recv(timeout=1.0) == (b"two", NEW_PEER)


async def test_the_view_sends_to_the_address_it_is_given() -> None:
    run_socket = _Socket()
    view = _SessionUDPView(run_socket, lambda: 0)
    await view.send(b"to egress", A_PEER)
    await view.send(b"path challenge", NEW_PEER)
    assert run_socket.sent == [(b"to egress", A_PEER), (b"path challenge", NEW_PEER)]


def test_the_view_drops_count_the_socket_the_unmatched_and_its_own() -> None:
    run_socket = _Socket()
    run_socket.drops = 2
    view = _SessionUDPView(run_socket, lambda: 3)
    for _ in range(SESSION_QUEUE_PACKETS):
        assert view.deliver(b"x", A_PEER)
    assert not view.deliver(b"one too many", A_PEER)
    assert view.recv_drops() == 2 + 3 + 1


async def test_closing_the_view_leaves_the_run_socket_open() -> None:
    run_socket = _Socket()
    view = _SessionUDPView(run_socket, lambda: 0)
    view.close()
    await view.aclose()
    assert not run_socket.closed
    await view.send(b"still sends", A_PEER)
    assert view.deliver(b"still takes packets", A_PEER)
