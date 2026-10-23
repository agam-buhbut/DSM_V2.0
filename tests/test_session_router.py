"""dsm.net.session_router (multi-client spec §2.5, §2.9, §3.1, §3.2): the
inner checks, each session's UDP and TUN views, and the TUN router.
In-memory fakes; no sockets, no TUN device, no session keys."""

from __future__ import annotations

import asyncio
import ipaddress
import logging

import pytest

from dsm.crypto.handshake import VerifiedClient
from dsm.net.session_router import (
    ClientTun,
    Verdict,
    _SessionUDPView,
    check_from_client,
)
from dsm.net.session_slot import SESSION_QUEUE_PACKETS, ServerSession, SessionTable
from dsm.net.transport.udp import UDPTransport
from dsm.net.tunnel import TunDevice

NETWORK = ipaddress.IPv4Network("10.8.0.0/24")
SERVER = ipaddress.IPv4Address("10.8.0.1")
OWN = ipaddress.IPv4Address("10.8.0.2").packed
IPV6 = bytes([0x60]) + bytes(15) + OWN + bytes(20)  # bytes 16-19: a client's address
A_PEER = ("198.51.100.7", 40000)
NEW_PEER = ("203.0.113.5", 51000)
CNS = ("dsm-a-client", "dsm-b-client", "dsm-c-client")


def _live(table: SessionTable, cn: str, number: int) -> ServerSession:
    """A session of ``cn`` that finished its handshake and is in ``table``."""
    client = VerifiedClient(cn=cn, noise_static=bytes([number]) * 32)
    attempt = object()
    table.admit(attempt, client)
    _, tunnel = table.confirm(attempt)
    session = ServerSession(
        number=number,
        client=client,
        tunnel=tunnel,
        session_keys=object(),  # nothing here reads keys
        transport=object(),
        shutdown=asyncio.Event(),
        tun_queue=asyncio.Queue(maxsize=SESSION_QUEUE_PACKETS),
        peer=("198.51.100.1", 40000 + number),
    )
    table.add(session)
    return session


def _lines(caplog: pytest.LogCaptureFixture) -> list[tuple[int, str]]:
    return [
        (r.levelno, r.getMessage())
        for r in caplog.records
        if r.name == "dsm.net.session_router"
    ]


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


class _SharedTun:
    """The shared TUN: records writes, or raises ``error``."""

    def __init__(self, error: OSError | None = None) -> None:
        self.written: list[bytes] = []
        self._error = error

    async def awrite(self, data: bytes) -> int:
        if self._error is not None:
            raise self._error
        self.written.append(data)
        return len(data)


async def test_client_tun_writes_only_what_the_client_may_send() -> None:
    shared = _SharedTun()
    tun = ClientTun(shared, _live(SessionTable(CNS), "dsm-a-client", 1), NETWORK)
    assert isinstance(tun, TunDevice)
    to_internet = _ipv4("10.8.0.2", "93.184.216.34")
    to_server = _ipv4("10.8.0.2", "10.8.0.1")
    for dropped in (
        _ipv4("10.8.0.3", "93.184.216.34"),  # another client's source
        _ipv4("10.8.0.2", "10.8.0.3"),  # to another client
        _ipv4("10.8.0.2", "10.8.0.255"),  # to the broadcast address
        IPV6,
        b"\x45" * 19,
    ):
        assert await tun.awrite(dropped) == 0
    assert await tun.awrite(to_internet) == len(to_internet)
    assert await tun.awrite(to_server) == len(to_server)
    assert shared.written == [to_internet, to_server]


async def test_a_wrong_source_logs_one_warning_with_the_cn_only(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger="dsm.net.session_router")
    tun = ClientTun(_SharedTun(), _live(SessionTable(CNS), "dsm-a-client", 1), NETWORK)
    for _ in range(3):  # one 10 s window: these run microseconds apart
        await tun.awrite(_ipv4("10.8.0.3", "93.184.216.34"))
    assert _lines(caplog) == [
        (
            logging.WARNING,
            "dropped a packet from client_cn=dsm-a-client whose source is not "
            "its tunnel address",
        )
    ]


async def test_client_to_client_logs_one_info_line_per_session(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger="dsm.net.session_router")
    table = SessionTable(CNS)
    a = ClientTun(_SharedTun(), _live(table, "dsm-a-client", 1), NETWORK)
    b = ClientTun(_SharedTun(), _live(table, "dsm-b-client", 2), NETWORK)
    for _ in range(2):
        await a.awrite(_ipv4("10.8.0.2", "10.8.0.3"))
        await b.awrite(_ipv4("10.8.0.3", "10.8.0.2"))
    assert _lines(caplog) == [
        (
            logging.INFO,
            f"dropped a packet from client_cn={cn} to another client "
            "(client-to-client traffic is blocked)",
        )
        for cn in ("dsm-a-client", "dsm-b-client")
    ]


async def test_client_tun_logs_a_non_ipv4_packet_at_debug(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger="dsm.net.session_router")
    tun = ClientTun(_SharedTun(), _live(SessionTable(CNS), "dsm-a-client", 1), NETWORK)
    for _ in range(2):  # one 10 s window
        assert await tun.awrite(IPV6) == 0
    assert _lines(caplog) == [
        (logging.DEBUG, "dropped a packet from client_cn=dsm-a-client that is not IPv4")
    ]


async def test_client_tun_reads_its_session_queue() -> None:
    session = _live(SessionTable(CNS), "dsm-a-client", 1)
    session.tun_queue.put_nowait(b"for a")
    assert await ClientTun(_SharedTun(), session, NETWORK).read() == b"for a"


async def test_a_tun_write_error_goes_up_to_its_session() -> None:
    """Not EAGAIN (the shared TUN drops that itself): the error ends this
    session only, as a TUN write error ends the session today."""
    session = _live(SessionTable(CNS), "dsm-a-client", 1)
    tun = ClientTun(_SharedTun(OSError(5, "EIO")), session, NETWORK)
    with pytest.raises(OSError):
        await tun.awrite(_ipv4("10.8.0.2", "93.184.216.34"))


def test_client_tun_cannot_change_the_mtu() -> None:
    session = _live(SessionTable(CNS), "dsm-a-client", 1)
    with pytest.raises(NotImplementedError):
        ClientTun(_SharedTun(), session, NETWORK).set_mtu(1280)
