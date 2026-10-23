"""UDPDispatcher (multi-client spec §2.5) and the header check it uses
(§6.1): each packet goes, unopened, to the session whose keys its header
fits; a packet no session fits goes to the acceptor. Real tuncore keys from
complete_bootstrap (random, so a wrong match is 1 in 2^31 per check, as on
the wire); no sockets."""

from __future__ import annotations

import asyncio
import logging

import pytest

import tuncore
from dsm.crypto.handshake import VerifiedClient
from dsm.net.session_router import UDPDispatcher, _SessionUDPView
from dsm.net.session_slot import SESSION_QUEUE_PACKETS, ServerSession, SessionTable


def _pair() -> tuple[tuncore.SessionKeyManager, tuncore.SessionKeyManager]:
    """(client keys, server keys) of one session."""
    client_eph = tuncore.BootstrapEphemeral.generate()
    server_eph = tuncore.BootstrapEphemeral.generate()
    client_pub = bytes(client_eph.public_key_bytes)
    server_pub = bytes(server_eph.public_key_bytes)
    client = tuncore.complete_bootstrap(client_eph, server_pub, is_initiator=True)
    server = tuncore.complete_bootstrap(server_eph, client_pub, is_initiator=False)
    return client, server


def _rotate(
    client: tuncore.SessionKeyManager, server: tuncore.SessionKeyManager
) -> None:
    """One key change; the server keeps its old receive keys for late packets.
    The ephemeral keys come back as lists of ints, hence ``bytes()``."""
    new_epoch, client_pub = client.initiate_rotation()
    server_pub, _ = server.prepare_rotation_responder(bytes(client_pub), new_epoch)
    server.apply_rotation_responder()
    client.complete_rotation_initiator(bytes(server_pub))


CNS = ("dsm-a-client", "dsm-b-client", "dsm-c-client")
A_PEER = ("198.51.100.7", 40000)
B_PEER = ("203.0.113.9", 51000)
NEW_PORT = ("203.0.113.9", 51999)
FRAME = bytes(1400)  # a handshake frame stand-in: fits no session's keys


class _Done(Exception):
    pass


class _Socket:
    """The run's UDP socket: recv() gives the listed packets, then raises
    _Done, so run() ends without waiting."""

    def __init__(self, packets: list[tuple[bytes, tuple[str, int]]]) -> None:
        self._packets = list(packets)

    async def recv(self, timeout: float | None = None) -> tuple[bytes, tuple[str, int]]:
        if not self._packets:
            raise _Done
        return self._packets.pop(0)

    async def send(self, data: bytes, addr: tuple[str, int]) -> None:
        del data, addr

    def recv_drops(self) -> int:
        return 0


class _Run:
    """A table, a dispatcher over a fake socket, and what it offered to the
    acceptor."""

    def __init__(
        self, packets: list[tuple[bytes, tuple[str, int]]] | None = None
    ) -> None:
        self.table = SessionTable(CNS)
        self.socket = _Socket(packets or [])
        self.offered: list[tuple[bytes, tuple[str, int]]] = []
        self.dispatcher = UDPDispatcher(
            self.socket,
            self.table,
            lambda data, addr: self.offered.append((data, addr)),
        )

    def connect(
        self, cn: str, peer: tuple[str, int], number: int, server_keys: object
    ) -> ServerSession:
        """A client of ``cn`` finished its handshake from ``peer``."""
        client = VerifiedClient(cn=cn, noise_static=bytes([number]) * 32)
        attempt = object()
        self.table.admit(attempt, client)
        _, tunnel = self.table.confirm(attempt)
        session = ServerSession(
            number=number,
            client=client,
            tunnel=tunnel,
            session_keys=server_keys,
            transport=_SessionUDPView(self.socket, lambda: self.dispatcher.unmatched),
            shutdown=asyncio.Event(),
            tun_queue=asyncio.Queue(maxsize=SESSION_QUEUE_PACKETS),
            peer=peer,
        )
        self.table.add(session)
        return session


def _view(session: ServerSession) -> _SessionUDPView:
    view = session.transport
    assert isinstance(view, _SessionUDPView)
    return view


def _queued(session: ServerSession) -> list[tuple[bytes, tuple[str, int]]]:
    """Everything on the session's view queue, in order."""
    queue = _view(session)._queue
    packets: list[tuple[bytes, tuple[str, int]]] = []
    while not queue.empty():
        packets.append(queue.get_nowait())
    return packets


class _Keys:
    """Fake session keys: the header check passes for the packets in ``own``,
    and records every check."""

    def __init__(self, *own: bytes) -> None:
        self.own = set(own)
        self.checked: list[bytes] = []

    def header_matches(self, wire: bytes) -> bool:
        self.checked.append(wire)
        return wire in self.own


def test_the_header_check_fits_only_its_own_keys() -> None:
    client, server = _pair()
    other, _ = _pair()
    wire = client.seal_packet(1, b"hello")
    assert server.header_matches(wire)
    assert not server.header_matches(other.seal_packet(1, b"hello"))
    assert not server.header_matches(server.seal_packet(1, b"other direction"))
    assert not server.header_matches(wire[:35])  # shorter than header and tag


def test_the_header_check_fits_the_previous_key_set_too() -> None:
    client, server = _pair()
    old = client.seal_packet(1, b"old keys")
    _rotate(client, server)
    new = client.seal_packet(2, b"new keys")
    assert server.header_matches(new)
    assert server.header_matches(old)


def test_the_header_check_changes_nothing() -> None:
    client, server = _pair()
    wire = client.seal_packet(1, b"hello")
    for _ in range(3):
        assert server.header_matches(wire)
    opened = server.open_packet(wire)
    assert opened is not None
    assert opened[1] == b"hello"
    assert server.open_packet(wire) is None  # opened once: now a replay


def test_a_packet_from_the_hint_address_reaches_its_holder() -> None:
    run = _Run()
    a_keys, a_server = _pair()
    a = run.connect("dsm-a-client", A_PEER, 1, a_server)
    b = run.connect("dsm-b-client", B_PEER, 2, _pair()[1])
    wire = a_keys.seal_packet(1, b"to the server")
    run.dispatcher.route(wire, A_PEER)
    assert _queued(a) == [(wire, A_PEER)]
    assert _queued(b) == []
    assert run.offered == []
    assert run.dispatcher.unmatched == 0


def test_the_hint_holder_is_checked_first_and_alone() -> None:
    run = _Run()
    a_keys, b_keys = _Keys(b"fits both"), _Keys(b"fits both")
    run.connect("dsm-a-client", A_PEER, 1, a_keys)
    b = run.connect("dsm-b-client", B_PEER, 2, b_keys)
    run.dispatcher.route(b"fits both", B_PEER)
    assert _queued(b) == [(b"fits both", B_PEER)]
    assert a_keys.checked == []  # one header check for a hinted packet


def test_a_packet_from_another_address_reaches_its_own_session() -> None:
    run = _Run()
    a = run.connect("dsm-a-client", A_PEER, 1, _pair()[1])
    b_keys, b_server = _pair()
    b = run.connect("dsm-b-client", B_PEER, 2, b_server)
    roamed = b_keys.seal_packet(1, b"after a NAT rebind")
    on_a_hint = b_keys.seal_packet(2, b"from a's address")
    run.dispatcher.route(roamed, NEW_PORT)  # no hint: every session is checked
    run.dispatcher.route(on_a_hint, A_PEER)  # a's check fails, then b's passes
    assert _queued(b) == [(roamed, NEW_PORT), (on_a_hint, A_PEER)]
    assert _queued(a) == []
    assert run.table.by_peer(NEW_PORT) is None  # a packet never moves a hint
    assert run.table.by_peer(A_PEER) is a


def test_the_dispatcher_opens_nothing_and_the_session_opens_once() -> None:
    run = _Run()
    a_keys, a_server = _pair()
    a = run.connect("dsm-a-client", A_PEER, 1, a_server)
    wire = a_keys.seal_packet(1, b"once")
    run.dispatcher.route(wire, A_PEER)
    run.dispatcher.route(wire, A_PEER)  # the same packet again: a replay
    (first, _), (second, _) = _queued(a)
    opened = a_server.open_packet(first)
    assert opened is not None
    assert opened[1] == b"once"
    assert a_server.open_packet(second) is None


def test_a_session_and_a_handshake_on_one_address_each_get_their_own() -> None:
    """A client restarted with a fixed port: its msg1 and its old session's
    packets share one address (spec §2.5, hint holder first)."""
    run = _Run()
    a_keys, a_server = _pair()
    a = run.connect("dsm-a-client", A_PEER, 1, a_server)
    data = a_keys.seal_packet(1, b"data")
    run.dispatcher.route(FRAME, A_PEER)
    run.dispatcher.route(data, A_PEER)
    assert run.offered == [(FRAME, A_PEER)]
    assert _queued(a) == [(data, A_PEER)]


def test_a_packet_no_session_fits_goes_to_the_acceptor_and_counts() -> None:
    run = _Run()
    run.dispatcher.route(FRAME, A_PEER)  # no session at all yet
    a = run.connect("dsm-a-client", A_PEER, 1, _pair()[1])
    run.dispatcher.route(b"short junk", NEW_PORT)
    assert run.offered == [(FRAME, A_PEER), (b"short junk", NEW_PORT)]
    assert run.dispatcher.unmatched == 2
    assert _queued(a) == []
    assert _view(a).recv_drops() == 2  # junk shares the socket


def test_a_full_view_drops_counts_and_logs_for_that_session_only(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger="dsm.net.session_router")
    run = _Run()
    a_keys, a_server = _pair()
    b_keys, b_server = _pair()
    a = run.connect("dsm-a-client", A_PEER, 1, a_server)
    b = run.connect("dsm-b-client", B_PEER, 2, b_server)
    for _ in range(SESSION_QUEUE_PACKETS):
        assert _view(a).deliver(b"queued", A_PEER)
    for seq in (1, 2):  # one 10 s window: these run microseconds apart
        run.dispatcher.route(a_keys.seal_packet(seq, b"one too many"), A_PEER)
    assert _view(a).recv_drops() == 2
    assert run.offered == []  # they were a's packets, not the acceptor's
    assert [
        (r.levelno, r.getMessage())
        for r in caplog.records
        if r.name == "dsm.net.session_router"
    ] == [(logging.DEBUG, "dropped a UDP packet: its session's queue is full")]
    wire = b_keys.seal_packet(1, b"b is not held up")
    run.dispatcher.route(wire, B_PEER)
    assert _queued(b) == [(wire, B_PEER)]
    assert _view(b).recv_drops() == 0


def test_held_frames_routed_after_add_reach_the_new_session() -> None:
    run = _Run()
    a_keys, a_server = _pair()
    early = a_keys.seal_packet(1, b"before the session was added")
    run.dispatcher.route(early, A_PEER)
    # A copy: route appends to run.offered on a miss, so looping over it
    # would never end if the packet missed.
    held = list(run.offered)
    assert held == [(early, A_PEER)]  # the acceptor holds it
    a = run.connect("dsm-a-client", A_PEER, 1, a_server)
    for frame, peer in held:  # on_client routes the held frames
        run.dispatcher.route(frame, peer)
    assert _queued(a) == [(early, A_PEER)]
    assert run.offered == held  # nothing new was offered


def test_packets_reach_their_session_in_arrival_order_across_a_key_change() -> None:
    run = _Run()
    a_keys, a_server = _pair()
    a = run.connect("dsm-a-client", A_PEER, 1, a_server)
    old1 = a_keys.seal_packet(1, b"old 1")
    old3 = a_keys.seal_packet(3, b"old 3")
    _rotate(a_keys, a_server)
    new2 = a_keys.seal_packet(2, b"new 2")
    for wire in (old1, new2, old3):
        run.dispatcher.route(wire, A_PEER)
    opened = [a_server.open_packet(wire) for wire, _ in _queued(a)]
    assert opened == [(1, b"old 1", True), (2, b"new 2", False), (3, b"old 3", True)]


def test_a_removed_session_gets_nothing_more() -> None:
    run = _Run()
    a_keys, a_server = _pair()
    a = run.connect("dsm-a-client", A_PEER, 1, a_server)
    assert run.table.remove(a)
    late = a_keys.seal_packet(1, b"late")
    run.dispatcher.route(late, A_PEER)
    assert _queued(a) == []
    assert run.offered == [(late, A_PEER)]


def test_a_match_without_a_session_view_is_dropped() -> None:
    """D9, fail closed: a session whose transport is not a view (never so in
    a UDP run) gets nothing, and its packet is neither offered nor counted."""
    run = _Run()
    a = run.connect("dsm-a-client", A_PEER, 1, _Keys(b"fits a"))
    a.transport = object()
    run.dispatcher.route(b"fits a", A_PEER)
    assert run.offered == []
    assert run.dispatcher.unmatched == 0


async def test_run_routes_every_packet_the_socket_gives() -> None:
    a_keys, a_server = _pair()
    wire = a_keys.seal_packet(1, b"data")
    run = _Run([(wire, A_PEER), (FRAME, NEW_PORT)])
    a = run.connect("dsm-a-client", A_PEER, 1, a_server)
    with pytest.raises(_Done):
        await run.dispatcher.run()
    assert _queued(a) == [(wire, A_PEER)]
    assert run.offered == [(FRAME, NEW_PORT)]
