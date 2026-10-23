"""The always-on handshake acceptor (spec §2.7): ClientAcceptor, its UDP
demux, TCP admit loop and worker, with the known-address lane's cookie
step, E3 and the failed-start penalty (spec §3.7), and the kept meanings of
the old in-session accept's tests (spec §7 item 2). Handshakes are scripted
fakes; the session table, the limiter and the gate are real; clocks are
fake. No sockets; nothing waits on the wall clock."""

from __future__ import annotations

import asyncio
import contextlib
import errno
import logging
import random
from typing import Any
from unittest.mock import patch

import pytest

from dsm.crypto.handshake import HANDSHAKE_FRAME_SIZE, HandshakeError, VerifiedClient
from dsm.net import handshake_acceptor as hsa
from dsm.net.handshake_gate import (
    GLOBAL_START_BURST,
    IN_SESSION_START_BURST,
    GateKeys,
    HandshakeGate,
    SourceLimiter,
    compute_mac1,
    stamp_msg1,
)
from dsm.net.session_slot import REPLACE_BURST, SessionTable
from dsm.net.transport.tcp import TCPTransport
from tests.test_handshake_acceptor_limits import (
    _Config,
    _Frozen,
    _minutes,
    _spin,
    _Stub,
    _Transport,
    _yield,
)
from tests.test_tcp_accept_concurrency import _Conn

Addr = tuple[str, int]
KNOWN = "198.51.100.7"
STRANGER = "203.0.113.1"


async def _forever() -> None:
    await asyncio.Event().wait()


def _track(
    made: dict[asyncio.Task[None], hsa._Attempt], rec: hsa._Attempt
) -> asyncio.Task[None]:
    """Give ``rec`` a running task of its own, as a real attempt has."""
    task = asyncio.ensure_future(_forever())
    made[task] = rec
    return task


async def _cancel(made: dict[asyncio.Task[None], hsa._Attempt]) -> None:
    for task in made:
        task.cancel()
    await asyncio.gather(*made, return_exceptions=True)


def _never(_task: object) -> bool:
    return False


def _known(ip: str) -> bool:
    return ip == KNOWN


async def test_a_known_start_may_push_out_a_young_stranger() -> None:
    made: dict[asyncio.Task[None], hsa._Attempt] = {}
    young = _track(made, hsa._Attempt(ip=STRANGER, started=0.0, signing=False))
    try:
        assert hsa._choose_push_out(
            made, 0.1, KNOWN, pool_full=True, past_admit=_never, is_known=_known
        ) == (young, hsa._PassedOn.SLOT_ONLY)
        # A stranger's start still waits for the age (spec §4.3).
        assert (
            hsa._choose_push_out(
                made,
                0.1,
                "203.0.113.2",
                pool_full=True,
                past_admit=_never,
                is_known=_known,
            )
            is None
        )
    finally:
        await _cancel(made)


async def test_a_known_start_never_takes_one_signing_or_past_admit() -> None:
    made: dict[asyncio.Task[None], hsa._Attempt] = {}
    _track(made, hsa._Attempt(ip=STRANGER, started=0.0, signing=True))
    admitted = _track(made, hsa._Attempt(ip="203.0.113.2", started=0.0, signing=False))
    try:
        for now in (0.1, 10.0):  # young (E3's any-age path) and old
            assert (
                hsa._choose_push_out(
                    made,
                    now,
                    KNOWN,
                    pool_full=True,
                    past_admit=lambda task: task is admitted,
                    is_known=_known,
                )
                is None
            )
    finally:
        await _cancel(made)


async def test_a_known_address_attempt_still_needs_the_age() -> None:
    made: dict[asyncio.Task[None], hsa._Attempt] = {}
    other = "198.51.100.8"
    _track(made, hsa._Attempt(ip=other, started=0.0, signing=False))

    def known(ip: str) -> bool:
        return ip in (KNOWN, other)

    try:
        for now, pushable in ((1.4, False), (1.5, True)):
            push = hsa._choose_push_out(
                made, now, KNOWN, pool_full=True, past_admit=_never, is_known=known
            )
            assert (push is not None) is pushable
    finally:
        await _cancel(made)


async def test_a_known_start_takes_the_oldest_it_may_push_out() -> None:
    made: dict[asyncio.Task[None], hsa._Attempt] = {}
    _track(made, hsa._Attempt(ip=STRANGER, started=0.5, signing=False))
    oldest = _track(made, hsa._Attempt(ip="203.0.113.2", started=0.2, signing=False))
    try:
        assert hsa._choose_push_out(
            made, 0.6, KNOWN, pool_full=True, past_admit=_never, is_known=_known
        ) == (oldest, hsa._PassedOn.SLOT_ONLY)
    finally:
        await _cancel(made)


async def test_e3_needs_a_full_pool_and_leaves_case_1_alone() -> None:
    made: dict[asyncio.Task[None], hsa._Attempt] = {}
    _track(made, hsa._Attempt(ip=STRANGER, started=0.0, signing=False))
    try:
        # A free slot: nothing is pushed out.
        assert (
            hsa._choose_push_out(
                made, 0.1, KNOWN, pool_full=False, past_admit=_never, is_known=_known
            )
            is None
        )
        # The known address at its own cap: only its own oldest, at the age.
        for _ in range(2):
            _track(made, hsa._Attempt(ip=KNOWN, started=0.0, signing=False))
        assert (
            hsa._choose_push_out(
                made, 0.1, KNOWN, pool_full=True, past_admit=_never, is_known=_known
            )
            is None
        )
    finally:
        await _cancel(made)


def test_a_record_is_not_proved_unless_its_start_says_so() -> None:
    assert not hsa._Attempt(ip=STRANGER, started=0.0, signing=False).proved
    assert hsa._Attempt(ip=STRANGER, started=0.0, signing=False, proved=True).proved


A_CN = "dsm-a-client"
B_CN = "dsm-b-client"
PEER: Addr = ("198.51.100.7", 40001)
MSG2 = b"msg2".ljust(HANDSHAKE_FRAME_SIZE, b"\x00")
REPLY = b"reply".ljust(HANDSHAKE_FRAME_SIZE, b"\x00")
KEYS = GateKeys.from_ca_der(bytes.fromhex("3003020101"), "dsm-test-server")
NOW = 1_800_000_000.0
# With A_CN first and B_CN last, B_CN is the 254th name: past the pool's 253
# addresses, so it gets none (spec §2.3).
PAST_THE_POOL = [A_CN, *(f"dsm-filler-{i}" for i in range(252)), B_CN]


def _client(cn: str) -> VerifiedClient:
    return VerifiedClient(cn=cn, noise_static=cn.encode().ljust(32, b"\x00"))


def _peer_of(transport: Any) -> Addr:
    """The peer of a UDP view, a first-frame TCP view or a bare connection."""
    if isinstance(transport, hsa._PerPeerUDPView):
        return transport._peer_addr
    return getattr(transport, "_real", transport).peer


async def _send(transport: Any, data: bytes, peer: Addr) -> None:
    if isinstance(transport, TCPTransport):
        await transport.send(data)
    else:
        await transport.send(data, peer)


class _Hs:
    """Fake server_handshake for UDP views and TCP connections, in the real
    one's order: reads msg1, sends msg2, asks admit_client as its peer's CN
    (``cns``; A_CN by default), sends the bootstrap reply, wins. A peer in
    ``stall`` stops after msg2, one in ``fail`` fails there, one in ``hold``
    waits for its event after the table's yes (its reply on its way)."""

    def __init__(self, cns: dict[Addr, str] | None = None) -> None:
        self.cns = cns if cns is not None else {}
        self.stall: set[Addr] = set()
        self.fail: set[Addr] = set()
        self.hold: dict[Addr, asyncio.Event] = {}
        self.started: list[Addr] = []
        self.admitted: list[Addr] = []
        self.replied: list[Addr] = []

    async def __call__(
        self, transport: Any, *_a: Any, admit_client: Any, **_k: Any
    ) -> tuple[object, bytes]:
        peer = _peer_of(transport)
        self.started.append(peer)
        await transport.recv()
        await _send(transport, MSG2, peer)
        if peer in self.stall:
            await asyncio.Event().wait()
        if peer in self.fail:
            raise HandshakeError("scripted failure")
        client = _client(self.cns.get(peer, A_CN))
        admit_client(client)
        self.admitted.append(peer)
        hold = self.hold.get(peer)
        if hold is not None:
            await hold.wait()
        await _send(transport, REPLY, peer)
        self.replied.append(peer)
        return object(), client.noise_static


def _gate(clock: _Frozen | None = None) -> HandshakeGate:
    return HandshakeGate(
        KEYS, clock=clock if clock is not None else _Frozen(), wall_clock=lambda: NOW
    )


def _msg1(seed: int) -> bytes:
    """A msg1 as a wire v2 client stamps it (the fakes never read the Noise
    part)."""
    frame = bytearray(random.Random(seed).randbytes(HANDSHAKE_FRAME_SIZE))
    stamp_msg1(frame, compute_mac1(bytes(frame[:32]), KEYS, NOW))
    return bytes(frame)


async def _attempt(
    hs: Any, transport: Any, peer: Addr, table: SessionTable, **kwargs: Any
) -> list[hsa.AcceptedClient]:
    """Run one worker to its end with ``hs`` as the handshake; return what it
    handed on."""
    got: list[hsa.AcceptedClient] = []
    with patch("dsm.crypto.handshake.server_handshake", new=hs):
        await asyncio.wait_for(
            hsa._run_attempt(
                _Config(8),
                _Stub(),
                _Stub(),
                _Stub(),
                _Stub(),
                transport,
                peer,
                got.append,
                who=str(peer),
                table=table,
                **kwargs,
            ),
            5.0,
        )
    return got


async def test_a_passing_udp_client_is_handed_on_with_its_held_frames() -> None:
    sock = _Transport()
    table = SessionTable([A_CN])
    limiter = SourceLimiter(clock=_minutes())
    inbox: asyncio.Queue[bytes] = asyncio.Queue()
    for frame in (b"msg1", b"early-1", b"early-2"):
        inbox.put_nowait(frame)  # frames that got in before it passed
    view = hsa._PerPeerUDPView(sock, PEER, inbox)
    (won,) = await _attempt(_Hs(), view, PEER, table, limiter=limiter)
    assert won.client == _client(A_CN)
    assert won.tunnel == table.assignment_for(A_CN)
    assert won.transport is sock  # the run's socket, not the view
    assert won.peer == PEER
    assert won.held == (b"early-1", b"early-2")  # oldest first
    assert sock.sent == [(MSG2, PEER), (REPLY, PEER)]
    assert table.ever_confirmed
    assert limiter.is_known(PEER[0])


async def test_a_client_the_table_refuses_gets_no_reply_and_is_not_known(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger="dsm.net.handshake_acceptor")
    sock = _Transport()
    table = SessionTable(PAST_THE_POOL)
    limiter = SourceLimiter(clock=_minutes())
    inbox: asyncio.Queue[bytes] = asyncio.Queue()
    inbox.put_nowait(b"msg1")
    view = hsa._PerPeerUDPView(sock, PEER, inbox)
    assert await _attempt(_Hs({PEER: B_CN}), view, PEER, table, limiter=limiter) == []
    assert sock.sent == [(MSG2, PEER)]  # no bootstrap reply
    assert not table.ever_confirmed
    assert not limiter.is_known(PEER[0])
    assert any(
        r.levelno == logging.DEBUG
        and r.getMessage().startswith("handshake refused by the session rules")
        for r in caplog.records
    )


async def test_a_handshake_that_skips_the_table_is_dropped(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Fail closed: server_handshake returned without asking the table (a
    bug), so the client is not let in unchecked."""

    async def _skips(view: Any, *_a: Any, **_k: Any) -> tuple[object, bytes]:
        await view.recv()
        return object(), b"pub"

    caplog.set_level(logging.ERROR)
    table = SessionTable([A_CN])
    inbox: asyncio.Queue[bytes] = asyncio.Queue()
    inbox.put_nowait(b"msg1")
    view = hsa._PerPeerUDPView(_Transport(), PEER, inbox)
    assert await _attempt(_skips, view, PEER, table) == []
    assert [r.getMessage() for r in caplog.records] == [
        "a handshake ended without the session check; dropped it"
    ]
    assert not table.ever_confirmed


async def test_a_passing_tcp_client_is_handed_its_connection() -> None:
    conn = _Conn(PEER, [_msg1(1)])
    limiter = SourceLimiter(clock=_minutes())
    record = hsa._Attempt(ip=PEER[0], started=0.0, signing=False, proved=True)
    (won,) = await _attempt(
        _Hs(),
        conn,
        PEER,
        SessionTable([A_CN]),
        gate=_gate(),
        limiter=limiter,
        record=record,
    )
    assert won.transport is conn  # the connection, not the first-frame view
    assert won.held == ()
    assert conn.sent == [MSG2, REPLY]
    assert not record.signing  # msg2 left
    assert record.proved
    assert limiter.is_known(PEER[0])


async def test_a_first_frame_the_shared_limits_refuse_loses_its_proved_bit() -> None:
    gate = _gate()
    limiter = SourceLimiter(clock=_Frozen())
    for i in range(int(GLOBAL_START_BURST)):
        assert limiter.try_shared(f"192.0.2.{i}")  # the overall limit is spent
    record = hsa._Attempt(ip=PEER[0], started=0.0, signing=False, proved=True)
    hs = _Hs()
    conn = _Conn(PEER, [_msg1(1)])
    assert (
        await _attempt(
            hs,
            conn,
            PEER,
            SessionTable([A_CN]),
            gate=gate,
            limiter=limiter,
            record=record,
        )
        == []
    )
    assert hs.started == []
    assert conn._frames.empty()  # refused after its first frame was read
    assert gate.load.under_load(0)  # trouble ...
    assert not record.proved  # ... but not the address's doing: no penalty


async def test_once_a_cn_connected_a_first_frame_pays_the_newcomer_limit() -> None:
    table = SessionTable([A_CN, B_CN])
    held_by = object()
    table.admit(held_by, _client(B_CN))  # B's device connected in this run
    table.confirm(held_by)
    limiter = SourceLimiter(clock=_Frozen())
    for i in range(int(IN_SESSION_START_BURST)):
        assert limiter.try_shared(f"192.0.2.{i}", in_session=True)
    hs = _Hs()
    record = hsa._Attempt(ip=PEER[0], started=0.0, signing=False, proved=True)
    conn = _Conn(PEER, [_msg1(1)])
    assert (
        await _attempt(
            hs, conn, PEER, table, gate=_gate(), limiter=limiter, record=record
        )
        == []
    )
    assert hs.started == []  # the newcomer limit refused it (spec §3.7 E1)
    # A known address skips that limit (spec §3.7).
    limiter.note_known(PEER[0], A_CN)
    record = hsa._Attempt(ip=PEER[0], started=0.0, signing=False, proved=True)
    conn = _Conn(PEER, [_msg1(2)])
    (won,) = await _attempt(
        _Hs(), conn, PEER, table, gate=_gate(), limiter=limiter, record=record
    )
    assert won.client.cn == A_CN


A: Addr = PEER
A2: Addr = ("198.51.100.7", 40002)  # the same device, restarted
B: Addr = ("203.0.113.9", 40009)


def _frame(addr: Addr, n: int = 0) -> bytes:
    return f"{addr[0]}:{addr[1]}-{n}".encode().ljust(HANDSHAKE_FRAME_SIZE, b"\x00")


class _Demux:
    """The UDP demux on an in-memory socket (read through its own recv),
    with the run's table, limiter and gate and Step S's clock. Leaving
    cancels it and every worker and waits for them, so every done-callback
    has run."""

    def __init__(
        self,
        hs: Any,
        table: SessionTable,
        *,
        limiter: SourceLimiter | None = None,
        gate: HandshakeGate | None = None,
        max_inflight: int = 8,
        clock: _Frozen | None = None,
    ) -> None:
        self.sock = _Transport()
        self.table = table
        # Not ``limiter or ...``: an empty SourceLimiter is falsy (__len__).
        self.limiter = (
            limiter if limiter is not None else SourceLimiter(clock=_minutes())
        )
        self.gate = gate
        self.clock = clock if clock is not None else _Frozen()
        self.max_inflight = max_inflight
        self.clients: list[hsa.AcceptedClient] = []
        self.workers: set[asyncio.Task[None]] = set()
        self.semaphore = asyncio.Semaphore(max_inflight)
        self.inboxes: dict[Addr, asyncio.Queue[bytes]] = {}
        self._patch = patch("dsm.crypto.handshake.server_handshake", new=hs)
        self.task: asyncio.Future[None] | None = None

    def feed(self, data: bytes, addr: Addr) -> None:
        self.sock._recv_queue.put_nowait((data, addr))

    def sent_to(self, addr: Addr) -> list[bytes]:
        return [data for data, dest in self.sock.sent if dest == addr]

    async def __aenter__(self) -> _Demux:
        self._patch.start()
        self.task = asyncio.ensure_future(
            hsa._demux(
                _Config(self.max_inflight),
                _Stub(),
                _Stub(),
                _Stub(),
                _Stub(),
                self.sock,
                self.clients.append,
                self.table,
                self.workers,
                self.semaphore,
                self.inboxes,
                self.limiter,
                gate=self.gate,
                clock=self.clock,
            )
        )
        return self

    async def __aexit__(self, *exc: object) -> None:
        try:
            assert self.task is not None
            self.task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self.task
            await hsa._cancel_and_drain(set(self.workers))
            await _yield()
        finally:
            self._patch.stop()


async def test_two_cns_both_become_sessions() -> None:
    table = SessionTable([A_CN, B_CN])
    async with _Demux(_Hs({A: A_CN, B: B_CN}), table) as run:
        run.feed(_frame(A), A)
        assert await _spin(lambda: len(run.clients) == 1)
        run.feed(_frame(B), B)  # while A's session is live
        assert await _spin(lambda: len(run.clients) == 2)
    a, b = run.clients
    assert (a.client.cn, a.peer, a.tunnel) == (A_CN, A, table.assignment_for(A_CN))
    assert (b.client.cn, b.peer, b.tunnel) == (B_CN, B, table.assignment_for(B_CN))
    assert a.tunnel != b.tunnel
    assert a.transport is run.sock and b.transport is run.sock
    assert run.inboxes == {}  # each attempt's inbox left with it


async def test_the_same_cn_takes_over_within_its_allowance(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="dsm.net.session_slot")
    hs = _Hs()
    # The device comes back from a new port each time; the table's clock
    # never refills its takeover allowance.
    peers = [("198.51.100.7", 41000 + i) for i in range(int(REPLACE_BURST) + 2)]
    async with _Demux(hs, SessionTable([A_CN], clock=_Frozen())) as run:
        for peer in peers:
            run.feed(_frame(peer), peer)
            assert await _spin(lambda p=peer: p in hs.started and not run.workers)
    served = int(REPLACE_BURST) + 1  # the first session, then its takeovers
    assert [c.peer for c in run.clients] == peers[:served]
    assert run.sent_to(peers[-1]) == [MSG2]  # past the allowance: no reply
    lines = [r.getMessage() for r in caplog.records if r.name == "dsm.net.session_slot"]
    taken_over = "client reconnected (client_cn=dsm-a-client); ending its old session"
    assert lines.count(taken_over) == served - 1
    assert any("reconnected too often" in line for line in lines)


async def test_a_second_attempt_of_one_cn_is_refused_while_the_first_finishes() -> None:
    hs = _Hs()
    hs.hold[A] = asyncio.Event()
    async with _Demux(hs, SessionTable([A_CN])) as run:
        run.feed(_frame(A), A)
        assert await _spin(lambda: A in hs.admitted)
        run.feed(_frame(A2), A2)  # the same CN while A is past the check
        assert await _spin(lambda: A2 in hs.started and len(run.workers) == 1)
        assert A2 not in hs.admitted
        hs.hold[A].set()
        assert await _spin(lambda: len(run.clients) == 1)
    assert run.sent_to(A2) == [MSG2]  # no bootstrap reply
    assert [c.peer for c in run.clients] == [A]


async def test_a_cn_with_no_address_gets_no_bootstrap_reply() -> None:
    hs = _Hs({B: B_CN})
    async with _Demux(hs, SessionTable(PAST_THE_POOL)) as run:
        run.feed(_frame(B), B)
        assert await _spin(lambda: B in hs.started and not run.workers)
    assert run.clients == []
    assert run.sent_to(B) == [MSG2]


class _FailsOnceAfterCheck(_Hs):
    """The first attempt passes the table's check, then its bootstrap reply
    cannot be sent. Later attempts run as in :class:`_Hs`."""

    def __init__(self) -> None:
        super().__init__()
        self.failed = False

    async def __call__(
        self, transport: Any, *a: Any, admit_client: Any, **k: Any
    ) -> tuple[object, bytes]:
        if self.failed:
            return await super().__call__(transport, *a, admit_client=admit_client, **k)
        self.failed = True
        peer = _peer_of(transport)
        self.started.append(peer)
        await transport.recv()
        admit_client(_client(A_CN))
        self.admitted.append(peer)
        raise OSError(errno.EPIPE, "send failed")


async def test_a_failure_after_the_check_gives_the_cn_back() -> None:
    """Else the CN stays marked and every later handshake of it is refused
    until the server restarts."""
    hs = _FailsOnceAfterCheck()
    async with _Demux(hs, SessionTable([A_CN])) as run:
        run.feed(_frame(A), A)
        assert await _spin(lambda: A in hs.admitted and not run.workers)
        assert run.clients == []
        run.feed(_frame(A, 1), A)  # the client resends msg1: a new attempt
        assert await _spin(lambda: len(run.clients) == 1)
    assert hs.admitted == [A, A]


async def test_held_frames_reach_the_session_in_order() -> None:
    hs = _Hs()
    hs.hold[A] = asyncio.Event()
    async with _Demux(hs, SessionTable([A_CN])) as run:
        run.feed(_frame(A, 0), A)
        assert await _spin(lambda: A in hs.admitted)
        # A resent frame and its first data packet reach its inbox while its
        # bootstrap reply is on its way.
        run.feed(_frame(A, 1), A)
        run.feed(_frame(A, 2), A)
        await _yield()
        hs.hold[A].set()
        assert await _spin(lambda: len(run.clients) == 1)
    assert run.clients[0].held == (_frame(A, 1), _frame(A, 2))


async def test_from_the_first_connection_new_starts_pay_the_newcomer_limit() -> None:
    limiter = SourceLimiter(clock=_Frozen())
    hs = _Hs()
    strangers = [(f"203.0.113.{i}", 1) for i in range(int(IN_SESSION_START_BURST) + 1)]
    hs.stall.update(strangers)
    async with _Demux(hs, SessionTable([A_CN]), limiter=limiter) as run:
        run.feed(_frame(A), A)  # before any connection: the overall limit only
        assert await _spin(lambda: len(run.clients) == 1)
        for stranger in strangers:
            run.feed(_frame(stranger), stranger)
        burst = int(IN_SESSION_START_BURST)
        assert await _spin(lambda: len(hs.started) == 1 + burst)
        await _yield()
    assert hs.started == [A, *strangers[:-1]]  # the last waits (spec §3.7 E1)


async def test_a_known_address_skips_the_shared_limits() -> None:
    limiter = SourceLimiter(clock=_Frozen())
    async with _Demux(_Hs(), SessionTable([A_CN]), limiter=limiter) as run:
        run.feed(_frame(A), A)
        assert await _spin(lambda: len(run.clients) == 1)
        while limiter.try_shared("192.0.2.1", in_session=True):
            pass  # the newcomer limit is spent
        run.feed(_frame(A2), A2)  # the same device, back from its known address
        assert await _spin(lambda: len(run.clients) == 2)
