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
    COOKIE_REPLY_BURST,
    GLOBAL_START_BURST,
    IN_SESSION_START_BURST,
    KNOWN_COOKIE_REPLY_BURST,
    GateKeys,
    HandshakeGate,
    SourceLimiter,
    compute_mac1,
    open_cookie_reply,
    stamp_mac2,
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


def _with_cookie(msg1: bytes, reply: bytes) -> bytes:
    """The client's resend after a cookie reply: same e and mac1, with mac2."""
    cookie = open_cookie_reply(reply, KEYS, msg1[32:48])
    assert cookie is not None
    frame = bytearray(msg1)
    stamp_mac2(frame, cookie)
    return bytes(frame)


async def test_under_load_a_known_address_gets_its_cookie_from_its_own_budget() -> None:
    gate = _gate()  # a frozen clock: no budget refills
    gate.load.note_trouble()  # under load: every new msg1 needs a cookie
    limiter = SourceLimiter(clock=_minutes())
    limiter.note_known(A[0], A_CN)  # A's device connected earlier in this run
    async with _Demux(_Hs(), SessionTable([A_CN]), limiter=limiter, gate=gate) as run:
        spoofed = [
            (f"203.0.{i // 250}.{i % 250}", 7000 + i)
            for i in range(int(COOKIE_REPLY_BURST) + 1)
        ]
        for i, src in enumerate(spoofed):
            run.feed(_msg1(100 + i), src)
        assert await _spin(run.sock._recv_queue.empty)
        await _yield()
        assert len(run.sock.sent) == COOKIE_REPLY_BURST  # the shared budget is dry
        first = _msg1(1)
        run.feed(first, A)
        assert await _spin(lambda: len(run.sent_to(A)) == 1)  # from its own budget
        run.feed(_with_cookie(first, run.sent_to(A)[0]), A)
        assert await _spin(lambda: len(run.clients) == 1)


async def test_a_spoofed_known_address_empties_only_its_own_budget(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger="dsm")
    gate = _gate()
    gate.load.note_trouble()
    # Frozen: a clock that moves would refill A's own budget before each take.
    limiter = SourceLimiter(clock=_Frozen())
    other: Addr = ("198.51.100.8", 40008)
    limiter.note_known(A[0], A_CN)
    limiter.note_known(other[0], B_CN)
    async with _Demux(
        _Hs(), SessionTable([A_CN, B_CN]), limiter=limiter, gate=gate
    ) as run:
        caplog.clear()
        # Someone who knows A's public address fakes it, from many ports.
        for i in range(int(KNOWN_COOKIE_REPLY_BURST) + 3):
            run.feed(_msg1(200 + i), (A[0], 9000 + i))
        assert await _spin(run.sock._recv_queue.empty)
        await _yield()
        assert len(run.sock.sent) == KNOWN_COOKIE_REPLY_BURST  # capped
        # Its dry budget logs nothing: no line may tell that it is known.
        assert [r for r in caplog.records if r.name.startswith("dsm")] == []
        run.feed(_msg1(1), other)  # another known address: its own budget
        run.feed(_msg1(2), B)  # a stranger: the shared budget is untouched
        assert await _spin(
            lambda: len(run.sent_to(other)) == 1 and len(run.sent_to(B)) == 1
        )


async def test_a_strangers_failed_start_is_penalized_only_when_it_was_proved(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="dsm.net.handshake_gate")
    clock = _Frozen()  # the gate's and the limiter's: nothing refills
    gate = _gate(clock)
    limiter = SourceLimiter(clock=clock)
    quiet: Addr = ("203.0.113.1", 1)
    loaded: Addr = ("203.0.113.2", 2)
    hs = _Hs()
    hs.fail.update({quiet, loaded})
    async with _Demux(hs, SessionTable([A_CN]), limiter=limiter, gate=gate) as run:
        run.feed(_msg1(1), quiet)  # a quiet server asks no cookie: not proved
        assert await _spin(lambda: quiet in hs.started and not run.workers)
        assert gate.load.under_load(0)  # its failure turned cookies on
        first = _msg1(2)
        run.feed(first, loaded)
        assert await _spin(lambda: len(run.sent_to(loaded)) == 1)
        run.feed(_with_cookie(first, run.sent_to(loaded)[0]), loaded)  # proved
        assert await _spin(lambda: loaded in hs.started and not run.workers)
    assert limiter.try_start(quiet[0])  # may start again at once
    assert not limiter.try_start(loaded[0])  # barred (spec §3.7 E2)
    assert any("last handshake failed" in r.getMessage() for r in caplog.records)


async def test_a_strangers_stall_is_penalized_only_when_it_was_proved() -> None:
    # A stall that runs into the attempt deadline (spec §3.7 E2).
    clock = _Frozen()  # the gate's and the limiter's: nothing refills
    gate = _gate(clock)
    limiter = SourceLimiter(clock=clock)
    quiet: Addr = ("203.0.113.1", 1)
    loaded: Addr = ("203.0.113.2", 2)
    hs = _Hs()
    hs.stall.update({quiet, loaded})
    with patch.object(hsa, "_HANDSHAKE_ATTEMPT_DEADLINE", 0.0):  # fires next pass
        async with _Demux(hs, SessionTable([A_CN]), limiter=limiter, gate=gate) as run:
            run.feed(_msg1(1), quiet)  # a quiet server asks no cookie: not proved
            assert await _spin(lambda: quiet in hs.started and not run.workers)
            assert gate.load.under_load(0)  # its timeout turned cookies on
            first = _msg1(2)
            run.feed(first, loaded)
            assert await _spin(lambda: len(run.sent_to(loaded)) == 1)
            run.feed(_with_cookie(first, run.sent_to(loaded)[0]), loaded)  # proved
            assert await _spin(lambda: loaded in hs.started and not run.workers)
    assert limiter.try_start(quiet[0])  # may start again at once
    assert not limiter.try_start(loaded[0])  # barred


async def test_a_proved_start_that_passes_bars_nothing() -> None:
    clock = _Frozen()
    gate = _gate(clock)
    gate.load.note_trouble()  # under load: A's msg1 needs a cookie
    limiter = SourceLimiter(clock=clock)
    async with _Demux(_Hs(), SessionTable([A_CN]), limiter=limiter, gate=gate) as run:
        first = _msg1(1)
        run.feed(first, A)
        assert await _spin(lambda: len(run.sent_to(A)) == 1)
        run.feed(_with_cookie(first, run.sent_to(A)[0]), A)
        assert await _spin(lambda: len(run.clients) == 1 and not run.workers)
    # Its finish said failed=True (it was proved), but its address was known
    # by then, and a known address is never barred.
    assert limiter.try_start(A[0])


async def test_a_known_address_pushes_out_a_young_stranger_from_a_full_pool() -> None:
    # Pins Task 5's E3 wiring, and that the young stranger, which did not
    # stall, costs its address nothing (spec §3.7 E2, E3).
    clock = _Frozen()  # the gate's and the limiter's: nothing refills
    gate = _gate(clock)
    gate.load.note_trouble()  # under load: every msg1 needs a cookie
    limiter = SourceLimiter(clock=clock)
    limiter.note_known(A[0], A_CN)
    hs = _Hs({B: B_CN})
    hs.stall.add(B)
    async with _Demux(
        hs, SessionTable([A_CN, B_CN]), limiter=limiter, gate=gate, max_inflight=1
    ) as run:
        stranger = _msg1(1)
        run.feed(stranger, B)
        assert await _spin(lambda: len(run.sent_to(B)) == 1)  # a cookie
        run.feed(_with_cookie(stranger, run.sent_to(B)[0]), B)  # proved
        # It takes the one slot and stalls after msg2 (not signing now).
        assert await _spin(lambda: run.sent_to(B)[1:] == [MSG2])
        first = _msg1(2)
        run.feed(first, A)  # Step S's clock never moves: B is 0 s old
        assert await _spin(lambda: len(run.sent_to(A)) == 1)  # its own cookie
        run.feed(_with_cookie(first, run.sent_to(A)[0]), A)
        assert await _spin(lambda: len(run.clients) == 1)
    assert run.clients[0].peer == A
    assert B not in hs.admitted
    assert limiter.try_start(B[0])  # pushed out young: not barred


async def test_a_known_address_never_pushes_out_an_attempt_past_admit() -> None:
    # Pins Task 5's E3 wiring.
    limiter = SourceLimiter(clock=_minutes())
    limiter.note_known(A[0], A_CN)
    hs = _Hs({B: B_CN})
    hs.hold[B] = asyncio.Event()  # past the table's check, its reply on its way
    async with _Demux(
        hs, SessionTable([A_CN, B_CN]), limiter=limiter, gate=_gate(), max_inflight=1
    ) as run:
        run.feed(_msg1(1), B)
        assert await _spin(lambda: B in hs.admitted)
        first = _msg1(2)
        run.feed(first, A)
        assert await _spin(lambda: len(run.sent_to(A)) == 1)
        run.feed(_with_cookie(first, run.sent_to(A)[0]), A)
        await _yield()
        assert A not in hs.started  # dropped: every slot is full
        hs.hold[B].set()
        assert await _spin(lambda: len(run.clients) == 1)
    assert run.clients[0].peer == B


async def test_a_proved_stranger_pushed_out_after_it_stalled_is_barred() -> None:
    # An old push-out victim did stall: its address pays (spec §3.7 E2).
    clock = _Frozen()  # the gate's and the limiter's: nothing refills
    gate = _gate(clock)
    gate.load.note_trouble()  # under load: every msg1 needs a cookie
    limiter = SourceLimiter(clock=clock)
    other: Addr = ("203.0.113.10", 40010)
    hs = _Hs()
    hs.stall.add(B)
    async with _Demux(
        hs, SessionTable([A_CN]), limiter=limiter, gate=gate, max_inflight=1
    ) as run:
        stalled = _msg1(1)
        run.feed(stalled, B)
        assert await _spin(lambda: len(run.sent_to(B)) == 1)  # a cookie
        run.feed(_with_cookie(stalled, run.sent_to(B)[0]), B)  # proved
        # It takes the one slot and stalls after msg2 (not signing now).
        assert await _spin(lambda: run.sent_to(B)[1:] == [MSG2])
        run.clock.now = 2.0  # Step S's clock: B is past _PUSH_OUT_AFTER_S
        first = _msg1(2)
        run.feed(first, other)
        assert await _spin(lambda: len(run.sent_to(other)) == 1)
        run.feed(_with_cookie(first, run.sent_to(other)[0]), other)
        assert await _spin(lambda: len(run.clients) == 1)
    assert run.clients[0].peer == other
    assert B not in hs.admitted
    assert not limiter.try_start(B[0])  # barred


async def test_a_proved_start_the_table_refuses_is_barred() -> None:
    clock = _Frozen()  # the gate's and the limiter's: nothing refills
    gate = _gate(clock)
    gate.load.note_trouble()  # under load: B's msg1 needs a cookie
    limiter = SourceLimiter(clock=clock)
    hs = _Hs({B: B_CN})
    async with _Demux(
        hs, SessionTable(PAST_THE_POOL), limiter=limiter, gate=gate
    ) as run:
        first = _msg1(1)
        run.feed(first, B)
        assert await _spin(lambda: len(run.sent_to(B)) == 1)  # a cookie
        run.feed(_with_cookie(first, run.sent_to(B)[0]), B)  # proved
        assert await _spin(lambda: B in hs.started and not run.workers)
    assert run.clients == []
    assert not limiter.try_start(B[0])  # refused by the table: barred


class _Admit:
    """The TCP admit loop on an in-memory connection queue, with the run's
    table, limiter and gate and Step S's clock. Leaving cancels it and every
    worker and waits for them, so every done-callback has run."""

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
        self.connections: asyncio.Queue[tuple[TCPTransport, Addr]] = asyncio.Queue()
        self.clock = clock if clock is not None else _Frozen()
        self.table = table
        self.limiter = (
            limiter if limiter is not None else SourceLimiter(clock=_minutes())
        )
        self.gate = gate
        self.max_inflight = max_inflight
        self.clients: list[hsa.AcceptedClient] = []
        self.workers: set[asyncio.Task[None]] = set()
        self.semaphore = asyncio.Semaphore(max_inflight)
        self.open_conns: dict[Addr, TCPTransport] = {}
        self._patch = patch("dsm.crypto.handshake.server_handshake", new=hs)
        self.task: asyncio.Future[None] | None = None

    def connect(self, peer: Addr, frames: list[bytes] | None = None) -> _Conn:
        conn = _Conn(peer, frames)
        self.connections.put_nowait((conn, peer))
        return conn

    async def __aenter__(self) -> _Admit:
        self._patch.start()
        self.task = asyncio.ensure_future(
            hsa._admit_tcp(
                _Config(self.max_inflight),
                _Stub(),
                _Stub(),
                _Stub(),
                _Stub(),
                self.connections,
                self.clients.append,
                self.table,
                self.workers,
                self.semaphore,
                self.open_conns,
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


async def test_two_tcp_connections_both_become_sessions_and_stay_open() -> None:
    async with _Admit(_Hs({A: A_CN, B: B_CN}), SessionTable([A_CN, B_CN])) as run:
        ca = run.connect(A, [b"msg1"])
        cb = run.connect(B, [b"msg1"])
        assert await _spin(lambda: len(run.clients) == 2)
        await _yield()
        assert run.open_conns == {}  # handed on: no longer the acceptor's
    assert [c.transport for c in run.clients] == [ca, cb]
    assert [c.client.cn for c in run.clients] == [A_CN, B_CN]
    assert not ca.closed and not cb.closed
    assert ca.sent == [MSG2, REPLY]


async def test_a_failed_tcp_attempt_is_closed_and_gives_its_address_back() -> None:
    limiter = SourceLimiter(clock=_minutes())
    hs = _Hs()
    hs.fail.add(B)
    async with _Admit(hs, SessionTable([A_CN]), limiter=limiter) as run:
        failed = run.connect(B, [b"msg1"])
        assert await _spin(lambda: failed.closed)
        assert run.open_conns == {}
    assert run.clients == []
    assert limiter.try_start(B[0])  # its two at once again
    assert limiter.try_start(B[0])


async def test_tcp_a_reconnecting_client_takes_over_on_the_runs_listener(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="dsm.net.session_slot")
    async with _Admit(_Hs(), SessionTable([A_CN])) as run:
        first = run.connect(A, [b"msg1"])
        assert await _spin(lambda: len(run.clients) == 1)
        back = run.connect(A2, [b"msg1"])  # the same device, a new connection
        assert await _spin(lambda: len(run.clients) == 2)
    assert [c.transport for c in run.clients] == [first, back]
    assert not back.closed  # the acceptor never closes a connection it handed on
    assert [
        r.getMessage() for r in caplog.records if r.name == "dsm.net.session_slot"
    ] == ["client reconnected (client_cn=dsm-a-client); ending its old session"]


async def test_a_silent_tcp_connection_costs_its_address_the_penalty() -> None:
    limiter = SourceLimiter(clock=_Frozen())
    with patch.object(hsa, "_TCP_FIRST_FRAME_DEADLINE", 0.0):  # fires next pass
        async with _Admit(
            _Hs(), SessionTable([A_CN]), limiter=limiter, gate=_gate()
        ) as run:
            silent = run.connect(B)
            assert await _spin(lambda: silent.closed)
    # The connection proved its address, and it sent no first frame in time:
    # a failed proven start (spec §3.7 E2).
    assert not limiter.try_start(B[0], shared=False)


async def test_a_tcp_attempt_cut_by_a_stop_costs_nothing() -> None:
    limiter = SourceLimiter(clock=_Frozen())
    with patch.object(hsa, "_TCP_FIRST_FRAME_DEADLINE", 3600.0):
        async with _Admit(
            _Hs(), SessionTable([A_CN]), limiter=limiter, gate=_gate()
        ) as run:
            waiting = run.connect(B)  # no first frame yet
            assert await _spin(lambda: bool(waiting._frames._getters))
    assert waiting.closed  # leaving stopped the loop and cancelled the worker
    assert limiter.try_start(B[0], shared=False)


async def test_a_known_tcp_connection_pushes_out_a_young_silent_stranger() -> None:
    # E3 in TCP mode: what keeps silent connections from holding every slot
    # against a known device (spec §3.7, §4.4).
    limiter = SourceLimiter(clock=_Frozen())
    limiter.note_known(A[0], A_CN)
    with patch.object(hsa, "_TCP_FIRST_FRAME_DEADLINE", 3600.0):
        async with _Admit(
            _Hs(), SessionTable([A_CN]), limiter=limiter, gate=_gate(), max_inflight=1
        ) as run:
            silent = run.connect(B)  # takes the one slot and sends nothing
            assert await _spin(lambda: bool(silent._frames._getters))
            known = run.connect(A, [_msg1(1)])  # Step S's clock: B is 0 s old
            assert await _spin(lambda: silent.closed and len(run.clients) == 1)
    assert run.clients[0].transport is known
    # Pushed out young, it did not stall: no penalty (spec §3.7 E2, E3).
    assert limiter.try_start(B[0], shared=False)


async def test_a_silent_tcp_stranger_pushed_out_after_it_stalled_is_barred() -> None:
    limiter = SourceLimiter(clock=_Frozen())
    other: Addr = ("203.0.113.10", 40010)
    with patch.object(hsa, "_TCP_FIRST_FRAME_DEADLINE", 3600.0):
        async with _Admit(
            _Hs(), SessionTable([A_CN]), limiter=limiter, gate=_gate(), max_inflight=1
        ) as run:
            silent = run.connect(B)  # takes the one slot and sends nothing
            assert await _spin(lambda: bool(silent._frames._getters))
            run.clock.now = 2.0  # Step S's clock: B is past _PUSH_OUT_AFTER_S
            run.connect(other, [_msg1(1)])  # a stranger
            assert await _spin(lambda: silent.closed and len(run.clients) == 1)
    # It was silent for 2 s and then pushed out: a stall (spec §3.7 E2).
    assert not limiter.try_start(B[0], shared=False)


@pytest.mark.parametrize("first", [b"short", bytes(HANDSHAKE_FRAME_SIZE)])
async def test_a_bad_tcp_first_frame_costs_a_stranger_the_penalty(
    first: bytes,
) -> None:
    # A wrong size or a bad mac1 is no good first frame: a stall (spec §3.7 E2).
    limiter = SourceLimiter(clock=_Frozen())
    async with _Admit(
        _Hs(), SessionTable([A_CN]), limiter=limiter, gate=_gate()
    ) as run:
        bad = run.connect(B, [first])
        assert await _spin(lambda: bad.closed)
    assert not limiter.try_start(B[0], shared=False)
