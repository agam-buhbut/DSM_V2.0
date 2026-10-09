"""The handshake accept that runs while a session is live (step R).

SessionWatch reads what the live session could not open (UDP) or the run's
listener queue (TCP), with the idle accept's pool, limits and deadline. The
handshake is a scripted fake that asks the session check (admit_client) as
the real one does; the slot and the limiter are real. No sockets; nothing
waits on the wall clock.
"""

from __future__ import annotations

import asyncio
import errno
import logging
from typing import Any
from unittest.mock import patch

import pytest

from dsm.crypto.handshake import HANDSHAKE_FRAME_SIZE, VerifiedClient
from dsm.net import handshake_acceptor as hsa
from dsm.net.handshake_acceptor import SessionWatch, Winner
from dsm.net.handshake_gate import SourceLimiter
from dsm.net.session_slot import SessionSlot
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
HOLDER = VerifiedClient(cn="dsm-a-client", noise_static=b"\x01" * 32)
BACK: Addr = ("198.51.100.7", 40001)  # the session's client, restarted
OTHER: Addr = ("203.0.113.9", 40002)  # another device
MSG2 = b"msg2".ljust(HANDSHAKE_FRAME_SIZE, b"\x00")


def _frame(addr: Addr, n: int = 0, size: int = HANDSHAKE_FRAME_SIZE) -> bytes:
    return f"{addr[0]}:{addr[1]}-{n}".encode().ljust(size, b"\x00")[:size]


def _queued(transport: _Transport) -> list[tuple[bytes, Addr]]:
    out: list[tuple[bytes, Addr]] = []
    while not transport._recv_queue.empty():
        out.append(transport._recv_queue.get_nowait())
    return out


def _slot() -> SessionSlot:
    """A slot whose session is held by HOLDER, as after an idle accept."""
    slot = SessionSlot()
    attempt = object()
    slot.admit(attempt, HOLDER, session_live=False)
    slot.confirm(attempt)
    return slot


class _Script:
    """Fake server_handshake. Each attempt reads one frame, sends msg2,
    then asks admit_client (when given) with the CN set for its peer
    (default: the holder's), then waits on its gate if it has one (the last
    frame on its way), then wins. A peer in ``stall`` stops after msg1."""

    def __init__(self, cns: dict[Addr, str] | None = None) -> None:
        self.cns = cns or {}
        self.gates: dict[Addr, asyncio.Event] = {}
        self.stall: set[Addr] = set()
        self.started: list[Addr] = []
        self.admitted: list[Addr] = []

    async def __call__(
        self, view: Any, *_a: Any, admit_client: Any = None, **_k: Any
    ) -> tuple[object, bytes]:
        tcp = isinstance(view, TCPTransport)
        peer: Addr = view.peer if tcp else view._peer_addr
        self.started.append(peer)
        await view.recv()
        if peer in self.stall:
            await asyncio.Event().wait()
        if tcp:
            await view.send(MSG2)
        else:
            await view.send(MSG2, peer)
        if admit_client is not None:
            admit_client(
                VerifiedClient(
                    cn=self.cns.get(peer, HOLDER.cn),
                    noise_static=HOLDER.noise_static,
                )
            )
        self.admitted.append(peer)
        gate = self.gates.get(peer)
        if gate is not None:
            await gate.wait()
        return object(), f"pub-{peer[0]}:{peer[1]}".encode()


class _Udp:
    """A live UDP session's side of things: the run's socket (in memory), the
    run's slot and limiter, and a SessionWatch on them."""

    def __init__(
        self,
        script: _Script,
        *,
        limiter: SourceLimiter | None = None,
        slot: SessionSlot | None = None,
    ) -> None:
        self.real = _Transport()
        self.slot = slot if slot is not None else _slot()
        # Not ``limiter or ...``: an empty SourceLimiter is falsy (__len__).
        self.limiter = (
            limiter if limiter is not None else SourceLimiter(clock=_minutes())
        )
        self._patch = patch("dsm.crypto.handshake.server_handshake", new=script)
        self.watch: SessionWatch | None = None
        self.stopped = False

    async def __aenter__(self) -> _Udp:
        self._patch.start()
        self.watch = SessionWatch(
            _Config(8),  # type: ignore[arg-type]
            _Stub(),  # type: ignore[arg-type]
            _Stub(),  # type: ignore[arg-type]
            _Stub(),  # type: ignore[arg-type]
            _Stub(),  # type: ignore[arg-type]
            self.limiter,
            self.slot,
            udp=self.real,
        )
        return self

    async def __aexit__(self, *exc: object) -> None:
        try:
            if not self.stopped:
                await self.stop()
        finally:
            self._patch.stop()

    def offer(self, addr: Addr, n: int = 0, size: int = HANDSHAKE_FRAME_SIZE) -> None:
        assert self.watch is not None and self.watch.offer is not None
        self.watch.offer(_frame(addr, n, size), addr)

    async def stop(self) -> Winner | None:
        assert self.watch is not None
        self.stopped = True
        return await asyncio.wait_for(self.watch.stop(), 5.0)


async def test_a_reconnecting_client_wins_and_its_packets_come_back_in_order(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="dsm.net.session_slot")
    script = _Script()
    gate = asyncio.Event()
    script.gates[BACK] = gate
    async with _Udp(script) as run:
        assert run.watch is not None
        run.offer(BACK, 0)  # its msg1
        assert await _spin(lambda: script.admitted == [BACK])
        assert run.real.sent == [(MSG2, BACK)]  # out on the run's socket
        run.offer(BACK, 1)  # a resent frame: into its inbox
        await _yield()
        assert not run.watch.end_session.is_set()
        gate.set()  # the last frame went out: it wins
        assert await _spin(run.watch.end_session.is_set)
        run.offer(BACK, 2, size=300)  # its first data packets, any size ...
        run.offer(OTHER, 0)  # ... but nobody else's, once a client won
        run.offer(BACK, 3, size=500)
        run.real._recv_queue.put_nowait((b"queued", BACK))  # already queued
        win = await run.stop()
    assert win is not None
    assert win.client_pub == b"pub-198.51.100.7:40001"
    assert win.transport is run.real
    assert run.slot.holder == HOLDER
    assert run.slot.admitted is None
    assert _queued(run.real) == [
        (_frame(BACK, 1), BACK),
        (_frame(BACK, 2, 300), BACK),
        (_frame(BACK, 3, 500), BACK),
        (b"queued", BACK),
    ]
    assert script.started == [BACK]
    assert [
        r.getMessage() for r in caplog.records if r.name == "dsm.net.session_slot"
    ] == ["client reconnected (client_cn=dsm-a-client); ending its old session"]


async def test_another_client_is_refused_before_the_last_frame(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    script = _Script({OTHER: "dsm-b-client"})
    async with _Udp(script) as run:
        assert run.watch is not None
        run.offer(OTHER)
        assert await _spin(lambda: script.started == [OTHER])
        await _yield()
        assert script.admitted == []
        assert not run.watch.end_session.is_set()
        assert await run.stop() is None
    assert run.slot.holder == HOLDER
    assert run.real.sent == [(MSG2, OTHER)]  # it saw msg2, then nothing
    slot_lines = [
        r.getMessage() for r in caplog.records if r.name == "dsm.net.session_slot"
    ]
    assert slot_lines == [
        "handshake refused: another client is connected (client_cn=dsm-b-client)"
    ]
    acceptor_lines = [
        r
        for r in caplog.records
        if r.name == "dsm.net.handshake_acceptor" and r.levelno >= logging.INFO
    ]
    assert acceptor_lines == []  # the per-attempt line for a refusal is DEBUG
    assert all(
        "203.0.113.9" not in r.getMessage()
        for r in caplog.records
        if r.levelno >= logging.INFO
    )


async def test_stop_with_no_winner_cancels_every_attempt_and_gives_all_back() -> None:
    clock = _Frozen()
    limiter = SourceLimiter(clock=clock)
    first: Addr = ("203.0.113.1", 1)
    second: Addr = ("203.0.113.2", 2)
    script = _Script()
    script.stall = {first, second}
    before = asyncio.all_tasks()
    async with _Udp(script, limiter=limiter) as run:
        run.offer(first)
        assert await _spin(lambda: script.started == [first])
        clock.now += 1.0  # the in-session budget: one new handshake a second
        run.offer(second)
        assert await _spin(lambda: script.started == [first, second])
        assert await run.stop() is None
    assert asyncio.all_tasks() - before == set()
    assert run.slot.admitted is None
    assert run.slot.holder == HOLDER
    for ip, _port in (first, second):  # each address may run its two again
        assert limiter.try_start(ip)
        assert limiter.try_start(ip)


async def test_stop_waits_for_an_attempt_past_the_check_and_it_wins() -> None:
    """Review Focus 3: its client may already have the last frame."""
    script = _Script()
    gate = asyncio.Event()
    script.gates[BACK] = gate
    async with _Udp(script) as run:
        assert run.watch is not None
        run.offer(BACK)
        assert await _spin(lambda: script.admitted == [BACK])
        stopping = asyncio.ensure_future(run.stop())
        await _yield()
        assert not stopping.done(), "stop must wait for the attempt past the check"
        gate.set()
        win = await asyncio.wait_for(stopping, 5.0)
    assert win is not None
    assert win.client_pub == b"pub-198.51.100.7:40001"
    assert run.slot.admitted is None


class _FailsOnceAfterCheck(_Script):
    """The first attempt passes the session check, then its bootstrap reply
    cannot be sent. Later attempts run as in :class:`_Script`."""

    def __init__(self) -> None:
        super().__init__()
        self.failed = False

    async def __call__(
        self, view: Any, *a: Any, admit_client: Any = None, **k: Any
    ) -> tuple[object, bytes]:
        if self.failed:
            return await super().__call__(view, *a, admit_client=admit_client, **k)
        self.failed = True
        peer: Addr = view._peer_addr
        self.started.append(peer)
        await view.recv()
        await view.send(MSG2, peer)
        assert admit_client is not None
        admit_client(VerifiedClient(cn=HOLDER.cn, noise_static=HOLDER.noise_static))
        self.admitted.append(peer)
        raise OSError(errno.EPIPE, "send failed")


async def test_an_attempt_that_fails_after_the_check_gives_the_slot_back() -> None:
    """Else the slot stays taken and every later handshake is refused until
    the server restarts."""
    script = _FailsOnceAfterCheck()
    async with _Udp(script) as run:
        assert run.watch is not None
        run.offer(BACK, 0)
        assert await _spin(lambda: script.admitted == [BACK])
        await _yield()
        assert run.slot.admitted is None
        assert not run.watch.end_session.is_set()
        run.offer(BACK, 1)  # the client resends msg1: a new attempt
        assert await _spin(run.watch.end_session.is_set)
        win = await run.stop()
    assert win is not None
    assert script.admitted == [BACK, BACK]
    assert run.slot.admitted is None
    assert run.slot.holder == HOLDER


async def test_in_a_session_new_handshakes_start_at_most_once_a_second() -> None:
    clock = _Frozen()
    limiter = SourceLimiter(clock=clock)
    first: Addr = ("203.0.113.1", 1)
    second: Addr = ("203.0.113.2", 2)
    script = _Script()
    script.stall = {first, second}
    async with _Udp(script, limiter=limiter) as run:
        run.offer(first)
        run.offer(second)
        assert await _spin(lambda: script.started == [first])
        await _yield()
        assert script.started == [first]  # the second waits for the next second
        clock.now += 1.0
        run.offer(second)
        assert await _spin(lambda: script.started == [first, second])
        assert await run.stop() is None
    # The idle accept shares this limiter: the session's start counts there.
    assert limiter.try_start(first[0])
    assert limiter.try_start(first[0])
    limiter.finish(first[0])
    limiter.finish(first[0])
    assert not limiter.try_start(first[0])  # 3 at once: 1 in the session + 2 now


async def test_before_a_winner_only_full_size_frames_get_in() -> None:
    script = _Script()
    async with _Udp(script) as run:
        for size in (0, 64, 1399, 1401):
            run.offer(OTHER, size=size)
        await _yield()
        assert script.started == []
        assert await run.stop() is None


async def test_a_full_intake_drops_with_one_debug_line(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger="dsm.net.handshake_acceptor")
    script = _Script()
    script.stall = {OTHER}
    async with _Udp(script) as run:
        for n in range(200):  # no yield in between: the demux cannot keep up
            run.offer(OTHER, n)
        full = [
            r
            for r in caplog.records
            if r.getMessage() == "in-session handshake queue full, dropping a frame"
        ]
        assert len(full) == 1
        assert full[0].levelno == logging.DEBUG
        assert await run.stop() is None


async def test_a_crash_is_logged_once_and_the_session_runs_on(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.ERROR)

    async def _broken(*_a: Any, **_k: Any) -> None:
        raise RuntimeError("demux bug")

    with patch.object(hsa, "_demux_loop", new=_broken):
        async with _Udp(_Script()) as run:
            assert run.watch is not None
            assert await _spin(lambda: bool(caplog.records))
            run.offer(BACK)  # never raises after a crash
            assert not run.watch.end_session.is_set()
            assert await run.stop() is None
    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert len(errors) == 1
    assert errors[0].getMessage() == (
        "in-session handshake accept failed; this session cannot be replaced "
        "until it ends"
    )
    assert errors[0].exc_info is not None


async def test_the_idle_accept_lets_one_attempt_past_the_check_at_a_time() -> None:
    first: Addr = ("203.0.113.1", 1)
    second: Addr = ("203.0.113.2", 2)
    script = _Script({first: "dsm-a-client", second: "dsm-b-client"})
    gate = asyncio.Event()
    script.gates[first] = gate
    slot = SessionSlot()
    transport = _Transport()
    with patch("dsm.crypto.handshake.server_handshake", new=script):
        task = asyncio.ensure_future(
            hsa._accept_until_winner(
                _Config(8),  # type: ignore[arg-type]
                _Stub(),  # type: ignore[arg-type]
                _Stub(),  # type: ignore[arg-type]
                _Stub(),  # type: ignore[arg-type]
                _Stub(),  # type: ignore[arg-type]
                transport,
                asyncio.Event(),
                SourceLimiter(clock=_minutes()),
                slot,
            )
        )
        transport.feed(first)
        assert await _spin(lambda: script.admitted == [first])
        transport.feed(second)
        assert await _spin(lambda: script.started == [first, second])
        await _yield()
        assert script.admitted == [first]  # refused before its last frame
        gate.set()
        _keys, pub, _transport = await asyncio.wait_for(task, 5.0)
    assert pub == b"pub-203.0.113.1:1"
    assert slot.holder is not None
    assert slot.holder.cn == "dsm-a-client"


async def test_tcp_a_reconnecting_client_wins_on_the_runs_listener() -> None:
    script = _Script()
    gate = asyncio.Event()
    script.gates[BACK] = gate
    script.stall = {OTHER}
    connections: asyncio.Queue[tuple[TCPTransport, Addr]] = asyncio.Queue()
    slot = _slot()
    with patch("dsm.crypto.handshake.server_handshake", new=script):
        watch = SessionWatch(
            _Config(8),  # type: ignore[arg-type]
            _Stub(),  # type: ignore[arg-type]
            _Stub(),  # type: ignore[arg-type]
            _Stub(),  # type: ignore[arg-type]
            _Stub(),  # type: ignore[arg-type]
            SourceLimiter(clock=_minutes()),
            slot,
            tcp=connections,
        )
        assert watch.offer is None
        back = _Conn(BACK, frames=[b"msg1"])
        other = _Conn(OTHER, frames=[b"msg1"])
        connections.put_nowait((back, BACK))
        assert await _spin(lambda: script.admitted == [BACK])
        connections.put_nowait((other, OTHER))
        assert await _spin(lambda: OTHER in script.started)
        gate.set()
        assert await _spin(watch.end_session.is_set)
        win = await asyncio.wait_for(watch.stop(), 5.0)
    assert win is not None
    assert win.transport is back
    assert not back.closed
    assert back.sent == [MSG2]
    assert other.closed  # a loser: cancelled and closed
    assert slot.holder == HOLDER
