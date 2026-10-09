"""Concurrent TCP accept (_accept_until_winner_tcp): connections are checked
side by side under the UDP acceptor's pool, per-address limits and attempt
deadline, and every connection but the winner is closed.

Connections are in-memory TCPTransport stand-ins fed straight into the
acceptor's queue (no sockets). The handshake is a scripted fake, except in
the one test that needs the real msg1 check. Nothing waits on the wall
clock.
"""

from __future__ import annotations

import asyncio
import contextlib
import itertools
import logging
from collections.abc import Callable
from typing import Any
from unittest.mock import patch

import pytest

from dsm.crypto.handshake import HandshakeError
from dsm.net import handshake_acceptor as hsa
from dsm.net.handshake_gate import SourceLimiter
from dsm.net.transport.tcp import FramingError, TCPTransport

Addr = tuple[str, int]
_WINNER: Addr = ("198.51.100.7", 40000)


class _Conn(TCPTransport):
    """One accepted connection, in memory."""

    def __init__(  # pylint: disable=super-init-not-called
        self, peer: Addr, frames: list[bytes] | None = None
    ) -> None:
        self.peer = peer
        self.closed = False
        self.sent: list[bytes] = []
        self._frames: asyncio.Queue[bytes] = asyncio.Queue()
        for frame in frames or []:
            self._frames.put_nowait(frame)

    async def recv(self, timeout: float | None = None) -> bytes:
        del timeout
        return await self._frames.get()

    async def send(self, data: bytes) -> None:
        self.sent.append(bytes(data))

    def close(self) -> None:
        self.closed = True

    async def aclose(self) -> None:
        self.closed = True


class _Config:
    def __init__(self, max_inflight: int = 8) -> None:
        self.max_inflight_handshakes = max_inflight
        self.rotation_packets = 5000
        self.rotation_seconds = 600


class _Stub:
    identity = object()
    attest_key = object()
    cert_der = b""
    ca_root = object()
    crl = None


class _Script:
    """Fake server_handshake, by peer: "win" (default), "stall" (until
    cancelled), "fail", "framing" (bad length prefix), "eof" (peer closed
    mid-frame) or "reset" (connection reset)."""

    def __init__(self, behaviour: dict[Addr, str]) -> None:
        self.behaviour = behaviour
        self.started: list[Addr] = []

    async def __call__(self, conn: Any, *_a: Any, **_k: Any) -> tuple[object, bytes]:
        peer: Addr = conn.peer
        self.started.append(peer)
        what = self.behaviour.get(peer, "win")
        if what == "stall":
            await asyncio.Event().wait()
        if what == "fail":
            raise HandshakeError("scripted failure")
        if what == "framing":
            raise FramingError("frame length 268435457 exceeds max 65536")
        if what == "eof":
            raise ConnectionError("TCP peer closed mid-frame (0 of 4 bytes received)")
        if what == "reset":
            raise ConnectionResetError(104, "Connection reset by peer")
        return object(), f"pub-{peer[0]}:{peer[1]}".encode()


async def _spin(until: Callable[[], bool], rounds: int = 1000) -> bool:
    """Yield to the event loop until ``until()`` holds (no wall-clock wait)."""
    for _ in range(rounds):
        if until():
            return True
        await asyncio.sleep(0)
    return until()


def _minutes() -> Callable[[], float]:
    """A clock that moves a minute per reading, so no rate bucket runs dry."""
    ticks = itertools.count(0.0, 60.0)
    return lambda: next(ticks)


class _Run:
    """Run _accept_until_winner_tcp on an in-memory connection queue."""

    def __init__(
        self,
        script: _Script | None,
        *,
        max_inflight: int = 8,
        limiter: SourceLimiter | None = None,
        keystore: Any = None,
    ) -> None:
        self.connections: asyncio.Queue[tuple[TCPTransport, Addr]] = asyncio.Queue()
        self.shutdown = asyncio.Event()
        self._config = _Config(max_inflight)
        self._limiter = limiter if limiter is not None else SourceLimiter()
        self._keystore = keystore if keystore is not None else _Stub()
        self._patch = (
            None
            if script is None
            else patch("dsm.crypto.handshake.server_handshake", new=script)
        )
        self.task: asyncio.Future[Any] | None = None

    def connect(self, peer: Addr, frames: list[bytes] | None = None) -> _Conn:
        conn = _Conn(peer, frames)
        self.connections.put_nowait((conn, peer))
        return conn

    async def __aenter__(self) -> _Run:
        accept = hsa._accept_until_winner_tcp  # AttributeError until this task lands
        if self._patch is not None:
            self._patch.start()
        self.task = asyncio.ensure_future(
            accept(
                self._config,
                self._keystore,
                _Stub(),
                _Stub(),
                _Stub(),
                self.connections,
                self.shutdown,
                self._limiter,
            )
        )
        return self

    async def __aexit__(self, *exc: object) -> None:
        self.shutdown.set()
        try:
            assert self.task is not None
            await asyncio.wait_for(self.task, 5.0)
        finally:
            if self._patch is not None:
                self._patch.stop()

    async def result(self) -> tuple[Any, Any, Any]:
        assert self.task is not None
        return await asyncio.wait_for(self.task, 5.0)


def test_the_attempt_deadline_is_twelve_seconds() -> None:
    assert hsa._HANDSHAKE_ATTEMPT_DEADLINE == 12.0


async def test_a_silent_connection_does_not_delay_a_second_client() -> None:
    """(red today) The old serial path held every client behind one silent
    connection for up to 30-48 s."""
    silent: Addr = ("203.0.113.10", 1111)
    script = _Script({silent: "stall"})
    async with _Run(script) as run:
        s = run.connect(silent)
        w = run.connect(_WINNER)
        _, pub, transport = await run.result()
    assert pub == b"pub-198.51.100.7:40000"
    assert transport is w and not w.closed
    assert s.closed
    assert script.started == [silent, _WINNER]


async def test_a_third_connection_from_one_address_is_closed_at_once() -> None:
    ip = "203.0.113.20"
    a, b, c = (ip, 1), (ip, 2), (ip, 3)
    script = _Script({a: "stall", b: "stall", c: "stall"})
    async with _Run(script) as run:
        ca, cb, cc = run.connect(a), run.connect(b), run.connect(c)
        assert await _spin(lambda: cc.closed and len(script.started) == 2)
        assert script.started == [a, b]
        assert not ca.closed and not cb.closed
        w = run.connect(_WINNER)
        _, _, transport = await run.result()
    assert transport is w
    assert ca.closed and cb.closed


async def test_a_full_pool_closes_new_connections_at_once() -> None:
    busy: Addr = ("203.0.113.70", 1)
    extra: Addr = ("203.0.113.71", 1)
    script = _Script({busy: "stall", extra: "stall"})
    async with _Run(script, max_inflight=1) as run:
        run.connect(busy)
        e = run.connect(extra)
        assert await _spin(lambda: e.closed)
        assert await _spin(lambda: busy in script.started)
        assert extra not in script.started


async def test_the_attempt_deadline_frees_the_slot_and_closes_the_connection() -> None:
    silent: Addr = ("203.0.113.30", 1)
    script = _Script({silent: "stall"})
    async with _Run(script, max_inflight=1) as run:
        with patch.object(hsa, "_HANDSHAKE_ATTEMPT_DEADLINE", 0.0):
            s = run.connect(silent)
            assert await _spin(lambda: s.closed)
        w = run.connect(_WINNER)
        _, pub, transport = await run.result()
    assert transport is w
    assert pub == b"pub-198.51.100.7:40000"


async def test_a_bad_frame_or_a_dropped_connection_ends_only_that_attempt(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Review Focus 2: each error closes only its own connection and gives
    the address back; no log line names the peer."""
    caplog.set_level(logging.DEBUG)
    ip = "203.0.113.40"
    bad = [
        ((ip, 1), "framing"),
        ((ip, 2), "eof"),
        ((ip, 3), "reset"),
        ((ip, 4), "fail"),
    ]
    script = _Script({**dict(bad), (ip, 5): "stall", (ip, 6): "stall"})
    async with _Run(script, limiter=SourceLimiter(clock=_minutes())) as run:
        for peer, _what in bad:
            conn = run.connect(peer)
            assert await _spin(lambda c=conn: c.closed), f"{peer} was not closed"
        x, y = run.connect((ip, 5)), run.connect((ip, 6))
        assert await _spin(lambda: len(script.started) == 6)
        assert not x.closed and not y.closed
        w = run.connect(_WINNER)
        _, _, transport = await run.result()
    assert transport is w
    assert all(ip not in r.getMessage() for r in caplog.records)
    assert all("198.51.100.7" not in r.getMessage() for r in caplog.records)


async def test_shutdown_closes_every_connection_and_leaves_no_task() -> None:
    """Review Focus 4."""
    peers: list[Addr] = [("203.0.113.50", 1), ("203.0.113.51", 1), ("203.0.113.52", 1)]
    script = _Script({p: "stall" for p in peers})
    before = asyncio.all_tasks()
    run = _Run(script, max_inflight=2)
    async with run:
        conns = [run.connect(p) for p in peers]
        assert await _spin(lambda: len(script.started) == 2)
    assert run.task is not None
    assert run.task.result() == (None, None, None)
    assert all(c.closed for c in conns)
    assert asyncio.all_tasks() - before == set()


async def test_losers_are_closed_and_give_their_address_back() -> None:
    """Review Focus 2: cancelled losers give their address back to the
    run's limiter, which the next accept cycle shares."""
    ip = "203.0.113.60"
    limiter = SourceLimiter(clock=_minutes())
    script = _Script({(ip, 1): "stall", (ip, 2): "stall"})
    async with _Run(script, limiter=limiter) as run:
        l1, l2 = run.connect((ip, 1)), run.connect((ip, 2))
        assert await _spin(lambda: len(script.started) == 2)
        w = run.connect(_WINNER)
        _, _, transport = await run.result()
    assert transport is w and not w.closed
    assert l1.closed and l2.closed
    later = _Script({(ip, 3): "stall", (ip, 4): "stall"})
    async with _Run(later, limiter=limiter) as run2:
        run2.connect((ip, 3))
        run2.connect((ip, 4))
        assert await _spin(lambda: len(later.started) == 2)


async def test_every_loser_is_closed_when_the_accept_returns() -> None:
    """The accept is awaited inline (as _accept_one_session does), so the
    losers must be closed by the time it returns, not a loop pass later."""
    losers: list[Addr] = [("203.0.113.65", 1), ("203.0.113.66", 1)]
    script = _Script({p: "stall" for p in losers})
    connections: asyncio.Queue[tuple[TCPTransport, Addr]] = asyncio.Queue()
    conns = [_Conn(p) for p in losers]
    for conn in conns:
        connections.put_nowait((conn, conn.peer))

    async def _then_the_winner() -> None:
        assert await _spin(lambda: len(script.started) == 2)
        connections.put_nowait((_Conn(_WINNER), _WINNER))

    feeder = asyncio.ensure_future(_then_the_winner())
    # asyncio.timeout, not wait_for: on 3.11 wait_for runs the accept in a
    # task of its own, so it would no longer be awaited inline.
    async with asyncio.timeout(5.0):
        with patch("dsm.crypto.handshake.server_handshake", new=script):
            _, _, transport = await hsa._accept_until_winner_tcp(
                _Config(),
                _Stub(),
                _Stub(),
                _Stub(),
                _Stub(),
                connections,
                asyncio.Event(),
                SourceLimiter(),
            )
            # No await between the return and this check.
            still_open = [c.peer for c in conns if not c.closed]
        await feeder
    assert isinstance(transport, _Conn) and transport.peer == _WINNER
    assert still_open == []


async def test_a_worker_cancelled_before_it_runs_gives_everything_back() -> None:
    """Review Focus 2: a worker whose body never ran (a loser can be
    cancelled right after it was made) still frees its slot and its address,
    and its connection is closed. The limiter lives for the whole run, so a
    leak here would lock the address out until restart."""
    ip = "203.0.113.90"
    peer: Addr = (ip, 1)
    limiter = SourceLimiter(clock=_minutes())
    semaphore = asyncio.Semaphore(1)
    workers: set[asyncio.Task[None]] = set()
    open_conns: dict[Addr, TCPTransport] = {}
    connections: asyncio.Queue[tuple[TCPTransport, Addr]] = asyncio.Queue()
    winner: asyncio.Future[Any] = asyncio.get_running_loop().create_future()
    script = _Script({peer: "stall"})
    conn = _Conn(peer)
    connections.put_nowait((conn, peer))
    with patch("dsm.crypto.handshake.server_handshake", new=script):
        admit = asyncio.ensure_future(
            hsa._tcp_admit_loop(
                _Config(1),
                _Stub(),
                _Stub(),
                _Stub(),
                _Stub(),
                connections,
                winner,
                workers,
                semaphore,
                open_conns,
                limiter,
            )
        )
        try:
            # One pass: the admit loop takes the connection and makes its
            # worker. The worker's first step is queued behind this task's, so
            # it is cancelled before it ever runs.
            await asyncio.sleep(0)
            assert len(workers) == 1
            (worker,) = workers
            worker.cancel()
            assert await _spin(worker.done)
            await asyncio.sleep(0)
        finally:
            admit.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await admit
    assert worker.cancelled()
    assert script.started == []  # the worker's body never ran
    assert conn.closed
    assert open_conns == {}
    assert not semaphore.locked()
    # As before the attempt: the address may run its full two at once.
    assert limiter.try_start(ip)
    assert limiter.try_start(ip)


async def test_a_wrong_size_first_frame_is_closed_before_any_signature() -> None:
    """Design test 22 for part 1: the real msg1 check refuses a short frame
    before the attest key signs anything, and nothing is sent back."""
    import tuncore

    class _Keystore:
        identity = tuncore.IdentityKeyPair.generate()

    peer: Addr = ("203.0.113.80", 1)
    with patch("dsm.crypto.handshake.build_attest_payload") as sign:
        async with _Run(None, keystore=_Keystore()) as run:
            conn = run.connect(peer, frames=[b"\x00" * 100])
            assert await _spin(lambda: conn.closed)
    sign.assert_not_called()
    assert conn.sent == []
