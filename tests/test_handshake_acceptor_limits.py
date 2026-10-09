"""UDP acceptor: junk never takes a slot, failures never pause the demux, and
SourceLimiter's per-address and overall limits apply to new sources.

The Noise handshake is a scripted fake patched at
dsm.crypto.handshake.server_handshake, as in test_handshake_concurrency.py.
Nothing waits on the wall clock: tests yield with ``asyncio.sleep(0)`` and
give limiters a fake clock.
"""

from __future__ import annotations

import asyncio
import contextlib
import itertools
from collections.abc import Callable
from typing import Any
from unittest.mock import patch

from dsm.crypto.handshake import HANDSHAKE_FRAME_SIZE, HandshakeError
from dsm.net import handshake_acceptor as hsa
from dsm.net.handshake_gate import SourceLimiter
from dsm.net.transport.udp import UDPTransport

Addr = tuple[str, int]
_WINNER: Addr = ("198.51.100.7", 51820)


class _Transport(UDPTransport):
    """The server's UDP socket, in memory: ``feed`` queues a datagram."""

    def __init__(self) -> None:  # pylint: disable=super-init-not-called
        self._recv_queue: asyncio.Queue[tuple[bytes, Addr]] = asyncio.Queue()
        self.sent: list[tuple[bytes, Addr]] = []

    async def recv(  # type: ignore[override]
        self, timeout: float | None = None
    ) -> tuple[bytes, Addr]:
        if timeout is None:
            return await self._recv_queue.get()
        return await asyncio.wait_for(self._recv_queue.get(), timeout)

    async def send(self, data: bytes, addr: Addr) -> None:  # type: ignore[override]
        self.sent.append((bytes(data), addr))

    def feed(self, addr: Addr, n: int = 0, size: int = HANDSHAKE_FRAME_SIZE) -> None:
        data = f"{addr[0]}:{addr[1]}-{n}".encode().ljust(size, b"\x00")[:size]
        self._recv_queue.put_nowait((data, addr))


class _Config:
    def __init__(self, max_inflight: int) -> None:
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
    """Fake server_handshake, by peer: "win" (default), "win_after2" (waits
    for a second frame), "fail", "timeout" (raises what the attempt deadline
    raises) or "stall" (until cancelled)."""

    def __init__(self, behaviour: dict[Addr, str]) -> None:
        self.behaviour = behaviour
        self.started: list[Addr] = []
        self.ended: list[Addr] = []

    async def __call__(self, view: Any, *_a: Any, **_k: Any) -> tuple[object, bytes]:
        addr: Addr = view._peer_addr
        self.started.append(addr)
        try:
            await view.recv()
            what = self.behaviour.get(addr, "win")
            if what == "fail":
                raise HandshakeError("scripted failure")
            if what == "timeout":
                raise TimeoutError
            if what == "stall":
                await asyncio.Event().wait()
            if what == "win_after2":
                await view.recv()
            return object(), f"pub-{addr[0]}:{addr[1]}".encode()
        finally:
            self.ended.append(addr)


async def _spin(until: Callable[[], bool], rounds: int = 1000) -> bool:
    """Yield to the event loop until ``until()`` holds (no wall-clock wait)."""
    for _ in range(rounds):
        if until():
            return True
        await asyncio.sleep(0)
    return until()


async def _yield(rounds: int = 50) -> None:
    for _ in range(rounds):
        await asyncio.sleep(0)


def _minutes() -> Callable[[], float]:
    """A clock that moves a minute per reading, so no rate bucket runs dry."""
    ticks = itertools.count(0.0, 60.0)
    return lambda: next(ticks)


class _Frozen:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


class _Run:
    """Run _accept_until_winner on a _Transport with a scripted handshake."""

    def __init__(
        self,
        script: _Script,
        *,
        max_inflight: int = 8,
        limiter: SourceLimiter | None = None,
    ) -> None:
        self.transport = _Transport()
        self.shutdown = asyncio.Event()
        self._max_inflight = max_inflight
        self._limiter = limiter
        self._patch = patch("dsm.crypto.handshake.server_handshake", new=script)
        self.task: asyncio.Future[Any] | None = None

    async def __aenter__(self) -> _Run:
        extra: dict[str, Any] = (
            {} if self._limiter is None else {"limiter": self._limiter}
        )
        coro = hsa._accept_until_winner(
            _Config(self._max_inflight),
            _Stub(),
            _Stub(),
            _Stub(),
            _Stub(),
            self.transport,
            self.shutdown,
            **extra,
        )
        self._patch.start()
        self.task = asyncio.ensure_future(coro)
        return self

    async def __aexit__(self, *exc: object) -> None:
        self.shutdown.set()
        try:
            assert self.task is not None
            await asyncio.wait_for(self.task, 5.0)
        finally:
            self._patch.stop()

    def done(self) -> bool:
        return self.task is not None and self.task.done()

    async def result(self) -> tuple[Any, Any, Any]:
        assert self.task is not None
        return await asyncio.wait_for(self.task, 5.0)


async def test_wrong_size_datagrams_from_new_sources_take_no_slot() -> None:
    """(red today) Scanner noise and stray packets never start a worker."""
    script = _Script({})
    async with _Run(script) as run:
        for i, size in enumerate((0, 1, 64, 148, 1399, 1401, 1472)):
            run.transport.feed((f"203.0.113.{i}", 4000 + i), size=size)
        assert await _spin(run.transport._recv_queue.empty)
        await _yield()
        assert script.started == []
        run.transport.feed(_WINNER)
        _, pub, _ = await run.result()
    assert pub == b"pub-198.51.100.7:51820"
    assert script.started == [_WINNER]
    assert run.transport.sent == []


async def test_failures_never_pause_routing_to_a_live_attempt() -> None:
    """(red today) F1: after failed attempts, a new source must not hold up
    frames for an attempt that is already running."""
    failers: list[Addr] = [(f"203.0.113.{i}", 1000 + i) for i in range(1, 6)]
    newcomer: Addr = ("203.0.113.9", 1009)
    script = _Script(
        {_WINNER: "win_after2", newcomer: "stall", **{a: "fail" for a in failers}}
    )
    async with _Run(script) as run:
        run.transport.feed(_WINNER)
        assert await _spin(lambda: _WINNER in script.started)
        for addr in failers:
            run.transport.feed(addr)
            assert await _spin(lambda a=addr: a in script.ended), f"{addr} was held up"
        run.transport.feed(newcomer)
        run.transport.feed(_WINNER, n=1)
        assert await _spin(run.done), "the running attempt's next frame was held up"
        _, pub, _ = await run.result()
    assert pub == b"pub-198.51.100.7:51820"


async def test_frames_for_a_running_attempt_are_routed_whatever_their_size() -> None:
    """Review Focus 3: only a new source's first datagram is size-checked."""
    script = _Script({_WINNER: "win_after2"})
    async with _Run(script) as run:
        run.transport.feed(_WINNER)
        assert await _spin(lambda: _WINNER in script.started)
        run.transport.feed(_WINNER, n=1, size=100)
        _, pub, _ = await run.result()
    assert pub == b"pub-198.51.100.7:51820"


async def test_a_third_attempt_from_one_address_takes_no_slot() -> None:
    """(red today) One address may run at most two attempts at once."""
    ip = "203.0.113.50"
    a, b, c = (ip, 1), (ip, 2), (ip, 3)
    script = _Script({a: "stall", b: "stall", c: "stall"})
    async with _Run(script) as run:
        for addr in (a, b, c):
            run.transport.feed(addr)
        assert await _spin(
            lambda: run.transport._recv_queue.empty() and len(script.started) >= 2
        )
        await _yield()
        assert script.started == [a, b]
        run.transport.feed(_WINNER)
        _, pub, _ = await run.result()
    assert pub == b"pub-198.51.100.7:51820"


async def test_every_way_an_attempt_ends_gives_its_address_back() -> None:
    """Review Focus 2: a failed, timed-out or cancelled attempt gives its
    address back. The limiter lives for the whole run, so a leak would lock
    the address out until restart."""
    ip = "203.0.113.60"
    limiter = SourceLimiter(clock=_minutes())
    failed, timed_out, loser_1, loser_2 = (ip, 1), (ip, 2), (ip, 3), (ip, 4)
    script = _Script(
        {failed: "fail", timed_out: "timeout", loser_1: "stall", loser_2: "stall"}
    )
    async with _Run(script, limiter=limiter) as run:
        run.transport.feed(failed)
        assert await _spin(lambda: failed in script.ended)
        run.transport.feed(timed_out)
        assert await _spin(lambda: timed_out in script.ended)
        run.transport.feed(loser_1)
        run.transport.feed(loser_2)
        assert await _spin(lambda: len(script.started) == 4)
        run.transport.feed(_WINNER)
        await run.result()  # the two stalls are cancelled as losers
    # The next accept cycle shares the limiter, as in run_server.
    later = _Script({(ip, 5): "stall", (ip, 6): "stall"})
    async with _Run(later, limiter=limiter) as run2:
        run2.transport.feed((ip, 5))
        run2.transport.feed((ip, 6))
        assert await _spin(lambda: len(later.started) == 2)


async def test_the_overall_budget_limits_new_attempts() -> None:
    """(red today) All addresses together start 8 at once, then 4 a second."""
    clock = _Frozen()
    sources: list[Addr] = [(f"203.0.113.{i}", 2000 + i) for i in range(10)]
    script = _Script({s: "stall" for s in sources})
    async with _Run(script, max_inflight=16, limiter=SourceLimiter(clock=clock)) as run:
        for s in sources[:9]:
            run.transport.feed(s)
        assert await _spin(
            lambda: run.transport._recv_queue.empty() and len(script.started) >= 8
        )
        await _yield()
        assert script.started == sources[:8]
        clock.now += 0.25
        run.transport.feed(sources[9])
        assert await _spin(lambda: sources[9] in script.started)


class _CancelsNewWorkers(_Transport):
    """Each time the demux reads, cancel every worker it has made since the
    last read. This runs inside the demux's own step, so each worker is
    cancelled before its first step, as a loser can be when the losers are
    cancelled right after it was made."""

    def __init__(self, workers: set[asyncio.Task[None]]) -> None:
        super().__init__()
        self._workers = workers
        self.cancelled: list[asyncio.Task[None]] = []

    async def recv(  # type: ignore[override]
        self, timeout: float | None = None
    ) -> tuple[bytes, Addr]:
        for task in list(self._workers):
            if task not in self.cancelled:
                task.cancel()
                self.cancelled.append(task)
        return await super().recv(timeout)


async def test_a_worker_cancelled_before_it_runs_gives_its_address_back() -> None:
    """Review Focus 2: a worker whose body never ran still frees its slot and
    its address. The limiter lives for the whole run, so a leak here would
    lock the address out until restart."""
    ip = "203.0.113.70"
    limiter = SourceLimiter(clock=_minutes())
    semaphore = asyncio.Semaphore(1)
    workers: set[asyncio.Task[None]] = set()
    inboxes: dict[Addr, asyncio.Queue[bytes]] = {}
    transport = _CancelsNewWorkers(workers)
    winner: asyncio.Future[Any] = asyncio.get_running_loop().create_future()
    script = _Script({})
    transport.feed((ip, 1))
    with patch("dsm.crypto.handshake.server_handshake", new=script):
        demux = asyncio.ensure_future(
            hsa._demux_loop(
                _Config(1),
                _Stub(),
                _Stub(),
                _Stub(),
                _Stub(),
                transport,
                winner,
                asyncio.Event(),
                workers,
                semaphore,
                inboxes,
                limiter,
            )
        )
        try:
            assert await _spin(lambda: len(transport.cancelled) == 1)
            assert await _spin(lambda: transport.cancelled[0].done())
            await _yield()
        finally:
            demux.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await demux
    assert transport.cancelled[0].cancelled()
    assert script.started == []  # the worker's body never ran
    assert not semaphore.locked()
    assert inboxes == {}
    # As before the attempt: the address may run its full two at once.
    assert limiter.try_start(ip)
    assert limiter.try_start(ip)
