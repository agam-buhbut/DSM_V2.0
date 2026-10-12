"""Step S, slot hardening (spec §4): the gate plumbing, the slot rule, the TCP
first-frame deadline and shared charge, push-out over UDP and TCP, and the
start WARNING. Handshakes are scripted fakes; ages come from Step S's own
injected clock, never the limiter's (re-review I5); nothing waits on the wall
clock. Laptop: run with --noconftest (tests/conftest.py imports dsm.server,
which needs the new tuncore); the run_server tests are box-only.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import random
import struct
from collections.abc import Callable
from typing import Any
from unittest.mock import patch

import pytest

from dsm.core.config import MAX_INFLIGHT_HANDSHAKES
from dsm.core.log import RepeatLog
from dsm.crypto.handshake import HANDSHAKE_FRAME_SIZE, VerifiedClient
from dsm.net import handshake_acceptor as hsa
from dsm.net.handshake_gate import (
    GLOBAL_START_BURST,
    GLOBAL_START_RATE,
    IN_SESSION_START_BURST,
    PER_SOURCE_BURST,
    PER_SOURCE_INFLIGHT,
    GateKeys,
    HandshakeGate,
    SourceLimiter,
    compute_mac1,
    stamp_msg1,
)
from dsm.net.session_slot import SessionSlot
from dsm.net.transport.tcp import TCPTransport
from dsm.net.transport.udp import UDPTransport
from tests.test_handshake_acceptor_limits import (
    _Config,
    _Frozen,
    _minutes,
    _spin,
    _Stub,
    _yield,
)
from tests.test_tcp_accept_concurrency import _Conn


def test_shared_false_charges_only_the_per_address_limits() -> None:
    limiter = SourceLimiter(clock=_Frozen())
    for i in range(int(GLOBAL_START_BURST)):
        assert limiter.try_start(f"203.0.113.{i}")
    assert not limiter.try_start("203.0.113.200")  # the overall limit is spent
    # A TCP connection at accept pays only its address's limits.
    assert limiter.try_start("198.51.100.9", shared=False)


def test_try_shared_charges_the_overall_and_newcomer_limits() -> None:
    limiter = SourceLimiter(clock=_Frozen())
    for i in range(int(IN_SESSION_START_BURST)):
        assert limiter.try_shared(f"198.51.100.{i}", in_session=True)
    assert not limiter.try_shared("198.51.100.50", in_session=True)
    # That refusal spent nothing: the overall tokens the newcomer calls did
    # not use are all still there.
    left = int(GLOBAL_START_BURST) - int(IN_SESSION_START_BURST)
    for i in range(left):
        assert limiter.try_shared(f"198.51.100.{100 + i}")
    assert not limiter.try_shared("198.51.100.200")


def test_an_inherited_share_skips_the_cap_and_adds_nothing() -> None:
    limiter = SourceLimiter(clock=_Frozen())
    ip = "198.51.100.9"
    for _ in range(PER_SOURCE_INFLIGHT):
        assert limiter.try_start(ip)
    assert not limiter.try_start(ip)  # at the in-flight cap
    assert limiter.try_start(ip, inherits_share=True)
    for _ in range(PER_SOURCE_INFLIGHT):
        limiter.finish(ip)
    with pytest.raises(RuntimeError):
        limiter.finish(ip)  # the inherit added no running attempt


def test_an_inherited_share_still_needs_the_address_rate() -> None:
    limiter = SourceLimiter(clock=_Frozen())
    ip = "198.51.100.9"
    for _ in range(PER_SOURCE_INFLIGHT):
        assert limiter.try_start(ip)
    for _ in range(int(PER_SOURCE_BURST) - PER_SOURCE_INFLIGHT):
        assert limiter.try_start(ip, inherits_share=True)
    assert not limiter.try_start(ip, inherits_share=True)  # the rate is spent


def test_a_tcp_inherit_pays_only_its_address() -> None:
    limiter = SourceLimiter(clock=_Frozen())
    ip = "198.51.100.9"
    for _ in range(PER_SOURCE_INFLIGHT):
        assert limiter.try_start(ip, shared=False)
    for i in range(int(GLOBAL_START_BURST)):
        assert limiter.try_shared(f"203.0.113.{i}")  # spend the overall limit
    assert limiter.try_start(ip, shared=False, inherits_share=True)


def test_an_inherit_still_pays_the_overall_limit() -> None:
    limiter = SourceLimiter(clock=_Frozen())
    ip = "198.51.100.9"
    for _ in range(PER_SOURCE_INFLIGHT):
        assert limiter.try_start(ip, shared=False)
    for i in range(int(GLOBAL_START_BURST)):
        assert limiter.try_shared(f"203.0.113.{i}")  # spend the overall limit
    assert not limiter.try_start(ip, inherits_share=True)
    # The refusal spent no address token: the one rate token left is still
    # there for a start that needs only the address.
    assert limiter.try_start(ip, shared=False, inherits_share=True)


def test_an_inherit_takes_one_overall_token() -> None:
    limiter = SourceLimiter(clock=_Frozen())
    ip = "198.51.100.9"
    for _ in range(PER_SOURCE_INFLIGHT):
        assert limiter.try_start(ip, shared=False)
    assert limiter.try_start(ip, inherits_share=True)
    for i in range(int(GLOBAL_START_BURST) - 1):
        assert limiter.try_shared(f"203.0.113.{i}")
    assert not limiter.try_shared("203.0.113.200")


def test_an_in_session_inherit_takes_the_newcomer_token_too() -> None:
    limiter = SourceLimiter(clock=_Frozen())
    ip = "198.51.100.9"
    for _ in range(PER_SOURCE_INFLIGHT):
        assert limiter.try_start(ip, shared=False)
    assert limiter.try_start(ip, in_session=True, inherits_share=True)
    assert not limiter.try_shared("203.0.113.1", in_session=True)
    # The overall limit lost exactly one token to that inherit.
    for i in range(int(GLOBAL_START_BURST) - 1):
        assert limiter.try_shared(f"203.0.113.{10 + i}")
    assert not limiter.try_shared("203.0.113.200")


def test_a_per_address_only_start_ignores_in_session() -> None:
    limiter = SourceLimiter(clock=_Frozen())
    assert limiter.try_start("198.51.100.9", in_session=True, shared=False)
    # Nothing shared was spent: the one newcomer token and every overall
    # token are still there.
    assert limiter.try_shared("203.0.113.1", in_session=True)
    for i in range(int(GLOBAL_START_BURST) - 1):
        assert limiter.try_shared(f"203.0.113.{10 + i}")
    assert not limiter.try_shared("203.0.113.200")


def test_the_step_s_numbers() -> None:
    assert hsa._TCP_FIRST_FRAME_DEADLINE == 3.0
    assert hsa._PUSH_OUT_AFTER_S == 1.5
    assert hsa._SIGNING_ALLOWANCE_S == 0.25
    assert hsa._SERVER_SIGNING_TIME_S == 0.21


def test_slot_rule_conditions_2_and_3_hold_for_the_code_constants() -> None:
    w = hsa._PUSH_OUT_AFTER_S + hsa._SIGNING_ALLOWANCE_S
    # (3) The TPM signs faster than the overall limit lets strangers start.
    assert GLOBAL_START_RATE * hsa._SERVER_SIGNING_TIME_S < 1
    # (2) The deepest queue strangers can build drains inside W, for every
    # slot count the config allows (more slots never deepen it).
    for slots in range(1, MAX_INFLIGHT_HANDSHAKES + 1):
        assert min(slots, GLOBAL_START_BURST) * hsa._SERVER_SIGNING_TIME_S < w


def test_slot_rule_ok_checks_condition_1() -> None:
    assert hsa._slot_rule_ok(8)  # the default meets it: 8 > 4 x 1.75
    assert not hsa._slot_rule_ok(7)  # 7 is not more than 7
    assert not hsa._slot_rule_ok(1)
    assert hsa._slot_rule_ok(16)


Addr = tuple[str, int]
_A: Addr = ("203.0.113.1", 40001)
_B: Addr = ("203.0.113.2", 40002)
_C: Addr = ("203.0.113.3", 40003)
_D: Addr = ("203.0.113.4", 40004)
_KEYS = GateKeys.from_ca_der(bytes.fromhex("3003020101"), "dsm-test-server")
_NOW = 1_800_000_000.0
_MSG2 = b"msg2".ljust(HANDSHAKE_FRAME_SIZE, b"\x00")
_HOLDER = VerifiedClient(cn="dsm-a-client", noise_static=b"\x01" * 32)


class _Ledger(SourceLimiter):
    """The run's limiter, noting every finish() by address before it runs, so
    a test sees each share given back exactly once (a second one shows up
    here even though the limiter then raises)."""

    def __init__(self, *, clock: Callable[[], float]) -> None:
        super().__init__(clock=clock)
        self.finished: list[str] = []

    def finish(self, ip: str) -> None:
        self.finished.append(ip)
        super().finish(ip)


def _inflight(limiter: SourceLimiter, ip: str) -> int:
    """The limiter's running count for ``ip`` (no public getter exists)."""
    src = limiter._sources.get(ip)
    return 0 if src is None else src.inflight


async def _slots_free(semaphore: asyncio.Semaphore) -> int:
    """Free slots, counted by taking them all and giving them back."""
    taken = 0
    while not semaphore.locked():
        await semaphore.acquire()
        taken += 1
    for _ in range(taken):
        semaphore.release()
    return taken


class _Ticks:
    """A Step S clock that gives the listed readings in order, then the last
    one for ever: two starts handled in one loop step can get different
    times."""

    def __init__(self, *readings: float) -> None:
        self._readings = list(readings)

    def __call__(self) -> float:
        if len(self._readings) > 1:
            return self._readings.pop(0)
        return self._readings[0]


def _real_gate() -> HandshakeGate:
    return HandshakeGate(_KEYS, clock=_Frozen(), wall_clock=lambda: _NOW)


def _good(seed: int, keys: GateKeys = _KEYS) -> bytes:
    """A msg1 stamped as a wire v2 client stamps it (the fakes never read
    the Noise part)."""
    frame = bytearray(random.Random(seed).randbytes(HANDSHAKE_FRAME_SIZE))
    stamp_msg1(frame, compute_mac1(bytes(frame[:32]), keys, _NOW))
    return bytes(frame)


def _peer_of(transport: Any) -> Addr:
    """The peer of a UDP view, a first-frame TCP view or a bare connection."""
    if isinstance(transport, hsa._PerPeerUDPView):
        return transport._peer_addr
    return getattr(transport, "_real", transport).peer


class _Hs:
    """Fake server_handshake for UDP views and TCP connections. Reads msg1;
    waits while the test holds its "TPM" (msg2 not sent: still signing);
    sends msg2; with "admit" passes the session check; sends msg2 again
    once its resend event is set; then stalls until cancelled, or returns
    with "win"."""

    def __init__(self, behaviour: dict[Addr, str] | None = None) -> None:
        self.behaviour = behaviour if behaviour is not None else {}
        self.tpm: dict[Addr, asyncio.Event] = {}
        self.resend: dict[Addr, asyncio.Event] = {}
        self.started: list[Addr] = []
        self.sent_msg2: list[Addr] = []
        self.cancelled: list[Addr] = []

    async def __call__(
        self, transport: Any, *_a: Any, admit_client: Any = None, **_k: Any
    ) -> tuple[object, bytes]:
        peer = _peer_of(transport)
        self.started.append(peer)
        try:
            await transport.recv()
            hold = self.tpm.get(peer)
            if hold is not None:
                await hold.wait()
            await self._send(transport, peer)
            what = self.behaviour.get(peer, "stall")
            if what == "admit":
                admit_client(_HOLDER)
            again = self.resend.get(peer)
            if again is not None:
                await again.wait()
                await self._send(transport, peer)
            if what != "win":
                await asyncio.Event().wait()
            return object(), f"pub-{peer[0]}:{peer[1]}".encode()
        except asyncio.CancelledError:
            self.cancelled.append(peer)
            raise

    async def _send(self, transport: Any, peer: Addr) -> None:
        if isinstance(transport, UDPTransport):
            await transport.send(_MSG2, peer)
        else:
            await transport.send(_MSG2)
        self.sent_msg2.append(peer)


class _Tcp:
    """_tcp_admit_loop on an in-memory connection queue. The pool, the open
    connections and the limiter stay here for the test; the patched
    handshake stays in place for the whole run; the gate is the run's real
    one (mac1 checked) or none. Leaving cancels the loop and every worker and
    waits for them, so every done-callback has run; errors raised inside
    callbacks land in ``loop_errors``."""

    def __init__(
        self,
        hs: _Hs,
        *,
        max_inflight: int = 1,
        gate: bool = True,
        limiter: SourceLimiter | None = None,
        no_slot: bool = False,
        session_live: bool = False,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.max_inflight = max_inflight
        self.connections: asyncio.Queue[tuple[TCPTransport, Addr]] = asyncio.Queue()
        self.semaphore = asyncio.Semaphore(max_inflight)
        self.workers: set[asyncio.Task[None]] = set()
        self.open_conns: dict[Addr, TCPTransport] = {}
        self.attempts: dict[asyncio.Task[None], Any] = {}
        self.limiter = limiter if limiter is not None else _Ledger(clock=_minutes())
        self.gate = _real_gate() if gate else None
        self.slot = None if no_slot else SessionSlot()
        self.session_live = session_live
        self.clock: Callable[[], float] = clock if clock is not None else _Frozen()
        # Loop keywords added by later tasks (Task 5: attempts and clock).
        self.extra: dict[str, Any] = {}
        self.loop_errors: list[dict[str, Any]] = []
        self.task: asyncio.Future[None] | None = None
        self._patch = patch("dsm.crypto.handshake.server_handshake", new=hs)
        self._old_handler: Any = None

    def connect(self, peer: Addr, frames: list[bytes] | None = None) -> _Conn:
        conn = _Conn(peer, frames)
        self.connections.put_nowait((conn, peer))
        return conn

    async def __aenter__(self) -> _Tcp:
        loop = asyncio.get_running_loop()
        self._old_handler = loop.get_exception_handler()
        loop.set_exception_handler(lambda _l, ctx: self.loop_errors.append(ctx))
        self._patch.start()
        winner: asyncio.Future[Any] = loop.create_future()
        self.task = asyncio.ensure_future(
            hsa._tcp_admit_loop(
                _Config(self.max_inflight),
                _Stub(),
                _Stub(),
                _Stub(),
                _Stub(),
                self.connections,
                winner,
                self.workers,
                self.semaphore,
                self.open_conns,
                self.limiter,
                slot=self.slot,
                session_live=self.session_live,
                gate=self.gate,
                **self.extra,
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
            asyncio.get_running_loop().set_exception_handler(self._old_handler)


def _spend_overall(limiter: SourceLimiter) -> None:
    for i in range(int(GLOBAL_START_BURST)):
        assert limiter.try_shared(f"192.0.2.{i}")


def _overall_left(limiter: SourceLimiter) -> int:
    """Overall tokens left (frozen clock), counted by spending them."""
    left = 0
    while limiter.try_shared(f"198.18.0.{left}"):
        left += 1
    return left


class _Writer:
    """The write side of an in-memory TCP stream: only close() is used."""

    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


async def test_a_silent_tcp_connection_is_cut_at_the_first_frame_deadline(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger="dsm.net.handshake_acceptor")
    hs = _Hs()
    limiter = _Ledger(clock=_Frozen())
    # A deadline of 0 fires on the next loop pass: no real time passes.
    with (
        patch.object(hsa, "_TCP_FIRST_FRAME_DEADLINE", 0.0),
        patch.object(
            hsa,
            "_tcp_first_frame_log",
            RepeatLog(hsa.log, logging.DEBUG, clock=_Frozen()),
        ),
    ):
        async with _Tcp(hs, limiter=limiter) as run:
            first = run.connect(_A)
            assert await _spin(lambda: first.closed)
            assert await _slots_free(run.semaphore) == 1
            second = run.connect(_B)
            assert await _spin(lambda: second.closed)
            assert run.gate is not None and run.gate.load.under_load(0)
    assert hs.started == []
    assert limiter.finished == [_A[0], _B[0]]
    assert _overall_left(limiter) == int(GLOBAL_START_BURST)  # no shared token
    lines = [r for r in caplog.records if "no first frame" in r.getMessage()]
    assert [r.levelno for r in lines] == [logging.DEBUG]  # one line per 10 s
    assert "203.0.113" not in lines[0].getMessage()


async def test_half_a_first_frame_is_cut_at_the_deadline_too() -> None:
    reader = asyncio.StreamReader()
    reader.feed_data(struct.pack("!I", HANDSHAKE_FRAME_SIZE) + b"\x00" * 100)
    writer = _Writer()
    conn = TCPTransport.from_streams(reader, writer)  # type: ignore[arg-type]
    hs = _Hs()
    limiter = _Ledger(clock=_minutes())
    with patch.object(hsa, "_TCP_FIRST_FRAME_DEADLINE", 0.0):
        async with _Tcp(hs, limiter=limiter) as run:
            run.connections.put_nowait((conn, _A))
            assert await _spin(lambda: writer.closed)
    assert hs.started == []
    assert limiter.finished == [_A[0]]
    assert _inflight(limiter, _A[0]) == 0
    assert run.gate is not None and run.gate.load.under_load(0)
    assert run.loop_errors == []


async def test_a_bad_first_frame_is_closed_and_spends_no_shared_token() -> None:
    hs = _Hs()
    limiter = _Ledger(clock=_Frozen())
    other_ca = GateKeys.from_ca_der(b"another CA", "dsm-test-server")
    async with _Tcp(hs, limiter=limiter) as run:
        short = run.connect(_A, [b"\x00" * 100])
        assert await _spin(lambda: short.closed)
        bad = run.connect(_B, [_good(2, other_ca)])
        assert await _spin(lambda: bad.closed)
        assert run.gate is not None and not run.gate.load.under_load(0)  # noise
    assert hs.started == []
    assert limiter.finished == [_A[0], _B[0]]  # each gave its share back once
    assert _overall_left(limiter) == int(GLOBAL_START_BURST)
    assert run.loop_errors == []


async def test_a_good_first_frame_spends_exactly_one_shared_token() -> None:
    # Green before and after this task: it pins "charged once, not twice".
    hs = _Hs()
    limiter = _Ledger(clock=_Frozen())
    async with _Tcp(hs, limiter=limiter) as run:
        conn = run.connect(_A, [_good(1)])
        assert await _spin(lambda: _A in hs.sent_msg2)
        assert conn._frames.empty()
    assert _overall_left(limiter) == int(GLOBAL_START_BURST) - 1


async def test_a_good_first_frame_is_closed_as_trouble_when_limits_refuse() -> None:
    hs = _Hs()
    limiter = _Ledger(clock=_Frozen())
    _spend_overall(limiter)
    async with _Tcp(hs, limiter=limiter) as run:
        conn = run.connect(_A, [_good(1)])
        assert await _spin(lambda: conn.closed)
        # Its first frame was read: refused after mac1, not at accept.
        assert conn._frames.empty()
        assert run.gate is not None and run.gate.load.under_load(0)
        assert await _slots_free(run.semaphore) == 1
    assert hs.started == []
    assert limiter.finished == [_A[0]]
    assert run.loop_errors == []
    # The refusal gave back the slot and the share but not the address's rate
    # token: it has the rest of its burst left, not all of it.
    assert _inflight(limiter, _A[0]) == 0
    more = 0
    while limiter.try_start(_A[0], shared=False):
        limiter.finish(_A[0])
        more += 1
    assert more == int(PER_SOURCE_BURST) - 1


async def test_in_a_session_the_first_frame_also_pays_the_newcomer_limit() -> None:
    hs = _Hs()
    async with _Tcp(
        hs, max_inflight=8, limiter=_Ledger(clock=_Frozen()), session_live=True
    ) as run:
        run.connect(_A, [_good(1)])
        assert await _spin(lambda: _A in hs.sent_msg2)
        second = run.connect(_B, [_good(2)])
        assert await _spin(lambda: second.closed)
        assert second._frames.empty()  # charged after its first frame
    assert _B not in hs.started


async def test_without_the_gate_a_tcp_connection_pays_everything_at_accept() -> None:
    # Green before and after: without a gate nothing changes (spec §4.2).
    hs = _Hs()
    limiter = _Ledger(clock=_Frozen())
    _spend_overall(limiter)
    async with _Tcp(hs, limiter=limiter, gate=False) as run:
        conn = run.connect(_A, [_good(1)])
        assert await _spin(lambda: conn.closed)
        assert not conn._frames.empty()  # closed at accept, never read
    assert hs.started == []
    assert limiter.finished == []


async def test_shutdown_while_waiting_for_the_first_frame_is_not_trouble() -> None:
    hs = _Hs()
    limiter = _Ledger(clock=_Frozen())
    # The real 3 s deadline: the shutdown comes long before it.
    async with _Tcp(hs, limiter=limiter) as run:
        conn = run.connect(_A)
        assert await _spin(lambda: bool(conn._frames._getters))  # worker is reading
    # Leaving the block cancelled the admit loop and the worker.
    assert conn.closed
    assert hs.started == []
    assert limiter.finished == [_A[0]]
    assert _inflight(limiter, _A[0]) == 0
    assert run.gate is not None and not run.gate.load.under_load(0)
    assert _overall_left(limiter) == int(GLOBAL_START_BURST)
    assert await _slots_free(run.semaphore) == 1
    assert run.loop_errors == []


async def test_a_frame_landing_as_the_deadline_fires_is_cut_as_a_timeout() -> None:
    hs = _Hs()
    limiter = _Ledger(clock=_Frozen())
    with patch.object(hsa, "_TCP_FIRST_FRAME_DEADLINE", 0.0):
        async with _Tcp(hs, limiter=limiter) as run:
            conn = run.connect(_A)
            assert await _spin(lambda: bool(conn._frames._getters))
            # The deadline's timer fires on the next loop pass. The read is
            # still waiting now, and the frame lands before the timer runs:
            # the timer wins, the frame stays unread.
            assert not conn._frames._getters[0].done()
            conn._frames.put_nowait(_good(1))
            assert await _spin(lambda: conn.closed)
            assert await _slots_free(run.semaphore) == 1
    assert not conn._frames.empty()
    assert hs.started == []
    assert limiter.finished == [_A[0]]
    assert _inflight(limiter, _A[0]) == 0
    assert run.gate is not None and run.gate.load.under_load(0)
    assert _overall_left(limiter) == int(GLOBAL_START_BURST)  # no shared token
    assert run.loop_errors == []
