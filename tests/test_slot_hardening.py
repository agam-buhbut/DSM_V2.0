"""Step S, slot hardening (spec §4): the gate plumbing, the slot rule, the TCP
first-frame deadline and shared charge, and push-out over UDP and TCP.
Handshakes are scripted fakes; ages come from Step S's own injected clock,
never the limiter's (re-review I5); nothing waits on the wall clock.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import random
import struct
from collections.abc import Callable
from dataclasses import replace
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
    Msg1Verdict,
    SourceLimiter,
    compute_mac1,
    stamp_msg1,
)
from dsm.net.session_slot import SessionTable
from dsm.net.transport.tcp import TCPTransport
from dsm.net.transport.udp import UDPTransport
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

    def finish(self, ip: str, *, failed: bool = False) -> None:
        self.finished.append(ip)
        super().finish(ip, failed=failed)


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


_REAL_FIRST_FRAME_DEADLINE = hsa._TCP_FIRST_FRAME_DEADLINE
_FAR_FIRST_FRAME_DEADLINE = 3600.0


def _table(ever_confirmed: bool) -> SessionTable:
    """The run's session table, giving _HOLDER's CN an address. With
    ``ever_confirmed`` a CN connected earlier in this run, so new starts pay
    the newcomer limit (spec §3.7 E1)."""
    table = SessionTable([_HOLDER.cn])
    if ever_confirmed:
        held_by = object()
        table.admit(held_by, _HOLDER)
        table.confirm(held_by)
    return table


class _Tcp:
    """_admit_tcp on an in-memory connection queue. The pool, the open
    connections, the records and the limiter stay here for the test; the
    patched handshake stays in place for the whole run; the gate is the
    run's real one (mac1 checked) or none; ``clock`` is Step S's own.
    The first-frame deadline is put far off for the run, so no assert races
    real time, unless the test patched it already (the deadline tests use 0).
    Leaving cancels the loop and every worker and waits for them, so every
    done-callback has run; errors raised inside callbacks land in
    ``loop_errors``."""

    def __init__(
        self,
        hs: _Hs,
        *,
        max_inflight: int = 1,
        gate: bool = True,
        limiter: SourceLimiter | None = None,
        ever_confirmed: bool = False,
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
        self.table = _table(ever_confirmed)
        self.clients: list[Any] = []
        self._frozen: _Frozen = clock if isinstance(clock, _Frozen) else _Frozen()
        self.clock: Callable[[], float] = clock if clock is not None else self._frozen
        self.extra: dict[str, Any] = {"attempts": self.attempts, "clock": self.clock}
        self.loop_errors: list[dict[str, Any]] = []
        self.task: asyncio.Future[None] | None = None
        self._patch = patch("dsm.crypto.handshake.server_handshake", new=hs)
        self._deadline_patch: Any = None
        self._old_handler: Any = None

    def at(self, t: float) -> None:
        """Set Step S's frozen clock to ``t``."""
        assert self.clock is self._frozen, "this run has its own clock"
        self._frozen.now = t

    def connect(self, peer: Addr, frames: list[bytes] | None = None) -> _Conn:
        conn = _Conn(peer, frames)
        self.connections.put_nowait((conn, peer))
        return conn

    async def __aenter__(self) -> _Tcp:
        loop = asyncio.get_running_loop()
        self._old_handler = loop.get_exception_handler()
        loop.set_exception_handler(lambda _l, ctx: self.loop_errors.append(ctx))
        self._patch.start()
        if hsa._TCP_FIRST_FRAME_DEADLINE == _REAL_FIRST_FRAME_DEADLINE:
            self._deadline_patch = patch.object(
                hsa, "_TCP_FIRST_FRAME_DEADLINE", _FAR_FIRST_FRAME_DEADLINE
            )
            self._deadline_patch.start()
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
            if self._deadline_patch is not None:
                self._deadline_patch.stop()
            self._patch.stop()
            asyncio.get_running_loop().set_exception_handler(self._old_handler)


def _spend_overall(limiter: SourceLimiter) -> None:
    for i in range(int(GLOBAL_START_BURST)):
        assert limiter.try_shared(f"192.0.2.{i}")


def _spend_rate(limiter: _Ledger, ip: str) -> None:
    """Use up ``ip``'s start tokens (a frozen limiter clock never refills
    them) and leave it with no running attempt. The base ``finish`` is used,
    so the ledger notes nothing."""
    for _ in range(int(PER_SOURCE_BURST)):
        assert limiter.try_start(ip, shared=False)
        SourceLimiter.finish(limiter, ip)


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
        hs, max_inflight=8, limiter=_Ledger(clock=_Frozen()), ever_confirmed=True
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
    # The deadline is far off: only the shutdown can end the wait.
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


class _OneStepSock(_Transport):
    """The run's UDP socket in memory. recv() returns at once, with no await,
    while datagrams are queued, so the demux handles several new sources in
    one step of its task on every Python version (3.11's wait_for would
    yield between them)."""

    async def recv(  # type: ignore[override]
        self, timeout: float | None = None
    ) -> tuple[bytes, Addr]:
        if not self._recv_queue.empty():
            return self._recv_queue.get_nowait()
        return await super().recv(timeout)


class _AdmitGate(HandshakeGate):
    """The run's gate, admitting every 1400-byte msg1 as a good mac1 (and,
    under load, a good mac2) would: push-out is under test here, not the
    cookie round trip, which has its own tests. Notes the load it was asked
    with."""

    def __init__(self) -> None:
        super().__init__(
            GateKeys(mac1_key=bytes(32), cookie_key=bytes(32)),
            clock=_Frozen(),
            wall_clock=lambda: _NOW,
        )
        self.under_load_seen: list[bool] = []

    def check_msg1(self, frame: bytes, src: Addr, *, under_load: bool) -> Msg1Verdict:
        del frame, src
        self.under_load_seen.append(under_load)
        return Msg1Verdict.ADMIT


class _Udp:
    """_demux on an in-memory socket. Pool, inboxes, records, the table and
    the limiter stay here for the test; the patched handshake stays in place
    for the whole run; ``clock`` is Step S's own; ``ever_confirmed``: a CN
    connected earlier in this run (spec §3.7 E1). Leaving cancels the demux
    and every worker and waits for them, so every done-callback has run."""

    def __init__(
        self,
        hs: _Hs,
        *,
        max_inflight: int = 1,
        gate: bool = True,
        limiter: SourceLimiter | None = None,
        ever_confirmed: bool = False,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.max_inflight = max_inflight
        self.sock = _OneStepSock()
        self.semaphore = asyncio.Semaphore(max_inflight)
        self.workers: set[asyncio.Task[None]] = set()
        self.inboxes: dict[Addr, asyncio.Queue[bytes]] = {}
        self.attempts: dict[asyncio.Task[None], Any] = {}
        self.limiter = limiter if limiter is not None else _Ledger(clock=_minutes())
        self.gate = _AdmitGate() if gate else None
        self.table = _table(ever_confirmed)
        self.clients: list[Any] = []
        self.clock: Any = clock if clock is not None else _Frozen()
        self.loop_errors: list[dict[str, Any]] = []
        self.task: asyncio.Future[None] | None = None
        self._patch = patch("dsm.crypto.handshake.server_handshake", new=hs)
        self._old_handler: Any = None

    def feed(self, addr: Addr, n: int = 0) -> None:
        self.sock.feed(addr, n)

    async def __aenter__(self) -> _Udp:
        loop = asyncio.get_running_loop()
        self._old_handler = loop.get_exception_handler()
        loop.set_exception_handler(lambda _l, ctx: self.loop_errors.append(ctx))
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
                attempts=self.attempts,
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
            asyncio.get_running_loop().set_exception_handler(self._old_handler)


async def _started(run: _Udp, hs: _Hs, addr: Addr, at: float) -> None:
    """Start ``addr`` at Step S time ``at`` and wait until its msg2 left."""
    run.clock.now = at
    run.feed(addr)
    assert await _spin(lambda: addr in hs.sent_msg2)


async def _settle(run: _Udp) -> None:
    """Let the demux take everything queued."""
    assert await _spin(run.sock._recv_queue.empty)
    await _yield()


_PUSHED = "pushed out a stalled handshake attempt to make room for a new one"


async def test_a_stalled_udp_attempt_is_pushed_out_only_once_old_enough(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="dsm.net.handshake_acceptor")
    hs = _Hs()
    run = _Udp(hs, max_inflight=2)
    with patch.object(
        hsa, "_push_out_log", RepeatLog(hsa.log, logging.INFO, clock=run.clock)
    ):
        async with run:
            await _started(run, hs, _A, 0.0)
            await _started(run, hs, _B, 0.5)
            run.clock.now = 1.4  # _A is 1.4 s old: not yet
            run.feed(_C)
            await _settle(run)
            assert _C not in hs.started and hs.cancelled == []
            run.clock.now = 1.5  # _A is 1.5 s old, _B only 1.0 s
            run.feed(_C, 1)  # _C's msg1 resend
            assert await _spin(lambda: _C in hs.sent_msg2)
            assert hs.cancelled == [_A]
            assert run.gate is not None and run.gate.under_load_seen[-1]
    lines = [r for r in caplog.records if r.getMessage().startswith(_PUSHED)]
    assert [(r.levelno, r.getMessage()) for r in lines] == [(logging.INFO, _PUSHED)]


async def test_nothing_is_pushed_out_while_a_slot_is_free() -> None:
    hs = _Hs()
    async with _Udp(hs, max_inflight=3) as run:
        await _started(run, hs, _A, 0.0)
        await _started(run, hs, _B, 0.1)
        run.clock.now = 5.0
        run.feed(_C)
        assert await _spin(lambda: _C in hs.sent_msg2)
        assert hs.cancelled == []


async def test_a_msg2_resend_does_not_restart_the_age() -> None:
    hs = _Hs()
    hs.resend[_A] = asyncio.Event()
    async with _Udp(hs) as run:
        await _started(run, hs, _A, 0.0)
        run.clock.now = 1.4
        hs.resend[_A].set()
        assert await _spin(lambda: hs.sent_msg2.count(_A) == 2)
        run.clock.now = 1.5  # 1.5 s from its msg1, 0.1 s from the resend
        run.feed(_B)
        assert await _spin(lambda: _B in hs.sent_msg2)
        assert hs.cancelled == [_A]


async def test_an_attempt_waiting_for_its_signature_is_never_pushed_out() -> None:
    hs = _Hs()
    hs.tpm[_A] = asyncio.Event()  # msg2 waits in the TPM queue
    async with _Udp(hs) as run:
        run.feed(_A)
        assert await _spin(lambda: _A in hs.started)
        run.clock.now = 10.0  # far past every wait, but msg2 has not left
        run.feed(_B)
        await _settle(run)
        assert _B not in hs.started and hs.cancelled == []
        hs.tpm[_A].set()
        assert await _spin(lambda: _A in hs.sent_msg2)
        run.feed(_B, 1)
        assert await _spin(lambda: _B in hs.sent_msg2)
        assert hs.cancelled == [_A]


async def test_the_age_counts_from_msg1_even_when_msg2_left_late() -> None:
    hs = _Hs()
    hs.tpm[_A] = asyncio.Event()
    async with _Udp(hs) as run:
        run.feed(_A)
        assert await _spin(lambda: _A in hs.started)
        run.clock.now = 1.4
        hs.tpm[_A].set()
        assert await _spin(lambda: _A in hs.sent_msg2)
        run.clock.now = 1.5
        run.feed(_B)
        assert await _spin(lambda: _B in hs.sent_msg2)
        assert hs.cancelled == [_A]


async def test_an_attempt_past_admit_is_never_pushed_out() -> None:
    hs = _Hs({_A: "admit"})
    async with _Udp(hs) as run:
        run.feed(_A)
        assert await _spin(lambda: any(map(run.table.is_admitted, run.attempts)))
        run.clock.now = 5.0
        run.feed(_B)
        await _settle(run)
        assert _B not in hs.started and hs.cancelled == []


async def test_without_the_gate_nothing_is_pushed_out() -> None:
    hs = _Hs()
    x1, x2, x3 = ("203.0.113.50", 1), ("203.0.113.50", 2), ("203.0.113.50", 3)
    async with _Udp(hs, max_inflight=2, gate=False) as run:
        await _started(run, hs, x1, 0.0)
        await _started(run, hs, x2, 0.1)  # pool full and the address at its cap
        run.clock.now = 60.0
        run.feed(_B)
        run.feed(x3)
        await _settle(run)
        assert hs.started == [x1, x2] and hs.cancelled == []


async def test_the_limiters_clock_never_dates_an_attempt() -> None:
    # The limiter's clock moves a minute per reading; Step S's stays at 0.
    hs = _Hs()
    async with _Udp(hs, limiter=_Ledger(clock=_minutes())) as run:
        await _started(run, hs, _A, 0.0)
        run.feed(_B)
        await _settle(run)
        assert _B not in hs.started and hs.cancelled == []


async def test_two_full_pool_starts_in_one_step_push_out_two_attempts() -> None:
    hs = _Hs()
    limiter = _Ledger(clock=_minutes())
    async with _Udp(hs, max_inflight=2, limiter=limiter) as run:
        await _started(run, hs, _A, 0.0)
        await _started(run, hs, _B, 0.1)
        run.clock.now = 2.0
        run.feed(_C)
        run.feed(_D)  # both handled in one step of the demux
        assert await _spin(lambda: _C in hs.sent_msg2 and _D in hs.sent_msg2)
        assert sorted(hs.cancelled) == sorted([_A, _B])  # never one twice
        await _yield()
        assert await _slots_free(run.semaphore) == 0
    assert await _slots_free(run.semaphore) == 2  # exactly what it was
    assert run.attempts == {}  # every record left with its attempt
    assert sorted(limiter.finished) == sorted(a[0] for a in (_A, _B, _C, _D))
    assert all(_inflight(limiter, a[0]) == 0 for a in (_A, _B, _C, _D))
    assert run.loop_errors == []


async def test_a_clock_that_steps_back_pushes_nothing_out() -> None:
    hs = _Hs()
    async with _Udp(hs) as run:
        await _started(run, hs, _A, 5.0)
        run.clock.now = 1.0  # a negative age reads as too young
        run.feed(_B)
        await _settle(run)
        assert _B not in hs.started and hs.cancelled == []


async def test_the_msg2_hook_fires_once_over_two_sends() -> None:
    fired: list[int] = []
    real = _Transport()
    view = hsa._PerPeerUDPView(
        real, _A, asyncio.Queue(), on_msg2=lambda: fired.append(1)
    )
    await view.send(_MSG2, _B)
    await view.send(_MSG2, _B)  # a resend
    assert fired == [1]
    assert real.sent == [(_MSG2, _A), (_MSG2, _A)]


async def test_the_push_out_line_is_info_with_a_count_and_no_address(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="dsm.net.handshake_acceptor")
    hs = _Hs()
    run = _Udp(hs)
    with patch.object(
        hsa, "_push_out_log", RepeatLog(hsa.log, logging.INFO, clock=run.clock)
    ):
        async with run:
            await _started(run, hs, _A, 0.0)
            await _started(run, hs, _B, 2.0)  # pushes _A out
            await _started(run, hs, _C, 4.0)  # pushes _B out: counted, no line
            await _started(run, hs, _D, 13.0)  # pushes _C out: line with count
            assert hs.cancelled == [_A, _B, _C]
    lines = [
        r.getMessage() for r in caplog.records if r.getMessage().startswith(_PUSHED)
    ]
    assert lines == [_PUSHED, f"{_PUSHED} (1 more in the last 11 s)"]
    assert not any("203.0.113" in line for line in lines)


class _FeedOnMsg2Sock(_OneStepSock):
    """Queues ``then``'s msg1 the moment msg2 goes out to ``to``, and waits
    on its queue with no poll timer, so the demux takes ``then`` on the very
    next loop pass on every Python version."""

    def __init__(self, to: Addr, then: Addr) -> None:
        super().__init__()
        self._to = to
        self._then = then

    async def recv(  # type: ignore[override]
        self, timeout: float | None = None
    ) -> tuple[bytes, Addr]:
        del timeout  # leaving the run cancels the demux
        return await self._recv_queue.get()

    async def send(self, data: bytes, addr: Addr) -> None:  # type: ignore[override]
        await super().send(data, addr)
        if addr == self._to:
            self.feed(self._then)


def _cancels_asked_at_push_out(asked: list[int]) -> Callable[..., None]:
    """``hsa._push_out``, noting how many cancels its victim already had.

    The race tests assert ``asked == [1]`` first: that is their precondition
    (the victim's own deadline had already asked to cancel it when the
    push-out came). A failure there means the race was not set up, because
    the order in which the loop runs callbacks within one pass changed; it is
    not a give-back bug, and the asserts after it are not reached.
    """
    push_out = hsa._push_out

    def _spy(attempts: Any, victim: asyncio.Task[None], how: Any) -> None:
        asked.append(victim.cancelling())
        push_out(attempts, victim, how)

    return _spy


async def test_a_push_out_racing_the_attempts_own_deadline_gives_back_once() -> None:
    # _A's attempt deadline, patched to 0, fires on the loop pass after its
    # msg2 left, and _B's msg1 is taken in that same pass: the push-out comes
    # after the deadline asked to cancel _A and before _A ran again.
    hs = _Hs()
    limiter = _Ledger(clock=_minutes())
    asked: list[int] = []
    run = _Udp(hs, limiter=limiter, clock=_Ticks(0.0, 2.0))
    run.sock = _FeedOnMsg2Sock(_A, _B)
    with (
        patch.object(hsa, "_HANDSHAKE_ATTEMPT_DEADLINE", 0.0),
        patch.object(hsa, "_push_out", _cancels_asked_at_push_out(asked)),
    ):
        async with run:
            run.feed(_A)
            # _B took _A's slot, then hit its own 0 s deadline.
            assert await _spin(lambda: _B in hs.started and not run.workers)
            assert await _slots_free(run.semaphore) == 1
    assert asked == [1]  # the deadline had already asked: a real race
    assert hs.cancelled == [_A, _B]  # _B by its own deadline
    assert limiter.finished == [_A[0], _B[0]]  # each share given back once
    assert _inflight(limiter, _A[0]) == 0 and _inflight(limiter, _B[0]) == 0
    assert await _slots_free(run.semaphore) == 1
    assert run.attempts == {}
    assert run.loop_errors == []


async def test_an_own_address_push_out_racing_its_deadline_gives_back_nothing() -> None:
    # As above, in case 1: x1 passes its slot and its share to x3, so its
    # done-callback gives back neither, even when its own deadline fired too.
    x1, x2, x3 = ("203.0.113.50", 1), ("203.0.113.50", 2), ("203.0.113.50", 3)
    hs = _Hs()
    limiter = _Ledger(clock=_minutes())
    asked: list[int] = []
    # Step S times: x2 starts at 1.0, its msg2 is stamped 1.0, x1 at 0.0 (the
    # oldest), x3 at 2.0.
    run = _Udp(hs, max_inflight=2, limiter=limiter, clock=_Ticks(1.0, 1.0, 0.0, 2.0))
    run.sock = _FeedOnMsg2Sock(x1, x3)
    async with run:
        run.feed(x2)  # the usual 12 s deadline: still running at the end
        assert await _spin(lambda: x2 in hs.sent_msg2)
        with (
            patch.object(hsa, "_HANDSHAKE_ATTEMPT_DEADLINE", 0.0),
            patch.object(hsa, "_push_out", _cancels_asked_at_push_out(asked)),
        ):
            run.feed(x1)
            # x3 took x1's slot and share, then hit its own 0 s deadline.
            assert await _spin(lambda: limiter.finished == [x3[0]])
        assert asked == [1]
        assert hs.cancelled == [x1, x3]  # x3 by its own deadline
        assert _inflight(limiter, x3[0]) == 1  # x2's share only
        assert await _slots_free(run.semaphore) == 1  # x2 holds the other
    assert limiter.finished == [x3[0], x3[0]]  # x3's, then x2's at the end
    assert _inflight(limiter, x3[0]) == 0
    assert await _slots_free(run.semaphore) == 2
    assert run.attempts == {}
    assert run.loop_errors == []


async def test_a_shutdown_in_the_push_out_pass_gives_back_once() -> None:
    # The run stops in the loop pass of a push-out: _A is marked and
    # cancelled but has not run again, and _B has not run at all. Stopping
    # cancels both once more; each done-callback still runs once.
    hs = _Hs()
    limiter = _Ledger(clock=_minutes())
    asked: list[int] = []
    async with _Udp(hs, limiter=limiter) as run:
        await _started(run, hs, _A, 0.0)
        victim = next(iter(run.attempts))
        run.clock.now = 2.0
        with patch.object(hsa, "_push_out", _cancels_asked_at_push_out(asked)):
            run.feed(_B)
            assert await _spin(lambda: asked != [])
        assert not victim.done() and _B not in hs.started  # both still pending
        # Stop as the accept does: the demux first, then every worker, with
        # no loop pass in between.
        assert run.task is not None
        run.task.cancel()
        await hsa._cancel_and_drain(set(run.workers))
    assert asked == [0]  # nothing but the push-out had asked before
    assert hs.started == [_A] and hs.cancelled == [_A]  # _B never ran
    assert sorted(limiter.finished) == sorted([_A[0], _B[0]])
    assert _inflight(limiter, _A[0]) == 0 and _inflight(limiter, _B[0]) == 0
    assert await _slots_free(run.semaphore) == 1
    assert run.attempts == {}
    assert run.loop_errors == []


class _SendFails(_Transport):
    """The run's UDP socket, whose every send fails."""

    async def send(self, data: bytes, addr: Addr) -> None:  # type: ignore[override]
        raise OSError("network is unreachable")


async def test_the_msg2_hook_waits_until_msg2_really_left() -> None:
    fired: list[int] = []
    view = hsa._PerPeerUDPView(
        _SendFails(), _A, asyncio.Queue(), on_msg2=lambda: fired.append(1)
    )
    with pytest.raises(OSError):
        await view.send(_MSG2, _A)
    assert fired == []  # still signing: msg2 did not go out


_X = "203.0.113.50"  # one address, several ports


async def test_an_address_at_its_cap_pushes_out_its_oldest_and_keeps_share() -> None:
    hs = _Hs()
    limiter = _Ledger(clock=_minutes())
    async with _Udp(hs, max_inflight=8, limiter=limiter) as run:
        await _started(run, hs, (_X, 1), 0.0)
        await _started(run, hs, (_X, 2), 0.2)  # the address is at its cap
        await _started(run, hs, (_X, 3), 2.0)
        await _yield()
        assert hs.cancelled == [(_X, 1)]  # its own oldest
        # The victim gave back neither its slot nor its share.
        assert limiter.finished == []
        assert _inflight(limiter, _X) == 2  # exactly what it was
        assert await _slots_free(run.semaphore) == 6
    assert limiter.finished == [_X, _X]
    assert await _slots_free(run.semaphore) == 8
    assert run.attempts == {}
    assert run.loop_errors == []


async def test_case_1_comes_before_case_2_even_with_every_slot_full() -> None:
    hs = _Hs()
    limiter = _Ledger(clock=_minutes())
    async with _Udp(hs, max_inflight=3, limiter=limiter) as run:
        await _started(run, hs, _A, 0.0)  # the oldest of all
        await _started(run, hs, (_X, 1), 0.2)
        await _started(run, hs, (_X, 2), 0.4)  # pool full, _X at its cap
        await _started(run, hs, (_X, 3), 2.0)
        await _yield()
        assert hs.cancelled == [(_X, 1)]  # _X's own oldest, not _A
        assert limiter.finished == []
        assert await _slots_free(run.semaphore) == 0
    assert run.loop_errors == []


async def test_after_case_2_the_victim_gives_back_its_share_not_its_slot() -> None:
    hs = _Hs()
    limiter = _Ledger(clock=_minutes())
    async with _Udp(hs, limiter=limiter) as run:
        await _started(run, hs, _A, 0.0)
        await _started(run, hs, _B, 2.0)
        await _yield()
        assert hs.cancelled == [_A]
        assert limiter.finished == [_A[0]]
        assert _inflight(limiter, _A[0]) == 0
        assert await _slots_free(run.semaphore) == 0  # _B holds the slot
    assert sorted(limiter.finished) == sorted([_A[0], _B[0]])
    assert await _slots_free(run.semaphore) == 1
    assert run.attempts == {}
    assert run.loop_errors == []


async def test_a_spent_rate_refuses_an_own_address_push_out(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="dsm.net.handshake_gate")
    hs = _Hs()
    # The limiter's clock never moves, so _X's rate bucket (3) does not refill.
    limiter = _Ledger(clock=_Frozen())
    async with _Udp(hs, max_inflight=8, limiter=limiter) as run:
        await _started(run, hs, (_X, 1), 0.0)  # token 1
        await _started(run, hs, (_X, 2), 0.1)  # token 2
        await _started(run, hs, (_X, 3), 2.0)  # token 3, pushes out (_X, 1)
        run.clock.now = 4.0  # (_X, 2) is 3.9 s old: pushable
        run.feed((_X, 4))
        await _settle(run)
        await _yield()
        assert (_X, 4) not in hs.started  # no token left: refused
        assert hs.cancelled == [(_X, 1)]  # (_X, 2) left alone
        assert _inflight(limiter, _X) == 2
    assert any("started too many lately" in r.getMessage() for r in caplog.records)
    assert run.loop_errors == []


async def test_a_refused_newcomer_leaves_the_old_attempt_alone() -> None:
    hs = _Hs()
    limiter = _Ledger(clock=_Frozen())
    async with _Udp(hs, limiter=limiter) as run:
        await _started(run, hs, _A, 0.0)  # 1 overall token
        for i in range(int(GLOBAL_START_BURST) - 1):
            assert limiter.try_shared(f"192.0.2.{i}")  # the rest
        run.clock.now = 2.0
        run.feed(_B)  # _A is pushable, but _B's start is refused
        await _settle(run)
        assert _B not in hs.started and hs.cancelled == []
        assert await _slots_free(run.semaphore) == 0
    assert run.loop_errors == []


async def test_an_in_session_push_out_needs_the_newcomer_token_too(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="dsm.net.handshake_gate")
    hs = _Hs()
    clock = _Frozen()  # the limiter's: the newcomer token does not refill
    limiter = _Ledger(clock=clock)
    async with _Udp(hs, limiter=limiter, ever_confirmed=True) as run:
        await _started(run, hs, _A, 0.0)  # its start took the one newcomer token
        victim = next(iter(run.attempts))
        run.clock.now = 2.0  # _A is pushable
        run.feed(_B)
        await _settle(run)
        await _yield()
        assert _B not in hs.started and hs.cancelled == []
        assert not victim.done() and victim.cancelling() == 0
        assert list(run.attempts) == [victim]
        assert limiter.finished == []
        assert await _slots_free(run.semaphore) == 0  # _A still holds it
        assert any("while a session runs" in r.getMessage() for r in caplog.records)
        # The refusal spent nothing: with the token back, _B pushes _A out.
        clock.now = 1.0
        run.feed(_B, 1)
        assert await _spin(lambda: _B in hs.sent_msg2)
        assert hs.cancelled == [_A]
    assert sorted(limiter.finished) == sorted([_A[0], _B[0]])
    assert await _slots_free(run.semaphore) == 1
    assert run.attempts == {}
    assert run.loop_errors == []


async def test_two_own_address_starts_in_one_step_push_out_two_own_attempts() -> None:
    hs = _Hs()
    limiter = _Ledger(clock=_minutes())
    async with _Udp(hs, max_inflight=8, limiter=limiter) as run:
        await _started(run, hs, (_X, 1), 0.0)
        await _started(run, hs, (_X, 2), 0.1)
        run.clock.now = 2.0
        run.feed((_X, 3))
        run.feed((_X, 4))  # both handled in one step of the demux
        assert await _spin(lambda: (_X, 3) in hs.sent_msg2 and (_X, 4) in hs.sent_msg2)
        await _yield()
        assert sorted(hs.cancelled) == [(_X, 1), (_X, 2)]  # two, each once
        assert _inflight(limiter, _X) == 2
        assert limiter.finished == []
        assert await _slots_free(run.semaphore) == 6
    assert limiter.finished == [_X, _X]
    assert await _slots_free(run.semaphore) == 8
    assert run.attempts == {}
    assert run.loop_errors == []


async def _accepted(
    run: _Tcp, peer: Addr, at: float, frames: list[bytes] | None = None
) -> _Conn:
    """Queue a connection at Step S time ``at`` and wait for its record."""
    run.at(at)
    before = len(run.attempts)
    conn = run.connect(peer, frames)
    assert await _spin(lambda: len(run.attempts) == before + 1)
    return conn


async def test_a_silent_tcp_connection_is_pushed_out_when_the_pool_is_full() -> None:
    hs = _Hs()
    limiter = _Ledger(clock=_minutes())
    async with _Tcp(hs, limiter=limiter) as run:
        silent = await _accepted(run, _A, 0.0)  # no first frame: not signing
        run.at(1.4)  # too young yet
        early = run.connect(_B, [_good(2)])
        assert await _spin(lambda: early.closed)
        assert not silent.closed
        run.at(1.5)
        run.connect(_C, [_good(3)])
        assert await _spin(lambda: silent.closed)
        assert await _spin(lambda: _C in hs.sent_msg2)
        await _yield()
        # Case 2: the victim gave its share back, not its slot (_C holds it).
        assert limiter.finished == [_A[0]]
        assert await _slots_free(run.semaphore) == 0
    assert sorted(limiter.finished) == sorted([_A[0], _C[0]])
    assert await _slots_free(run.semaphore) == 1
    assert run.attempts == {}
    assert run.loop_errors == []


async def test_a_silent_tcp_push_out_spends_no_shared_token() -> None:
    hs = _Hs()
    limiter = _Ledger(clock=_Frozen())
    async with _Tcp(hs, limiter=limiter) as run:
        silent = await _accepted(run, _A, 0.0)
        run.at(2.0)  # _A is pushable
        newcomer = run.connect(_B)  # silent too: no first frame
        assert await _spin(lambda: silent.closed)
        await _yield()
        assert not newcomer.closed
        assert limiter.finished == [_A[0]]  # case 2: its share, not its slot
        assert await _slots_free(run.semaphore) == 0  # _B holds the slot
    # Neither start, nor the push-out, took a token from the shared limits.
    assert _overall_left(limiter) == int(GLOBAL_START_BURST)
    assert await _slots_free(run.semaphore) == 1
    assert run.attempts == {}
    assert run.loop_errors == []


async def test_a_refused_tcp_newcomer_leaves_the_old_attempt_alone() -> None:
    hs = _Hs()
    clock = _Frozen()  # the limiter's: the tokens do not refill by themselves
    limiter = _Ledger(clock=clock)
    _spend_rate(limiter, _B[0])  # _B may not start again for now
    async with _Tcp(hs, limiter=limiter) as run:
        silent = await _accepted(run, _A, 0.0)
        victim = next(iter(run.attempts))
        run.at(2.0)  # _A is pushable
        refused = run.connect(_B, [_good(2)])
        assert await _spin(lambda: refused.closed)
        await _yield()
        assert not silent.closed
        assert not victim.done() and victim.cancelling() == 0
        assert list(run.attempts) == [victim]
        assert run.attempts[victim].passed_on is None
        assert limiter.finished == []
        assert await _slots_free(run.semaphore) == 0  # _A still holds it
        # The refusal spent nothing: with _B's tokens back, it pushes _A out.
        clock.now = 5.0
        run.connect(_B, [_good(3)])
        assert await _spin(lambda: silent.closed)
        assert await _spin(lambda: _B in hs.sent_msg2)
    assert sorted(limiter.finished) == sorted([_A[0], _B[0]])
    assert await _slots_free(run.semaphore) == 1
    assert run.attempts == {}
    assert run.loop_errors == []


async def test_a_refused_tcp_own_address_start_leaves_its_oldest_alone() -> None:
    hs = _Hs()
    ip = "203.0.113.50"
    clock = _Frozen()  # the limiter's: the tokens do not refill by themselves
    limiter = _Ledger(clock=clock)
    async with _Tcp(hs, max_inflight=8, limiter=limiter) as run:
        c1 = await _accepted(run, (ip, 1), 0.0)
        c2 = await _accepted(run, (ip, 2), 0.2)  # the address is at its cap
        # Its third and last start token, taken without a running attempt.
        assert limiter.try_start(ip, shared=False, inherits_share=True)
        run.at(2.0)  # both are pushable
        refused = run.connect((ip, 3), [_good(3)])
        assert await _spin(lambda: refused.closed)
        await _yield()
        assert not c1.closed and not c2.closed
        assert len(run.attempts) == 2
        assert all(rec.passed_on is None for rec in run.attempts.values())
        # Case 1: neither the share nor the slot of the oldest went anywhere.
        assert limiter.finished == []
        assert _inflight(limiter, ip) == 2
        assert await _slots_free(run.semaphore) == 6
        # The refusal spent nothing: with the tokens back, it pushes c1 out.
        clock.now = 5.0
        run.connect((ip, 4), [_good(4)])
        assert await _spin(lambda: c1.closed)
        assert await _spin(lambda: (ip, 4) in hs.sent_msg2)
        await _yield()
        assert not c2.closed
        assert limiter.finished == []
        assert _inflight(limiter, ip) == 2
        assert await _slots_free(run.semaphore) == 6
    assert limiter.finished == [ip, ip]
    assert await _slots_free(run.semaphore) == 8
    assert run.attempts == {}
    assert run.loop_errors == []


async def test_a_tcp_attempts_age_counts_from_its_accept_not_its_first_frame() -> None:
    hs = _Hs()
    async with _Tcp(hs) as run:
        first = await _accepted(run, _A, 0.0)
        run.at(1.0)
        first._frames.put_nowait(_good(1))  # the first frame comes late
        assert await _spin(lambda: _A in hs.sent_msg2)
        run.at(1.5)  # 1.5 s from the accept, 0.5 s from the frame
        run.connect(_B, [_good(2)])
        assert await _spin(lambda: first.closed)
        assert await _spin(lambda: _B in hs.sent_msg2)
    assert run.attempts == {}
    assert run.loop_errors == []


async def test_a_tcp_attempt_is_never_pushed_out_while_its_msg2_waits() -> None:
    hs = _Hs()
    hs.tpm[_A] = asyncio.Event()
    async with _Tcp(hs) as run:
        held = await _accepted(run, _A, 0.0, [_good(1)])
        assert await _spin(lambda: _A in hs.started)
        run.at(10.0)
        refused = run.connect(_B, [_good(2)])
        assert await _spin(lambda: refused.closed)
        assert not held.closed
        hs.tpm[_A].set()
        assert await _spin(lambda: _A in hs.sent_msg2)
        run.connect(_C, [_good(3)])
        assert await _spin(lambda: held.closed)
    assert run.attempts == {}
    assert run.loop_errors == []


async def test_a_tcp_attempt_past_admit_is_never_pushed_out() -> None:
    hs = _Hs({_A: "admit"})
    async with _Tcp(hs) as run:
        held = await _accepted(run, _A, 0.0, [_good(1)])
        assert await _spin(lambda: any(map(run.table.is_admitted, run.attempts)))
        run.at(5.0)
        refused = run.connect(_B, [_good(2)])
        assert await _spin(lambda: refused.closed)
        assert not held.closed
    assert run.attempts == {}
    assert run.loop_errors == []


async def test_without_the_gate_no_tcp_connection_is_pushed_out() -> None:
    hs = _Hs()
    x1, x2, x3 = ("203.0.113.50", 1), ("203.0.113.50", 2), ("203.0.113.50", 3)
    async with _Tcp(hs, max_inflight=2, gate=False) as run:
        c1 = await _accepted(run, x1, 0.0, [_good(1)])
        c2 = await _accepted(run, x2, 0.1, [_good(2)])
        assert await _spin(lambda: x1 in hs.sent_msg2 and x2 in hs.sent_msg2)
        run.at(60.0)
        other = run.connect(_B, [_good(3)])
        same = run.connect(x3, [_good(4)])
        assert await _spin(lambda: other.closed and same.closed)
        assert not c1.closed and not c2.closed
    assert run.attempts == {}
    assert run.loop_errors == []


async def test_a_tcp_address_at_its_cap_pushes_out_its_own_oldest() -> None:
    hs = _Hs()
    limiter = _Ledger(clock=_minutes())
    ip = "203.0.113.50"
    async with _Tcp(hs, max_inflight=8, limiter=limiter) as run:
        c1 = await _accepted(run, (ip, 1), 0.0)
        c2 = await _accepted(run, (ip, 2), 0.2)
        run.at(2.0)
        run.connect((ip, 3), [_good(3)])
        assert await _spin(lambda: c1.closed)
        assert await _spin(lambda: (ip, 3) in hs.sent_msg2)
        await _yield()
        assert not c2.closed
        # Case 1: the victim gave back neither its slot nor its share.
        assert limiter.finished == []
        assert _inflight(limiter, ip) == 2
        assert await _slots_free(run.semaphore) == 6
    assert limiter.finished.count(ip) == 2
    assert await _slots_free(run.semaphore) == 8
    assert run.attempts == {}


async def test_a_tcp_attempt_pushed_out_before_its_first_step_gives_back_once() -> None:
    hs = _Hs()
    limiter = _Ledger(clock=_minutes())
    run = _Tcp(hs, limiter=limiter, clock=_Ticks(0.0, 2.0))
    victim = run.connect(_A)  # both queued: one step of the loop takes both
    run.connect(_B, [_good(2)])
    async with run:
        assert await _spin(lambda: victim.closed)
        assert await _spin(lambda: _B in hs.sent_msg2)
        await _yield()
        assert limiter.finished == [_A[0]]  # its share, once; not its slot
        assert await _slots_free(run.semaphore) == 0
    assert hs.started == [_B]  # the victim's body never ran
    assert sorted(limiter.finished) == sorted([_A[0], _B[0]])
    assert await _slots_free(run.semaphore) == 1
    assert run.attempts == {}
    assert run.loop_errors == []


async def test_two_tcp_connections_in_one_step_push_out_two_attempts() -> None:
    hs = _Hs()
    limiter = _Ledger(clock=_minutes())
    async with _Tcp(hs, max_inflight=2, limiter=limiter) as run:
        a = await _accepted(run, _A, 0.0)
        b = await _accepted(run, _B, 0.1)
        run.at(2.0)
        run.connect(_C, [_good(3)])
        run.connect(_D, [_good(4)])  # Queue.get() does not yield: one step
        assert await _spin(lambda: a.closed and b.closed)
        assert await _spin(lambda: _C in hs.sent_msg2 and _D in hs.sent_msg2)
    assert await _slots_free(run.semaphore) == 2
    assert sorted(limiter.finished) == sorted(p[0] for p in (_A, _B, _C, _D))
    assert run.attempts == {}
    assert run.loop_errors == []


async def test_the_first_frame_view_fires_its_msg2_hook_once() -> None:
    fired: list[int] = []
    conn = _Conn(_A)
    view = hsa._FirstFrameTCP(conn, b"first", on_msg2=lambda: fired.append(1))
    assert await view.recv() == b"first"
    await view.send(_MSG2)
    await view.send(_MSG2)  # a resend
    assert fired == [1]
    assert conn.sent == [_MSG2, _MSG2]


class _SendFailsConn(_Conn):
    """One accepted connection whose every send fails."""

    async def send(self, data: bytes) -> None:
        raise OSError("connection reset by peer")


async def test_the_first_frame_views_hook_waits_until_msg2_really_left() -> None:
    fired: list[int] = []
    view = hsa._FirstFrameTCP(
        _SendFailsConn(_A), b"first", on_msg2=lambda: fired.append(1)
    )
    with pytest.raises(OSError):
        await view.send(_MSG2)
    assert fired == []  # still signing: msg2 did not go out


class _QueuesNext(_Conn):
    """A connection that hands ``then`` to the admit loop as its worker first
    reads (``at="read"``) or as its msg2 goes out (``at="msg2"``). A 0 s
    deadline the worker entered earlier in that same step was queued first
    (call_soon), so on the next loop pass the deadline asks to cancel this
    attempt, then the admit loop takes ``then``, before this attempt runs
    again."""

    def __init__(
        self,
        peer: Addr,
        connections: asyncio.Queue[tuple[TCPTransport, Addr]],
        then: _Conn,
        *,
        at: str,
        frames: list[bytes] | None = None,
    ) -> None:
        super().__init__(peer, frames)
        self._connections = connections
        self._then: _Conn | None = then
        self._at = at

    def _hand_over(self) -> None:
        then, self._then = self._then, None
        if then is not None:
            self._connections.put_nowait((then, then.peer))

    async def recv(self, timeout: float | None = None) -> bytes:
        if self._at == "read":
            self._hand_over()
        return await super().recv(timeout)

    async def send(self, data: bytes) -> None:
        await super().send(data)
        if self._at == "msg2":
            self._hand_over()


async def test_a_tcp_push_out_racing_the_first_frame_deadline_gives_back_once() -> None:
    # _A sends nothing. Its first-frame deadline, patched to 0, fires on the
    # loop pass after its worker began to read, and _B is taken in that same
    # pass: the push-out comes after the deadline asked to cancel _A and
    # before _A ran again.
    hs = _Hs()
    limiter = _Ledger(clock=_minutes())
    asked: list[int] = []
    run = _Tcp(hs, limiter=limiter, clock=_Ticks(0.0, 2.0))
    new = _Conn(_B, [_good(2)])
    victim = _QueuesNext(_A, run.connections, new, at="read")
    run.connections.put_nowait((victim, _A))
    with (
        patch.object(hsa, "_TCP_FIRST_FRAME_DEADLINE", 0.0),
        patch.object(hsa, "_push_out", _cancels_asked_at_push_out(asked)),
    ):
        async with run:
            assert await _spin(lambda: victim.closed)
            assert await _spin(lambda: _B in hs.sent_msg2)
            await _yield()
            # Case 2: its share given back once, not its slot (_B holds it).
            assert limiter.finished == [_A[0]]
            assert await _slots_free(run.semaphore) == 0
            assert not new.closed
    assert asked == [1]  # the deadline had already asked: a real race
    assert hs.started == [_B]
    assert sorted(limiter.finished) == sorted([_A[0], _B[0]])
    assert _inflight(limiter, _A[0]) == 0 and _inflight(limiter, _B[0]) == 0
    assert await _slots_free(run.semaphore) == 1
    assert run.attempts == {}
    assert run.loop_errors == []


async def test_a_tcp_own_address_push_out_racing_the_first_frame_deadline() -> None:
    # As above, in case 1: x1 passes its slot and its share to x3, so its
    # done-callback gives back neither, even though its deadline fired too.
    ip = "203.0.113.50"
    x1, x2, x3 = (ip, 1), (ip, 2), (ip, 3)
    hs = _Hs()
    limiter = _Ledger(clock=_minutes())
    asked: list[int] = []
    # Step S times: x2 accepted at 1.0, its msg2 stamped 1.0, x1 at 0.0 (the
    # oldest), x3 at 2.0.
    run = _Tcp(hs, max_inflight=4, limiter=limiter, clock=_Ticks(1.0, 1.0, 0.0, 2.0))
    new = _Conn(x3, [_good(3)])
    victim = _QueuesNext(x1, run.connections, new, at="read")
    with (
        patch.object(hsa, "_TCP_FIRST_FRAME_DEADLINE", 0.0),
        patch.object(hsa, "_push_out", _cancels_asked_at_push_out(asked)),
    ):
        async with run:
            run.connect(x2, [_good(2)])  # its frame is there: the 0 s cannot cut it
            assert await _spin(lambda: x2 in hs.sent_msg2)
            run.connections.put_nowait((victim, x1))
            assert await _spin(lambda: victim.closed)
            assert await _spin(lambda: x3 in hs.sent_msg2)
            await _yield()
            assert limiter.finished == []
            assert _inflight(limiter, ip) == 2  # x2's share and x3's (was x1's)
            assert await _slots_free(run.semaphore) == 2
    assert asked == [1]
    assert hs.started == [x2, x3]
    assert limiter.finished == [ip, ip]  # x2's and x3's, at the end
    assert _inflight(limiter, ip) == 0
    assert await _slots_free(run.semaphore) == 4
    assert run.attempts == {}
    assert run.loop_errors == []


async def test_a_tcp_push_out_racing_the_attempt_deadline_gives_back_once() -> None:
    # _A's attempt deadline, patched to 0, fires on the loop pass after its
    # msg2 left, and _B is taken in that same pass.
    hs = _Hs()
    limiter = _Ledger(clock=_minutes())
    asked: list[int] = []
    run = _Tcp(hs, limiter=limiter, clock=_Ticks(0.0, 2.0))
    new = _Conn(_B, [_good(2)])
    victim = _QueuesNext(_A, run.connections, new, at="msg2", frames=[_good(1)])
    run.connections.put_nowait((victim, _A))
    with (
        patch.object(hsa, "_HANDSHAKE_ATTEMPT_DEADLINE", 0.0),
        patch.object(hsa, "_push_out", _cancels_asked_at_push_out(asked)),
    ):
        async with run:
            # _B took _A's slot, then hit its own 0 s deadline.
            assert await _spin(lambda: _B in hs.sent_msg2 and not run.workers)
            assert await _slots_free(run.semaphore) == 1
            assert victim.closed and new.closed
    assert asked == [1]  # the deadline had already asked: a real race
    assert hs.cancelled == [_A, _B]  # _B by its own deadline
    assert limiter.finished == [_A[0], _B[0]]  # each share given back once
    assert _inflight(limiter, _A[0]) == 0 and _inflight(limiter, _B[0]) == 0
    assert await _slots_free(run.semaphore) == 1
    assert run.attempts == {}
    assert run.loop_errors == []


async def test_a_tcp_own_address_push_out_racing_the_attempt_deadline() -> None:
    # As above, in case 1: x1 passes its slot and its share to x3, so its
    # done-callback gives back neither, even though its deadline fired too.
    ip = "203.0.113.50"
    x1, x2, x3 = (ip, 1), (ip, 2), (ip, 3)
    hs = _Hs()
    limiter = _Ledger(clock=_minutes())
    asked: list[int] = []
    # Step S times: x2 accepted at 1.0, its msg2 stamped 1.0, x1 at 0.0 (the
    # oldest), x3 at 2.0.
    run = _Tcp(hs, max_inflight=2, limiter=limiter, clock=_Ticks(1.0, 1.0, 0.0, 2.0))
    new = _Conn(x3, [_good(3)])
    victim = _QueuesNext(x1, run.connections, new, at="msg2", frames=[_good(1)])
    async with run:
        run.connect(x2, [_good(2)])  # the usual 12 s deadline: still running
        assert await _spin(lambda: x2 in hs.sent_msg2)
        with (
            patch.object(hsa, "_HANDSHAKE_ATTEMPT_DEADLINE", 0.0),
            patch.object(hsa, "_push_out", _cancels_asked_at_push_out(asked)),
        ):
            run.connections.put_nowait((victim, x1))
            # x3 took x1's slot and share, then hit its own 0 s deadline.
            assert await _spin(lambda: limiter.finished == [ip])
        assert asked == [1]
        assert hs.cancelled == [x1, x3]  # x3 by its own deadline
        assert victim.closed and new.closed
        assert _inflight(limiter, ip) == 1  # x2's share only
        assert await _slots_free(run.semaphore) == 1  # x2 holds the other
    assert limiter.finished == [ip, ip]  # x3's, then x2's at the end
    assert _inflight(limiter, ip) == 0
    assert await _slots_free(run.semaphore) == 2
    assert run.attempts == {}
    assert run.loop_errors == []


async def test_a_shutdown_in_the_tcp_push_out_pass_gives_back_once() -> None:
    # The run stops in the loop pass of a push-out: _A is marked and
    # cancelled but has not run again, and _B has not run at all. Stopping
    # cancels both once more; each done-callback still runs once.
    hs = _Hs()
    limiter = _Ledger(clock=_minutes())
    asked: list[int] = []
    async with _Tcp(hs, limiter=limiter) as run:
        old = await _accepted(run, _A, 0.0, [_good(1)])
        assert await _spin(lambda: _A in hs.sent_msg2)
        victim = next(iter(run.attempts))
        run.at(2.0)
        with patch.object(hsa, "_push_out", _cancels_asked_at_push_out(asked)):
            new = run.connect(_B, [_good(2)])
            assert await _spin(lambda: asked != [])
        assert not victim.done() and _B not in hs.started  # both still pending
        assert not old.closed
        # Stop as the accept does: the admit loop first, then every worker,
        # with no loop pass in between.
        assert run.task is not None
        run.task.cancel()
        await hsa._cancel_and_drain(set(run.workers))
    assert asked == [0]  # nothing but the push-out had asked before
    assert hs.started == [_A] and hs.cancelled == [_A]  # _B never ran
    assert old.closed and new.closed
    assert sorted(limiter.finished) == sorted([_A[0], _B[0]])
    assert _inflight(limiter, _A[0]) == 0 and _inflight(limiter, _B[0]) == 0
    assert await _slots_free(run.semaphore) == 1
    assert run.attempts == {}
    assert run.loop_errors == []


async def test_a_shutdown_in_an_own_address_tcp_push_out_pass_gives_back_once() -> None:
    # As above, in case 1: x3 took x1's slot and share in the pass the run
    # stops. x1 gives back neither; x2 and x3 each give back their own once.
    ip = "203.0.113.50"
    x1, x2, x3 = (ip, 1), (ip, 2), (ip, 3)
    hs = _Hs()
    limiter = _Ledger(clock=_minutes())
    asked: list[int] = []
    async with _Tcp(hs, max_inflight=4, limiter=limiter) as run:
        old = await _accepted(run, x1, 0.0, [_good(1)])
        young = await _accepted(run, x2, 1.0, [_good(2)])
        assert await _spin(lambda: x1 in hs.sent_msg2 and x2 in hs.sent_msg2)
        victim = next(iter(run.attempts))
        run.at(2.0)  # x1 is 2.0 s old, x2 only 1.0 s
        with patch.object(hsa, "_push_out", _cancels_asked_at_push_out(asked)):
            new = run.connect(x3, [_good(3)])
            assert await _spin(lambda: asked != [])
        assert not victim.done() and x3 not in hs.started  # both still pending
        assert not old.closed
        assert limiter.finished == [] and _inflight(limiter, ip) == 2
        # Stop as the accept does: the admit loop first, then every worker,
        # with no loop pass in between.
        assert run.task is not None
        run.task.cancel()
        await hsa._cancel_and_drain(set(run.workers))
    assert asked == [0]  # nothing but the push-out had asked before
    assert hs.started == [x1, x2]  # x3 never ran
    assert sorted(hs.cancelled) == sorted([x1, x2])
    assert old.closed and young.closed and new.closed
    assert limiter.finished == [ip, ip]  # x2's and x3's; none for x1
    assert _inflight(limiter, ip) == 0
    assert await _slots_free(run.semaphore) == 4
    assert run.attempts == {}
    assert run.loop_errors == []


async def test_the_tcp_client_acceptor_hands_its_clock_to_push_out() -> None:
    # With the default clock both connections would be about 0 s old and the
    # second one would be closed as pool saturated.
    hs = _Hs()
    limiter = _Ledger(clock=_minutes())
    connections: asyncio.Queue[tuple[TCPTransport, Addr]] = asyncio.Queue()
    silent = _Conn(_A)
    new = _Conn(_B, [_good(2)])
    acceptor = hsa.ClientAcceptor(
        _Config(1),
        _Stub(),
        _Stub(),
        _Stub(),
        _Stub(),
        limiter,
        _table(False),
        _real_gate(),
        lambda _accepted: None,
        tcp=connections,
        clock=_Ticks(0.0, 2.0),
    )
    with (
        patch("dsm.crypto.handshake.server_handshake", new=hs),
        patch.object(hsa, "_TCP_FIRST_FRAME_DEADLINE", _FAR_FIRST_FRAME_DEADLINE),
    ):
        run = asyncio.ensure_future(acceptor.run())
        connections.put_nowait((silent, _A))
        assert await _spin(lambda: bool(silent._frames._getters))  # it waits
        connections.put_nowait((new, _B))
        assert await _spin(lambda: silent.closed)
        assert await _spin(lambda: _B in hs.sent_msg2)
        assert not new.closed
        assert limiter.finished == [_A[0]]
        await asyncio.wait_for(acceptor.stop(), 5.0)
        await run
    assert new.closed
    assert hs.started == [_B]
    assert sorted(limiter.finished) == sorted([_A[0], _B[0]])


async def test_the_udp_client_acceptor_hands_its_clock_to_push_out() -> None:
    # With the default clock both starts would be about 0 s old and the
    # second one would be dropped as pool saturated.
    hs = _Hs()
    limiter = _Ledger(clock=_minutes())
    acceptor = hsa.ClientAcceptor(
        _Config(1),
        _Stub(),
        _Stub(),
        _Stub(),
        _Stub(),
        limiter,
        _table(False),
        _AdmitGate(),
        lambda _accepted: None,
        udp=_Transport(),
        clock=_Ticks(0.0, 2.0),
    )
    with patch("dsm.crypto.handshake.server_handshake", new=hs):
        run = asyncio.ensure_future(acceptor.run())
        acceptor.offer(_good(1), _A)
        assert await _spin(lambda: _A in hs.sent_msg2)
        acceptor.offer(_good(2), _B)
        assert await _spin(lambda: _B in hs.sent_msg2)
        assert hs.cancelled == [_A]
        await _yield()
        assert limiter.finished == [_A[0]]
        await asyncio.wait_for(acceptor.stop(), 5.0)
        await run
    assert hs.started == [_A, _B]
    assert sorted(limiter.finished) == sorted([_A[0], _B[0]])


@pytest.mark.parametrize(
    ("slots", "warned"), [(1, True), (4, True), (7, True), (8, False), (16, False)]
)
async def test_run_server_warns_at_start_when_too_few_slots(
    slots: int, warned: bool, caplog: pytest.LogCaptureFixture
) -> None:
    # [BOX-ONLY] dsm.server needs the new tuncore; imported here so the rest
    # of this file still runs on the laptop.
    from tests.test_server_dns_fatal import _base_patches, _run_until, _server_config

    caplog.set_level(logging.WARNING, logger="dsm")

    config = replace(
        _server_config(), max_inflight_handshakes=slots, dns_blocklist=False
    )
    captured: dict[str, Any] = {}
    with _base_patches(captured):
        assert await _run_until(config, captured) == 0
    lines = [
        r.getMessage()
        for r in caplog.records
        if r.levelno == logging.WARNING and "slot rule" in r.getMessage()
    ]
    if warned:
        # "Use 8" from every low value, not just slots + 1.
        assert lines == [
            f"max_inflight_handshakes={slots} is too low for the handshake slot "
            "rule: a steady stream of stalled handshakes could keep every slot "
            "busy, so new devices wait. Use 8 or more."
        ]
    else:
        assert lines == []
