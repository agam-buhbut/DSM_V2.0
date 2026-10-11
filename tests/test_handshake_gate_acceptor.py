"""The handshake gate in the acceptor (wire v2, spec §7.4 and §7.6; T10
§3.16 tests 9, 11-14 and 22). The Noise handshake is a scripted fake, as in
test_handshake_acceptor_limits.py; the gate, the limiter and the slot are
real; clocks are frozen. No sockets; nothing waits on the wall clock.
Laptop: partly (old wheel and shim). The shim has no XChaCha, so the tests
that send or open a cookie reply (spoofed starts, the reply cap under a
flood, one address with many ports, a replayed msg1) need tuncore's
xchacha_seal and xchacha_open from the Task 5 wheel and run in CI.
"""

from __future__ import annotations

import asyncio
import logging
import random
from typing import Any
from unittest.mock import patch

import pytest

from dsm.crypto.handshake import HANDSHAKE_FRAME_SIZE
from dsm.net import handshake_acceptor as hsa
from dsm.net.handshake_acceptor import SessionWatch
from dsm.net.handshake_gate import (
    BAD_MAC1_LINE,
    COOKIE_REPLY_BURST,
    GateKeys,
    HandshakeGate,
    SourceLimiter,
    compute_mac1,
    open_cookie_reply,
    stamp_mac2,
    stamp_msg1,
)
from dsm.net.transport.tcp import TCPTransport
from tests import test_handshake_acceptor_in_session as in_session
from tests.test_handshake_acceptor_in_session import _Script as _SessionScript
from tests.test_handshake_acceptor_in_session import _slot
from tests.test_handshake_acceptor_limits import (
    _Config,
    _Frozen,
    _minutes,
    _Script,
    _spin,
    _Stub,
    _Transport,
    _yield,
)
from tests.test_tcp_accept_concurrency import _Conn

Addr = tuple[str, int]
KEYS = GateKeys.from_ca_der(bytes.fromhex("3003020101"), "dsm-test-server")
NOW = 1_800_000_000.0
REAL: Addr = ("198.51.100.7", 51820)


def _gate(clock: _Frozen | None = None) -> HandshakeGate:
    return HandshakeGate(
        KEYS, clock=clock if clock is not None else _Frozen(), wall_clock=lambda: NOW
    )


def _msg1(seed: int, keys: GateKeys = KEYS, now: float = NOW) -> bytes:
    """A msg1 as a wire v2 client stamps it (the scripted handshake never
    reads the Noise part)."""
    frame = bytearray(random.Random(seed).randbytes(HANDSHAKE_FRAME_SIZE))
    stamp_msg1(frame, compute_mac1(bytes(frame[:32]), keys, now))
    return bytes(frame)


def _with_cookie(msg1: bytes, reply: bytes) -> bytes:
    """The client's resend after a cookie reply: same e and mac1, with mac2."""
    cookie = open_cookie_reply(reply, KEYS, msg1[32:48])
    assert cookie is not None
    frame = bytearray(msg1)
    stamp_mac2(frame, cookie)
    return bytes(frame)


def _to(transport: _Transport, addr: Addr) -> list[bytes]:
    return [data for data, dest in transport.sent if dest == addr]


def _pub(addr: Addr) -> bytes:
    return f"pub-{addr[0]}:{addr[1]}".encode()


class _Accept:
    """_accept_until_winner with a gate, on an in-memory socket."""

    def __init__(self, script: Any, gate: HandshakeGate) -> None:
        self.transport = _Transport()
        self.shutdown = asyncio.Event()
        self.gate = gate
        self.limiter = SourceLimiter(clock=_minutes())
        self._patch = patch("dsm.crypto.handshake.server_handshake", new=script)
        self.task: asyncio.Future[Any] | None = None

    def feed(self, data: bytes, addr: Addr) -> None:
        self.transport._recv_queue.put_nowait((data, addr))

    async def __aenter__(self) -> _Accept:
        self._patch.start()
        self.task = asyncio.ensure_future(
            hsa._accept_until_winner(
                _Config(8),
                _Stub(),
                _Stub(),
                _Stub(),
                _Stub(),
                self.transport,
                self.shutdown,
                self.limiter,
                None,
                self.gate,
            )
        )
        return self

    async def __aexit__(self, *exc: object) -> None:
        self.shutdown.set()
        try:
            assert self.task is not None
            await asyncio.wait_for(self.task, 5.0)
        finally:
            self._patch.stop()

    async def result(self) -> tuple[Any, Any, Any]:
        assert self.task is not None
        return await asyncio.wait_for(self.task, 5.0)


async def test_a_quiet_server_admits_the_first_good_msg1_without_a_cookie() -> None:
    # T10 test 14: no extra round trip when nothing is going on.
    script = _Script({})
    async with _Accept(script, _gate()) as run:
        run.feed(_msg1(1), REAL)
        _, pub, _ = await run.result()
    assert pub == _pub(REAL)
    assert run.transport.sent == []


async def test_frames_without_a_good_mac1_get_no_answer_and_leave_no_trace() -> None:
    # T10 test 12, junk flood: no reply, no worker, no limiter entry, no load.
    script = _Script({})
    gate = _gate()
    rng = random.Random(3)
    bad = [rng.randbytes(HANDSHAKE_FRAME_SIZE) for _ in range(1000)]
    bad += [
        _msg1(1, GateKeys.from_ca_der(b"another CA", "dsm-test-server")),
        _msg1(2, GateKeys.from_ca_der(bytes.fromhex("3003020101"), "another")),
        _msg1(3, now=NOW - 600),
        _msg1(4, now=NOW + 600),
    ]
    async with _Accept(script, gate) as run:
        for i, frame in enumerate(bad):
            run.feed(frame, (f"203.0.{i // 250}.{i % 250}", 5000 + i))
        assert await _spin(run.transport._recv_queue.empty, rounds=20_000)
        await _yield()
        assert script.started == []
        assert run.transport.sent == []
        assert len(run.limiter) == 0
        assert not gate.load.under_load(0)
        run.feed(_msg1(7), REAL)
        _, pub, _ = await run.result()
    assert pub == _pub(REAL)


async def test_spoofed_starts_park_one_slot_and_the_real_client_gets_in() -> None:
    # T10 test 9: before v2, 8 spoofed msg1s parked every slot.
    spoofed: list[Addr] = [(f"203.0.113.{i}", 4000 + i) for i in range(8)]
    script = _Script({addr: "stall" for addr in spoofed})
    async with _Accept(script, _gate()) as run:
        for i, addr in enumerate(spoofed):
            run.feed(_msg1(i), addr)
        assert await _spin(lambda: len(run.transport.sent) == 7)
        # Only the first took a slot. From then on a handshake was running,
        # so each later one got a cookie reply (to its spoofed address, where
        # nobody reads it) and left no state.
        assert await _spin(lambda: script.started == [spoofed[0]])
        first = _msg1(100)
        run.feed(first, REAL)
        assert await _spin(lambda: len(_to(run.transport, REAL)) == 1)
        reply = _to(run.transport, REAL)[0]
        assert len(reply) == HANDSHAKE_FRAME_SIZE
        run.feed(_with_cookie(first, reply), REAL)
        _, pub, _ = await run.result()
    assert pub == _pub(REAL)
    assert script.started == [spoofed[0], REAL]


async def test_a_mac1_flood_under_load_costs_capped_cookie_replies() -> None:
    # T10 test 11: a K-holder spoofing 1000 sources.
    script = _Script({REAL: "stall"})
    async with _Accept(script, _gate()) as run:
        run.feed(_msg1(0), REAL)  # one attempt runs: the server is under load
        assert await _spin(lambda: script.started == [REAL])
        for i in range(1000):
            run.feed(_msg1(1000 + i), (f"203.0.{i // 250}.{i % 250}", 6000 + i))
        assert await _spin(run.transport._recv_queue.empty, rounds=20_000)
        await _yield()
        assert script.started == [REAL]
        assert len(run.transport.sent) == COOKIE_REPLY_BURST  # frozen clock
        assert len(run.limiter) == 1


async def test_one_address_with_many_ports_holds_two_slots_at_most() -> None:
    # T10 test 13: a proven attacker on one IP; a real client elsewhere.
    attacker: list[Addr] = [("203.0.113.66", 7000 + i) for i in range(6)]
    script = _Script({addr: "stall" for addr in attacker})
    async with _Accept(script, _gate()) as run:
        run.feed(_msg1(0), attacker[0])  # idle: admitted without a cookie
        assert await _spin(lambda: script.started == [attacker[0]])
        for i, addr in enumerate(attacker[1:], start=1):
            first = _msg1(i)
            run.feed(first, addr)
            assert await _spin(lambda a=addr: len(_to(run.transport, a)) == 1)
            run.feed(_with_cookie(first, _to(run.transport, addr)[0]), addr)
        await _yield(200)
        assert script.started == attacker[:2]  # PER_SOURCE_INFLIGHT
        first = _msg1(99)
        run.feed(first, REAL)
        assert await _spin(lambda: len(_to(run.transport, REAL)) == 1)
        run.feed(_with_cookie(first, _to(run.transport, REAL)[0]), REAL)
        _, pub, _ = await run.result()
    assert pub == _pub(REAL)


async def test_a_replayed_msg1_takes_one_slot_and_the_client_still_gets_in() -> None:
    # Review Focus 5 (T10 R3): a captured msg1 keeps a valid mac1 for 5-15
    # minutes. Replayed from elsewhere while the server is idle, it takes
    # the one slot an idle server gives without a cookie.
    replayer: Addr = ("203.0.113.99", 9999)
    script = _Script({replayer: "stall"})
    async with _Accept(script, _gate()) as run:
        run.feed(_msg1(1), replayer)
        assert await _spin(lambda: script.started == [replayer])
        fresh = _msg1(2)
        run.feed(fresh, REAL)
        assert await _spin(lambda: len(_to(run.transport, REAL)) == 1)
        run.feed(_with_cookie(fresh, _to(run.transport, REAL)[0]), REAL)
        _, pub, _ = await run.result()
    assert pub == _pub(REAL)
    assert script.started == [replayer, REAL]


async def test_a_failed_attempt_turns_cookies_on_for_30_s() -> None:
    # Spec §7.4, T10 §3.5: trouble puts the server under load for 30 s.
    clock = _Frozen()
    gate = _gate(clock)
    failer: Addr = ("203.0.113.5", 5005)
    script = _Script({failer: "fail"})
    async with _Accept(script, gate) as run:
        run.feed(_msg1(1), failer)
        assert await _spin(lambda: script.ended == [failer])
        await _yield()
        assert gate.load.under_load(0)
        clock.now = 29.9
        assert gate.load.under_load(0)
        clock.now = 30.0
        assert not gate.load.under_load(0)


class _TcpScript:
    """Fake server_handshake for TCP: reads the first frame, asks the session
    check when the accept gives one (as the real one does, with the session
    holder's CN), then wins."""

    def __init__(self) -> None:
        self.frames: list[bytes] = []

    async def __call__(
        self, conn: Any, *_a: Any, admit_client: Any = None, **_k: Any
    ) -> tuple[object, bytes]:
        self.frames.append(await conn.recv())
        if admit_client is not None:
            admit_client(in_session.HOLDER)
        return object(), b"pub-tcp"


async def _tcp_accept(gate: HandshakeGate, conns: list[_Conn]) -> tuple[Any, Any, Any]:
    connections: asyncio.Queue[tuple[TCPTransport, Addr]] = asyncio.Queue()
    for conn in conns:
        connections.put_nowait((conn, conn.peer))
    return await asyncio.wait_for(
        hsa._accept_until_winner_tcp(
            _Config(8),
            _Stub(),
            _Stub(),
            _Stub(),
            _Stub(),
            connections,
            asyncio.Event(),
            SourceLimiter(clock=_minutes()),
            None,
            gate=gate,
        ),
        5.0,
    )


async def test_the_first_tcp_frame_needs_the_size_and_a_good_mac1() -> None:
    # Spec §7.6, T10 test 22: closed before msg2, before any signature.
    script = _TcpScript()
    gate = _gate()
    short = _Conn(("203.0.113.1", 1), [b"\x00" * 100])
    bad = _Conn(("203.0.113.2", 2), [random.Random(1).randbytes(HANDSHAKE_FRAME_SIZE)])
    good_frame = _msg1(3)
    good = _Conn(REAL, [good_frame])
    with patch("dsm.crypto.handshake.server_handshake", new=script):
        _, pub, transport = await _tcp_accept(gate, [short, bad, good])
    assert pub == b"pub-tcp"
    assert transport is good  # the real connection, not the first-frame view
    assert script.frames == [good_frame]  # handed back to the handshake
    assert short.closed and bad.closed
    assert short.sent == [] and bad.sent == []
    assert not gate.load.under_load(0)  # a bad first frame is not trouble


async def test_tcp_asks_no_cookie_even_under_load() -> None:
    # Review Focus 4: TCP has no cookies; a good mac1 is enough.
    script = _TcpScript()
    gate = _gate()
    gate.load.note_trouble()
    assert gate.load.under_load(0)
    good = _Conn(REAL, [_msg1(4)])
    with patch("dsm.crypto.handshake.server_handshake", new=script):
        _, pub, _ = await _tcp_accept(gate, [good])
    assert pub == b"pub-tcp"
    assert good.sent == []


@pytest.mark.parametrize(
    ("max_inflight", "peers"),
    [
        # The third connection from one address: 2 per address at most.
        (8, [("203.0.113.8", 1), ("203.0.113.8", 2), ("203.0.113.8", 3)]),
        # The second connection: the pool of 1 is full.
        (1, [("203.0.113.8", 1), ("203.0.113.9", 2)]),
    ],
)
async def test_a_refused_tcp_start_is_trouble(
    max_inflight: int, peers: list[Addr]
) -> None:
    # Spec §7.4, T10 §3.5: a start the limits or the pool refuse is trouble.
    gate = _gate()
    conns = [_Conn(peer) for peer in peers]  # no frames: workers wait on recv
    connections: asyncio.Queue[tuple[TCPTransport, Addr]] = asyncio.Queue()
    shutdown = asyncio.Event()
    with patch("dsm.crypto.handshake.server_handshake", new=_TcpScript()):
        task = asyncio.ensure_future(
            hsa._accept_until_winner_tcp(
                _Config(max_inflight),
                _Stub(),
                _Stub(),
                _Stub(),
                _Stub(),
                connections,
                shutdown,
                SourceLimiter(clock=_minutes()),
                None,
                gate,
            )
        )
        for conn in conns[:-1]:
            connections.put_nowait((conn, conn.peer))
        await _yield()
        assert not gate.load.under_load(0)
        refused = conns[-1]
        connections.put_nowait((refused, refused.peer))
        assert await _spin(lambda: refused.closed)
        assert gate.load.under_load(0)
        shutdown.set()
        assert await asyncio.wait_for(task, 5.0) == (None, None, None)
    assert refused.sent == []


async def test_full_size_packets_the_session_cannot_open_are_dropped_at_mac1(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Review Focus 1: duplicates, replays and late old-key packets of the
    # live client reach the in-session accept as new sources.
    caplog.set_level(logging.INFO, logger="dsm")
    gate = _gate()
    script = _SessionScript()
    real = _Transport()
    limiter = SourceLimiter(clock=_minutes())
    live: Addr = ("198.51.100.7", 40000)
    back: Addr = ("198.51.100.7", 40001)
    with patch("dsm.crypto.handshake.server_handshake", new=script):
        watch = SessionWatch(
            _Config(8),
            _Stub(),
            _Stub(),
            _Stub(),
            _Stub(),
            limiter,
            _slot(),
            gate,
            udp=real,
        )
        assert watch.offer is not None
        rng = random.Random(5)
        for _ in range(60):
            watch.offer(rng.randbytes(HANDSHAKE_FRAME_SIZE), live, False)
            await asyncio.sleep(0)
        await _yield(200)
        assert script.started == []
        assert real.sent == []
        assert len(limiter) == 0
        assert not gate.load.under_load(0)
        lines = [r for r in caplog.records if r.getMessage().startswith(BAD_MAC1_LINE)]
        assert len(lines) == 1
        assert lines[0].levelno == logging.INFO
        # The client that comes back still gets in, without a cookie.
        watch.offer(_msg1(9), back, False)
        assert await _spin(lambda: script.admitted == [back])
        win = await watch.stop()
    assert win is not None


async def test_the_in_session_tcp_accept_checks_the_first_frame_too() -> None:
    # The TCP twin of the test above: the watch hands the gate to its TCP
    # accept, so a bad first frame is closed before any handshake starts.
    gate = _gate()
    script = _TcpScript()
    connections: asyncio.Queue[tuple[TCPTransport, Addr]] = asyncio.Queue()
    other_ca = GateKeys.from_ca_der(b"another CA", "dsm-test-server")
    bad = _Conn(("203.0.113.2", 2), [_msg1(1, other_ca)])
    good_frame = _msg1(2)
    back = _Conn(("198.51.100.7", 40001), [good_frame])
    with patch("dsm.crypto.handshake.server_handshake", new=script):
        watch = SessionWatch(
            _Config(8),
            _Stub(),
            _Stub(),
            _Stub(),
            _Stub(),
            SourceLimiter(clock=_minutes()),
            _slot(),
            gate,
            tcp=connections,
        )
        connections.put_nowait((bad, bad.peer))
        assert await _spin(lambda: bad.closed)
        await _yield()
        assert script.frames == []  # no handshake attempt
        assert bad.sent == []
        assert not watch.end_session.is_set()
        assert not gate.load.under_load(0)
        # The client that comes back still gets in.
        connections.put_nowait((back, back.peer))
        assert await _spin(watch.end_session.is_set)
        win = await asyncio.wait_for(watch.stop(), 5.0)
    assert win is not None
    assert win.transport is back
    assert script.frames == [good_frame]
