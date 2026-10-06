"""REKEY_INIT retries: two quick ones first, then REKEY_ACK_TIMEOUT each,
and the wait starts when the INIT really leaves the scheduler."""

from __future__ import annotations

import asyncio
import time

from dsm.core.fsm import SessionFSM, State
from dsm.rekey import (
    MAX_REKEY_RETRIES,
    MIN_REKEY_INTERVAL,
    REKEY_ACK_TIMEOUT,
    REKEY_RETRY_BUDGET,
    rekey_retry_delay,
)
from dsm.session import (
    DataPathContext,
    LivenessState,
    RekeyState,
    _paced_rekey_init,
    tun_send_loop,
)
from dsm.traffic.shaper import TrafficShaper


class _RecordingScheduler:
    def __init__(self) -> None:
        self.queued: list[bytes] = []
        self.senders: list[object] = []

    def enqueue(
        self,
        data: bytes,
        target_size: int,
        *,
        send_via: object = None,
        control: bool = False,
    ) -> None:
        assert control
        self.queued.append(data)
        self.senders.append(send_via)


class _Keys:
    epoch = 0

    def needs_rotation(self) -> bool:
        return False


class _QuietTun:
    async def read(self) -> bytes:
        await asyncio.sleep(3600)
        return b""


def _context(sent: list[bytes]) -> tuple[DataPathContext, _RecordingScheduler]:
    async def send_fn(data: bytes, size: int) -> None:
        sent.append(data)

    fsm = SessionFSM()
    for state in (State.CONNECTING, State.HANDSHAKING, State.ESTABLISHED):
        fsm.transition(state)
    fsm.transition(State.REKEYING)
    sched = _RecordingScheduler()
    ctx = DataPathContext(
        tun=_QuietTun(),  # type: ignore[arg-type]
        session_keys=_Keys(),  # type: ignore[arg-type]
        fsm=fsm,
        shaper=TrafficShaper(128, 1400),
        send_fn=send_fn,
        scheduler=sched,  # type: ignore[arg-type]
        rekey=RekeyState(),
        liveness=LivenessState(),
        shutdown=asyncio.Event(),
    )
    return ctx, sched


def test_retry_delays() -> None:
    delays = [rekey_retry_delay(i) for i in range(MAX_REKEY_RETRIES)]
    assert delays[:3] == [1.5, 2.5, REKEY_ACK_TIMEOUT]
    assert REKEY_RETRY_BUDGET == sum(delays) == 68.0
    assert REKEY_RETRY_BUDGET > MIN_REKEY_INTERVAL
    # The quick delays never wait longer than the normal timeout.
    assert rekey_retry_delay(0, ack_timeout=0.5) == 0.5


async def _first_retry(retries_used: int, sent_ago: float) -> RekeyState:
    ctx, sched = _context([])
    ctx.rekey.in_progress = True
    ctx.rekey.last_init_payload = b"\x00\x00\x00\x01" + b"\x01" * 32
    ctx.rekey.last_init_sent_at = time.monotonic() - sent_ago
    ctx.rekey.retries_used = retries_used
    task = asyncio.create_task(tun_send_loop(ctx))
    try:
        for _ in range(100):
            if sched.queued:
                break
            await asyncio.sleep(0.01)
    finally:
        ctx.shutdown.set()
        await asyncio.gather(task, return_exceptions=True)
    return ctx.rekey


async def test_first_retry_after_one_and_a_half_seconds() -> None:
    rekey = await _first_retry(retries_used=0, sent_ago=1.6)
    assert rekey.retries_used == 1


async def test_second_retry_after_two_and_a_half_seconds() -> None:
    rekey = await _first_retry(retries_used=1, sent_ago=2.6)
    assert rekey.retries_used == 2


async def test_retry_clock_starts_when_the_init_is_sent() -> None:
    sent: list[bytes] = []
    ctx, sched = _context(sent)
    ctx.rekey.in_progress = True
    ctx.rekey.last_init_sent_at = 1.0  # queue time, long ago

    _paced_rekey_init(ctx)(b"init", 128)
    assert sched.queued == [b"init"] and sent == []
    send_via = sched.senders[0]
    assert callable(send_via)
    before = time.monotonic()
    await send_via(b"init", 128)
    assert sent == [b"init"]
    assert ctx.rekey.last_init_sent_at is not None
    assert ctx.rekey.last_init_sent_at >= before


async def test_send_time_not_noted_once_the_rekey_is_done() -> None:
    sent: list[bytes] = []
    ctx, sched = _context(sent)
    _paced_rekey_init(ctx)(b"init", 128)
    send_via = sched.senders[0]
    assert callable(send_via)
    await send_via(b"init", 128)
    assert sent == [b"init"]
    assert ctx.rekey.last_init_sent_at is None
