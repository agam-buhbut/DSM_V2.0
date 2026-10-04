"""Shaper mode: packets leave only in the shaper's slots.

The scheduler sleeps until the shaper's ``next_wake`` and nothing else wakes
it, not even a burst of ``enqueue`` calls. A queued packet takes the very
next slot (no jitter, no extra delay), and control messages (the cached
REKEY_ACK replay, the server's PATH_CHALLENGE) leave only in slots too. A
scripted stand-in for the shaper (the I/O boundary of this unit) records
every poll. Event-driven: the tests wait on events with timeouts, never on
fixed sleeps. Times come from ``time.monotonic``, the scheduler's default
clock.
"""

from __future__ import annotations

import asyncio
import struct
import time

from dsm.core.fsm import SessionFSM, State
from dsm.rekey import handle_rekey_init
from dsm.server import _queue_path_challenge
from dsm.session import DataPathContext, LivenessState, RekeyState
from dsm.traffic.scheduler import SendScheduler
from dsm.traffic.shaper import TrafficShaper

# Real-time asyncio timers may fire up to the clock resolution early.
_EARLY_SLACK_S = 1e-3


class _ScriptedShaper:
    """Answers each poll from a script of (slots_due, seconds to next wake);
    the last entry repeats. Records (now, queue_len, oldest_wait, real_sent)."""

    def __init__(self, script: list[tuple[int, float]]) -> None:
        self._script = script
        self.polls: list[tuple[float, int, float, int]] = []
        self.polled = asyncio.Event()

    def poll(
        self, now: float, queue_len: int, oldest_wait: float, real_sent: int
    ) -> tuple[int, float]:
        self.polls.append((now, queue_len, oldest_wait, real_sent))
        self.polled.set()
        slots, delay = self._script[min(len(self.polls), len(self._script)) - 1]
        return slots, now + delay

    async def wait_for_polls(self, count: int) -> None:
        while len(self.polls) < count:
            self.polled.clear()
            await asyncio.wait_for(self.polled.wait(), timeout=3)


class _FakeKeys:
    """Only the epoch is read on the paths under test."""

    def __init__(self, epoch: int) -> None:
        self.epoch = epoch


def _established_fsm() -> SessionFSM:
    fsm = SessionFSM()
    fsm.transition(State.CONNECTING)
    fsm.transition(State.HANDSHAKING)
    fsm.transition(State.ESTABLISHED)
    return fsm


async def test_enqueue_does_not_wake_the_loop() -> None:
    sent: list[tuple[float, bytes]] = []
    delivered = asyncio.Event()

    async def send_fn(data: bytes, size: int) -> None:
        sent.append((time.monotonic(), data))
        delivered.set()

    # Poll 1: no slot, next wake in 0.3 s. Poll 2: one slot, then far away.
    shaper = _ScriptedShaper([(0, 0.3), (1, 30.0)])
    sched = SendScheduler(
        send_fn,
        jitter_ms_min=0,
        jitter_ms_max=0,
        shaper=shaper,  # type: ignore[arg-type]
    )
    await sched.start()
    try:
        await shaper.wait_for_polls(1)
        first_poll = shaper.polls[0][0]
        sched.enqueue(b"real", 128)
        for _ in range(20):
            sched.enqueue(b"burst", 128)
        await asyncio.wait_for(delivered.wait(), timeout=3)
        # Nothing polled or left before the scheduled wake.
        assert len(shaper.polls) == 2
        second_poll, queue_len, oldest_wait, _ = shaper.polls[1]
        assert second_poll >= first_poll + 0.3 - _EARLY_SLACK_S
        assert sent[0][0] >= first_poll + 0.3 - _EARLY_SLACK_S
        assert queue_len == 21
        assert oldest_wait > 0.0
        assert len(sent) == 1, "one slot means one packet"
    finally:
        await sched.stop()


async def test_real_packets_go_first_chaff_fills_and_real_sent_is_reported() -> None:
    sent: list[bytes] = []

    async def send_fn(data: bytes, size: int) -> None:
        sent.append(data)

    async def chaff_fn() -> tuple[bytes, int]:
        return b"chaff", 128

    shaper = _ScriptedShaper([(3, 0.05), (0, 30.0)])
    sched = SendScheduler(
        send_fn,
        chaff_fn=chaff_fn,
        jitter_ms_min=0,
        jitter_ms_max=0,
        shaper=shaper,  # type: ignore[arg-type]
    )
    sched.enqueue(b"real-1", 128)
    sched.enqueue(b"real-2", 128)
    await sched.start()
    try:
        await shaper.wait_for_polls(2)
        assert sorted(sent[:2]) == [b"real-1", b"real-2"]
        assert sent[2:] == [b"chaff"]
        assert shaper.polls[0][3] == 0
        assert shaper.polls[1][3] == 2, "real_sent counts the real packets only"
    finally:
        await sched.stop()


async def test_closed_chaff_gate_leaves_free_slots_empty() -> None:
    sent: list[bytes] = []

    async def send_fn(data: bytes, size: int) -> None:
        sent.append(data)

    async def chaff_fn() -> tuple[bytes, int]:
        return b"chaff", 128

    shaper = _ScriptedShaper([(2, 0.05), (0, 30.0)])
    sched = SendScheduler(
        send_fn,
        chaff_fn=chaff_fn,
        should_chaff_fn=lambda: False,
        shaper=shaper,  # type: ignore[arg-type]
    )
    await sched.start()
    try:
        await shaper.wait_for_polls(2)
        assert sent == []
    finally:
        await sched.stop()


async def test_stop_does_not_wait_for_a_distant_wake() -> None:
    shaper = _ScriptedShaper([(0, 3600.0)])

    async def send_fn(data: bytes, size: int) -> None:
        raise AssertionError("nothing is due")

    sched = SendScheduler(send_fn, shaper=shaper)  # type: ignore[arg-type]
    await sched.start()
    await shaper.wait_for_polls(1)
    started = time.monotonic()
    await asyncio.wait_for(sched.stop(), timeout=2)
    assert time.monotonic() - started < 1.0


async def test_a_queued_packet_takes_the_next_slot_without_jitter() -> None:
    sent: list[bytes] = []

    async def send_fn(data: bytes, size: int) -> None:
        sent.append(data)

    shaper = _ScriptedShaper([(0, 0.1), (2, 30.0)])
    # A large jitter range and extra delay must both be ignored in shaper mode.
    sched = SendScheduler(
        send_fn,
        jitter_ms_min=500,
        jitter_ms_max=500,
        shaper=shaper,  # type: ignore[arg-type]
    )
    await sched.start()
    try:
        await shaper.wait_for_polls(1)
        sched.enqueue(b"first", 128)
        sched.enqueue(b"second", 128, extra_delay=5.0)
        await shaper.wait_for_polls(2)
        _, queue_len, oldest_wait, _ = shaper.polls[1]
        assert queue_len == 2
        assert oldest_wait < 0.5, "the packet was sendable at once"
        assert sent == [b"first", b"second"], "both left, in queue order"
    finally:
        await sched.stop()


async def test_without_a_shaper_the_jitter_still_applies() -> None:
    sent: list[float] = []
    delivered = asyncio.Event()

    async def send_fn(data: bytes, size: int) -> None:
        sent.append(time.monotonic())
        delivered.set()

    sched = SendScheduler(send_fn, jitter_ms_min=200, jitter_ms_max=200)
    await sched.start()
    try:
        queued_at = time.monotonic()
        sched.enqueue(b"real", 128)
        await asyncio.wait_for(delivered.wait(), timeout=3)
        assert sent[0] >= queued_at + 0.2 - _EARLY_SLACK_S
    finally:
        await sched.stop()


async def test_cached_rekey_ack_replay_leaves_only_in_a_slot() -> None:
    sent: list[float] = []
    direct: list[bytes] = []
    delivered = asyncio.Event()

    async def send_fn(data: bytes, size: int) -> None:
        sent.append(time.monotonic())
        delivered.set()

    async def direct_send(data: bytes, size: int) -> None:
        direct.append(data)

    shaper = _ScriptedShaper([(0, 0.3), (1, 30.0)])
    sched = SendScheduler(send_fn, shaper=shaper)  # type: ignore[arg-type]
    await sched.start()
    try:
        await shaper.wait_for_polls(1)
        first_poll = shaper.polls[0][0]
        # A duplicate REKEY_INIT for the epoch we already moved to: the
        # responder replays its cached ACK instead of rotating again.
        epoch = 1
        await handle_rekey_init(
            struct.pack("!I", epoch) + b"\x11" * 32,
            _FakeKeys(epoch),  # type: ignore[arg-type]
            _established_fsm(),
            TrafficShaper(128, 1400),
            direct_send,
            cached_ack_epoch=epoch,
            cached_ack_payload=b"\x22" * 36,
            paced_send=sched.enqueue,
        )
        await asyncio.wait_for(delivered.wait(), timeout=3)
        assert direct == [], "the replay must not go out directly"
        assert len(sent) == 1
        assert sent[0] >= first_poll + 0.3 - _EARLY_SLACK_S
    finally:
        await sched.stop()


async def test_path_challenge_leaves_only_in_a_slot_to_the_candidate() -> None:
    main_sends: list[bytes] = []
    challenges: list[tuple[float, tuple[str, int]]] = []
    delivered = asyncio.Event()

    async def send_fn(data: bytes, size: int) -> None:
        main_sends.append(data)

    async def path_send(data: bytes, size: int, addr: tuple[str, int]) -> None:
        challenges.append((time.monotonic(), addr))
        delivered.set()

    shaper = _ScriptedShaper([(0, 0.3), (1, 30.0)])
    sched = SendScheduler(send_fn, shaper=shaper)  # type: ignore[arg-type]
    ctx = DataPathContext(
        tun=None,  # type: ignore[arg-type]
        session_keys=_FakeKeys(0),  # type: ignore[arg-type]
        fsm=_established_fsm(),
        shaper=TrafficShaper(128, 1400),
        send_fn=send_fn,
        scheduler=sched,
        rekey=RekeyState(),
        liveness=LivenessState(),
        shutdown=asyncio.Event(),
    )
    await sched.start()
    try:
        await shaper.wait_for_polls(1)
        first_poll = shaper.polls[0][0]
        candidate = ("203.0.113.9", 4444)
        _queue_path_challenge(ctx, path_send, candidate, b"\x33" * 16)
        await asyncio.wait_for(delivered.wait(), timeout=3)
        assert challenges[0][1] == candidate
        assert challenges[0][0] >= first_poll + 0.3 - _EARLY_SLACK_S
        assert main_sends == [], "the challenge must not go to the committed egress"
    finally:
        await sched.stop()
