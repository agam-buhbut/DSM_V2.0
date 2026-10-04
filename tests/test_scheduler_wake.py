"""Shaper mode: packets leave only in the shaper's slots.

The scheduler sleeps until the shaper's ``next_wake`` and nothing else wakes
it, not even a burst of ``enqueue`` calls. A queued packet takes the very
next slot (no jitter, no extra delay), and control messages (rekey packets,
PATH_CHALLENGE and PATH_RESPONSE) leave only in slots too. They wait in
their own small queue that goes ahead of data, so a full data queue neither
delays nor drops them. A scripted stand-in for the shaper (the I/O boundary
of this unit) records every poll. Event-driven: the tests wait on events
with timeouts, never on fixed sleeps. Times come from ``time.monotonic``,
the scheduler's default clock, unless a test injects a fake one.
"""

from __future__ import annotations

import asyncio
import logging
import struct
import time

import pytest

from dsm.core.fsm import SessionFSM, State
from dsm.core.protocol import InnerPacket, PacketType
from dsm.rekey import MAX_REKEY_RETRIES, handle_rekey_init
from dsm.server import _queue_path_challenge
from dsm.session import (
    DataPathContext,
    LivenessState,
    RekeyState,
    _handle_path_challenge,
    _handle_rekey_init,
    tun_send_loop,
)
from dsm.traffic.scheduler import MAX_QUEUE_SIZE, SendScheduler
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
    sched = SendScheduler(
        send_fn,
        shaper=shaper,  # type: ignore[arg-type]
    )
    await sched.start()
    try:
        await shaper.wait_for_polls(1)
        sched.enqueue(b"first", 128)
        sched.enqueue(b"second", 128)
        await shaper.wait_for_polls(2)
        _, queue_len, oldest_wait, _ = shaper.polls[1]
        assert queue_len == 2
        assert oldest_wait < 0.5, "the packet was sendable at once"
        assert sent == [b"first", b"second"], "both left, in queue order"
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


class _FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class _RecordingScheduler:
    """Stands in for the scheduler at the call sites: records each queued
    packet and whether it was queued as a control message."""

    def __init__(self) -> None:
        self.queued: list[tuple[bytes, bool]] = []
        self.senders: list[object] = []

    def enqueue(
        self,
        data: bytes,
        target_size: int,
        *,
        send_via: object = None,
        control: bool = False,
    ) -> None:
        self.queued.append((data, control))
        self.senders.append(send_via)


async def _unused_send(data: bytes, size: int) -> None:
    raise AssertionError("nothing goes out directly")


def _context(scheduler: object, keys: object, tun: object = None) -> DataPathContext:
    return DataPathContext(
        tun=tun,  # type: ignore[arg-type]
        session_keys=keys,  # type: ignore[arg-type]
        fsm=_established_fsm(),
        shaper=TrafficShaper(128, 1400),
        send_fn=_unused_send,
        scheduler=scheduler,  # type: ignore[arg-type]
        rekey=RekeyState(),
        liveness=LivenessState(),
        shutdown=asyncio.Event(),
    )


async def test_a_control_packet_behind_a_full_data_queue_leaves_in_the_next_slot() -> (
    None
):
    sent: list[bytes] = []
    delivered = asyncio.Event()

    async def send_fn(data: bytes, size: int) -> None:
        sent.append(data)
        delivered.set()

    shaper = _ScriptedShaper([(1, 30.0)])
    sched = SendScheduler(send_fn, shaper=shaper)  # type: ignore[arg-type]
    for i in range(MAX_QUEUE_SIZE):
        sched.enqueue(i.to_bytes(4, "big"), 128)
    sched.enqueue(b"rekey-ack", 128, control=True)
    await sched.start()
    try:
        await asyncio.wait_for(delivered.wait(), timeout=3)
        assert sent == [b"rekey-ack"], "the control packet takes the first slot"
        _, queue_len, _, _ = shaper.polls[0]
        assert queue_len == MAX_QUEUE_SIZE + 1, "queue_len counts both queues"
    finally:
        await sched.stop()


async def test_data_overflow_never_drops_a_control_packet() -> None:
    sent: list[bytes] = []
    all_sent = asyncio.Event()

    async def send_fn(data: bytes, size: int) -> None:
        sent.append(data)
        if len(sent) == MAX_QUEUE_SIZE + 1:
            all_sent.set()

    shaper = _ScriptedShaper([(MAX_QUEUE_SIZE + 1, 30.0)])
    sched = SendScheduler(send_fn, shaper=shaper)  # type: ignore[arg-type]
    sched.enqueue(b"path-challenge", 128, control=True)
    for i in range(MAX_QUEUE_SIZE + 100):
        sched.enqueue(i.to_bytes(4, "big"), 128)
    await sched.start()
    try:
        await asyncio.wait_for(all_sent.wait(), timeout=3)
    finally:
        await sched.stop()
    assert sent[0] == b"path-challenge"
    # The data queue dropped its own 100 oldest packets, nothing else.
    assert sent[1] == (100).to_bytes(4, "big")
    assert sent[-1] == (MAX_QUEUE_SIZE + 99).to_bytes(4, "big")


async def test_a_full_control_queue_drops_its_oldest_and_says_so(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from dsm.traffic.scheduler import MAX_CONTROL_QUEUE_SIZE

    sent: list[bytes] = []
    all_sent = asyncio.Event()
    total = MAX_CONTROL_QUEUE_SIZE + 1

    async def send_fn(data: bytes, size: int) -> None:
        sent.append(data)
        if len(sent) == total:
            all_sent.set()

    shaper = _ScriptedShaper([(total, 30.0)])
    sched = SendScheduler(send_fn, shaper=shaper)  # type: ignore[arg-type]
    name = "dsm.traffic.scheduler"
    with caplog.at_level(logging.WARNING, logger=name):
        for i in range(MAX_CONTROL_QUEUE_SIZE + 5):
            sched.enqueue(b"control-%d" % i, 128, control=True)
        sched.enqueue(b"data", 128)
    await sched.start()
    try:
        await asyncio.wait_for(all_sent.wait(), timeout=3)
    finally:
        await sched.stop()
    # The 5 oldest control packets were dropped; the rest go first, in order.
    expected = [b"control-%d" % i for i in range(5, MAX_CONTROL_QUEUE_SIZE + 5)]
    assert sent == expected + [b"data"]
    assert [r.getMessage() for r in caplog.records if r.name == name] == [
        "control queue full, dropping oldest control packet"
    ]


async def test_a_control_packet_does_not_wake_the_loop() -> None:
    sent: list[tuple[float, bytes]] = []
    delivered = asyncio.Event()

    async def send_fn(data: bytes, size: int) -> None:
        sent.append((time.monotonic(), data))
        delivered.set()

    # Poll 1: no slot, next wake in 0.3 s. Poll 2: one slot, then far away.
    shaper = _ScriptedShaper([(0, 0.3), (1, 30.0)])
    sched = SendScheduler(send_fn, shaper=shaper)  # type: ignore[arg-type]
    await sched.start()
    try:
        await shaper.wait_for_polls(1)
        first_poll = shaper.polls[0][0]
        sched.enqueue(b"data", 128)
        sched.enqueue(b"rekey-init", 128, control=True)
        await asyncio.wait_for(delivered.wait(), timeout=3)
        # Nothing polled or left before the scheduled wake.
        assert len(shaper.polls) == 2
        assert shaper.polls[1][0] >= first_poll + 0.3 - _EARLY_SLACK_S
        assert sent[0][0] >= first_poll + 0.3 - _EARLY_SLACK_S
        assert [data for _, data in sent] == [b"rekey-init"]
    finally:
        await sched.stop()


@pytest.mark.parametrize("control_first", [True, False])
async def test_oldest_wait_comes_from_the_older_queue(control_first: bool) -> None:
    clock = _FakeClock()
    shaper = _ScriptedShaper([(0, 30.0)])
    sched = SendScheduler(_unused_send, shaper=shaper, clock=clock)  # type: ignore[arg-type]
    sched.enqueue(b"older", 128, control=control_first)
    clock.now = 1001.0
    sched.enqueue(b"newer", 128, control=not control_first)
    clock.now = 1002.5
    await sched.start()
    try:
        await shaper.wait_for_polls(1)
    finally:
        await sched.stop()
    now, queue_len, oldest_wait, _ = shaper.polls[0]
    assert now == 1002.5
    assert queue_len == 2
    assert oldest_wait == 2.5


async def test_the_rekey_ack_replay_and_path_response_are_queued_as_control() -> None:
    recorder = _RecordingScheduler()
    ctx = _context(recorder, _FakeKeys(1))
    # A duplicate REKEY_INIT for the epoch we already moved to: the cached
    # ACK is replayed.
    ctx.rekey.cached_ack_epoch = 1
    ctx.rekey.cached_ack_payload = b"\x22" * 36
    await _handle_rekey_init(
        ctx,
        InnerPacket(
            ptype=PacketType.REKEY_INIT,
            epoch_id=1,
            payload=struct.pack("!I", 1) + b"\x11" * 32,
        ),
    )
    await _handle_path_challenge(
        ctx,
        InnerPacket(ptype=PacketType.PATH_CHALLENGE, epoch_id=1, payload=b"\x33" * 16),
    )
    assert [control for _, control in recorder.queued] == [True, True]


async def test_the_path_challenge_is_queued_as_control_to_the_candidate() -> None:
    recorder = _RecordingScheduler()
    ctx = _context(recorder, _FakeKeys(0))

    async def path_send(data: bytes, size: int, addr: tuple[str, int]) -> None:
        pass

    _queue_path_challenge(ctx, path_send, ("203.0.113.9", 4444), b"\x33" * 16)
    assert [control for _, control in recorder.queued] == [True]
    assert recorder.senders[0] is not None


async def test_a_rekey_init_and_its_retries_are_queued_as_control(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import dsm.session as session_mod

    # Every pass of the send loop counts as an ACK timeout.
    monkeypatch.setattr(session_mod, "REKEY_ACK_TIMEOUT", 0.0)

    class _RotatingKeys:
        epoch = 0

        def needs_rotation(self) -> bool:
            return True

        def initiate_rotation(self) -> tuple[int, bytes]:
            return 1, b"\x01" * 32

    class _QuietTun:
        async def read(self) -> bytes:
            await asyncio.sleep(3600)
            return b""

    recorder = _RecordingScheduler()
    ctx = _context(recorder, _RotatingKeys(), _QuietTun())
    await asyncio.wait_for(tun_send_loop(ctx), timeout=10)
    # The first INIT, then one resend per timeout until the loop gives up.
    assert ctx.shutdown.is_set()
    assert len(recorder.queued) == 1 + MAX_REKEY_RETRIES
    assert all(control for _, control in recorder.queued)
