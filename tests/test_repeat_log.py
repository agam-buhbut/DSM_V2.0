"""Events that can repeat once per packet log at most one line per 10 s.

At the shaper's packet rate (8-12 packets/s at idle, up to ~960/s at the top
tier) a full send queue, a failing send or a socket error would otherwise
log one line per packet. Each logs the first event, then at most one line
per 10 s with a count of the events in between. A fake clock drives time.
"""

from __future__ import annotations

import asyncio
import logging

import pytest

from dsm.core.log import REPEAT_LOG_INTERVAL_S, RepeatLog
from dsm.net.transport.udp import _UDPProtocol
from dsm.traffic.scheduler import MAX_QUEUE_SIZE, SendScheduler


class _FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class _OneBigSlotBatch:
    """Lets every queued packet leave at the first poll, then nothing."""

    def __init__(self) -> None:
        self.polls = 0

    def poll(
        self, now: float, queue_len: int, oldest_wait: float, real_sent: int
    ) -> tuple[int, float]:
        self.polls += 1
        return (queue_len if self.polls == 1 else 0), now + 3600.0


def _messages(caplog: pytest.LogCaptureFixture, name: str) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.name == name]


def test_the_first_event_is_logged_and_repeats_are_counted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    clock = _FakeClock()
    repeat = RepeatLog(logging.getLogger("dsm.test"), logging.WARNING, clock=clock)
    with caplog.at_level(logging.WARNING, logger="dsm.test"):
        for _ in range(500):
            repeat.log("thing failed: %s", "OSError")
            clock.now += 0.001
        assert _messages(caplog, "dsm.test") == ["thing failed: OSError"]

        clock.now = 1000.0 + REPEAT_LOG_INTERVAL_S
        repeat.log("thing failed: %s", "OSError")
    assert _messages(caplog, "dsm.test")[1:] == [
        "thing failed: OSError (499 more in the last 10 s)"
    ]


def test_at_most_one_line_per_interval(caplog: pytest.LogCaptureFixture) -> None:
    clock = _FakeClock()
    repeat = RepeatLog(logging.getLogger("dsm.test"), logging.WARNING, clock=clock)
    with caplog.at_level(logging.WARNING, logger="dsm.test"):
        # 60 s of events at 1000 a second.
        for i in range(60_000):
            clock.now = 1000.0 + i / 1000
            repeat.log("queue full")
    assert (
        _messages(caplog, "dsm.test")
        == ["queue full"] + ["queue full (9999 more in the last 10 s)"] * 5
    )


def test_a_count_left_over_goes_out_with_the_next_event(
    caplog: pytest.LogCaptureFixture,
) -> None:
    clock = _FakeClock()
    repeat = RepeatLog(logging.getLogger("dsm.test"), logging.ERROR, clock=clock)
    with caplog.at_level(logging.ERROR, logger="dsm.test"):
        for _ in range(3):
            repeat.log("UDP error: %s", "refused")
        clock.now += 3600.0
        repeat.log("UDP error: %s", "refused")
        clock.now += 3600.0
        repeat.log("UDP error: %s", "refused")
    assert _messages(caplog, "dsm.test") == [
        "UDP error: refused",
        "UDP error: refused (2 more in the last 3600 s)",
        "UDP error: refused",
    ]
    assert all(r.levelno == logging.ERROR for r in caplog.records)


async def test_a_full_queue_logs_the_first_drop_then_a_count(
    caplog: pytest.LogCaptureFixture,
) -> None:
    clock = _FakeClock()
    sent: list[bytes] = []
    all_sent = asyncio.Event()

    async def send_fn(data: bytes, target_size: int) -> None:
        sent.append(data)
        if len(sent) == MAX_QUEUE_SIZE:
            all_sent.set()

    sched = SendScheduler(send_fn, shaper=_OneBigSlotBatch(), clock=clock)  # type: ignore[arg-type]
    name = "dsm.traffic.scheduler"
    with caplog.at_level(logging.WARNING, logger=name):
        for i in range(MAX_QUEUE_SIZE + 100):
            sched.enqueue(i.to_bytes(4, "big"), 128)
        assert _messages(caplog, name) == [
            "scheduler queue full, dropping oldest packet"
        ]
        clock.now += REPEAT_LOG_INTERVAL_S
        sched.enqueue(b"one more", 128)
    assert _messages(caplog, name)[1:] == [
        "scheduler queue full, dropping oldest packet (99 more in the last 10 s)"
    ]
    # What is sent does not change: the oldest 101 packets were dropped.
    await sched.start()
    try:
        await asyncio.wait_for(all_sent.wait(), timeout=3)
    finally:
        await sched.stop()
    assert sent[0] == (101).to_bytes(4, "big")
    assert sent[-1] == b"one more"


async def test_a_failing_send_logs_the_first_failure_then_a_count(
    caplog: pytest.LogCaptureFixture,
) -> None:
    clock = _FakeClock()
    sched = SendScheduler(_never_send, shaper=_OneBigSlotBatch(), clock=clock)  # type: ignore[arg-type]
    name = "dsm.traffic.scheduler"
    with caplog.at_level(logging.WARNING, logger=name):
        for _ in range(300):
            assert await sched._keep_alive(_refused(), "send") is None
        # A different failure is a new kind: its first one is logged at once.
        assert await sched._keep_alive(_timed_out(), "send") is None
        assert await sched._keep_alive(_refused(), "chaff generation") is None
        clock.now += REPEAT_LOG_INTERVAL_S
        assert await sched._keep_alive(_refused(), "send") is None
    assert _messages(caplog, name) == [
        "send failed: ConnectionRefusedError",
        "send failed: TimeoutError",
        "chaff generation failed: ConnectionRefusedError",
        "send failed: ConnectionRefusedError (299 more in the last 10 s)",
    ]


async def test_udp_socket_errors_log_the_first_then_a_count(
    caplog: pytest.LogCaptureFixture,
) -> None:
    clock = _FakeClock()
    protocol = _UDPProtocol(asyncio.Queue(), clock=clock)
    name = "dsm.net.transport.udp"
    refused = ConnectionRefusedError(111, "Connection refused")
    with caplog.at_level(logging.ERROR, logger=name):
        for _ in range(960):
            protocol.error_received(refused)
        clock.now += REPEAT_LOG_INTERVAL_S
        protocol.error_received(refused)
    assert _messages(caplog, name) == [
        "UDP error: [Errno 111] Connection refused",
        "UDP error: [Errno 111] Connection refused (959 more in the last 10 s)",
    ]


async def _never_send(data: bytes, target_size: int) -> None:
    raise AssertionError("nothing is sent in this test")


async def _refused() -> None:
    raise ConnectionRefusedError


async def _timed_out() -> None:
    raise TimeoutError
