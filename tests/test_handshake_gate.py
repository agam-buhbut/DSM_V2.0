"""Per-address and overall limits on new handshake attempts (SourceLimiter)."""

from __future__ import annotations

import logging

import pytest

from dsm.net import handshake_gate as gate
from dsm.net.handshake_gate import SourceLimiter, TokenBucket


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_the_limits_are_the_designed_values() -> None:
    assert gate.PER_SOURCE_INFLIGHT == 2
    assert gate.PER_SOURCE_RATE == 0.25
    assert gate.PER_SOURCE_BURST == 3.0
    assert gate.GLOBAL_START_RATE == 4.0
    assert gate.GLOBAL_START_BURST == 8.0
    assert gate.MAX_TRACKED_SOURCES == 4096


def test_an_address_runs_at_most_two_attempts_at_once() -> None:
    limiter = SourceLimiter(clock=_Clock())
    assert limiter.try_start("198.51.100.1")
    assert limiter.try_start("198.51.100.1")
    assert not limiter.try_start("198.51.100.1")
    assert limiter.try_start("198.51.100.2")
    limiter.finish("198.51.100.1")
    assert limiter.try_start("198.51.100.1")


def test_an_address_starts_three_at_once_then_one_every_four_seconds() -> None:
    clock = _Clock()
    limiter = SourceLimiter(clock=clock)
    ip = "198.51.100.1"
    for _ in range(3):
        assert limiter.try_start(ip)
        limiter.finish(ip)
    assert not limiter.try_start(ip)
    clock.now += 3.75
    assert not limiter.try_start(ip)
    clock.now += 0.25
    assert limiter.try_start(ip)
    limiter.finish(ip)
    assert not limiter.try_start(ip)


def test_all_addresses_start_eight_at_once_then_four_a_second() -> None:
    clock = _Clock()
    limiter = SourceLimiter(clock=clock)
    for i in range(8):
        assert limiter.try_start(f"203.0.113.{i}")
    assert not limiter.try_start("203.0.113.200")
    clock.now += 0.25
    assert limiter.try_start("203.0.113.200")
    assert not limiter.try_start("203.0.113.201")


def test_a_refused_address_spends_nothing_and_is_not_remembered() -> None:
    clock = _Clock()
    limiter = SourceLimiter(clock=clock)
    for i in range(8):
        assert limiter.try_start(f"203.0.113.{i}")
    assert not limiter.try_start("198.51.100.9")
    assert len(limiter) == 8
    clock.now += 2.0
    for _ in range(3):
        assert limiter.try_start("198.51.100.9")
        limiter.finish("198.51.100.9")


def test_a_busy_address_does_not_spend_the_overall_budget() -> None:
    limiter = SourceLimiter(clock=_Clock())
    assert limiter.try_start("198.51.100.1")
    assert limiter.try_start("198.51.100.1")
    for _ in range(50):
        assert not limiter.try_start("198.51.100.1")
    for i in range(6):
        assert limiter.try_start(f"203.0.113.{i}")
    assert not limiter.try_start("203.0.113.99")


def test_a_client_restarting_every_ten_seconds_is_never_refused() -> None:
    """Review Focus 1: systemd restarts the client every 10 s and each try
    runs into the 12 s cutoff, so two of its attempts overlap."""
    clock = _Clock()
    limiter = SourceLimiter(clock=clock)
    ip = "198.51.100.7"
    running: list[float] = []  # end time of each running attempt
    for n in range(30):
        clock.now = 1000.0 + 10.0 * n
        for end in [e for e in running if e <= clock.now]:
            limiter.finish(ip)
            running.remove(end)
        assert limiter.try_start(ip), f"restart {n} was refused"
        running.append(clock.now + 12.0)


def test_a_full_table_forgets_the_idle_address_that_started_longest_ago() -> None:
    limiter = SourceLimiter(clock=_Clock(), max_sources=2)
    for _ in range(3):
        assert limiter.try_start("10.0.0.1")
        limiter.finish("10.0.0.1")
    assert not limiter.try_start("10.0.0.1")  # its 3 starts are spent
    assert limiter.try_start("10.0.0.2")
    limiter.finish("10.0.0.2")
    assert limiter.try_start("10.0.0.3")  # the table is full: 10.0.0.1 goes
    assert len(limiter) == 2
    assert limiter.try_start("10.0.0.1")  # forgotten, so it starts afresh
    assert len(limiter) == 2


def test_an_address_with_an_attempt_running_is_never_forgotten() -> None:
    limiter = SourceLimiter(clock=_Clock(), max_sources=2)
    assert limiter.try_start("10.0.0.1")
    assert limiter.try_start("10.0.0.2")
    assert not limiter.try_start("10.0.0.3")
    assert len(limiter) == 2
    limiter.finish("10.0.0.1")
    assert limiter.try_start("10.0.0.3")
    assert len(limiter) == 2


def test_refusals_are_logged_at_info_without_the_address(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    limiter = SourceLimiter(clock=_Clock())
    busy = "198.51.100.77"
    assert limiter.try_start(busy)
    assert limiter.try_start(busy)
    assert not limiter.try_start(busy)
    for i in range(6):
        assert limiter.try_start(f"203.0.113.{i}")
    assert not limiter.try_start("203.0.113.250")
    records = [r for r in caplog.records if r.name == "dsm.net.handshake_gate"]
    messages = [r.getMessage() for r in records]
    assert any("already has 2 running" in m for m in messages)
    assert any("too many new handshakes overall" in m for m in messages)
    assert all(r.levelno == logging.INFO for r in records)
    assert all(busy not in m and "203.0.113" not in m for m in messages)


def test_repeated_refusals_log_one_line_per_ten_seconds(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="dsm.net.handshake_gate")
    clock = _Clock()
    limiter = SourceLimiter(clock=clock)
    assert limiter.try_start("198.51.100.1")
    assert limiter.try_start("198.51.100.1")
    for _ in range(50):
        assert not limiter.try_start("198.51.100.1")
    clock.now += 10.0
    assert not limiter.try_start("198.51.100.1")
    messages = [
        r.getMessage() for r in caplog.records if r.name == "dsm.net.handshake_gate"
    ]
    assert len(messages) == 2
    assert "(49 more in the last 10 s)" in messages[1]


def test_a_bucket_never_holds_more_than_its_burst() -> None:
    bucket = TokenBucket(rate=1.0, burst=2.0, now=0.0)
    assert bucket.ready(1000.0)
    bucket.take()
    assert bucket.ready(1000.0)
    bucket.take()
    assert not bucket.ready(1000.0)


def test_a_clock_that_steps_back_adds_no_tokens() -> None:
    bucket = TokenBucket(rate=1.0, burst=1.0, now=100.0)
    assert bucket.ready(100.0)
    bucket.take()
    assert not bucket.ready(50.0)
    assert not bucket.ready(100.5)
    assert bucket.ready(101.0)
