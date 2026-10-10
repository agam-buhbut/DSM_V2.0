"""While a session runs, new handshakes may start at most once a second, on
top of the per-address and overall limits (owner decision 2026-10-09). Each
admitted attempt costs a TPM signature."""

from __future__ import annotations

import logging

import pytest

from dsm.net import handshake_gate as gate
from dsm.net.handshake_gate import SourceLimiter


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_the_in_session_budget_is_one_a_second() -> None:
    assert gate.IN_SESSION_START_RATE == 1.0
    assert gate.IN_SESSION_START_BURST == 1.0


def test_in_a_session_one_new_handshake_starts_each_second() -> None:
    clock = _Clock()
    limiter = SourceLimiter(clock=clock)
    assert limiter.try_start("198.51.100.1", in_session=True)
    assert not limiter.try_start("203.0.113.2", in_session=True)
    clock.now += 0.5
    assert not limiter.try_start("203.0.113.2", in_session=True)
    clock.now += 0.5
    assert limiter.try_start("203.0.113.2", in_session=True)
    assert not limiter.try_start("203.0.113.3", in_session=True)


def test_the_idle_accept_is_not_held_to_the_session_budget() -> None:
    limiter = SourceLimiter(clock=_Clock())
    assert limiter.try_start("198.51.100.1", in_session=True)
    for i in range(7):  # the overall burst of 8, one spent above
        assert limiter.try_start(f"203.0.113.{i}")
    assert not limiter.try_start("203.0.113.99")


def test_a_session_refusal_spends_nothing_and_is_not_remembered() -> None:
    limiter = SourceLimiter(clock=_Clock())
    assert limiter.try_start("198.51.100.1", in_session=True)
    for _ in range(20):
        assert not limiter.try_start("198.51.100.9", in_session=True)
    assert len(limiter) == 1
    for i in range(7):  # the overall budget is untouched by the refusals
        assert limiter.try_start(f"203.0.113.{i}")
    assert not limiter.try_start("203.0.113.99")


def test_a_refusal_by_another_limit_spends_no_session_token() -> None:
    limiter = SourceLimiter(clock=_Clock())
    busy = "198.51.100.1"
    assert limiter.try_start(busy)
    assert limiter.try_start(busy)
    assert not limiter.try_start(busy, in_session=True)  # already has 2 running
    assert limiter.try_start("203.0.113.5", in_session=True)


def test_session_refusals_log_one_info_line_without_the_address(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger="dsm.net.handshake_gate")
    limiter = SourceLimiter(clock=_Clock())
    assert limiter.try_start("198.51.100.1", in_session=True)
    for _ in range(5):
        assert not limiter.try_start("203.0.113.77", in_session=True)
    records = [r for r in caplog.records if r.name == "dsm.net.handshake_gate"]
    assert [(r.levelno, r.getMessage()) for r in records] == [
        (
            logging.INFO,
            "new handshake refused: too many new handshakes while a session runs",
        )
    ]
    assert all("203.0.113.77" not in r.getMessage() for r in records)
