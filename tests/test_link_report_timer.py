"""The report loop waits a random 0.5-1.5 s between steps, drawn from the OS
RNG, so reports do not keep a fixed 1 s rhythm a watcher could pick them out
by. The random source is injected; nothing sleeps.
"""

from __future__ import annotations

import asyncio
import random
import secrets
import statistics

import pytest

from dsm import session
from dsm.core.fsm import SessionFSM
from dsm.session import (
    DataPathContext,
    LivenessState,
    RekeyState,
    _report_wait,
    link_report_loop,
)
from dsm.traffic.autocap import REPORT_INTERVAL_S, LinkStats


def test_waits_vary_and_stay_between_half_and_one_and_a_half_intervals() -> None:
    rng = random.Random(7)
    waits = [_report_wait(rng) for _ in range(1000)]
    low, high = 0.5 * REPORT_INTERVAL_S, 1.5 * REPORT_INTERVAL_S
    assert all(low <= w <= high for w in waits)
    assert len(set(waits)) > 990, "the waits do not vary"
    assert min(waits) < low + 0.05 and max(waits) > high - 0.05, "range not used"
    assert statistics.fmean(waits) == pytest.approx(REPORT_INTERVAL_S, abs=0.05)


def test_the_default_source_is_the_os_rng() -> None:
    assert isinstance(session._REPORT_RNG, secrets.SystemRandom)


class _RecordingRng:
    """Records each draw's bounds and returns a tiny wait, so the loop runs
    fast."""

    def __init__(self) -> None:
        self.bounds: list[tuple[float, float]] = []

    def uniform(self, a: float, b: float) -> float:
        self.bounds.append((a, b))
        return 0.001


class _Ticks:
    """Stands in for AutoCap: stops the loop at the third tick."""

    def __init__(self, stop: asyncio.Event) -> None:
        self.stop = stop
        self.ticks = 0

    def tick(self) -> None:
        self.ticks += 1
        if self.ticks == 3:
            self.stop.set()


async def _no_send(data: bytes, target_size: int) -> None:
    return None


async def test_the_loop_draws_every_wait(monkeypatch: pytest.MonkeyPatch) -> None:
    rng = _RecordingRng()
    monkeypatch.setattr(session, "_REPORT_RNG", rng)
    shutdown = asyncio.Event()
    auto = _Ticks(shutdown)
    ctx = DataPathContext(
        tun=None,  # type: ignore[arg-type]
        session_keys=None,  # type: ignore[arg-type]
        fsm=SessionFSM(),
        shaper=None,  # type: ignore[arg-type]
        send_fn=_no_send,
        scheduler=None,  # type: ignore[arg-type]
        rekey=RekeyState(),
        liveness=LivenessState(),
        shutdown=shutdown,
        link_stats=LinkStats(),
        autocap=auto,  # type: ignore[arg-type]
    )
    await asyncio.wait_for(link_report_loop(ctx), timeout=5.0)
    assert auto.ticks == 3
    assert rng.bounds == [(0.5 * REPORT_INTERVAL_S, 1.5 * REPORT_INTERVAL_S)] * 3
