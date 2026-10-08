"""The tier cap through the FFI (``tuncore.Shaper.set_tier_cap``, ``tier``)
and the ``TrafficShaper`` wrapper: the clamp and the tier listener.

The core draws its secret values from the OS RNG, so these tests drive it
with an injected clock and check only what holds for every draw. The exact,
seeded behavior is pinned by the Rust tests in the inline ``mod cap_tests``
at the end of rust/tuncore/src/shaper.rs.
"""

from __future__ import annotations

import pytest

import tuncore
from dsm.traffic.shaper import TrafficShaper

T0 = 1000.0
TIERS = [10.0, 50.0, 200.0, 800.0]


def _core() -> tuncore.Shaper:
    return tuncore.Shaper(TIERS, 0.5, 0.0, (0.0, 0.0), 128, 1400, T0)


def _wrapper() -> TrafficShaper:
    return TrafficShaper(clock=lambda: T0, decoy_interval_s=0.0)


def _climb(shaper: tuncore.Shaper | TrafficShaper, seconds: float) -> float:
    """Poll with a big backlog that arrived at T0, for ``seconds``.

    Step-up points are 0.25-0.5 s apart at the 0.5 s budget, so 3 s reach
    the top of four tiers. Returns the next wake.
    """
    now = T0
    while now < T0 + seconds:
        _, now = shaper.poll(now, 1000, now - T0, 0)
    return now


def test_tier_starts_idle_and_follows_a_climb() -> None:
    core = _core()
    assert core.tier() == 0
    _climb(core, 3.0)
    assert core.tier() == 3


def test_a_lower_cap_steps_down_at_the_next_poll() -> None:
    core = _core()
    now = _climb(core, 3.0)
    core.set_tier_cap(2)
    assert core.tier() == 3, "set_tier_cap alone moved the tier"
    core.poll(now, 0, 0.0, 0)
    assert core.tier() == 2


@pytest.mark.parametrize(("cap", "top"), [(2, 2), (1, 1), (0, 1), (3, 3), (99, 3)])
def test_a_backlog_stops_at_the_cap_and_zero_counts_as_one(cap: int, top: int) -> None:
    core = _core()
    core.set_tier_cap(cap)
    _climb(core, 5.0)
    assert core.tier() == top


def test_a_negative_cap_raises_overflow_error() -> None:
    with pytest.raises(OverflowError):
        _core().set_tier_cap(-1)


@pytest.mark.parametrize(("cap", "top"), [(-5, 1), (2**80, 3)])
def test_the_wrapper_clamps_instead_of_raising(cap: int, top: int) -> None:
    shaper = _wrapper()
    shaper.set_tier_cap(cap)
    _climb(shaper, 5.0)
    assert shaper.tier == top


def test_watch_tier_calls_the_listener_once_per_change() -> None:
    shaper = _wrapper()
    seen: list[int] = []
    shaper.watch_tier(seen.append)
    after_each_poll: list[int] = []
    now = T0
    while now < T0 + 3.0:
        _, now = shaper.poll(now, 1000, now - T0, 0)
        after_each_poll.append(shaper.tier)
    changes = [
        tier
        for before, tier in zip([0, *after_each_poll], after_each_poll)
        if tier != before
    ]
    assert seen == changes
    assert seen[-1] == 3
    assert len(after_each_poll) > len(changes), "no poll without a change"


class _CountingCore:
    """Wraps the core and counts ``tier`` calls."""

    def __init__(self, core: tuncore.Shaper) -> None:
        self._core = core
        self.tier_calls = 0

    def poll(
        self, now: float, queue_len: int, oldest_wait: float, real_sent: int
    ) -> tuple[int, float]:
        return self._core.poll(now, queue_len, oldest_wait, real_sent)

    def tier(self) -> int:
        self.tier_calls += 1
        return self._core.tier()


def test_without_a_listener_poll_makes_no_extra_call() -> None:
    shaper = _wrapper()
    counting = _CountingCore(shaper._core)
    shaper._core = counting  # type: ignore[assignment]
    _climb(shaper, 3.0)
    assert counting.tier_calls == 0


def test_repr_shows_no_cap_or_tier() -> None:
    core = _core()
    core.set_tier_cap(2)
    shaper = _wrapper()
    shaper.set_tier_cap(2)
    for text in (repr(core).lower(), repr(shaper).lower()):
        assert "cap" not in text
        assert "tier" not in text
