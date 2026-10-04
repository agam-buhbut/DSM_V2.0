"""Black-box tests for the Rust tier shaper (``tuncore.Shaper``).

The core draws its secret values from the OS RNG, so these tests drive it
with an injected clock (the ``now`` argument) and check bounds and averages,
never exact values. The exact, seeded behavior, including the key property
that traffic fitting the current tier never moves send times, is pinned by
the Rust tests in rust/tuncore/src/shaper.rs.
"""

from __future__ import annotations

import statistics
from collections import deque
from collections.abc import Iterable

import pytest

import tuncore
from dsm.core import protocol

T0 = 1000.0
TIERS = [10.0, 50.0, 200.0, 800.0]
# Secret per-session tier scale is 0.8-1.2, so tier 0 runs at 8-12 packets/s.
TIER0_MIN_PPS = TIERS[0] * 0.8
TIER0_MAX_PPS = TIERS[0] * 1.2
PUBLISHED_SIZES = (128, 256, 384, 512, 640, 768, 896, 1024, 1152, 1280, 1400)
PUBLISHED_WEIGHTS = (20, 15, 12, 10, 8, 7, 6, 6, 5, 6, 5)


def _shaper(
    *,
    decoy_interval_s: float = 0.0,
    linger_s: tuple[float, float] = (0.0, 0.0),
    padding_min: int = 128,
    padding_max: int = 1400,
) -> tuncore.Shaper:
    return tuncore.Shaper(
        TIERS, 0.5, decoy_interval_s, linger_s, padding_min, padding_max, T0
    )


def _run(
    shaper: tuncore.Shaper, end: float, arrivals: Iterable[float] = ()
) -> list[float]:
    """Drive ``shaper`` like the scheduler: poll at each ``next_wake``, send
    real packets first, chaff for the rest. Returns the departure times."""
    pending = deque(sorted(arrivals))
    queue: deque[float] = deque()
    departures: list[float] = []
    real_sent = 0
    now = T0
    while now <= end:
        while pending and pending[0] <= now:
            queue.append(pending.popleft())
        oldest_wait = now - queue[0] if queue else 0.0
        slots, next_wake = shaper.poll(now, len(queue), oldest_wait, real_sent)
        real_sent = 0
        for _ in range(slots):
            if queue:
                queue.popleft()
                real_sent += 1
            departures.append(now)
        assert next_wake > now
        now = next_wake
    return departures


def _count(departures: list[float], start: float, end: float) -> int:
    return sum(1 for t in departures if start <= t < end)


def test_exports_the_published_size_list() -> None:
    assert tuncore.SIZE_CLASSES == PUBLISHED_SIZES
    assert tuncore.SIZE_CLASS_WEIGHTS == PUBLISHED_WEIGHTS
    assert protocol.SIZE_CLASSES == PUBLISHED_SIZES
    assert protocol.SIZE_CLASS_WEIGHTS == PUBLISHED_WEIGHTS
    assert (tuncore.CHAFF_PERTURB_UP_P, tuncore.CHAFF_PERTURB_DOWN_P) == (0.15, 0.30)


@pytest.mark.parametrize(
    "args",
    [
        ([10.0], 0.5, 0.0, (0.0, 0.0), 128, 1400),  # one tier
        ([10.0] * 9, 0.5, 0.0, (0.0, 0.0), 128, 1400),  # nine tiers
        ([50.0, 10.0], 0.5, 0.0, (0.0, 0.0), 128, 1400),  # not rising
        ([0.5, 10.0], 0.5, 0.0, (0.0, 0.0), 128, 1400),  # below 1 pps
        ([10.0, 5001.0], 0.5, 0.0, (0.0, 0.0), 128, 1400),  # above 5000 pps
        (TIERS, 0.009, 0.0, (0.0, 0.0), 128, 1400),  # budget too small
        (TIERS, 5.01, 0.0, (0.0, 0.0), 128, 1400),  # budget too large
        (TIERS, 0.5, 299.0, (0.0, 0.0), 128, 1400),  # decoys too often
        (TIERS, 0.5, 86401.0, (0.0, 0.0), 128, 1400),  # decoys too rare
        (TIERS, 0.5, 0.0, (0.0, 10.0), 128, 1400),  # linger min 0, max > 0
        (TIERS, 0.5, 0.0, (10.0, 5.0), 128, 1400),  # linger min > max
        (TIERS, 0.5, 0.0, (10.0, 7201.0), 128, 1400),  # linger too long
        (TIERS, 0.5, 0.0, (0.0, 0.0), 512, 256),  # padding min > max
    ],
)
def test_rejects_bad_config_with_value_error(args: tuple[object, ...]) -> None:
    with pytest.raises(ValueError):
        tuncore.Shaper(*args, T0)  # type: ignore[arg-type]


@pytest.mark.parametrize("bad_now", [float("nan"), float("inf")])
def test_rejects_a_start_time_that_is_not_finite(bad_now: float) -> None:
    with pytest.raises(ValueError):
        tuncore.Shaper(TIERS, 0.5, 0.0, (0.0, 0.0), 128, 1400, bad_now)


def test_no_getters_and_nothing_in_repr() -> None:
    shaper = _shaper()
    public = {name for name in dir(shaper) if not name.startswith("_")}
    assert public == {
        "active_classes",
        "chaff_size_class",
        "poll",
        "real_size_class",
        "set_size_class_ceiling",
    }
    text = repr(shaper).lower()
    for word in ("scale", "spread", "hold", "tier", "decoy", "secret"):
        assert word not in text
    with pytest.raises(AttributeError):
        _ = shaper.tier_scale  # type: ignore[attr-defined]


def test_idle_rate_stays_in_the_tier_zero_band() -> None:
    departures = _run(_shaper(), T0 + 120.0)
    rate = len(departures) / 120.0
    assert TIER0_MIN_PPS * 0.95 <= rate <= TIER0_MAX_PPS * 1.05
    gaps = [b - a for a, b in zip(departures, departures[1:])]
    # Gap spread w is 0.3-0.7, so a tier-0 gap is at most 1.7 / 8 s.
    assert max(gaps) <= 1.7 / TIER0_MIN_PPS + 1e-9


def test_a_backlog_steps_the_rate_up_within_the_budget() -> None:
    burst_at = T0 + 30.0
    departures = _run(_shaper(), T0 + 33.0, [burst_at] * 300)
    before = _count(departures, T0 + 20.0, burst_at) / 10.0
    assert before <= TIER0_MAX_PPS * 1.1
    # The step-up comes no later than the 0.5 s budget; from then on the
    # rate is at least tier 1 (50 x 0.8 = 40 packets/s).
    after = _count(departures, burst_at + 0.5, burst_at + 1.5)
    assert after >= 30


def test_a_stall_restarts_the_schedule_instead_of_bursting() -> None:
    shaper = _shaper()
    shaper.poll(T0 + 0.5, 0, 0.0, 0)
    slots, next_wake = shaper.poll(T0 + 30.0, 0, 0.0, 0)
    assert slots == 1
    assert next_wake > T0 + 30.0


@pytest.mark.parametrize("bad_now", [float("inf"), float("nan")])
def test_a_poll_time_that_is_not_finite_means_no_time_passes(bad_now: float) -> None:
    shaper = _shaper()
    max_gap = 1.7 / TIER0_MIN_PPS
    slots, next_wake = shaper.poll(bad_now, 0, 0.0, 0)
    assert slots == 0
    # Finite, and still the first send the session drew: one gap after the start.
    assert T0 < next_wake <= T0 + max_gap + 1e-9
    # The schedule is not stuck: a normal poll afterwards sends and moves on.
    slots, next_wake = shaper.poll(T0 + 0.5, 0, 0.0, 0)
    assert slots >= 1
    assert T0 + 0.5 < next_wake <= T0 + 0.5 + max_gap + 1e-9


def test_each_session_draws_its_own_timing() -> None:
    rates = [len(_run(_shaper(), T0 + 60.0)) / 60.0 for _ in range(20)]
    assert all(TIER0_MIN_PPS * 0.95 <= r <= TIER0_MAX_PPS * 1.05 for r in rates)
    # The secret scale (0.8-1.2) differs per session, so the idle rates spread.
    assert statistics.pstdev(rates) > 0.2


def test_sizes_come_from_the_active_classes_and_obey_the_ceiling() -> None:
    shaper = _shaper(padding_min=256, padding_max=1024)
    assert shaper.active_classes() == [256, 384, 512, 640, 768, 896, 1024]
    for _ in range(2000):
        assert shaper.chaff_size_class() in (256, 384, 512, 640, 768, 896, 1024)
        assert shaper.real_size_class(100) in (256, 384, 512, 640, 768, 896, 1024)
    shaper.set_size_class_ceiling(512)
    assert shaper.active_classes() == [256, 384, 512]
    for _ in range(2000):
        assert shaper.chaff_size_class() <= 512
        assert shaper.real_size_class(1) <= 512
    # A payload no class can carry gets the exact size it needs.
    assert shaper.real_size_class(1361) == 1401
