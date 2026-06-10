"""Tests for dsm.traffic.shaper — Poisson chaff scheduling.

These tests pin down the post-H-ANON-2/H-ANON-3 redesign properties:

* No active/idle binary switch — there is no observable transition.
* Chaff inter-arrival times come from a Poisson process (memoryless,
  exponential).
* The target rate is a slow EMA of total wire-packet rate (real +
  chaff), clamped to [_CHAFF_RATE_FLOOR_PPS, _CHAFF_RATE_CEIL_PPS].
* ``burst_smoothing_delay()`` is permanently ``None`` — the EMA's
  inherent lag is the smoothing now, an explicit per-packet jitter at
  the burst onset would re-create the very leak it once masked.
"""

import statistics
import time
import unittest

from dsm.traffic.shaper import (
    _CHAFF_RATE_CEIL_PPS,
    _CHAFF_RATE_FLOOR_PPS,
    _INITIAL_RATE_PPS,
    _RATE_EMA_ALPHA,
    TrafficShaper,
)


def _collect_chaff_ipts(
    shaper: TrafficShaper, n_samples: int, sim_now_start: float = 0.0
) -> list[float]:
    """Sample ``n_samples`` consecutive chaff inter-arrival times by
    advancing simulated time to whatever ``_next_chaff_time`` the shaper
    just scheduled. Returns deltas between successive fires.

    This bypasses real wall-clock waiting: it sets ``_next_chaff_time``
    directly via the Poisson scheduler and reads the gap between fires.
    """
    times: list[float] = []
    # Bootstrap: prime the next-chaff timer at the simulated origin.
    shaper._next_chaff_time = sim_now_start
    for _ in range(n_samples):
        # Pretend "now" is exactly the scheduled fire time.
        now = shaper._next_chaff_time
        shaper._schedule_next_chaff(now)
        times.append(shaper._next_chaff_time - now)
    return times


class TestPoissonChaffScheduling(unittest.TestCase):
    """The chaff scheduler is a Poisson process at ``_target_rate_pps``."""

    def test_should_send_chaff_fires_when_scheduled_time_arrives(self) -> None:
        shaper = TrafficShaper()
        # Force the next-fire time into the past — should fire immediately.
        shaper._next_chaff_time = time.monotonic() - 0.1
        self.assertTrue(shaper.should_send_chaff())

    def test_should_send_chaff_holds_off_when_future_scheduled(self) -> None:
        shaper = TrafficShaper()
        shaper._next_chaff_time = time.monotonic() + 60.0
        self.assertFalse(shaper.should_send_chaff())

    def test_fire_immediately_reschedules_next(self) -> None:
        shaper = TrafficShaper()
        shaper._next_chaff_time = time.monotonic() - 0.1
        self.assertTrue(shaper.should_send_chaff())
        # After firing, the next time must be in the future (Poisson gap
        # of at least 1ms, per the floor clamp on the exponential sample).
        self.assertGreater(shaper._next_chaff_time, time.monotonic())

    def test_chaff_ipts_are_exponential(self) -> None:
        """Inter-arrival times match an exponential distribution.

        For Exp(lambda) the mean = stdev = 1/lambda. We sample 2000 gaps
        at a fixed rate and check that mean and stdev land within ±25%
        of 1/rate (loose enough to be deterministic, tight enough to
        reject any fixed-cadence regression).
        """
        shaper = TrafficShaper()
        # Pin a known rate; floor=1pps, mean gap = 1.0s. Stays inside
        # the exponential clamp [1ms, 5s] for all samples.
        shaper._target_rate_pps = 4.0
        gaps = _collect_chaff_ipts(shaper, n_samples=2000)
        expected_mean = 1.0 / 4.0
        mean = statistics.fmean(gaps)
        stdev = statistics.stdev(gaps)
        self.assertAlmostEqual(mean, expected_mean, delta=expected_mean * 0.25)
        # For Exp the stdev equals the mean.
        self.assertAlmostEqual(stdev, expected_mean, delta=expected_mean * 0.30)

    def test_chaff_rate_matches_target(self) -> None:
        """N fires over a simulated window come out near ``rate * window``."""
        shaper = TrafficShaper()
        shaper._target_rate_pps = 10.0
        gaps = _collect_chaff_ipts(shaper, n_samples=2000)
        observed_rate = len(gaps) / sum(gaps)
        # Within ±15% of the target.
        self.assertAlmostEqual(observed_rate, 10.0, delta=10.0 * 0.15)

    def test_exponential_clamp_caps_max_gap(self) -> None:
        """Even at the floor rate the sampled gap is bounded at 5s."""
        shaper = TrafficShaper()
        shaper._target_rate_pps = _CHAFF_RATE_FLOOR_PPS  # 1 pps, mean 1s
        gaps = _collect_chaff_ipts(shaper, n_samples=5000)
        # csprng_exponential's clamp uses float math; tolerate 1ulp slack
        # below the nominal 1ms / above 5s boundaries.
        self.assertLessEqual(max(gaps), 5.0 + 1e-9)
        self.assertGreaterEqual(min(gaps), 0.001 - 1e-9)


class TestNoModeBoundary(unittest.TestCase):
    """The redesign removed the active/idle binary switch — make sure
    nothing in the API reintroduces it under a different name."""

    def test_no_idle_threshold_symbol(self) -> None:
        import dsm.traffic.shaper as shaper_mod

        self.assertFalse(
            hasattr(shaper_mod, "IDLE_THRESHOLD"),
            "IDLE_THRESHOLD must be gone — its presence is the H-ANON-2 leak",
        )
        for name in (
            "IDLE_BURST_MIN",
            "IDLE_BURST_MAX",
            "IDLE_GAP_LAMBDA",
            "RESAMPLE_MIN",
            "RESAMPLE_MAX",
            "_ACTIVE_CHAFF_BASE_PROB",
            "_CHAFF_RATE_BASE",
        ):
            self.assertFalse(
                hasattr(shaper_mod, name),
                f"{name} must be gone — leftover from the mode-based design",
            )

    def test_shaper_has_no_burst_state(self) -> None:
        shaper = TrafficShaper()
        for name in (
            "_idle_burst_remaining",
            "_next_idle_burst",
            "_chaff_rate_multiplier",
            "_next_resample",
        ):
            self.assertFalse(
                hasattr(shaper, name),
                f"{name} on TrafficShaper is mode-design state",
            )

    def test_burst_smoothing_is_permanently_none(self) -> None:
        """The boundary-masking jitter is dead — its trigger condition
        was the same idle→active boundary the redesign eliminated."""
        shaper = TrafficShaper()
        self.assertIsNone(shaper.burst_smoothing_delay())
        shaper.observe_real_packet(1400)
        self.assertIsNone(shaper.burst_smoothing_delay())
        for _ in range(50):
            shaper.observe_real_packet(1400)
        self.assertIsNone(shaper.burst_smoothing_delay())


class TestRateEMA(unittest.TestCase):
    """``_target_rate_pps`` is an EMA of total wire-packet rate.
    Updated by every real and every chaff send."""

    def test_initial_rate_is_floor(self) -> None:
        shaper = TrafficShaper()
        self.assertEqual(shaper._target_rate_pps, _INITIAL_RATE_PPS)
        self.assertGreaterEqual(_INITIAL_RATE_PPS, _CHAFF_RATE_FLOOR_PPS)

    def test_real_packet_updates_rate(self) -> None:
        shaper = TrafficShaper()
        before = shaper._target_rate_pps
        # Two packets ~10ms apart simulate ~100pps instant rate.
        now = time.monotonic()
        shaper._observe_wire_send(now)
        shaper._observe_wire_send(now + 0.01)
        self.assertGreater(shaper._target_rate_pps, before)

    def test_chaff_packet_updates_rate(self) -> None:
        shaper = TrafficShaper()
        before = shaper._target_rate_pps
        now = time.monotonic()
        shaper.observe_chaff_packet()
        # Need a second observation to compute an EMA-eligible dt.
        # Patch in a manual time so we have a known instant rate.
        shaper._last_wire_time = now
        shaper._observe_wire_send(now + 0.05)  # 20pps instant
        self.assertGreater(shaper._target_rate_pps, before)

    def test_rate_clamped_to_floor(self) -> None:
        shaper = TrafficShaper()
        # Force a huge dt — without the floor clamp this would pull the
        # EMA toward 1 / (2s) = 0.5pps, below the floor.
        shaper._last_wire_time = time.monotonic() - 10.0
        shaper._target_rate_pps = _CHAFF_RATE_FLOOR_PPS
        for _ in range(100):
            shaper._observe_wire_send(time.monotonic())
            shaper._last_wire_time = time.monotonic() - 10.0
        self.assertGreaterEqual(shaper._target_rate_pps, _CHAFF_RATE_FLOOR_PPS)

    def test_rate_clamped_to_ceiling(self) -> None:
        shaper = TrafficShaper()
        # Hammer ten thousand back-to-back observations at zero dt.
        now = time.monotonic()
        shaper._last_wire_time = now
        for i in range(10_000):
            shaper._observe_wire_send(now)  # dt = 0 → instant = ceiling
        self.assertLessEqual(shaper._target_rate_pps, _CHAFF_RATE_CEIL_PPS)

    def test_rate_ema_lags_real_traffic_onset(self) -> None:
        """An EMA alpha of 0.05 means the rate cannot snap up within a
        single packet — that lag is what hides the activity boundary.
        After one observation at 100pps, the EMA should still be far
        below 100pps."""
        shaper = TrafficShaper()
        now = time.monotonic()
        shaper._last_wire_time = now
        shaper._target_rate_pps = _CHAFF_RATE_FLOOR_PPS  # 1pps
        # Inject a single 100pps observation (10ms gap).
        shaper._observe_wire_send(now + 0.01)
        # After one sample at instant=100, EMA = 0.95*1 + 0.05*100 = 5.95
        # — nowhere near the activity-onset rate.
        self.assertLess(shaper._target_rate_pps, 10.0)

    def test_ema_alpha_is_small(self) -> None:
        """Regression lock: the EMA alpha must be small enough that a
        burst takes seconds to bleed through, not milliseconds."""
        self.assertLessEqual(_RATE_EMA_ALPHA, 0.10)
        self.assertGreater(_RATE_EMA_ALPHA, 0.0)


class TestChaffPipelineFeedsRateEMA(unittest.TestCase):
    """``make_chaff_packet`` MUST notify the shaper so chaff sends feed
    the EMA. Without this, real-traffic silence + chaff-only periods
    would diverge the EMA from the actual wire rate and re-expose the
    activity boundary."""

    def test_make_chaff_packet_increments_wire_history(self) -> None:
        import asyncio

        from dsm.traffic.shaper import make_chaff_packet

        shaper = TrafficShaper()
        before = len(shaper._recent_wire_times)
        asyncio.run(make_chaff_packet(shaper, epoch_id=0))
        after = len(shaper._recent_wire_times)
        self.assertEqual(after, before + 1)


class TestNoFixedCadence(unittest.TestCase):
    """Statistical sanity: chaff IPTs MUST NOT cluster around any
    constant value (would indicate a leftover fixed cadence)."""

    def test_ipts_have_high_relative_variance(self) -> None:
        """For Exp(lambda) the coefficient of variation = stdev/mean = 1.
        For a fixed-cadence stream it would be ≈ 0. Reject anything
        below 0.5."""
        shaper = TrafficShaper()
        shaper._target_rate_pps = 20.0
        gaps = _collect_chaff_ipts(shaper, n_samples=2000)
        cv = statistics.stdev(gaps) / statistics.fmean(gaps)
        self.assertGreater(
            cv,
            0.5,
            f"coefficient of variation {cv:.3f} too low — fixed cadence?",
        )

    def test_ipts_pass_basic_memoryless_check(self) -> None:
        """Memoryless property: ``P(X > s+t | X > s) = P(X > t)``.
        Approximate check — split samples above/below the median and
        verify the upper half conditional distribution still has roughly
        exponential shape (its conditional mean ≈ unconditional mean +
        median, with substantial tolerance)."""
        shaper = TrafficShaper()
        shaper._target_rate_pps = 5.0
        gaps = _collect_chaff_ipts(shaper, n_samples=3000)
        med = statistics.median(gaps)
        upper_tail = [g - med for g in gaps if g > med]
        # Conditional mean should be close to the unconditional mean
        # 1 / lambda = 0.2 (memoryless property). Loose tolerance — the
        # 5s tail clamp will pull it slightly down.
        cond_mean = statistics.fmean(upper_tail)
        expected = 1.0 / 5.0
        self.assertAlmostEqual(cond_mean, expected, delta=expected * 0.5)


class TestPaddingStillWorks(unittest.TestCase):
    """Regression: pad_packet behavior is unchanged by the redesign."""

    def test_pad_packet_returns_target_in_size_classes(self) -> None:
        from dsm.core.protocol import SIZE_CLASSES, InnerPacket, PacketType

        shaper = TrafficShaper(128, 1400)
        inner = InnerPacket(ptype=PacketType.DATA, epoch_id=0, payload=b"x" * 40)
        seen = set()
        for _ in range(500):
            _, target = shaper.pad_packet(inner)
            seen.add(target)
        for t in seen:
            self.assertIn(t, SIZE_CLASSES)
            self.assertGreaterEqual(t, 128)
            self.assertLessEqual(t, 1400)


if __name__ == "__main__":
    unittest.main()
