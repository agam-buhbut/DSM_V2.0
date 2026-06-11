"""Phase 2.1: envelope estimator + paced release (deterministic clock).

These tests drive an injected monotonic clock (no wall-clock sleeps) and
assert the envelope's paced-release contract directly. The CSPRNG is NOT
seedable, so we assert on the DETERMINISTIC pacing math (release_budget),
not on chaff randomness.
"""

from __future__ import annotations

import unittest

from dsm.traffic.shaper import TrafficShaper


class _Clock:
    """Injectable monotonic clock for deterministic pacing tests."""

    def __init__(self, start: float = 1000.0) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, dt: float) -> None:
        self.t += dt


class TestEnvelopeRelease(unittest.TestCase):
    def _shaper(self, clock: _Clock) -> TrafficShaper:
        # Explicit envelope profile so the test is independent of config
        # defaults: floor 1pps, ceiling 100pps, rise x2/s, fall 4s half-life,
        # 250ms budget. (Construction-time floor randomization is pinned by
        # passing equal min/max bounds.)
        return TrafficShaper(
            clock=clock,
            envelope_idle_floor_min_pps=1.0,
            envelope_idle_floor_max_pps=1.0,
            envelope_ceiling_pps=100.0,
            envelope_rise_per_s=2.0,
            envelope_fall_half_life_s=4.0,
            envelope_latency_budget_ms=250,
        )

    def test_idle_release_tracks_floor(self) -> None:
        clk = _Clock()
        s = self._shaper(clk)
        # No real queued: over 10s at 1pps floor, ~10 packets released.
        released = 0
        for _ in range(1000):
            clk.advance(0.01)  # 10ms ticks
            s.update_envelope(clk(), real_queue_depth=0, oldest_real_age_s=0.0)
            released += s.release_budget(clk())
        self.assertAlmostEqual(released, 10, delta=2)

    def test_release_credit_no_rounding_bias(self) -> None:
        # At 1pps with 10ms ticks the per-tick budget is 0.01 pkt — must
        # accumulate via fractional credit, not round to 0 every tick.
        clk = _Clock()
        s = self._shaper(clk)
        total = 0
        for _ in range(500):
            clk.advance(0.01)
            s.update_envelope(clk(), 0, 0.0)
            total += s.release_budget(clk())
        self.assertGreaterEqual(total, 3)  # ~5 expected; never 0

    def test_burst_onset_is_smeared_not_stepped(self) -> None:
        # 200 real packets arrive at t=0 (a burst). With a 2x/s rise cap and
        # a 1pps start, the envelope must NOT jump to drain them in <1 tick:
        # the first 100ms must release far fewer than 200.
        clk = _Clock()
        s = self._shaper(clk)
        depth = 200
        released_first_100ms = 0
        for _ in range(10):  # 10 x 10ms = 100ms
            clk.advance(0.01)
            s.update_envelope(clk(), real_queue_depth=depth, oldest_real_age_s=0.0)
            n = s.release_budget(clk())
            released_first_100ms += n
            depth = max(0, depth - n)
        # Onset smeared: well under half the burst in the first 100ms.
        self.assertLess(released_first_100ms, 50)
        self.assertGreater(depth, 100)

    def test_latency_budget_overrides_rise_cap(self) -> None:
        # A single real packet that has waited past the 250ms budget must be
        # releasable even though the rise cap alone would still be low.
        clk = _Clock()
        s = self._shaper(clk)
        clk.advance(0.30)  # 300ms > 250ms budget
        s.update_envelope(clk(), real_queue_depth=1, oldest_real_age_s=0.30)
        self.assertGreaterEqual(s.release_budget(clk()), 1)


class TestEnvelopeFallToFloor(unittest.TestCase):
    def test_envelope_decays_toward_floor_over_half_life(self) -> None:
        # Drive the envelope up under a burst, then go idle and confirm it
        # decays toward the idle floor on roughly the configured half-life.
        clk = _Clock()
        s = TrafficShaper(
            clock=clk,
            envelope_idle_floor_min_pps=1.0,
            envelope_idle_floor_max_pps=1.0,
            envelope_ceiling_pps=1000.0,
            envelope_rise_per_s=4.0,
            envelope_fall_half_life_s=2.0,
            envelope_latency_budget_ms=250,
        )
        # Ramp up: sustained queue for ~2s.
        for _ in range(200):
            clk.advance(0.01)
            s.update_envelope(clk(), real_queue_depth=500, oldest_real_age_s=0.0)
        peak = s._envelope_pps
        self.assertGreater(peak, 5.0, "sanity: envelope rose under burst")
        # Now idle for exactly one half-life (2s) — the gap above the floor
        # must roughly halve.
        gap_before = peak - 1.0
        clk.advance(2.0)
        s.update_envelope(clk(), real_queue_depth=0, oldest_real_age_s=0.0)
        gap_after = s._envelope_pps - 1.0
        self.assertAlmostEqual(gap_after, gap_before * 0.5, delta=gap_before * 0.1)
        # Keep idling: it must approach (never undercut) the floor.
        for _ in range(2000):
            clk.advance(0.01)
            s.update_envelope(clk(), real_queue_depth=0, oldest_real_age_s=0.0)
        self.assertAlmostEqual(s._envelope_pps, 1.0, delta=0.1)


class TestSoftCeiling(unittest.TestCase):
    def test_chaff_fill_never_exceeds_ceiling(self) -> None:
        # With NO real queue (chaff-fill only) the envelope must never rise
        # above the soft ceiling regardless of how long it runs.
        clk = _Clock()
        s = TrafficShaper(
            clock=clk,
            envelope_idle_floor_min_pps=1.0,
            envelope_idle_floor_max_pps=1.0,
            envelope_ceiling_pps=50.0,
            envelope_rise_per_s=2.0,
            envelope_fall_half_life_s=4.0,
            envelope_latency_budget_ms=250,
        )
        # A bounded real queue (under budget) drives the envelope up but the
        # soft ceiling must cap it.
        for _ in range(2000):
            clk.advance(0.01)
            s.update_envelope(clk(), real_queue_depth=10_000, oldest_real_age_s=0.0)
        self.assertLessEqual(s._envelope_pps, 50.0 + 1e-9)

    def test_budget_override_may_pierce_ceiling(self) -> None:
        # When the oldest real packet has waited past the budget the override
        # raises the envelope to drain it even above the soft ceiling.
        clk = _Clock()
        s = TrafficShaper(
            clock=clk,
            envelope_idle_floor_min_pps=1.0,
            envelope_idle_floor_max_pps=1.0,
            envelope_ceiling_pps=50.0,
            envelope_rise_per_s=2.0,
            envelope_fall_half_life_s=4.0,
            envelope_latency_budget_ms=250,
        )
        clk.advance(0.01)
        s.update_envelope(clk(), real_queue_depth=0, oldest_real_age_s=0.0)
        # 100 packets that have waited past the 250ms budget: desired =
        # 100 / 0.25 = 400 pps, well above the 50pps ceiling.
        clk.advance(0.30)
        s.update_envelope(clk(), real_queue_depth=100, oldest_real_age_s=0.30)
        self.assertGreater(s._envelope_pps, 50.0)


class TestNoCeilingSnapOnBurst(unittest.TestCase):
    def test_same_tick_sends_do_not_snap_envelope(self) -> None:
        clk = _Clock()
        s = TrafficShaper(
            clock=clk,
            envelope_idle_floor_min_pps=1.0,
            envelope_idle_floor_max_pps=1.0,
            envelope_ceiling_pps=100.0,
            envelope_rise_per_s=2.0,
            envelope_fall_half_life_s=4.0,
            envelope_latency_budget_ms=250,
        )
        # Many update_envelope calls at the SAME now (dt=0) must not move
        # the envelope at all — no snap-to-ceiling.
        before = s._envelope_pps
        for _ in range(1000):
            s.update_envelope(clk(), real_queue_depth=500, oldest_real_age_s=0.0)
        self.assertEqual(s._envelope_pps, before)

    def test_rise_capped_under_sustained_burst(self) -> None:
        clk = _Clock()
        s = TrafficShaper(
            clock=clk,
            envelope_idle_floor_min_pps=1.0,
            envelope_idle_floor_max_pps=1.0,
            envelope_ceiling_pps=1000.0,
            envelope_rise_per_s=2.0,
            envelope_fall_half_life_s=4.0,
            envelope_latency_budget_ms=10_000,  # huge budget: no override
        )
        # 1s of sustained large queue at a huge latency budget: the rise cap
        # (2x/s) must bound the envelope to ~<= 2x the start, not the ceiling.
        for _ in range(100):
            clk.advance(0.01)
            s.update_envelope(clk(), real_queue_depth=500, oldest_real_age_s=0.0)
        self.assertLessEqual(s._envelope_pps, 1.0 * 2.0 + 0.5)  # ~2pps, not 1000


if __name__ == "__main__":
    unittest.main()
