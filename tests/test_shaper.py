"""Tests for dsm.traffic.shaper — burst-edge smoothing."""

import time
import unittest

from dsm.traffic.shaper import SMOOTHING_WINDOW, TrafficShaper


class TestBurstSmoothing(unittest.TestCase):
    def test_idle_state_no_smoothing(self) -> None:
        shaper = TrafficShaper()
        self.assertIsNone(shaper.burst_smoothing_delay())

    def test_first_real_packet_arms_window(self) -> None:
        shaper = TrafficShaper()
        shaper.observe_real_packet(1400)
        delay = shaper.burst_smoothing_delay()
        self.assertIsNotNone(delay)
        assert delay is not None
        self.assertGreaterEqual(delay, 0.001)
        self.assertLessEqual(delay, 0.025)

    def test_smoothing_window_expires(self) -> None:
        shaper = TrafficShaper()
        shaper.observe_real_packet(1400)
        # Force the window into the past.
        shaper._burst_smoothing_until = time.monotonic() - 0.1
        self.assertIsNone(shaper.burst_smoothing_delay())

    def test_re_arms_after_idle_gap(self) -> None:
        shaper = TrafficShaper()
        shaper.observe_real_packet(1400)
        shaper._burst_smoothing_until = time.monotonic() - 0.1
        # Simulate a long idle gap, then a new packet.
        shaper._last_real_time = time.monotonic() - 10.0
        shaper.observe_real_packet(1400)
        delay = shaper.burst_smoothing_delay()
        self.assertIsNotNone(delay)

    def test_active_burst_does_not_rearm(self) -> None:
        shaper = TrafficShaper()
        shaper.observe_real_packet(1400)
        armed_until = shaper._burst_smoothing_until
        # Immediate follow-up packet: still active, window not re-extended.
        shaper.observe_real_packet(1400)
        self.assertAlmostEqual(shaper._burst_smoothing_until, armed_until, delta=0.01)

    def test_smoothing_window_matches_constant(self) -> None:
        shaper = TrafficShaper()
        before = time.monotonic()
        shaper.observe_real_packet(1400)
        self.assertGreaterEqual(shaper._burst_smoothing_until, before + SMOOTHING_WINDOW - 0.01)


if __name__ == "__main__":
    unittest.main()
