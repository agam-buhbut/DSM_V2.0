"""Tests for dsm.traffic.shaper — padding + no-mode-boundary invariants.

The chaff wire rate is governed by the adaptive envelope
(``update_envelope`` / ``release_budget``, covered in
test_adaptive_envelope.py). These tests pin the remaining shaper
properties:

* No active/idle binary switch — there is no observable transition, and
  no mode-design state or symbols sneak back in under a new name.
* ``pad_packet`` padding behavior is unchanged by the redesign.
"""

import unittest

from dsm.traffic.shaper import TrafficShaper


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
