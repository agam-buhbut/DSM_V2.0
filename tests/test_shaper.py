"""Tests for dsm.traffic.shaper — the Python side of the tier shaper.

When packets leave is decided by the Rust tier shaper (covered in
test_tier_shaper.py and the Rust tests in rust/tuncore/src/shaper.rs).
These tests pin the remaining shaper properties:

* No active/idle binary switch and no adaptive-envelope API — nothing from
  the replaced designs sneaks back in under a new name.
* The wrapper exposes no secret timing values, and the size list comes from
  the Rust core.
* ``pad_packet`` padding behavior is unchanged by the redesign.
* ``pad_chaff_to_class`` raises instead of growing the class, and an
  out-of-range size ceiling is clamped before it reaches the Rust core.
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


class TestNoEnvelope(unittest.TestCase):
    """The adaptive envelope was replaced by the tier shaper."""

    def test_envelope_api_and_state_are_gone(self) -> None:
        import dsm.traffic.shaper as shaper_mod

        shaper = TrafficShaper()
        for name in (
            "update_envelope",
            "release_budget",
            "_envelope_pps",
            "_idle_floor_pps",
            "_release_credit",
        ):
            self.assertFalse(
                hasattr(shaper, name), f"{name} is adaptive-envelope state"
            )
        leftovers = [n for n in dir(shaper_mod) if n.startswith("_ENVELOPE_")]
        self.assertEqual(leftovers, [])

    def test_envelope_keyword_arguments_are_rejected(self) -> None:
        with self.assertRaises(TypeError):
            TrafficShaper(envelope_latency_budget_ms=1000)  # type: ignore[call-arg]


class TestNoSecretGetters(unittest.TestCase):
    def test_wrapper_exposes_only_packet_and_schedule_calls(self) -> None:
        public = {n for n in dir(TrafficShaper()) if not n.startswith("_")}
        self.assertEqual(
            public,
            {
                "from_config",
                "make_chaff_padded",
                "pad_chaff_to_class",
                "pad_packet",
                "poll",
                "set_size_class_ceiling",
            },
        )


class TestSizeListComesFromRust(unittest.TestCase):
    def test_protocol_reexports_the_rust_size_list(self) -> None:
        import tuncore
        from dsm.core import protocol

        self.assertIs(protocol.SIZE_CLASSES, tuncore.SIZE_CLASSES)
        self.assertIs(protocol.SIZE_CLASS_WEIGHTS, tuncore.SIZE_CLASS_WEIGHTS)


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


class TestPadChaffToClass(unittest.TestCase):
    """pad_chaff_to_class pads to the class it is given or raises ValueError.
    It no longer bumps the class up to fit the payload."""

    def test_a_class_out_of_use_raises(self) -> None:
        from dsm.core.protocol import InnerPacket, PacketType

        shaper = TrafficShaper(128, 1400)
        shaper.set_size_class_ceiling(512)
        empty = InnerPacket(ptype=PacketType.CHAFF, epoch_id=0, payload=b"")
        # 640 is in the size list, but the ceiling took it out of use.
        with self.assertRaises(ValueError):
            shaper.pad_chaff_to_class(empty, 640)

    def test_a_payload_too_big_for_the_class_raises(self) -> None:
        from dsm.core.protocol import InnerPacket, PacketType

        shaper = TrafficShaper(128, 1400)
        # The 128-byte class holds 88 payload bytes: 128 minus the outer
        # header (20), the GCM tag (16) and the inner header (4).
        fits = InnerPacket(ptype=PacketType.CHAFF, epoch_id=0, payload=b"x" * 88)
        padded, target = shaper.pad_chaff_to_class(fits, 128)
        self.assertEqual((len(padded), target), (92, 128))
        too_big = InnerPacket(ptype=PacketType.CHAFF, epoch_id=0, payload=b"x" * 89)
        with self.assertRaises(ValueError):
            shaper.pad_chaff_to_class(too_big, 128)


class TestSizeCeilingClamp(unittest.TestCase):
    def test_out_of_range_ceilings_are_clamped_not_raised(self) -> None:
        """The core takes a ceiling of 0-65535. The wrapper clamps first, so
        an out-of-range value never raises OverflowError."""
        shaper = TrafficShaper(128, 1400)
        # Below 0 acts as 0: only the smallest class stays in use.
        shaper.set_size_class_ceiling(-1)
        self.assertEqual(shaper._active_classes, (128,))
        # Above 65535 acts as 65535, so padding_max (1400) is the cap again.
        shaper.set_size_class_ceiling(65536)
        self.assertEqual(
            shaper._active_classes,
            (128, 256, 384, 512, 640, 768, 896, 1024, 1152, 1280, 1400),
        )


if __name__ == "__main__":
    unittest.main()
