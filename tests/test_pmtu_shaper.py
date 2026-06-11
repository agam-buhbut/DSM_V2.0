"""Phase 1.7: when auto_mtu lowers the path, the shaper's size-class ceiling
must drop so outer packets fit the constrained PMTU (no 1400-class on a
sub-1428 DF path).
"""

from __future__ import annotations

import unittest

from dsm.core.protocol import SIZE_CLASSES, InnerPacket, PacketType
from dsm.traffic.shaper import TrafficShaper

# On-wire datagram overhead beyond the DSM outer packet (IP 20 + UDP 8).
_LINK_OVERHEAD = 28


class ShaperCeilingClamp(unittest.TestCase):
    def test_clamp_caps_size_classes_to_fit_path(self) -> None:
        shaper = TrafficShaper(128, 1400)
        # Path MTU 1300 -> outer ceiling = 1300 - 28 = 1272.
        shaper.set_size_class_ceiling(1300 - _LINK_OVERHEAD)
        # Sample many padded packets; every outer target must be <= 1272.
        for _ in range(200):
            inner = InnerPacket(ptype=PacketType.DATA, epoch_id=0, payload=b"x" * 64)
            _padded, target = shaper.pad_packet(inner)
            self.assertLessEqual(
                target + _LINK_OVERHEAD,
                1300,
                f"outer {target} + link {_LINK_OVERHEAD} exceeds path 1300",
            )

    def test_clamp_is_idempotent_and_raise_restores(self) -> None:
        shaper = TrafficShaper(128, 1400)
        shaper.set_size_class_ceiling(1272)
        capped = max(shaper._active_classes)
        self.assertLessEqual(capped, 1272)
        # Raising the ceiling back to the original padding_max restores the
        # full class set (bounded by padding_max=1400).
        shaper.set_size_class_ceiling(1400)
        self.assertEqual(max(shaper._active_classes), max(SIZE_CLASSES))

    def test_clamp_below_smallest_class_keeps_one_class(self) -> None:
        shaper = TrafficShaper(128, 1400)
        # Absurdly small ceiling: must still leave at least one usable class.
        shaper.set_size_class_ceiling(50)
        self.assertGreaterEqual(len(shaper._active_classes), 1)

    def test_default_no_ceiling_unchanged(self) -> None:
        # Without calling set_size_class_ceiling, the active classes are the
        # full padding-bounded set — behavior is unchanged from before 1.7.
        shaper = TrafficShaper(128, 1400)
        expected = tuple(sc for sc in SIZE_CLASSES if 128 <= sc <= 1400)
        self.assertEqual(shaper._active_classes, expected)
        self.assertEqual(max(shaper._active_classes), max(SIZE_CLASSES))


if __name__ == "__main__":
    unittest.main()
