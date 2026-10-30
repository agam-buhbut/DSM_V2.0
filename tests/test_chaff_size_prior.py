"""Chaff sizes never follow real traffic.

Chaff once tracked a live EMA of real packet sizes (shaper.py:292), which
leaked the user's application profile. Since finding #55 every packet,
real or chaff, takes the largest active class, so nothing about real
traffic can move chaff sizes. These tests pin that, and that chaff still
obeys the padding range and the live size ceiling.
"""

from __future__ import annotations

import asyncio
import collections
import unittest

from dsm.core.protocol import SIZE_CLASSES, InnerPacket, PacketType
from dsm.traffic.shaper import TrafficShaper, make_chaff_packet


def _chaff_size_hist(shaper: TrafficShaper, n: int) -> collections.Counter:
    """Draw ``n`` chaff packets and return a Counter of their outer sizes."""

    async def _run() -> collections.Counter:
        c: collections.Counter = collections.Counter()
        for _ in range(n):
            _, target = await make_chaff_packet(shaper, epoch_id=0)
            c[target] += 1
        return c

    return asyncio.run(_run())


class TestChaffSizeFixedPrior(unittest.TestCase):
    def test_chaff_size_does_not_track_skewed_real_traffic(self) -> None:
        """CORE discriminator: after a large stream of big real packets,
        chaff is still exactly the one size, the largest class. The old live
        EMA would have moved it."""
        shaper = TrafficShaper(128, 1400)
        # Drive real (large-payload) packets through the real sizing path:
        # this is what *would* have skewed the old EMA.
        big = InnerPacket(ptype=PacketType.DATA, epoch_id=0, payload=b"x" * 1300)
        for _ in range(2000):
            shaper.pad_packet(big)
        hist = _chaff_size_hist(shaper, 4000)
        self.assertEqual(set(hist), {SIZE_CLASSES[-1]})


class TestChaffSizePriorRespectsActiveClasses(unittest.TestCase):
    def test_chaff_stays_within_padding_filtered_classes(self) -> None:
        """With padding_min/padding_max narrowing the classes, chaff takes
        the top class of the range, never one outside it."""
        shaper = TrafficShaper(256, 1024)
        active = tuple(sc for sc in SIZE_CLASSES if 256 <= sc <= 1024)
        hist = _chaff_size_hist(shaper, 5000)
        self.assertEqual(set(hist), {active[-1]})

    def test_ceiling_change_rebuilds_chaff_prior(self) -> None:
        """set_size_class_ceiling narrows the active set — chaff must respect
        the new ceiling, not keep drawing from the old (wider) prior."""
        shaper = TrafficShaper(128, 1400)
        shaper.set_size_class_ceiling(512)
        active = tuple(sc for sc in SIZE_CLASSES if 128 <= sc <= 512)
        hist = _chaff_size_hist(shaper, 5000)
        for sc in hist:
            self.assertIn(sc, active, f"chaff emitted size {sc} above ceiling")


if __name__ == "__main__":
    unittest.main()
