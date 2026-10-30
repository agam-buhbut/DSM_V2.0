"""H-ANON: REAL packet sizes never follow real traffic.

Pentest finding (HIGH): real packets formerly padded to a size class sampled
from a live ``SizeTracker`` EMA whose padded output was fed back into the same
EMA (``observe_real_packet``). That feedback loop collapsed real sizes onto
the user's modal class while chaff kept a spread mix, a passive, size-only
de-anonymization. Finding #55 showed the same gap with the fixed mix: a
full-size real packet always took 1400 B while chaff took it about 5% of
the time. Now every packet, real or chaff, takes the largest active class.

These tests pin that real sizing is stateless (a long one-sided stream does
not change later packets) and the unavoidable "can't pad down" floor.
Deterministic: no clock, no pacing, no I/O, no network.
"""

from __future__ import annotations

import collections
import unittest

from dsm.core.protocol import (
    GCM_TAG_SIZE,
    INNER_HEADER_SIZE,
    OUTER_HEADER_SIZE,
    SIZE_CLASSES,
    InnerPacket,
    PacketType,
)
from dsm.traffic.shaper import TrafficShaper

PADDING_MIN = 128
PADDING_MAX = 1400

# Small payload: the smallest size class (128) easily fits it.
_SMALL_PAYLOAD = b"x" * 4


class TestRealSizeFixedPrior(unittest.TestCase):
    def test_skewed_stream_does_not_pin_distribution(self) -> None:
        """A deliberately one-sided real stream (all near-max payloads) must
        not change how SUBSEQUENT small payloads are sized: sizing is
        stateless, so a later small packet takes the same one size.
        """
        shaper = TrafficShaper(PADDING_MIN, PADDING_MAX)
        big = InnerPacket(ptype=PacketType.DATA, epoch_id=0, payload=b"x" * 1300)
        for _ in range(3000):
            shaper.pad_packet(big)  # would have hammered the old EMA to 1400
        # Now small packets on the SAME shaper: the same one size, proving no
        # carried-over state.
        small = InnerPacket(ptype=PacketType.DATA, epoch_id=0, payload=_SMALL_PAYLOAD)
        n = 20_000
        hist: collections.Counter[int] = collections.Counter()
        for _ in range(n):
            _, target = shaper.pad_packet(small)
            hist[target] += 1
        self.assertEqual(set(hist), {SIZE_CLASSES[-1]})


class TestCantPadDownFloor(unittest.TestCase):
    """The honest, documented residual: a payload of P bytes must pad to a
    class >= P, so near-MTU payloads always use the large class."""

    def test_near_mtu_payload_always_uses_large_class(self) -> None:
        shaper = TrafficShaper(PADDING_MIN, PADDING_MAX)
        # A payload that only the largest class can carry.
        max_payload = (
            SIZE_CLASSES[-1] - OUTER_HEADER_SIZE - GCM_TAG_SIZE - INNER_HEADER_SIZE
        )
        inner = InnerPacket(
            ptype=PacketType.DATA, epoch_id=0, payload=b"x" * max_payload
        )
        for _ in range(500):
            _, target = shaper.pad_packet(inner)
            self.assertEqual(
                target,
                SIZE_CLASSES[-1],
                "near-MTU payload must land in the large class (can't-pad-down "
                "floor) — and must never be sized below its own payload",
            )

    def test_target_never_below_payload(self) -> None:
        """General floor invariant across payload sizes: the chosen outer size
        always leaves room for the payload + headers + tag."""
        shaper = TrafficShaper(PADDING_MIN, PADDING_MAX)
        for plen in (0, 1, 100, 300, 700, 1100):
            inner = InnerPacket(ptype=PacketType.DATA, epoch_id=0, payload=b"x" * plen)
            min_outer = OUTER_HEADER_SIZE + INNER_HEADER_SIZE + plen + GCM_TAG_SIZE
            for _ in range(200):
                _, target = shaper.pad_packet(inner)
                self.assertGreaterEqual(
                    target,
                    min_outer,
                    f"payload {plen}: target {target} < required {min_outer} "
                    "(padded below payload — would truncate)",
                )


if __name__ == "__main__":
    unittest.main()
