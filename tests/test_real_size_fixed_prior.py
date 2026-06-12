"""H-ANON: REAL packet sizes are drawn from the FIXED published prior and do
NOT collapse under a self-reinforcing feedback loop.

Pentest finding (HIGH): real packets formerly padded to a size class sampled
from a live ``SizeTracker`` EMA whose padded output was fed back into the same
EMA (``observe_real_packet``). That Polya-urn positive-feedback loop collapsed
the real-traffic size distribution onto ONE dominant class within ~30-50
packets, re-spiking the aggregate (real + chaff) wire-size histogram at the
user's modal class — a passive, size-only de-anonymization. The fix makes real
packets draw from the SAME fixed published prior chaff uses (bumped up only to
fit the payload), with no feedback.

These tests mirror the chaff discriminator in ``test_chaff_size_prior.py`` but
for the REAL sizing path (``pad_packet``):

* The real-packet size distribution matches the published prior (for small
  payloads, where the bump-to-fit floor never raises the drawn class).
* The distribution does NOT collapse under a long, deliberately skewed real
  stream — the core regression lock for the feedback loop.
* The unavoidable "can't pad down" floor is asserted honestly: a near-MTU
  payload always lands in the large class.

The CSPRNG is not seedable, so assertions are on the size-class *distribution*
over a LARGE sample with generous statistical bounds. Deterministic otherwise:
no clock, no pacing, no I/O, no network.
"""

from __future__ import annotations

import collections
import unittest

from dsm.core.protocol import (
    GCM_TAG_SIZE,
    INNER_HEADER_SIZE,
    OUTER_HEADER_SIZE,
    SIZE_CLASS_WEIGHTS,
    SIZE_CLASSES,
    InnerPacket,
    PacketType,
)
from dsm.traffic.shaper import TrafficShaper

PADDING_MIN = 128
PADDING_MAX = 1400

# Small payload: the smallest size class (128) easily fits it, so the
# bump-to-fit floor never raises the drawn class. The observed real-packet
# size distribution is then exactly the fixed prior.
_SMALL_PAYLOAD = b"x" * 4


def _real_size_hist(payload: bytes, n: int) -> collections.Counter[int]:
    """Pad ``n`` real packets with ``payload`` and return a size Counter.

    A fresh shaper per call: real-packet sizing must be stateless, so the
    history of prior draws must not influence this Counter at all.
    """
    shaper = TrafficShaper(PADDING_MIN, PADDING_MAX)
    inner = InnerPacket(ptype=PacketType.DATA, epoch_id=0, payload=payload)
    c: collections.Counter[int] = collections.Counter()
    for _ in range(n):
        _, target = shaper.pad_packet(inner)
        c[target] += 1
    return c


def _expected_prior() -> dict[int, float]:
    """The published prior probability per class (no perturbation — real
    packets draw the prior directly, unlike chaff's ±1)."""
    total = float(sum(SIZE_CLASS_WEIGHTS))
    return {sc: w / total for sc, w in zip(SIZE_CLASSES, SIZE_CLASS_WEIGHTS)}


class TestRealSizeFixedPrior(unittest.TestCase):
    def test_small_payload_matches_fixed_prior(self) -> None:
        """For a small payload the real-packet size distribution equals the
        published prior — every class appears at ~its prior weight."""
        n = 50_000
        hist = _real_size_hist(_SMALL_PAYLOAD, n)
        expected = _expected_prior()
        for sc in SIZE_CLASSES:
            emp = hist[sc] / n
            exp = expected[sc]
            self.assertAlmostEqual(
                emp,
                exp,
                delta=0.02,
                msg=f"class {sc}: empirical {emp:.4f} vs expected {exp:.4f}",
            )

    def test_real_size_support_is_all_classes(self) -> None:
        """The smallest class (prior weight 20/100) must stay well represented —
        it would be ~never produced if the old EMA had collapsed onto a large
        class. This is the direct anti-collapse assertion."""
        n = 20_000
        hist = _real_size_hist(_SMALL_PAYLOAD, n)
        for sc in SIZE_CLASSES:
            self.assertIn(
                sc, hist, f"class {sc} never produced — distribution collapsed"
            )
        smallest = SIZE_CLASSES[0]
        self.assertGreater(
            hist[smallest] / n,
            0.10,
            "smallest class under-represented — feedback collapse not removed",
        )

    def test_distribution_does_not_collapse_over_long_stream(self) -> None:
        """CORE regression lock for the Polya-urn feedback loop.

        Drive a long continuous real stream through ONE shaper (the exact
        condition that collapsed the old EMA) and assert the size distribution
        stays spread across many classes — no single class dominates, and the
        smallest class keeps real mass. Before the fix, by ~100 packets one
        class held >0.9 of the mass and by ~300 it held 1.0.
        """
        shaper = TrafficShaper(PADDING_MIN, PADDING_MAX)
        inner = InnerPacket(ptype=PacketType.DATA, epoch_id=0, payload=_SMALL_PAYLOAD)
        hist: collections.Counter[int] = collections.Counter()
        n = 10_000
        for _ in range(n):
            _, target = shaper.pad_packet(inner)
            hist[target] += 1
        dominant_mass = max(hist.values()) / n
        self.assertLess(
            dominant_mass,
            0.30,
            f"one size class holds {dominant_mass:.3f} of the mass — the "
            "real-traffic distribution collapsed (feedback loop alive)",
        )
        # The smallest class (prior 0.20) must remain well represented even
        # after a long single-shaper stream.
        self.assertGreater(
            hist[SIZE_CLASSES[0]] / n,
            0.10,
            "smallest class starved over a long stream — distribution collapsed",
        )
        self.assertGreater(len(hist), 5, "real sizes pinned to too few classes")

    def test_skewed_stream_does_not_pin_distribution(self) -> None:
        """A deliberately one-sided real stream (all near-max payloads, which
        all land in the large class) must NOT pull SUBSEQUENT small-payload
        draws toward the large class — sizing is stateless, so a later small
        packet still follows the full prior.
        """
        shaper = TrafficShaper(PADDING_MIN, PADDING_MAX)
        big = InnerPacket(ptype=PacketType.DATA, epoch_id=0, payload=b"x" * 1300)
        for _ in range(3000):
            shaper.pad_packet(big)  # would have hammered the old EMA to 1400
        # Now small packets on the SAME shaper: the smallest class must still
        # appear near its prior weight, proving no carried-over state.
        small = InnerPacket(ptype=PacketType.DATA, epoch_id=0, payload=_SMALL_PAYLOAD)
        n = 20_000
        hist: collections.Counter[int] = collections.Counter()
        for _ in range(n):
            _, target = shaper.pad_packet(small)
            hist[target] += 1
        expected = _expected_prior()
        smallest = SIZE_CLASSES[0]
        self.assertAlmostEqual(
            hist[smallest] / n,
            expected[smallest],
            delta=0.03,
            msg="small-payload sizing skewed by prior large-payload stream — "
            "state leaked across packets",
        )


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
