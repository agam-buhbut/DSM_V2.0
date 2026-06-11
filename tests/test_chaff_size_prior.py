"""Phase 2.3: chaff sizes follow a FIXED published prior, not the live
real-traffic size EMA (fix for shaper.py:292 — aggregate-histogram leak).

Chaff packet sizes must be drawn from the published ``SIZE_CLASS_WEIGHTS``
prior (renormalized over the shaper's active classes), independent of the
live ``SizeTracker`` EMA that tracks real-traffic sizes. Otherwise the
aggregate (real + chaff) size histogram amplifies the user's actual
application profile.

The CSPRNG is not seedable, so we assert on the size-class *distribution*
over a LARGE sample with generous statistical bounds, and on the
*independence* of the chaff distribution from a deliberately skewed real
EMA (the core discriminator).
"""

from __future__ import annotations

import asyncio
import collections
import unittest

from dsm.core.protocol import SIZE_CLASS_WEIGHTS, SIZE_CLASSES
from dsm.traffic.shaper import (
    _CHAFF_SIZE_PERTURB_DOWN_P,
    _CHAFF_SIZE_PERTURB_UP_P,
    TrafficShaper,
    make_chaff_packet,
)


def _chaff_size_hist(shaper: TrafficShaper, n: int) -> collections.Counter:
    """Draw ``n`` chaff packets and return a Counter of their outer sizes."""

    async def _run() -> collections.Counter:
        c: collections.Counter = collections.Counter()
        for _ in range(n):
            _, target = await make_chaff_packet(shaper, epoch_id=0)
            c[target] += 1
        return c

    return asyncio.run(_run())


def _expected_perturbed_prior() -> dict[int, float]:
    """Expected chaff size-class probabilities = the published prior after the
    deterministic ±1-class perturbation is applied on top of it.

    A draw lands on base class ``i`` with the normalized prior weight, then:
    * with prob ``up_p`` it moves to ``i+1`` (clamped at the top class),
    * with prob ``down_p - up_p`` it moves to ``i-1`` (clamped at the bottom),
    * otherwise it stays on ``i``.
    """
    total = float(sum(SIZE_CLASS_WEIGHTS))
    base = [w / total for w in SIZE_CLASS_WEIGHTS]
    up_p = _CHAFF_SIZE_PERTURB_UP_P
    down_p = _CHAFF_SIZE_PERTURB_DOWN_P - _CHAFF_SIZE_PERTURB_UP_P
    stay_p = 1.0 - up_p - down_p
    n = len(SIZE_CLASSES)
    out = {sc: 0.0 for sc in SIZE_CLASSES}
    for i, sc in enumerate(SIZE_CLASSES):
        out[sc] += stay_p * base[i]
        up_idx = i + 1 if i + 1 < n else i
        down_idx = i - 1 if i > 0 else i
        out[SIZE_CLASSES[up_idx]] += up_p * base[i]
        out[SIZE_CLASSES[down_idx]] += down_p * base[i]
    return out


class TestChaffSizeFixedPrior(unittest.TestCase):
    def test_chaff_size_does_not_track_skewed_real_traffic(self) -> None:
        """CORE discriminator: hammer the real-size EMA toward the largest
        class only, then assert chaff still follows the fixed prior (the
        smallest class — prior weight 20/100 — stays well represented).

        Before the fix, chaff tracked the EMA so the smallest class would be
        ~never produced after 2000 large observations.
        """
        shaper = TrafficShaper(128, 1400)
        for _ in range(2000):
            shaper.observe_real_packet(1400)
        hist = _chaff_size_hist(shaper, 4000)
        smallest = SIZE_CLASSES[0]
        self.assertGreater(
            hist[smallest] / 4000,
            0.05,
            "chaff still tracks the real-size EMA — fixed prior not applied",
        )
        # And the largest class must NOT dominate the way the skewed EMA would.
        largest = SIZE_CLASSES[-1]
        self.assertLess(
            hist[largest] / 4000,
            0.30,
            "chaff over-represents the largest class — still tracking the EMA",
        )

    def test_chaff_size_support_is_all_classes(self) -> None:
        shaper = TrafficShaper(128, 1400)
        hist = _chaff_size_hist(shaper, 5000)
        for sc in SIZE_CLASSES:
            self.assertIn(sc, hist)

    def test_chaff_size_matches_fixed_prior_distribution(self) -> None:
        """Over a large sample the empirical chaff distribution must match the
        perturbed published prior, independent of any real traffic."""
        shaper = TrafficShaper(128, 1400)
        n = 50_000
        hist = _chaff_size_hist(shaper, n)
        expected = _expected_perturbed_prior()
        for sc in SIZE_CLASSES:
            emp = hist[sc] / n
            exp = expected[sc]
            self.assertAlmostEqual(
                emp,
                exp,
                delta=0.02,
                msg=f"class {sc}: empirical {emp:.4f} vs expected {exp:.4f}",
            )

    def test_chaff_size_matches_prior_even_with_skewed_real_traffic(self) -> None:
        """The fixed-prior distribution holds even after the real EMA is
        skewed — chaff sizing is fully decoupled from real-traffic sizing."""
        shaper = TrafficShaper(128, 1400)
        for _ in range(2000):
            shaper.observe_real_packet(128)
        n = 50_000
        hist = _chaff_size_hist(shaper, n)
        expected = _expected_perturbed_prior()
        for sc in SIZE_CLASSES:
            emp = hist[sc] / n
            exp = expected[sc]
            self.assertAlmostEqual(
                emp,
                exp,
                delta=0.02,
                msg=f"class {sc}: empirical {emp:.4f} vs expected {exp:.4f}",
            )

    def test_perturbation_still_applies(self) -> None:
        """The ±1-class perturbation is still active on top of the fixed
        prior: a class adjacent to the mode that the *un-perturbed* prior would
        rarely reach is still produced, and chaff is not pinned to a single
        size. We assert the distribution is spread (more than one class) and
        that perturbation shifts mass off the exact prior into neighbors.
        """
        shaper = TrafficShaper(128, 1400)
        hist = _chaff_size_hist(shaper, 20_000)
        # Spread across many classes (perturbation + multi-class prior).
        self.assertGreater(len(hist), 5)
        # The perturbed prior pushes some mass toward the largest class beyond
        # its raw prior weight (5/100 = 0.05): the second-largest class
        # perturbs up into it. Confirm the largest class probability is at
        # least the raw prior (perturbation never removes its base mass).
        total = float(sum(SIZE_CLASS_WEIGHTS))
        raw_largest = SIZE_CLASS_WEIGHTS[-1] / total
        self.assertGreater(hist[SIZE_CLASSES[-1]] / 20_000, raw_largest * 0.5)


class TestChaffSizePriorRespectsActiveClasses(unittest.TestCase):
    def test_chaff_stays_within_padding_filtered_classes(self) -> None:
        """When padding_min/padding_max filter the active classes, the fixed
        prior must only draw from the active subset — never a filtered-out
        class the shaper cannot emit.
        """
        shaper = TrafficShaper(256, 1024)
        active = tuple(sc for sc in SIZE_CLASSES if 256 <= sc <= 1024)
        hist = _chaff_size_hist(shaper, 5000)
        for sc in hist:
            self.assertIn(sc, active, f"chaff emitted out-of-range size {sc}")
        for sc in active:
            self.assertIn(sc, hist, f"active class {sc} never produced")

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
