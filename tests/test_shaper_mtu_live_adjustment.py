"""Live size-class ceiling adjustment (auto_mtu interaction) for the shaper.

When the DSM path MTU drops at runtime, the auto_mtu adapter calls
``TrafficShaper.set_size_class_ceiling`` to cap the outer-packet size the
shaper may emit (Phase 1.7/1.11). The security-relevant invariant pinned
here is that the cap is *live*: after it is lowered, BOTH chaff sizing
(the fixed published-prior sampler, Task 2.3 — ``make_chaff_padded`` /
``pad_chaff`` / ``_sample_chaff_wire_class``) AND real-packet padding
(``pad_packet``) immediately respect the narrowed active class set, so no
emitted wire size exceeds the new ceiling.

A stale ceiling would let the shaper keep padding to (or sampling chaff
at) a class larger than the path can carry — that is both a correctness
bug (oversize packets) and a fingerprint (a size-distribution step that
lags the MTU change is observable to a passive adversary). The KEY
assertions below would fail if ``set_size_class_ceiling`` did not rebuild
the active class set / the chaff prior, so they discriminate the real
behavior rather than passing vacuously.

Deterministic: no clock or pacing is exercised (sizing is path-only), no
I/O, no network. Each sampler is hammered enough trials that the size
support is fully populated; the assertion is a strict upper-bound on the
observed support, so it cannot be satisfied by an under-sampled draw.
"""

from __future__ import annotations

import asyncio
import unittest

from dsm.core.protocol import SIZE_CLASSES, InnerPacket, PacketType
from dsm.traffic.shaper import TrafficShaper, make_chaff_packet

PADDING_MIN = 128
PADDING_MAX = 1400

# A mid-range ceiling that strictly drops several classes (the original
# active set runs up to 1400; SIZE_CLASSES near 512 are 128/256/384/512).
LOWERED_CEILING = 512
# Trials high enough that every active class is hit with overwhelming
# probability, so an upper-bound-on-support assertion is meaningful.
_TRIALS = 3000


def _real_chaff_sizes(shaper: TrafficShaper, trials: int) -> set[int]:
    """Collect chaff WIRE sizes from the hot single-draw path.

    Exercises ``make_chaff_packet`` -> ``make_chaff_padded`` ->
    ``_sample_chaff_wire_class`` (the fixed-prior chaff sampler, Task 2.3).
    """

    async def _run() -> set[int]:
        sizes: set[int] = set()
        for _ in range(trials):
            _, target = await make_chaff_packet(shaper, epoch_id=0)
            sizes.add(target)
        return sizes

    return asyncio.run(_run())


def _pad_chaff_sizes(shaper: TrafficShaper, trials: int) -> set[int]:
    """Collect chaff wire sizes from the standalone ``pad_chaff`` path.

    An empty payload is used so the only thing driving the wire class is the
    fixed-prior draw (``_sample_chaff_wire_class``); a non-trivial payload
    could legitimately bump the class up to fit, which is a separate concern
    from the ceiling invariant under test.
    """
    sizes: set[int] = set()
    inner = InnerPacket(ptype=PacketType.CHAFF, epoch_id=0, payload=b"")
    for _ in range(trials):
        _, target = shaper.pad_chaff(inner)
        sizes.add(target)
    return sizes


def _real_pad_sizes(shaper: TrafficShaper, trials: int) -> set[int]:
    """Collect REAL-packet padding targets (``pad_packet`` / live EMA).

    A tiny payload is used so the bumped-up minimum can never exceed any
    active class — i.e. the only thing selecting the target class is the EMA
    sampler over the active set, which is exactly the ceiling-constrained
    quantity under test (an oversize payload would instead exercise the
    distinct ``_serialize_padded`` overflow path).
    """
    sizes: set[int] = set()
    inner = InnerPacket(ptype=PacketType.DATA, epoch_id=0, payload=b"x")
    for _ in range(trials):
        _, target = shaper.pad_packet(inner)
        sizes.add(target)
    return sizes


class TestSizeClassCeilingLiveAdjustment(unittest.TestCase):
    """``set_size_class_ceiling`` is live: chaff + pad sizes obey the new cap."""

    def test_lowering_ceiling_caps_all_emitted_sizes(self) -> None:
        shaper = TrafficShaper(PADDING_MIN, PADDING_MAX)

        # Pre-condition: before lowering, the shaper actually emits classes
        # ABOVE the target ceiling. Without this the post-adjustment cap could
        # be vacuously satisfied (nothing was ever large in the first place),
        # which would make the test non-discriminating.
        before_chaff = _real_chaff_sizes(shaper, _TRIALS)
        before_real = _real_pad_sizes(shaper, _TRIALS)
        self.assertTrue(
            any(s > LOWERED_CEILING for s in before_chaff),
            "precondition: chaff must reach above the ceiling before lowering",
        )
        self.assertTrue(
            any(s > LOWERED_CEILING for s in before_real),
            "precondition: real padding must reach above the ceiling first",
        )

        # Runtime auto_mtu drop: lower the ceiling.
        shaper.set_size_class_ceiling(LOWERED_CEILING)

        after_chaff = _real_chaff_sizes(shaper, _TRIALS)
        after_pad_chaff = _pad_chaff_sizes(shaper, _TRIALS)
        after_real = _real_pad_sizes(shaper, _TRIALS)

        # KEY assertion: after the live adjustment NOTHING the shaper emits —
        # hot-path chaff, standalone-padded chaff, or real-packet padding —
        # exceeds the new ceiling. A stale active set / un-rebuilt chaff prior
        # would leave classes 640..1400 in the support and fail here.
        for label, sizes in (
            ("make_chaff_packet", after_chaff),
            ("pad_chaff", after_pad_chaff),
            ("pad_packet", after_real),
        ):
            with self.subTest(path=label):
                self.assertTrue(
                    sizes.issubset(set(SIZE_CLASSES)),
                    f"{label} emitted a non-size-class wire size: {sizes}",
                )
                self.assertLessEqual(
                    max(sizes),
                    LOWERED_CEILING,
                    f"{label} emitted a size above the lowered ceiling "
                    f"{LOWERED_CEILING}: {sorted(sizes)}",
                )
                self.assertGreaterEqual(
                    min(sizes),
                    PADDING_MIN,
                    f"{label} emitted below padding_min: {sorted(sizes)}",
                )

    def test_chaff_prior_renormalized_over_narrowed_set(self) -> None:
        """The fixed chaff prior must be rebuilt over the new active set.

        Beyond "no size exceeds the ceiling", Task 2.3 requires the chaff
        sampler to draw from the published prior *renormalized over the active
        subset*. After lowering, the chaff support must be EXACTLY the surviving
        classes (every one of them reachable, none beyond the cap) — proving the
        prior was rebuilt rather than merely clamped.
        """
        shaper = TrafficShaper(PADDING_MIN, PADDING_MAX)
        shaper.set_size_class_ceiling(LOWERED_CEILING)

        expected = {sc for sc in SIZE_CLASSES if PADDING_MIN <= sc <= LOWERED_CEILING}
        observed = _real_chaff_sizes(shaper, _TRIALS)
        self.assertEqual(
            observed,
            expected,
            "chaff support after lowering must equal the surviving classes "
            f"{sorted(expected)}, got {sorted(observed)}",
        )

    def test_raising_ceiling_back_restores_wider_support(self) -> None:
        """Raising the ceiling again re-admits the larger classes (live both
        ways). Bounded above by padding_max, so it never exceeds policy."""
        shaper = TrafficShaper(PADDING_MIN, PADDING_MAX)
        shaper.set_size_class_ceiling(LOWERED_CEILING)
        narrowed = _real_chaff_sizes(shaper, _TRIALS)
        self.assertLessEqual(max(narrowed), LOWERED_CEILING)

        shaper.set_size_class_ceiling(PADDING_MAX)
        widened = _real_chaff_sizes(shaper, _TRIALS)
        self.assertGreater(
            max(widened),
            LOWERED_CEILING,
            "raising the ceiling must re-admit classes above the old cap",
        )
        self.assertLessEqual(
            max(widened),
            PADDING_MAX,
            "raising the ceiling must never exceed the configured padding_max",
        )

    def test_ceiling_clamped_to_padding_max(self) -> None:
        """A ceiling above ``padding_max`` cannot widen past the policy cap.

        ``set_size_class_ceiling`` takes ``min(max_outer, padding_max)``, so a
        path that reports a larger MTU than the operator's padding policy still
        only emits up to ``padding_max``.
        """
        narrow_max = 640
        shaper = TrafficShaper(PADDING_MIN, narrow_max)
        shaper.set_size_class_ceiling(2000)  # far above padding_max
        sizes = _real_chaff_sizes(shaper, _TRIALS)
        self.assertLessEqual(
            max(sizes),
            narrow_max,
            "ceiling above padding_max must stay clamped to padding_max",
        )

    def test_absurdly_low_ceiling_keeps_one_class(self) -> None:
        """A ceiling below the smallest class degrades gracefully (Phase 1.11).

        The active set must never empty out — at least the smallest usable
        class survives so the shaper can still emit, and chaff sampling does
        not raise on a one-element prior.
        """
        shaper = TrafficShaper(PADDING_MIN, PADDING_MAX)
        shaper.set_size_class_ceiling(1)  # below every SIZE_CLASS
        sizes = _real_chaff_sizes(shaper, 200)
        self.assertEqual(
            sizes,
            {PADDING_MIN},
            "below the smallest class the shaper must keep exactly the "
            f"smallest class ({PADDING_MIN}), got {sorted(sizes)}",
        )


if __name__ == "__main__":
    unittest.main()
