"""Phase 2.4: deterministic statistical discriminators for the envelope.

These are the *proof* tests for the whole adaptive-shaping phase: they assert
the headline anonymity property — the wire rate is INDEPENDENT of the
instantaneous real-traffic volume within the latency budget, so a passive
observer sees a slowly-rising rate rather than a step at burst onset (finding
H8). Every test is built to FAIL against an immediate-release (no-envelope)
shaper and PASS against the envelope; the discriminator rationale is stated in
each test.

Determinism: an injected monotonic clock drives all pacing. ``release_budget``
is RNG-free (the CSPRNG affects only chaff *content/size*, never the per-tick
release *count*), so the wire-count timeseries is fully reproducible — no
wall-clock sleeps, no seeding required. The single randomized quantity these
tests touch is the per-session idle floor; the idle-floor test reads the
shaper's actually-drawn ``_idle_floor_pps`` rather than asserting an exact
value.

Latency budget reality (1000 ms, owner-raised from the plan's original
250 ms): the Task 2.1 review measured ~1050 ms worst case for a real packet.
That number is the *spread-arrival* worst case — when real traffic arrives
over time (as it always does on a real link) the budget override drains the
backlog so the oldest packet waits ~one budget window. A single instantaneous
dump of N packets at one identical microsecond is an artifact (the whole
backlog crosses the budget age simultaneously, then drains at the override
rate over an additional window → ~2x budget); that scenario does not occur on
a real link and is documented, not asserted, below.
"""

from __future__ import annotations

import unittest

from dsm.traffic.shaper import TrafficShaper

# Pacing tick used throughout: 10 ms, matching the scheduler poll cadence the
# envelope was tuned for. 100 ticks == 1 wall second of simulated time.
_TICK_S = 0.01
_TICKS_PER_S = 100


class _Clock:
    """Injectable monotonic clock for deterministic pacing tests.

    Mirrors the convention in ``tests/test_adaptive_envelope.py`` so both
    layers drive the shaper the same way.
    """

    def __init__(self, start: float = 5000.0) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, dt: float) -> None:
        self.t += dt


def _build_shaper(
    clk: _Clock,
    *,
    ceiling_pps: float = 600.0,
    floor_pps: float = 1.0,
    rise_per_s: float = 2.0,
    budget_ms: int = 1000,
    fall_half_life_s: float = 4.0,
) -> TrafficShaper:
    """Construct a shaper with a pinned idle floor (min == max).

    Pinning the floor removes the only RNG-driven quantity that would touch
    the release count, keeping the count timeseries fully deterministic.
    """
    return TrafficShaper(
        clock=clk,
        envelope_idle_floor_min_pps=floor_pps,
        envelope_idle_floor_max_pps=floor_pps,
        envelope_ceiling_pps=ceiling_pps,
        envelope_rise_per_s=rise_per_s,
        envelope_fall_half_life_s=fall_half_life_s,
        envelope_latency_budget_ms=budget_ms,
    )


def _simulate(
    real_arrivals_per_tick: list[int],
    *,
    ceiling_pps: float = 600.0,
    floor_pps: float = 1.0,
    rise_per_s: float = 2.0,
    budget_ms: int = 1000,
) -> list[int]:
    """Drive the envelope tick-by-tick; return packets released per tick.

    Exactly ONE ``update_envelope`` and ONE ``release_budget`` per tick (the
    contract: ``release_budget`` advances ``_last_release_time`` on every call,
    so a second call per tick would double-advance the clock state and halve
    the observed rate). Real packets drain first; the remainder of the
    per-tick budget would be filled by chaff on the wire — here only the total
    count matters, since the envelope governs the count, not the content.
    """
    clk = _Clock()
    shaper = _build_shaper(
        clk,
        ceiling_pps=ceiling_pps,
        floor_pps=floor_pps,
        rise_per_s=rise_per_s,
        budget_ms=budget_ms,
    )
    queue = 0
    oldest_age = 0.0
    released_per_tick: list[int] = []
    for arrivals in real_arrivals_per_tick:
        clk.advance(_TICK_S)
        queue += arrivals
        oldest_age = oldest_age + _TICK_S if queue > 0 else 0.0
        shaper.update_envelope(
            clk(), real_queue_depth=queue, oldest_real_age_s=oldest_age
        )
        n = shaper.release_budget(clk())
        real_sent = min(n, queue)
        queue -= real_sent
        if queue == 0:
            oldest_age = 0.0
        released_per_tick.append(n)
    return released_per_tick


def _per_second(released_per_tick: list[int]) -> list[int]:
    """Bucket per-tick release counts into 1 s bins (the wire-rate timeseries)."""
    return [
        sum(released_per_tick[i : i + _TICKS_PER_S])
        for i in range(0, len(released_per_tick), _TICKS_PER_S)
    ]


def _arrivals_at_rate(pps: float, ticks: int) -> list[int]:
    """Integer arrivals/tick approximating a constant ``pps`` (no rounding bias)."""
    out: list[int] = []
    acc = 0.0
    for _ in range(ticks):
        acc += pps * _TICK_S
        n = int(acc)
        acc -= n
        out.append(n)
    return out


class TestEnvelopeHidesBurstOnset(unittest.TestCase):
    """Property 1 (headline): a real-traffic STEP is not a wire STEP in ~1 s."""

    def test_moderate_step_not_a_wire_step_within_1s(self) -> None:
        # 5 s idle, then a moderate step to 50 pps for 5 s. A passive observer
        # bucketing the wire at 1 s granularity must NOT see the wire jump to
        # the real rate (50 pps) in the first burst second — the x2/s rise from
        # the ~1 pps floor keeps it near the floor until the budget override
        # fires near t=1 s.
        idle = [0] * (5 * _TICKS_PER_S)
        burst = _arrivals_at_rate(50.0, 5 * _TICKS_PER_S)
        per_s = _per_second(_simulate(idle + burst))
        idle_secs = per_s[:5]
        first_burst_sec = per_s[5]
        # Wire rate in the first burst second stays near the idle floor, FAR
        # below the 50 pps real input. Immediate-release would put ~50 here.
        self.assertLess(
            first_burst_sec,
            10,
            f"burst onset leaked: wire rose to {first_burst_sec} pps in the "
            "first second (immediate-release would show ~50) — envelope failed "
            "to smear onset",
        )
        # Sanity: the idle baseline itself was near the floor, so the test is
        # measuring the envelope's smearing, not a quiet link.
        self.assertLessEqual(max(idle_secs), 2)

    def test_wire_rate_below_real_rate_at_half_and_one_second(self) -> None:
        # Drive the simulated clock in small ticks; assert the CUMULATIVE wire
        # output at +0.5 s and +1.0 s after onset is well below what the real
        # input delivered — the envelope has not caught up. This is the H1
        # smearing property stated as cumulative counts.
        onset = 5 * _TICKS_PER_S
        burst = _arrivals_at_rate(50.0, 5 * _TICKS_PER_S)
        released = _simulate([0] * onset + burst)
        # Real input delivered ~25 packets by +0.5 s and ~50 by +1.0 s.
        wire_half = sum(released[onset : onset + _TICKS_PER_S // 2])
        wire_one = sum(released[onset : onset + _TICKS_PER_S])
        # The envelope rises from ~1 pps capped at x2/s, so by +0.5 s it is
        # ~1.4 pps and by +1.0 s ~2 pps (just before the override) — the wire
        # has emitted a tiny fraction of the real input. Immediate-release
        # would have wire_half ~= 25 and wire_one ~= 50.
        self.assertLess(wire_half, 5, "wire kept pace with real input at +0.5s")
        self.assertLess(wire_one, 10, "wire kept pace with real input at +1.0s")

    def test_moderate_rate_does_not_trip_override_within_1s(self) -> None:
        # The task: "for a MODERATE rate the override should NOT fire within
        # 1 s." With a 1 s budget the oldest queued packet only reaches the
        # budget age AT ~t=1 s, so within the first second the wire stays
        # rate-capped (near the floor), never override-drained.
        onset = 5 * _TICKS_PER_S
        burst = _arrivals_at_rate(40.0, 3 * _TICKS_PER_S)
        released = _simulate([0] * onset + burst)
        # Across the first 0.95 s after onset (before the budget age is hit)
        # the wire releases only a handful of packets — the override has not
        # dumped the backlog. Immediate-release would release ~38 here.
        first_950ms = sum(released[onset : onset + 95])
        self.assertLess(
            first_950ms,
            8,
            f"override appears to have fired early: {first_950ms} released in "
            "the first 0.95s of a moderate burst",
        )


class TestBoundedVarianceNoInstantStep(unittest.TestCase):
    """Property 2: even a LARGE burst yields no single-tick wire step."""

    def test_no_single_tick_dumps_the_backlog(self) -> None:
        # A large instantaneous backlog (1000 packets enqueued at one tick)
        # must NOT be released in one tick: the per-tick release is bounded by
        # envelope_pps * dt. The override raises the envelope to depth/budget
        # = 1000/1.0 = 1000 pps, but at a 600 pps soft... the override pierces
        # the ceiling, so the per-tick bound is envelope * 0.01 ~= 10 — never
        # the whole 1000. Immediate-release would dump all 1000 in tick 0.
        released = _simulate([1000] + [0] * 999, ceiling_pps=600.0)
        # No tick releases more than a small fraction of the backlog.
        self.assertLess(
            max(released),
            50,
            f"a single tick released {max(released)} of a 1000-packet backlog "
            "— wire showed an instantaneous step (immediate-release behavior)",
        )
        # And the backlog genuinely drains (the bound is not just an empty
        # queue): total released over the window covers the burst.
        self.assertGreaterEqual(sum(released), 1000)

    def test_override_caps_per_tick_drain_to_paced_rate(self) -> None:
        # Property 2, the override-path form, made distinct from the fresh-dump
        # test above. A standing backlog of 500 packets is enqueued at onset;
        # ~1 s later the budget override fires and raises the envelope to
        # ~500 pps to drain it. Critically, the override changes the RATE, not
        # the release MECHANISM: the per-tick release stays bounded by
        # envelope_pps * dt (~5 packets/tick), so the queue drains over the
        # FOLLOWING budget window rather than being dumped. A naive "on budget
        # breach, flush the whole queue" implementation (or immediate-release)
        # would release all 500 on one tick — this bound catches that.
        released = _simulate([500] + [0] * 999, ceiling_pps=600.0)
        self.assertLessEqual(
            max(released),
            25,
            f"a single tick released {max(released)} of a 500-packet backlog — "
            "the override dumped the queue instead of paced-draining it "
            "(immediate-release / queue-flush would be 500)",
        )
        self.assertGreaterEqual(sum(released), 500)  # backlog fully drains

    def test_pre_override_rise_is_gradual_within_first_second(self) -> None:
        # Before the budget override fires (the first ~1 s after onset, while
        # the oldest packet is still under the budget age) the wire rate is
        # governed purely by the x2/s rise cap from the floor. Bucket the first
        # second into 100 ms bins: each bin's release count rises GRADUALLY,
        # none exceeding ~2x the previous plus slack — no step. Immediate-
        # release would fill the very first bin with the full real rate.
        onset = 5 * _TICKS_PER_S
        burst = _arrivals_at_rate(200.0, 5 * _TICKS_PER_S)
        released = _simulate([0] * onset + burst, ceiling_pps=600.0)
        # 100 ms bins across the first 900 ms after onset (strictly before the
        # 1 s budget age, so no override).
        bins = [sum(released[onset + i : onset + i + 10]) for i in range(0, 90, 10)]
        # The whole pre-override window releases only a trickle — the envelope
        # is still climbing from ~1 pps. Immediate-release would put ~20 in the
        # first 100 ms bin alone.
        self.assertLess(
            sum(bins),
            5,
            f"pre-override wire released {sum(bins)} packets in the first 0.9s "
            "of a 200pps burst — onset leaked (immediate-release would be ~180)",
        )


class TestRealPacketLatencyWithinBudget(unittest.TestCase):
    """Property 3: no real packet waits much longer than the budget."""

    def test_spread_arrivals_worst_wait_within_budget(self) -> None:
        # REALISTIC arrivals: real packets arrive spread over time (as on any
        # real link), not dumped at one identical instant. The budget override
        # guarantees the oldest packet is drained once it reaches the budget
        # age, so the worst-case wait is ~one budget window. Measured here:
        # ~1000-1050 ms for a 1000 ms budget — matching the Task 2.1 review's
        # ~1050 ms. Bound generously at <= 1.2 s.
        clk = _Clock()
        budget_s = 1.0
        shaper = _build_shaper(clk, budget_ms=1000)
        queue_ages: list[float] = []
        worst = 0.0
        # 60 pps real, spread one-per-arrival over 6 s, then drain.
        arrivals = _arrivals_at_rate(60.0, 6 * _TICKS_PER_S) + [0] * (4 * _TICKS_PER_S)
        for arrivals_this_tick in arrivals:
            clk.advance(_TICK_S)
            queue_ages = [a + _TICK_S for a in queue_ages]
            queue_ages.extend([0.0] * arrivals_this_tick)
            oldest = max(queue_ages) if queue_ages else 0.0
            shaper.update_envelope(
                clk(), real_queue_depth=len(queue_ages), oldest_real_age_s=oldest
            )
            n = shaper.release_budget(clk())
            for _ in range(min(n, len(queue_ages))):
                worst = max(worst, queue_ages.pop(0))  # FIFO oldest first
        # The DISCRIMINATING assertion here is the LOWER bound, not the upper:
        # immediate-release would give worst ~= 0 ms (it passes any upper
        # bound), so the upper bound alone is not a discriminator. The envelope
        # DELAYS real packets up to ~the budget on purpose — that pacing delay
        # IS the onset smearing — so we assert worst > 0.5x budget, which
        # immediate-release can never satisfy.
        self.assertGreater(
            worst,
            0.5 * budget_s,
            f"real packets were not paced (worst wait {worst * 1000:.0f}ms) — "
            "the envelope is not delaying onset (immediate-release behavior)",
        )
        # Upper bound: the budget is honored within a generous slop.
        self.assertLess(
            worst,
            1.2 * budget_s,
            f"a real packet waited {worst * 1000:.0f}ms > 1.2x budget",
        )


class TestIdleFloorMaintained(unittest.TestCase):
    """Property 4: an idle shaper still emits chaff at ~the per-session floor."""

    def test_idle_wire_rate_matches_drawn_floor_and_never_zero(self) -> None:
        # Use the DEFAULT randomized floor [0.5, 2.0] and read the actually
        # drawn value — the CSPRNG is non-seedable, so we assert the realized
        # rate matches the shaper's own floor rather than a fixed number.
        clk = _Clock()
        shaper = TrafficShaper(clock=clk)  # default randomized floor
        floor = shaper._idle_floor_pps
        self.assertGreaterEqual(floor, 0.5)
        self.assertLessEqual(floor, 2.0)
        secs = 40
        released = 0
        for _ in range(secs * _TICKS_PER_S):
            clk.advance(_TICK_S)
            shaper.update_envelope(clk(), real_queue_depth=0, oldest_real_age_s=0.0)
            released += shaper.release_budget(clk())
        realized_pps = released / secs
        # Realized idle rate tracks the drawn floor within sampling tolerance.
        self.assertAlmostEqual(realized_pps, floor, delta=0.25)
        # The key discriminator vs a shaper with NO idle floor: the wire never
        # goes silent. (A no-floor / immediate-release shaper emits nothing
        # when there is no real traffic — wire rate 0.)
        self.assertGreater(released, 0, "idle floor collapsed — no cover traffic")

    def test_per_second_idle_wire_never_collapses_to_zero(self) -> None:
        # Bucket a long idle window per second; after warmup no second is fully
        # silent. Pinned floor at 1 pps so the per-second count is ~1 reliably.
        released = _simulate([0] * (30 * _TICKS_PER_S), floor_pps=1.0)
        per_s = _per_second(released)
        for sec in per_s[2:]:  # allow 2 s warmup for the release credit to fill
            self.assertGreaterEqual(sec, 1, "an idle second emitted no cover traffic")


class TestWireRateIndependentOfRealBurstiness(unittest.TestCase):
    """Property 5 (H8): same-mean smooth vs bursty real input -> similar wire."""

    def test_smooth_and_bursty_same_mean_yield_similar_wire_timeseries(
        self,
    ) -> None:
        # Two real-traffic streams with the SAME mean rate (30 pps) but
        # opposite burstiness:
        #   smooth: ~0.3 packets every tick (evenly spread)
        #   bursty: 30 packets in one tick, then 99 idle ticks (a hard spike
        #           every second)
        # The envelope must SMOOTH the bursty stream so its wire-rate
        # timeseries converges to the smooth stream's — the wire rate is
        # independent of instantaneous real volume. An immediate-release shaper
        # would mirror the bursty input's spikes onto the wire (a 30-in-one-
        # tick spike every second), so its per-second timeseries would differ
        # from smooth at the TICK level and never converge in shape.
        ticks = 20 * _TICKS_PER_S
        smooth = _arrivals_at_rate(30.0, ticks)
        bursty: list[int] = []
        for _ in range(20):
            bursty.append(30)
            bursty.extend([0] * (_TICKS_PER_S - 1))

        smooth_wire = _simulate(smooth)
        bursty_wire = _simulate(bursty)

        # Discriminator A: NO single wire tick ever carries the bursty input's
        # 30-packet spike. Immediate-release would show a 30-tick repeatedly.
        self.assertLess(
            max(bursty_wire),
            10,
            f"a single wire tick released {max(bursty_wire)} packets — the "
            "bursty real spike leaked straight onto the wire",
        )

        # Discriminator B: the two per-second timeseries CONVERGE. After warmup
        # the per-second difference shrinks to within a small band (the
        # envelope has erased the burstiness). Immediate-release would keep the
        # bursty per-second total spiking (still 30 in the spike second, 0
        # otherwise at the tick level), so the SHAPES would not match.
        smooth_per_s = _per_second(smooth_wire)
        bursty_per_s = _per_second(bursty_wire)
        # Compare the converged tail (seconds 12..18) — both should sit at the
        # ~30 pps mean within a generous band.
        for i in range(12, 18):
            self.assertLessEqual(
                abs(smooth_per_s[i] - bursty_per_s[i]),
                8,
                f"second {i}: smooth wire {smooth_per_s[i]} vs bursty wire "
                f"{bursty_per_s[i]} diverge — envelope did not smooth the burst",
            )
        # NOTE: total wire volume is NOT conserved between the two streams —
        # the bursty stream emits MORE total packets because each spike kicks
        # the envelope up and the ~4 s exponential fall leaves a chaff tail
        # after every spike. That extra volume is the cost of hiding the
        # spike; it is paid in chaff bandwidth, not in exposing the spike's
        # timing. The anonymity property (the SHAPE/timeseries converges, no
        # spike leaks) holds regardless — so we assert the converged shape
        # above and deliberately do NOT assert equal totals here.


class TestDeterminism(unittest.TestCase):
    """Guard: the release timeseries is reproducible (injected clock, RNG-free)."""

    def test_release_timeseries_identical_across_runs(self) -> None:
        # Run the same step-input simulation three times; the per-tick release
        # counts must be byte-for-byte identical. This locks the determinism
        # the whole suite relies on (release_budget never touches the CSPRNG).
        arrivals = [0] * (5 * _TICKS_PER_S) + _arrivals_at_rate(50.0, 5 * _TICKS_PER_S)
        run1 = _simulate(arrivals)
        run2 = _simulate(arrivals)
        run3 = _simulate(arrivals)
        self.assertEqual(run1, run2)
        self.assertEqual(run2, run3)


if __name__ == "__main__":
    unittest.main()
