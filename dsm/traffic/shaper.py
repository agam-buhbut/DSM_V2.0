"""Adaptive traffic shaping: padding, chaff generation, size distribution.

Wire-rate model (Phase 2 adaptive envelope):

The shaper governs a single paced *target wire rate* (real + chaff packets
per second) — the envelope — with no active/idle modes and no burst
geometry. The scheduler polls ``release_budget`` each tick and emits exactly
that many packets (real queue first, chaff fills the rest), so the wire rate
is determined by the envelope, not by the instantaneous real-traffic volume.

The envelope is updated by ``update_envelope`` each tick:

* With no real packets queued it decays exponentially toward a per-session
  randomized idle floor (``fall_half_life_s``), so an idle session keeps a
  steady, non-constant chaff baseline.
* With real packets queued it rises toward the rate needed to drain them,
  but the per-second rise is CAPPED (``rise_per_s``, a multiplicative
  cap > 1). The cap is what smears burst onset across seconds: within the
  latency budget the wire rate is independent of the instantaneous real
  volume, so a passive observer sees a slowly-rising rate rather than a
  step at the moment real traffic starts.
* The rise cap (and the soft ceiling) are OVERRIDDEN only when the oldest
  queued real packet has waited past ``latency_budget_s`` — a real packet
  is never delayed longer than the budget for the sake of onset hiding.

Residual: the envelope hides burst *onset* within the latency budget, but a
*sustained* high real-traffic volume still drives the envelope up to (and is
visible at) the elevated wire rate — concealing sustained volume is out of
scope for this model and is a documented residual.

Size distribution: REAL packets pad to the size class that fits their actual
size (the live ``SizeTracker`` EMA informs padding). CHAFF packet sizes are
drawn from a FIXED published prior (``SIZE_CLASS_WEIGHTS``, renormalized over
the active classes) — decoupled from the real-traffic EMA (Task 2.3, fix for
shaper.py:292) — with a per-chaff-packet ±1 class perturbation on top. So the
aggregate (real + chaff) size histogram trends toward the published
fleet-wide prior rather than amplifying the user's actual application profile.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable

from dsm.core.protocol import (
    GCM_TAG_SIZE,
    INNER_HEADER_SIZE,
    INNER_STRUCT,
    MAX_INNER_PAYLOAD,
    OUTER_HEADER_SIZE,
    SIZE_CLASS_WEIGHTS,
    SIZE_CLASSES,
    InnerPacket,
    PacketType,
)
from dsm.core.rand import csprng_float

# EMA decay for the size-class distribution. Kept at the historical 0.15
# so chaff sizes track real-traffic size mix on the order of ~10 packets.
EMA_ALPHA = 0.15

# Adaptive-envelope defaults (Phase 2 / Fork 8). These mirror the Config
# defaults so a TrafficShaper built without explicit envelope kwargs still
# produces the owner-confirmed profile. The envelope is a paced target wire
# rate (real+chaff) that rises slowly under a real-traffic burst and decays
# toward a per-session idle floor when idle — making the wire rate
# independent of instantaneous real volume within the latency budget.
_ENVELOPE_IDLE_FLOOR_MIN_PPS = 0.5
_ENVELOPE_IDLE_FLOOR_MAX_PPS = 2.0
_ENVELOPE_CEILING_PPS = 600.0
_ENVELOPE_RISE_PER_S = 2.0
_ENVELOPE_FALL_HALF_LIFE_S = 4.0
# 1s latency budget (owner-chosen): gives the x2/s rise a full second to
# absorb a burst before the budget override fires, hiding onset more strongly.
_ENVELOPE_LATENCY_BUDGET_MS = 1000

# Chaff size-class perturbation: with probability _CHAFF_SIZE_PERTURB_UP_P
# bump the sampled chaff size one class up; with the next slice
# (_CHAFF_SIZE_PERTURB_DOWN_P - _CHAFF_SIZE_PERTURB_UP_P) bump one class
# down; otherwise leave it. Together they decorrelate chaff sizes from
# the EMA-tracked real distribution.
_CHAFF_SIZE_PERTURB_UP_P = 0.15
_CHAFF_SIZE_PERTURB_DOWN_P = 0.30


class SizeTracker:
    """Track real traffic size class distribution via EMA."""

    def __init__(self, classes: tuple[int, ...] | None = None) -> None:
        self._classes = classes or SIZE_CLASSES
        # M-ANON-1: initialize from the published web-traffic prior
        # (SIZE_CLASS_WEIGHTS) rather than uniform. With α=0.15 the EMA
        # takes ~30 observations to forget the prior; uniform-init
        # means chaff sizes for the first ~30 real packets are drawn
        # from an unrealistic distribution that a passive observer can
        # tell apart from steady-state. Seeding from the long-run
        # prior makes cold-start chaff statistically indistinguishable
        # from steady-state chaff.
        if classes is None or classes == SIZE_CLASSES:
            total = float(sum(SIZE_CLASS_WEIGHTS))
            self._weights: list[float] = [w / total for w in SIZE_CLASS_WEIGHTS]
        else:
            # Custom classes (e.g., filtered by padding_min/max) —
            # fall back to uniform since we don't have a matching prior.
            n = len(self._classes)
            self._weights = [1.0 / n] * n

    def observe(self, size_class: int) -> None:
        """Update the distribution based on an observed real packet size class.

        M-PERF-3: the previous implementation ran a second normalization
        loop after every observation. The math proves it's a no-op when
        the EMA invariant holds: ``sum(w_new) = decay * sum(w_old) +
        EMA_ALPHA = decay * 1 + EMA_ALPHA = 1``. So as long as the
        weights start summing to 1 (they do, ``[1/n] * n``), they stay
        summing to 1 modulo float-rounding (which is bounded by IEEE 754
        relative error * n iterations — never observable for n=11 and
        any realistic session length). The renormalization loop is
        removed; correctness preserved by the EMA invariant.
        """
        idx = self.class_index(size_class)
        w = self._weights
        decay = 1 - EMA_ALPHA
        for i in range(
            len(w)
        ):  # pylint: disable=consider-using-enumerate  # deliberate in-place index write
            w[i] = decay * w[i] + (EMA_ALPHA if i == idx else 0.0)

    def sample_with_idx(self) -> tuple[int, int]:
        """Sample a size class AND return its index in one scan.

        M-PERF-4: callers that immediately need the index for chaff
        perturbation (``pad_packet`` / ``make_chaff_packet``) save a
        redundant linear scan via ``class_index`` after ``sample``.
        """
        r = csprng_float()
        cumulative = 0.0
        for i, w in enumerate(self._weights):
            cumulative += w
            if r < cumulative:
                return self._classes[i], i
        last = len(self._classes) - 1
        return self._classes[last], last

    def sample(self) -> int:
        """Sample a size class from the current distribution."""
        sc, _ = self.sample_with_idx()
        return sc

    def class_index(self, size: int) -> int:
        """Find the index of the matching or next-larger class."""
        for i, sc in enumerate(self._classes):
            if sc >= size:
                return i
        return len(self._classes) - 1


class TrafficShaper:
    """Adaptive chaff and padding engine.

    The wire rate is governed by a single paced envelope (real + chaff). The
    scheduler polls ``release_budget`` each tick and emits exactly that many
    packets; ``update_envelope`` rises (bounded by ``rise_per_s``) under a real
    backlog and decays toward a per-session idle floor when idle. There is no
    active/idle mode switch — within the latency budget the wire rate is
    independent of instantaneous real volume, so a passive observer sees a
    slowly-rising rate rather than a step at real-traffic onset.
    """

    def __init__(
        self,
        padding_min: int = 128,
        padding_max: int = 1400,
        *,
        clock: Callable[[], float] = time.monotonic,
        envelope_idle_floor_min_pps: float = _ENVELOPE_IDLE_FLOOR_MIN_PPS,
        envelope_idle_floor_max_pps: float = _ENVELOPE_IDLE_FLOOR_MAX_PPS,
        envelope_ceiling_pps: float = _ENVELOPE_CEILING_PPS,
        envelope_rise_per_s: float = _ENVELOPE_RISE_PER_S,
        envelope_fall_half_life_s: float = _ENVELOPE_FALL_HALF_LIFE_S,
        envelope_latency_budget_ms: int = _ENVELOPE_LATENCY_BUDGET_MS,
    ) -> None:
        self._padding_min = padding_min
        self._padding_max = padding_max
        # Filter SIZE_CLASSES to the configured range so that
        # padding_min/padding_max actually constrain packet sizes.
        self._active_classes = tuple(
            sc for sc in SIZE_CLASSES if padding_min <= sc <= padding_max
        )
        if not self._active_classes:
            # Phase 1.11: padding_min may exceed the largest SIZE_CLASS (1400)
            # while still passing Config's <=1500 range check. Clamp to the
            # largest available class rather than crashing on an empty
            # generator.
            largest = SIZE_CLASSES[-1]
            candidates = [sc for sc in SIZE_CLASSES if sc >= padding_min]
            self._active_classes = (candidates[0],) if candidates else (largest,)
        self._size_tracker = SizeTracker(self._active_classes)
        # Task 2.3: chaff sizes are drawn from a FIXED published prior, NOT
        # the live real-traffic EMA above. Precomputed once so each draw is
        # allocation-free (a single cumulative scan in _sample_chaff_size).
        self._chaff_prior_cumulative = self._build_chaff_prior_cumulative()

        # ── Adaptive envelope (Phase 2) ──────────────────────────────────
        # The envelope is a paced target wire rate (real+chaff) that the
        # scheduler polls each tick. Names avoid the IDLE_*/_ACTIVE_*/
        # _chaff_rate_multiplier banned set so there is no active/idle binary.
        self._clock = clock
        # Per-session randomized idle floor (Fork 4): removes the exact-1pps
        # constant DSM baseline. Drawn once and fixed for the session lifetime
        # — re-drawing would itself be a time-varying signal.
        lo, hi = envelope_idle_floor_min_pps, envelope_idle_floor_max_pps
        self._idle_floor_pps = lo + csprng_float() * (hi - lo)
        self._ceiling_pps = float(envelope_ceiling_pps)
        self._rise_per_s = float(envelope_rise_per_s)
        self._fall_half_life_s = float(envelope_fall_half_life_s)
        self._latency_budget_s = envelope_latency_budget_ms / 1000.0
        self._envelope_pps = self._idle_floor_pps
        self._last_envelope_time: float | None = None
        self._last_release_time: float | None = None
        # Fractional-packet accumulator so a slow envelope (<1 pkt/tick)
        # still releases the right rate on average (no per-tick rounding bias).
        self._release_credit = 0.0
        # Hard-deadline cold-start nudge: when a real packet has breached the
        # latency budget the NEXT release_budget must emit at least one packet
        # even if it has no rate-derived credit yet (the very first poll of a
        # session). In steady state the elevated envelope rate already drains
        # the backlog within the budget, so this nudge is a no-op there — it
        # never dumps the queue (that would re-expose burst onset).
        self._deadline_pending = False

    def set_size_class_ceiling(self, max_outer: int) -> None:
        """Phase 1.7: cap the size classes the shaper pads to at ``max_outer``
        (the DSM outer-packet size budget = path_mtu - IP - UDP).

        Filters the active classes to those <= max_outer and rebuilds the
        size tracker so subsequent pad_packet / chaff sizes fit a constrained
        path. Always keeps at least one class (the smallest), so an absurdly
        low ceiling degrades gracefully rather than emptying the set. The
        ceiling is bounded above by the configured ``padding_max`` (raising it
        cannot exceed the operator's padding policy).
        """
        ceiling = min(max_outer, self._padding_max)
        kept = tuple(sc for sc in SIZE_CLASSES if self._padding_min <= sc <= ceiling)
        if not kept:
            # Below the smallest configured class — keep one usable class.
            # Mirror __init__'s guard: prefer the smallest class >= padding_min,
            # else the largest available (padding_min may exceed every class —
            # 1450 still passes Config's <=1500 check — so the generator can be
            # empty; never crash on min() of an empty iterable).
            candidates = [sc for sc in SIZE_CLASSES if sc >= self._padding_min]
            kept = (candidates[0],) if candidates else (SIZE_CLASSES[-1],)
        self._active_classes = kept
        self._size_tracker = SizeTracker(self._active_classes)
        # Task 2.3: rebuild the fixed chaff-size prior over the narrowed active
        # set so chaff never samples a class the shaper can no longer emit.
        self._chaff_prior_cumulative = self._build_chaff_prior_cumulative()

    def _build_chaff_prior_cumulative(self) -> tuple[float, ...]:
        """Precompute cumulative weights for the fixed chaff-size prior.

        The prior is the published ``SIZE_CLASS_WEIGHTS`` restricted to the
        current ``_active_classes`` (so padding_min/padding_max and any
        size-class ceiling are respected) and renormalized over that subset.
        A class outside the published set (none exist today, but the active
        filter could in principle hold one) falls back to weight 1. Returns
        ascending cumulative weights summing to 1.0 for a single-scan sample
        in ``_sample_chaff_size``.
        """
        weight_by_class: dict[int, int] = dict(zip(SIZE_CLASSES, SIZE_CLASS_WEIGHTS))
        weights = [float(weight_by_class.get(sc, 1)) for sc in self._active_classes]
        total = sum(weights)
        if total <= 0.0:
            # Degenerate guard (shouldn't happen: published weights are > 0).
            n = len(self._active_classes)
            weights = [1.0] * n
            total = float(n)
        cumulative: list[float] = []
        running = 0.0
        for w in weights:
            running += w / total
            cumulative.append(running)
        return tuple(cumulative)

    def _sample_chaff_size(self) -> tuple[int, int]:
        """Sample a chaff size class from the FIXED published prior.

        Mirrors ``SizeTracker.sample_with_idx`` (one CSPRNG draw + a cumulative
        scan, allocation-free) but reads the frozen ``_chaff_prior_cumulative``
        weights instead of the live EMA — so chaff sizing is independent of the
        real-traffic size distribution. Returns ``(size_class, index)``.
        """
        r = csprng_float()
        for i, cum in enumerate(self._chaff_prior_cumulative):
            if r < cum:
                return self._active_classes[i], i
        last = len(self._active_classes) - 1
        return self._active_classes[last], last

    def _sample_chaff_wire_class(self) -> int:
        """Final chaff size class = FIXED prior draw + ±1-class perturbation.

        The perturbation (Fork 6) is applied ON TOP of the fixed prior, not the
        live EMA: with probability ``_CHAFF_SIZE_PERTURB_UP_P`` bump one class
        up, with the next slice down, else leave it (clamped at the active-set
        boundaries). Used for BOTH the chaff payload budget (``make_chaff``) and
        the chaff wire size (``pad_chaff``) so the two agree distributionally.

        Allocation-free: two CSPRNG draws (prior + perturbation), no per-call
        list construction.
        """
        size_class, idx = self._sample_chaff_size()
        r = csprng_float()
        classes = self._active_classes
        if r < _CHAFF_SIZE_PERTURB_UP_P:
            if idx + 1 < len(classes):
                size_class = classes[idx + 1]
        elif r < _CHAFF_SIZE_PERTURB_DOWN_P:
            if idx > 0:
                size_class = classes[idx - 1]
        return size_class

    def pad_packet(self, inner: InnerPacket) -> tuple[bytes, int]:
        """Serialize and pad a REAL inner packet to a size class.

        Returns (inner_plaintext_with_padding, target_outer_size).

        The target class is sampled from the live ``SizeTracker`` EMA, which
        tracks real-traffic sizes — so a real packet pads to a class near the
        real-traffic size mix. (Chaff uses ``pad_chaff`` / the fixed prior
        instead, Task 2.3.)
        """
        target_outer, idx = self._size_tracker.sample_with_idx()
        return self._serialize_padded(inner, target_outer, idx)

    def pad_chaff(self, inner: InnerPacket) -> tuple[bytes, int]:
        """Serialize and pad a CHAFF inner packet to a FIXED-prior size class.

        Returns (inner_plaintext_with_padding, target_outer_size).

        Task 2.3 (fix for shaper.py:292): the chaff WIRE size is drawn from the
        fixed published prior + ±1-class perturbation
        (``_sample_chaff_wire_class``) instead of the live real-traffic EMA used
        by ``pad_packet``. So the chaff size histogram — the quantity a passive
        observer measures — is independent of the user's application profile;
        the aggregate (real + chaff) histogram trends toward the fleet-wide
        published prior.

        Standalone draw: this picks its OWN wire class. The internal hot path
        (``make_chaff_packet``) instead draws the class ONCE and sizes the
        payload to it (so a large payload never bumps a small wire class off the
        prior); a caller padding an externally-built chaff packet via this
        method accepts a possible bump-up when the payload exceeds the drawn
        class.
        """
        return self.pad_chaff_to_class(inner, self._sample_chaff_wire_class())

    def pad_chaff_to_class(
        self, inner: InnerPacket, target_outer: int
    ) -> tuple[bytes, int]:
        """Pad a chaff packet to a pre-chosen fixed-prior class (Task 2.3)."""
        idx = self._active_classes.index(target_outer)
        return self._serialize_padded(inner, target_outer, idx)

    def _serialize_padded(
        self, inner: InnerPacket, target_outer: int, idx: int
    ) -> tuple[bytes, int]:
        """Build the padded inner plaintext for a pre-chosen target class.

        Shared by ``pad_packet`` (EMA target) and ``pad_chaff`` (fixed-prior
        target). Bumps ``target_outer`` up to the next class that fits the
        payload (or to the exact minimum if no class is large enough), then
        builds the header + payload + random padding into a single pre-sized
        bytearray to avoid an intermediate ``serialized`` copy.
        """
        payload_len = len(inner.payload)
        if payload_len > MAX_INNER_PAYLOAD:
            raise ValueError(f"payload too large: {payload_len} > {MAX_INNER_PAYLOAD}")
        serialized_len = INNER_HEADER_SIZE + payload_len

        # M-PERF-4: the bump-up loop reuses idx without re-scanning.
        min_outer = OUTER_HEADER_SIZE + serialized_len + GCM_TAG_SIZE
        while target_outer < min_outer:
            if idx + 1 < len(self._active_classes):
                idx += 1
                target_outer = self._active_classes[idx]
            else:
                target_outer = min_outer
                break

        target_ct = target_outer - OUTER_HEADER_SIZE
        inner_pad_len = max(0, target_ct - GCM_TAG_SIZE - serialized_len)

        buf = bytearray(serialized_len + inner_pad_len)
        flags = (inner.epoch_id & 0x0F) << 4
        INNER_STRUCT.pack_into(buf, 0, inner.ptype, flags, payload_len)
        buf[INNER_HEADER_SIZE : INNER_HEADER_SIZE + payload_len] = inner.payload
        if inner_pad_len > 0:
            buf[INNER_HEADER_SIZE + payload_len :] = os.urandom(inner_pad_len)
        return bytes(buf), target_outer

    def observe_real_packet(self, size_class: int) -> None:
        """Track a real outgoing packet's size class for REAL-packet padding.

        Feeds the live ``SizeTracker`` EMA that ``pad_packet`` samples when
        padding real packets. Task 2.3: this no longer affects CHAFF sizing —
        chaff is drawn from the fixed published prior (``_sample_chaff_size``),
        decoupled from the real-traffic size distribution. The wire *rate* is
        governed entirely by the envelope (``update_envelope`` /
        ``release_budget``).
        """
        self._size_tracker.observe(size_class)

    def update_envelope(
        self, now: float, real_queue_depth: int, oldest_real_age_s: float
    ) -> None:
        """Advance the paced wire-rate envelope one tick.

        With no real packets queued the envelope decays exponentially toward
        the per-session idle floor (Fork 2 fall). With real packets queued it
        rises toward the rate needed to drain them within the latency budget,
        but the per-second rise is CAPPED (Fork 2) — this is what smears burst
        onset across seconds. The cap holds UNLESS the oldest queued packet has
        already exceeded the latency budget, in which case the budget OVERRIDES
        the rise cap AND the soft ceiling so no real packet stalls behind a
        slowly-rising envelope (Fork 1 / 3).

        O(1) and allocation-free; safe to call once per scheduler poll.

        Args:
            now: current monotonic time (the injected clock's reading).
            real_queue_depth: real packets currently waiting in the scheduler.
            oldest_real_age_s: age of the oldest queued real packet (0 if none).
        """
        # The budget override is age-based, not rate-based, so it is evaluated
        # even on the cold-start tick (before any dt baseline) — a packet
        # already past its deadline must not wait for a second poll.
        if real_queue_depth > 0 and oldest_real_age_s >= self._latency_budget_s:
            desired = real_queue_depth / self._latency_budget_s
            self._envelope_pps = max(self._envelope_pps, desired)
            self._deadline_pending = True
            # Advance the envelope clock so a later non-override tick computes
            # dt from this tick, not from before the override window.
            self._last_envelope_time = now
            return
        if self._last_envelope_time is None:
            self._last_envelope_time = now
            return
        dt = now - self._last_envelope_time
        # Task 2.2: a zero/negative monotonic delta (two polls in the same
        # tick) must NOT move the envelope — early-return so a sub-tick burst
        # cannot snap the rate to the ceiling.
        if dt <= 0:
            return
        self._last_envelope_time = now
        if real_queue_depth <= 0:
            decay = 0.5 ** (dt / self._fall_half_life_s)
            self._envelope_pps = (
                self._idle_floor_pps
                + (self._envelope_pps - self._idle_floor_pps) * decay
            )
            return
        self._raise_envelope(dt, real_queue_depth)

    def _raise_envelope(self, dt: float, real_queue_depth: int) -> None:
        """Capped rise branch of ``update_envelope`` (budget not yet breached).

        Extracted to keep ``update_envelope`` small. The oldest-packet budget
        override is handled by the caller before delegating here.
        """
        # Rate needed to clear the queue within the latency budget.
        desired = real_queue_depth / self._latency_budget_s
        # Bounded multiplicative rise (cap per second), clamped to the ceiling.
        max_rise = self._rise_per_s**dt
        target = min(desired, self._envelope_pps * max_rise, self._ceiling_pps)
        self._envelope_pps = max(self._envelope_pps, target)

    def release_budget(self, now: float) -> int:
        """Number of packets the scheduler may emit on the wire this tick.

        Fractional-packet credit avoids per-tick rounding bias at low rates.
        If a real packet has breached its latency budget, at least one packet
        leaves even on a cold-start tick with no rate-derived credit yet — but
        the rate (not a queue dump) drains the rest, so onset stays smeared.
        MUST be called exactly once per scheduler tick — it advances
        ``_last_release_time`` on every call.
        """
        deadline = self._deadline_pending
        self._deadline_pending = False
        if self._last_release_time is None:
            self._last_release_time = now
            return 1 if deadline else 0
        dt = now - self._last_release_time
        if dt <= 0:
            return 1 if deadline else 0
        self._last_release_time = now
        self._release_credit += self._envelope_pps * dt
        n = int(self._release_credit)
        self._release_credit -= n
        # The deadline nudge only matters when the rate produced nothing this
        # tick (genuine cold start); otherwise the elevated rate already drains
        # the breached backlog and max() leaves n untouched.
        return max(n, 1) if deadline else n

    def make_chaff(self, epoch_id: int = 0) -> InnerPacket:
        """Generate a chaff packet with perturbed size to break correlation.

        Task 2.3: the chaff size class is drawn from the FIXED published prior
        + ±1-class perturbation (``_sample_chaff_wire_class``), NOT the live
        real-traffic ``SizeTracker`` EMA. So chaff no longer mirrors the user's
        app profile and the aggregate (real + chaff) size histogram trends
        toward the fleet-wide published prior rather than amplifying the user's
        actual traffic. ``pad_chaff`` draws the wire size from the same
        distribution, so the payload sized here fits without distortion.

        M-ANON-8: pick payload_len uniformly within the chosen size
        class's plaintext budget so that — post-AEAD — the chaff's
        ``inner_length`` field doesn't always read as "filled the slot".
        Real DATA packets have variable inner_length (the actual IP
        payload size); chaff with inner_length always == max-for-class
        is trivially distinguishable from real DATA by a post-key-
        compromise adversary even though the ``ptype`` field already
        identifies the chaff. With a matching distribution the
        inner_length field stops being a second distinguishing signal.
        """
        # Task 2.3: draw the size class from the fixed prior + ±1 perturbation.
        size_class = self._sample_chaff_wire_class()
        return self._chaff_for_class(epoch_id, size_class)

    def make_chaff_padded(self, epoch_id: int = 0) -> tuple[bytes, int]:
        """Build a padded chaff packet with a SINGLE fixed-prior size draw.

        Returns (inner_plaintext_with_padding, target_outer_size).

        Task 2.3 hot path: draw the wire class once (fixed prior + ±1
        perturbation) and use it for BOTH the payload budget and the wire size,
        so the emitted size histogram is the perturbed fixed prior with no
        bump-up distortion and is fully decoupled from the real-traffic EMA.
        """
        size_class = self._sample_chaff_wire_class()
        chaff = self._chaff_for_class(epoch_id, size_class)
        return self.pad_chaff_to_class(chaff, size_class)

    def _chaff_for_class(self, epoch_id: int, size_class: int) -> InnerPacket:
        """Build a chaff ``InnerPacket`` whose inner_length fits ``size_class``.

        Extracted so ``make_chaff`` and the joint single-draw path in
        ``make_chaff_packet`` size the payload to the SAME class that the wire
        size will use — otherwise an independently-drawn payload could exceed a
        small wire class and force a bump-up, skewing the wire histogram off the
        fixed prior.
        """
        # Maximum plaintext slot for this size class.
        max_payload = max(
            0,
            size_class - OUTER_HEADER_SIZE - GCM_TAG_SIZE - INNER_HEADER_SIZE,
        )
        # M-ANON-8: pick inner_length uniformly in [0, max_payload] so the
        # chaff's inner_length field matches real DATA's variable length; the
        # inner-padding path fills the rest of the slot to the wire class.
        import secrets as _secrets

        payload_len = _secrets.randbelow(max_payload + 1) if max_payload > 0 else 0
        return InnerPacket(
            ptype=PacketType.CHAFF,
            epoch_id=epoch_id,
            payload=os.urandom(payload_len),
        )


async def make_chaff_packet(
    shaper: TrafficShaper, epoch_id: int = 0
) -> tuple[bytes, int]:
    """Generate a padded chaff packet ready for encryption.

    The wire rate is paced entirely by the envelope (``release_budget``), so
    chaff generation no longer feeds any rate state — it only produces a
    size-class-matched padded packet for the scheduler's chaff fill.

    Task 2.3: the wire size is drawn from the fixed published prior + ±1-class
    perturbation, NOT the live real-traffic EMA — so the chaff wire-size
    histogram is decoupled from the user's application profile. The class is
    drawn ONCE and used for both the payload budget and the wire size, so the
    emitted histogram is the perturbed fixed prior with no bump-up distortion.
    """
    return shaper.make_chaff_padded(epoch_id)
