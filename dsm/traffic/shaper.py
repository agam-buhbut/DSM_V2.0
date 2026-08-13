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

Size distribution: BOTH real and chaff packets pad to a size class drawn from
the SAME FIXED published prior (``SIZE_CLASS_WEIGHTS``, renormalized over the
active classes). A real packet's class is the fixed-prior draw bumped UP to the
smallest class that fits its actual payload (you cannot pad a packet below its
own size); chaff adds a per-chaff-packet ±1-class perturbation on top of the
draw. Real-packet sizing carries NO state — there is no EMA feeding the next
draw — so the aggregate (real + chaff) wire-size histogram trends toward the
published fleet-wide prior rather than amplifying the user's application
profile.
"""

from __future__ import annotations

import os
import secrets
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

# Adaptive-envelope defaults. These mirror the Config
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
            # padding_min may exceed the largest SIZE_CLASS (1400)
            # while still passing Config's <=1500 range check. Clamp to a
            # usable class rather than crashing on an empty generator.
            self._active_classes = self._fallback_classes(padding_min)
        # BOTH real and chaff packets size from this fixed published
        # prior (no live real-traffic EMA — see module docstring). Precomputed
        # once so each draw is allocation-free (a single cumulative scan in
        # _sample_size_class).
        self._size_prior_cumulative = self._build_size_prior_cumulative()

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

    @staticmethod
    def _fallback_classes(padding_min: int) -> tuple[int, ...]:
        """One usable size class when the configured range excludes every
        SIZE_CLASS: the smallest class >= ``padding_min`` (padding_min can
        exceed 1400 while still passing Config's <=1500 check), else the
        largest class. Never returns empty."""
        candidates = [sc for sc in SIZE_CLASSES if sc >= padding_min]
        return (candidates[0],) if candidates else (SIZE_CLASSES[-1],)

    def set_size_class_ceiling(self, max_outer: int) -> None:
        """Cap the size classes the shaper pads to at ``max_outer``
        (the DSM outer-packet size budget = path_mtu - IP - UDP).

        Filters the active classes to those <= max_outer and rebuilds the
        fixed size prior so subsequent pad_packet / chaff sizes fit a
        constrained path. Always keeps at least one class (the smallest), so an
        absurdly low ceiling degrades gracefully rather than emptying the set.
        The ceiling is bounded above by the configured ``padding_max`` (raising
        it cannot exceed the operator's padding policy).
        """
        ceiling = min(max_outer, self._padding_max)
        kept = tuple(sc for sc in SIZE_CLASSES if self._padding_min <= sc <= ceiling)
        if not kept:
            # Below the smallest configured class — keep one usable class
            # (mirror __init__'s guard).
            kept = self._fallback_classes(self._padding_min)
        self._active_classes = kept
        # Rebuild the fixed size prior over the narrowed active set so neither
        # real nor chaff sizing ever samples a class the shaper can no longer
        # emit.
        self._size_prior_cumulative = self._build_size_prior_cumulative()

    def _build_size_prior_cumulative(self) -> tuple[float, ...]:
        """Precompute cumulative weights for the fixed size prior.

        The prior is the published ``SIZE_CLASS_WEIGHTS`` restricted to the
        current ``_active_classes`` (so padding_min/padding_max and any
        size-class ceiling are respected) and renormalized over that subset.
        A class outside the published set (none exist today, but the active
        filter could in principle hold one) falls back to weight 1. Returns
        ascending cumulative weights summing to 1.0 for a single-scan sample
        in ``_sample_size_class``. Shared by BOTH real-packet sizing
        (``pad_packet``) and chaff sizing (``_sample_chaff_wire_class``).
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

    def _sample_size_class(self) -> tuple[int, int]:
        """Sample a size class from the FIXED published prior.

        One CSPRNG draw + a cumulative scan (allocation-free) over the frozen
        ``_size_prior_cumulative`` weights. There is NO live EMA — sizing is
        stateless and independent of the real-traffic size distribution. Shared
        by ``pad_packet`` (real packets, no perturbation) and
        ``_sample_chaff_wire_class`` (chaff, ±1 perturbation on top). Returns
        ``(size_class, index)``.
        """
        r = csprng_float()
        for i, cum in enumerate(self._size_prior_cumulative):
            if r < cum:
                return self._active_classes[i], i
        last = len(self._active_classes) - 1
        return self._active_classes[last], last

    def _sample_chaff_wire_class(self) -> int:
        """Final chaff size class = FIXED prior draw + ±1-class perturbation.

        The perturbation is applied ON TOP of the fixed prior: with
        probability ``_CHAFF_SIZE_PERTURB_UP_P`` bump one class up, with the
        next slice down, else leave it (clamped at the active-set boundaries).
        Used for BOTH the chaff payload budget and the chaff wire size
        (``make_chaff_padded`` draws it once for both) so the two agree
        distributionally. Real
        packets (``pad_packet``) draw from the SAME prior but WITHOUT this
        perturbation — they bump up to fit their payload instead.

        Allocation-free: two CSPRNG draws (prior + perturbation), no per-call
        list construction.
        """
        size_class, idx = self._sample_size_class()
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

        The target class is drawn from the fixed published prior
        (``_sample_size_class`` — the SAME prior chaff uses,
        WITHOUT chaff's ±1 perturbation), then ``_serialize_padded`` bumps it UP
        to the smallest class that fits the actual payload. Real and chaff
        sizing both trend to the fixed prior; the only residual is the
        unavoidable "can't pad down" floor (a P-byte payload must use a class
        >= P), so large payloads still over-represent the large class.
        """
        target_outer, idx = self._sample_size_class()
        return self._serialize_padded(inner, target_outer, idx)

    def pad_chaff_to_class(
        self, inner: InnerPacket, target_outer: int
    ) -> tuple[bytes, int]:
        """Pad a chaff packet to a pre-chosen fixed-prior class."""
        idx = self._active_classes.index(target_outer)
        return self._serialize_padded(inner, target_outer, idx)

    def _serialize_padded(
        self, inner: InnerPacket, target_outer: int, idx: int
    ) -> tuple[bytes, int]:
        """Build the padded inner plaintext for a pre-chosen target class.

        Shared by ``pad_packet`` and ``pad_chaff_to_class`` — both draw the target
        from the same fixed prior. Bumps ``target_outer`` up to the next class
        that fits the payload (or to the exact minimum if no class is large
        enough — the "can't pad down" floor), then builds the header + payload +
        random padding into a single pre-sized bytearray to avoid an
        intermediate ``serialized`` copy.
        """
        payload_len = len(inner.payload)
        if payload_len > MAX_INNER_PAYLOAD:
            raise ValueError(f"payload too large: {payload_len} > {MAX_INNER_PAYLOAD}")
        serialized_len = INNER_HEADER_SIZE + payload_len

        # The bump-up loop reuses idx without re-scanning.
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
        # A zero/negative monotonic delta (two polls in the same
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
        # Clamp dt to the envelope interval before accruing credit. A
        # scheduler/send stall balloons dt and would otherwise let one tick
        # emit a burst of range(credit) packets — leaking the stall as a
        # timing side-channel. Capping at the latency budget bounds the
        # per-tick credit to the pacing the envelope is allowed to sustain.
        dt = min(dt, self._latency_budget_s)
        self._release_credit += self._envelope_pps * dt
        n = int(self._release_credit)
        self._release_credit -= n
        # The deadline nudge only matters when the rate produced nothing this
        # tick (genuine cold start); otherwise the elevated rate already drains
        # the breached backlog and max() leaves n untouched.
        return max(n, 1) if deadline else n

    def make_chaff_padded(self, epoch_id: int = 0) -> tuple[bytes, int]:
        """Build a padded chaff packet with a SINGLE fixed-prior size draw.

        Returns (inner_plaintext_with_padding, target_outer_size).

        Hot path: draw the wire class once (fixed prior + ±1
        perturbation) and use it for BOTH the payload budget and the wire size,
        so the emitted size histogram is the perturbed fixed prior with no
        bump-up distortion and is fully decoupled from the real-traffic EMA.
        """
        size_class = self._sample_chaff_wire_class()
        chaff = self._chaff_for_class(epoch_id, size_class)
        return self.pad_chaff_to_class(chaff, size_class)

    def _chaff_for_class(self, epoch_id: int, size_class: int) -> InnerPacket:
        """Build a chaff ``InnerPacket`` whose inner_length fits ``size_class``.

        Extracted so the single-draw path in ``make_chaff_padded`` sizes the
        payload to the SAME class that the wire
        size will use — otherwise an independently-drawn payload could exceed a
        small wire class and force a bump-up, skewing the wire histogram off the
        fixed prior.
        """
        max_payload = max(
            0,
            size_class - OUTER_HEADER_SIZE - GCM_TAG_SIZE - INNER_HEADER_SIZE,
        )
        # Pick inner_length uniformly in [0, max_payload] so the
        # chaff's inner_length field matches real DATA's variable length; the
        # inner-padding path fills the rest of the slot to the wire class.
        payload_len = secrets.randbelow(max_payload + 1) if max_payload > 0 else 0
        return InnerPacket(
            ptype=PacketType.CHAFF,
            epoch_id=epoch_id,
            payload=os.urandom(payload_len),
        )


async def make_chaff_packet(
    shaper: TrafficShaper, epoch_id: int = 0
) -> tuple[bytes, int]:
    """Generate a padded chaff packet ready for encryption.

    Pacing is entirely the envelope's job (``release_budget``); this only
    produces a size-class-matched padded packet for the scheduler's fill.
    """
    return shaper.make_chaff_padded(epoch_id)
