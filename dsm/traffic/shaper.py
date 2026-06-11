"""Adaptive traffic shaping: padding, chaff generation, size distribution.

Chaff scheduling model (post audit Pass 6, H-ANON-2 / H-ANON-3):

The shaper exposes a SINGLE rate model — no active/idle modes, no burst
geometry. Every send on the wire (real or chaff) feeds an EMA of recent
total packets-per-second (``_target_rate_pps``). Chaff is then scheduled
as a Poisson process at that rate: the next chaff time is

    next_chaff = now + Exp(1 / _target_rate_pps)

with ``_target_rate_pps`` clamped to ``[_CHAFF_RATE_FLOOR_PPS,
_CHAFF_RATE_CEIL_PPS]``. Inter-arrival times are exponential, so chaff
IPTs are memoryless — there is no fixed cadence or burst structure to
fingerprint, and there is no observable boundary between "user active"
and "user idle" because both states are smoothly tracked by the same
EMA on the same underlying process.

Why the EMA alpha is small: a fast EMA would let a single real-packet
burst snap the chaff rate up within tens of milliseconds, recreating
the very boundary this redesign removes. ``_RATE_EMA_ALPHA = 0.05`` is
deliberately slower than ``EMA_ALPHA`` (used for size class tracking)
so rate changes lag behind real-traffic onset over several seconds.

Size distribution still mirrors observed real traffic via the
``SizeTracker`` EMA, with per-chaff-packet ±1 class perturbation.
"""

from __future__ import annotations

import os
import time
from collections import deque

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
from dsm.core.rand import csprng_exponential, csprng_float

# EMA decay for the size-class distribution. Kept at the historical 0.15
# so chaff sizes track real-traffic size mix on the order of ~10 packets.
EMA_ALPHA = 0.15

# EMA decay for the wire-packet rate (``_target_rate_pps``). Deliberately
# slower than ``EMA_ALPHA`` so a real-traffic onset takes seconds — not
# milliseconds — to bleed into the chaff rate. A fast EMA would re-create
# the active/idle boundary this redesign removes.
_RATE_EMA_ALPHA = 0.05

# Chaff rate bounds (packets per second). Floor keeps chaff present even
# when no real traffic has ever been observed (anonymity baseline);
# ceiling prevents a real-traffic spike from triggering an unbounded
# chaff response that would itself become a fingerprint.
_CHAFF_RATE_FLOOR_PPS = 1.0
_CHAFF_RATE_CEIL_PPS = 200.0

# Initial chaff rate before the EMA has any samples. Starts at the floor
# so a freshly-built shaper does not appear noisier than the steady state.
_INITIAL_RATE_PPS = _CHAFF_RATE_FLOOR_PPS

# Maximum dt between consecutive wire sends that the rate EMA will
# convert into an instantaneous rate. Without a ceiling on dt, a long
# silence followed by one packet would update the EMA toward
# ``1 / dt`` ≈ 0 pps and pull the chaff rate to the floor on the first
# real packet, exposing the silence/activity boundary. Capping dt at 2s
# means very-low rates are clamped to ``0.5 pps`` before EMA mixing.
_MAX_RATE_SAMPLE_DT = 2.0

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

    Chaff is scheduled as a Poisson process at ``_target_rate_pps``,
    which is an EMA of observed wire-packet rate (real + chaff). There
    is no active/idle mode switch and no burst structure — the single
    rate model means a passive observer cannot distinguish "user active"
    from "user idle" from the chaff IPT distribution.
    """

    def __init__(self, padding_min: int = 128, padding_max: int = 1400) -> None:
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

        # Wire-rate EMA state. ``_last_wire_time`` is the monotonic
        # timestamp of the most recent send of any kind; the EMA mixes in
        # ``1 / dt`` on each new send.
        self._target_rate_pps: float = _INITIAL_RATE_PPS
        self._last_wire_time: float | None = None

        # Per-packet history kept for diagnostics / future audit; bounded
        # by ``maxlen`` so it never grows without bound.
        self._recent_wire_times: deque[float] = deque(maxlen=200)

        # Next scheduled chaff emission time (Poisson). Initialised to
        # "fire on the first poll" so a fresh shaper does not have a
        # cold-start dead zone.
        self._next_chaff_time: float = 0.0

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

    def pad_packet(self, inner: InnerPacket) -> tuple[bytes, int]:
        """Serialize and pad an inner packet to a size class.

        Returns (inner_plaintext_with_padding, target_outer_size).

        Builds the header + payload + random padding into a single
        pre-sized bytearray to avoid the intermediate ``serialized``
        copy and the concat's temporary buffer.
        """
        payload_len = len(inner.payload)
        if payload_len > MAX_INNER_PAYLOAD:
            raise ValueError(f"payload too large: {payload_len} > {MAX_INNER_PAYLOAD}")
        serialized_len = INNER_HEADER_SIZE + payload_len

        # M-PERF-4: sample + idx in one scan; the bump-up loop below
        # reuses idx without re-scanning via class_index.
        target_outer, idx = self._size_tracker.sample_with_idx()
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
        """Track a real outgoing packet for adaptive chaff rate + size."""
        self._observe_wire_send(time.monotonic())
        self._size_tracker.observe(size_class)

    def observe_chaff_packet(self) -> None:
        """Track an outgoing chaff packet for adaptive chaff rate.

        Chaff sends feed the same EMA as real sends so the target rate
        reflects total wire activity. Without this, a long real-traffic
        silence would drag the rate to the floor even while the shaper
        was emitting chaff — exposing the boundary again.
        """
        self._observe_wire_send(time.monotonic())

    def burst_smoothing_delay(self) -> float | None:
        """Legacy no-op: returns ``None`` unconditionally.

        Prior versions injected geometric per-packet jitter on the
        idle→active boundary to mask the EMA's lag at burst onset. With
        the single-rate Poisson model that boundary no longer exists,
        and re-introducing jitter that fires only at the transition
        would re-create the very leak it was designed to mask. Kept on
        the public API so ``tun_send_loop`` does not need a conditional.
        """
        return None

    def should_send_chaff(self) -> bool:
        """Poisson-process chaff decision.

        Returns ``True`` when the scheduled next chaff time has arrived;
        on each fire, immediately re-schedules the next chaff time as
        ``now + Exp(1 / _target_rate_pps)``. Inter-arrival times are
        exponential, so the IPT distribution is memoryless — there is
        no fixed cadence and no observable burst structure.
        """
        now = time.monotonic()
        if now < self._next_chaff_time:
            return False
        self._schedule_next_chaff(now)
        return True

    def make_chaff(self, epoch_id: int = 0) -> InnerPacket:
        """Generate a chaff packet with perturbed size to break correlation.

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
        # M-PERF-4: sample + idx in one scan; perturb branches reuse
        # idx directly instead of re-scanning via class_index.
        size_class, idx = self._size_tracker.sample_with_idx()
        # Perturb size class ±1 to decorrelate from real traffic. Total
        # perturb probability is _CHAFF_SIZE_PERTURB_DOWN_P (the upper
        # bound), split into the first slice = up, the second slice = down.
        r = csprng_float()
        classes = self._active_classes
        if r < _CHAFF_SIZE_PERTURB_UP_P:
            if idx + 1 < len(classes):
                size_class = classes[idx + 1]
        elif r < _CHAFF_SIZE_PERTURB_DOWN_P:
            if idx > 0:
                size_class = classes[idx - 1]
        # Maximum plaintext slot for this size class.
        max_payload = max(
            0,
            size_class - OUTER_HEADER_SIZE - GCM_TAG_SIZE - INNER_HEADER_SIZE,
        )
        # M-ANON-8: pick inner_length uniformly in [0, max_payload].
        # pad_packet fills the rest of the slot with random bytes via
        # the inner-padding path, so the on-the-wire size still lands on
        # the chosen size class regardless of inner_length.
        import secrets as _secrets

        payload_len = _secrets.randbelow(max_payload + 1) if max_payload > 0 else 0
        return InnerPacket(
            ptype=PacketType.CHAFF,
            epoch_id=epoch_id,
            payload=os.urandom(payload_len),
        )

    def _observe_wire_send(self, now: float) -> None:
        """Update the wire-rate EMA from a single send observation.

        Converts the gap ``dt`` since the previous send into an
        instantaneous rate ``1 / dt`` and mixes it into the EMA. ``dt``
        is clamped to ``_MAX_RATE_SAMPLE_DT`` to keep a single very-long
        silence from pulling the rate to the floor on the next packet.
        """
        self._recent_wire_times.append(now)
        if self._last_wire_time is None:
            self._last_wire_time = now
            return
        dt = now - self._last_wire_time
        self._last_wire_time = now
        if dt <= 0:
            # Two sends in the same monotonic tick: treat as max rate.
            instant = _CHAFF_RATE_CEIL_PPS
        else:
            instant = 1.0 / min(dt, _MAX_RATE_SAMPLE_DT)
        self._target_rate_pps = (
            1.0 - _RATE_EMA_ALPHA
        ) * self._target_rate_pps + _RATE_EMA_ALPHA * instant
        if self._target_rate_pps < _CHAFF_RATE_FLOOR_PPS:
            self._target_rate_pps = _CHAFF_RATE_FLOOR_PPS
        elif self._target_rate_pps > _CHAFF_RATE_CEIL_PPS:
            self._target_rate_pps = _CHAFF_RATE_CEIL_PPS

    def _schedule_next_chaff(self, now: float) -> None:
        """Schedule the next chaff emission as ``now + Exp(1 / rate)``."""
        rate = self._target_rate_pps
        if rate < _CHAFF_RATE_FLOOR_PPS:
            rate = _CHAFF_RATE_FLOOR_PPS
        elif rate > _CHAFF_RATE_CEIL_PPS:
            rate = _CHAFF_RATE_CEIL_PPS
        mean_dt = 1.0 / rate
        # Bound the sampled delay to ``[1ms, 5s]`` — the lower bound stops
        # a single tick from triggering hundreds of chaff fires at the
        # ceiling rate, the upper stops the floor from producing dead
        # silences longer than a real-traffic-free user would tolerate.
        gap = csprng_exponential(mean_dt, 0.001, 5.0)
        self._next_chaff_time = now + gap


async def make_chaff_packet(
    shaper: TrafficShaper, epoch_id: int = 0
) -> tuple[bytes, int]:
    """Generate a padded chaff packet ready for encryption.

    Notifies the shaper that a chaff packet is on its way out so the
    wire-rate EMA includes it. Callers MUST funnel all chaff through
    this helper — bypassing it would let real traffic drag the EMA to
    the floor while chaff fires invisibly, re-exposing the boundary.
    """
    chaff = shaper.make_chaff(epoch_id)
    padded, target = shaper.pad_packet(chaff)
    shaper.observe_chaff_packet()
    return padded, target
