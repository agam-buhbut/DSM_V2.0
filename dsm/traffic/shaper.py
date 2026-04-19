"""Adaptive traffic shaping: padding, chaff generation, size distribution.

Chaff is adaptive — not static-rate:
- Active mode: chaff rate tracks real traffic (0.5x-1.5x), re-sampled every 1-3s
- Idle mode: mimics browsing burst patterns (exponential inter-burst gaps)
- Size distribution mirrors observed real traffic via exponential moving average
"""

from __future__ import annotations

import os
import secrets
import time

from dsm.core.rand import csprng_exponential, csprng_float
from collections import deque

from dsm.core.protocol import (
    INNER_HEADER_SIZE,
    GCM_TAG_SIZE,
    OUTER_HEADER_SIZE,
    SIZE_CLASSES,
    InnerPacket,
    PacketType,
)

# Exponential moving average decay factor
EMA_ALPHA = 0.15
# Idle threshold: no real data for this many seconds triggers idle chaff
IDLE_THRESHOLD = 0.2
# Re-sample chaff rate every 1-3 seconds
RESAMPLE_MIN = 1.0
RESAMPLE_MAX = 3.0
# Idle mode burst parameters
IDLE_BURST_MIN = 3
IDLE_BURST_MAX = 15
IDLE_GAP_LAMBDA = 1.5  # Exponential distribution parameter (mean gap ~1.5s)

# Burst-edge smoothing: on every idle→active transition, apply a small random
# delay to each real packet for SMOOTHING_WINDOW seconds. Chaff tracks the EMA
# of real traffic, which lags the rate step at the edge of a burst; injecting
# jitter on the first ~2s of an active burst masks the transition itself.
SMOOTHING_WINDOW = 2.0
SMOOTHING_LAMBDA = 0.010  # mean ≈10ms; clamped to [1ms, 25ms]


class SizeTracker:
    """Track real traffic size class distribution via EMA."""

    def __init__(self, classes: tuple[int, ...] | None = None) -> None:
        self._classes = classes or SIZE_CLASSES
        n = len(self._classes)
        self._weights: list[float] = [1.0 / n] * n

    def observe(self, size_class: int) -> None:
        """Update the distribution based on an observed real packet size class."""
        idx = self.class_index(size_class)
        self._weights = [
            (1 - EMA_ALPHA) * w + (EMA_ALPHA if i == idx else 0.0)
            for i, w in enumerate(self._weights)
        ]
        total = sum(self._weights)
        if total > 0:
            self._weights = [w / total for w in self._weights]

    def sample(self) -> int:
        """Sample a size class from the current distribution."""
        r = csprng_float()
        cumulative = 0.0
        for sc, w in zip(self._classes, self._weights):
            cumulative += w
            if r < cumulative:
                return sc
        return self._classes[-1]

    def class_index(self, size: int) -> int:
        """Find the index of the matching or next-larger class."""
        for i, sc in enumerate(self._classes):
            if sc >= size:
                return i
        return len(self._classes) - 1


class TrafficShaper:
    """Adaptive chaff and padding engine."""

    def __init__(self, padding_min: int = 128, padding_max: int = 1400) -> None:
        self._padding_min = padding_min
        self._padding_max = padding_max
        # Filter SIZE_CLASSES to the configured range so that
        # padding_min/padding_max actually constrain packet sizes.
        self._active_classes = tuple(
            sc for sc in SIZE_CLASSES if padding_min <= sc <= padding_max
        )
        if not self._active_classes:
            # Fallback: use the smallest class >= padding_min
            self._active_classes = (min(sc for sc in SIZE_CLASSES if sc >= padding_min),)
        self._size_tracker = SizeTracker(self._active_classes)

        # Rate tracking
        self._real_packet_times: deque[float] = deque(maxlen=100)
        self._last_real_time: float | None = None
        self._chaff_rate_multiplier = 1.0
        self._next_resample = 0.0

        # Idle burst state
        self._idle_burst_remaining = 0
        self._next_idle_burst = 0.0

        self._burst_smoothing_until: float = 0.0

    def pad_packet(self, inner: InnerPacket) -> tuple[bytes, int]:
        """Serialize and pad an inner packet to a size class.

        Returns (inner_plaintext_with_padding, target_outer_size).
        """
        serialized = inner.serialize()
        # Choose size class
        target_outer = self._size_tracker.sample()

        # Ensure target can fit the data
        # outer = OUTER_HEADER + ciphertext + outer_padding
        # ciphertext = inner_plaintext + GCM_TAG
        min_outer = OUTER_HEADER_SIZE + len(serialized) + GCM_TAG_SIZE
        while target_outer < min_outer:
            idx = self._size_tracker.class_index(target_outer)
            if idx + 1 < len(self._active_classes):
                target_outer = self._active_classes[idx + 1]
            else:
                target_outer = min_outer
                break

        # Add inner padding to fill the encrypted envelope
        # target ciphertext size = target_outer - OUTER_HEADER_SIZE - (outer padding will be added later)
        # Inner padding fills: target_ciphertext - GCM_TAG - len(serialized)
        target_ct = target_outer - OUTER_HEADER_SIZE
        inner_pad_len = max(0, target_ct - GCM_TAG_SIZE - len(serialized))
        padded = serialized + os.urandom(inner_pad_len)

        return padded, target_outer

    def observe_real_packet(self, size_class: int) -> None:
        """Track a real outgoing packet for adaptive chaff."""
        now = time.monotonic()
        if self._last_real_time is None or (now - self._last_real_time) > IDLE_THRESHOLD:
            # Arm the burst-smoothing window — subsequent real packets within
            # SMOOTHING_WINDOW will get a geometric delay applied before send.
            self._burst_smoothing_until = now + SMOOTHING_WINDOW
        self._real_packet_times.append(now)
        self._last_real_time = now
        self._size_tracker.observe(size_class)

    def burst_smoothing_delay(self) -> float | None:
        """Geometric delay within the burst-smoothing window, else None."""
        if time.monotonic() >= self._burst_smoothing_until:
            return None
        return csprng_exponential(SMOOTHING_LAMBDA, 0.001, 0.025)

    def should_send_chaff(self) -> bool:
        """Determine if a chaff packet should be sent now."""
        now = time.monotonic()
        time_since_real = now - self._last_real_time if self._last_real_time is not None else float("inf")

        if time_since_real < IDLE_THRESHOLD:
            # Active mode: probability-based interleaving
            self._maybe_resample(now)
            return (csprng_float()) < (0.3 * self._chaff_rate_multiplier)

        # Idle mode: burst pattern
        return self._idle_burst_check(now)

    def make_chaff(self, epoch_id: int = 0) -> InnerPacket:
        """Generate a chaff packet with perturbed size distribution to prevent correlation."""
        size_class = self._size_tracker.sample()
        # Perturb size class ±1 with 30% probability to decorrelate from real traffic
        r = csprng_float()
        classes = self._active_classes
        if r < 0.15:
            idx = self._size_tracker.class_index(size_class)
            if idx + 1 < len(classes):
                size_class = classes[idx + 1]
        elif r < 0.30:
            idx = self._size_tracker.class_index(size_class)
            if idx > 0:
                size_class = classes[idx - 1]
        # Chaff payload is random bytes sized to fill the target
        payload_len = max(0, size_class - OUTER_HEADER_SIZE - GCM_TAG_SIZE - INNER_HEADER_SIZE)
        return InnerPacket(
            ptype=PacketType.CHAFF,
            epoch_id=epoch_id,
            payload=os.urandom(payload_len),
        )

    def _maybe_resample(self, now: float) -> None:
        """Re-sample chaff rate multiplier periodically."""
        if now < self._next_resample:
            return
        self._chaff_rate_multiplier = 0.5 + (csprng_float())
        self._next_resample = now + RESAMPLE_MIN + (csprng_float()) * (RESAMPLE_MAX - RESAMPLE_MIN)

    def _idle_burst_check(self, now: float) -> bool:
        """Idle mode: emit chaff in bursts mimicking browsing patterns."""
        if self._idle_burst_remaining > 0:
            self._idle_burst_remaining -= 1
            return True

        if now >= self._next_idle_burst:
            # Start a new burst
            self._idle_burst_remaining = IDLE_BURST_MIN + secrets.randbelow(IDLE_BURST_MAX - IDLE_BURST_MIN + 1)
            gap = csprng_exponential(IDLE_GAP_LAMBDA, 0.5, 5.0)
            self._next_idle_burst = now + gap
            self._idle_burst_remaining -= 1
            return True

        return False


async def make_chaff_packet(shaper: TrafficShaper, epoch_id: int = 0) -> tuple[bytes, int]:
    """Generate a padded chaff packet ready for encryption."""
    chaff = shaper.make_chaff(epoch_id)
    padded, target = shaper.pad_packet(chaff)
    return padded, target
