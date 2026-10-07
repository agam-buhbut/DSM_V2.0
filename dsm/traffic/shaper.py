"""Traffic shaping: packet sizes, padding and chaff, driven by the Rust core.

The tier shaper core (``tuncore.Shaper``, rust/tuncore/src/shaper.rs) decides
WHEN packets leave and HOW BIG they are. Packets leave at a steady rate that
only changes in a few fixed steps ("tiers"); real packets take free slots and
chaff fills the rest. Apart from decoys, the rate steps up when real packets
have waited too long or have filled nearly all of the tier for a few seconds,
and it steps down slowly; decoys imitate real busy periods; every session
picks its own secret timing values, which Python cannot read.

This module only builds packet bytes. Real and chaff packets get their size
from the same fixed, published size mix (``SIZE_CLASS_WEIGHTS``): a real
packet's class is bumped up to fit its payload, a chaff packet's class gets a
one-class nudge up or down. No size state carries over between packets.
"""

from __future__ import annotations

import os
import secrets
import time
from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING

import tuncore
from dsm.core.config import (
    DEFAULT_SHAPER_DECOY_INTERVAL_S,
    DEFAULT_SHAPER_LATENCY_BUDGET_MS,
    DEFAULT_SHAPER_LINGER_S,
    DEFAULT_SHAPER_TIERS_PPS,
)
from dsm.core.protocol import (
    GCM_TAG_SIZE,
    INNER_HEADER_SIZE,
    INNER_STRUCT,
    MAX_INNER_PAYLOAD,
    OUTER_HEADER_SIZE,
    InnerPacket,
    PacketType,
)

if TYPE_CHECKING:
    from dsm.core.config import Config

# Chaff size nudge: a draw below UP_P moves one class up. A draw from UP_P up
# to just below DOWN_P moves one class down. The Rust core owns the values;
# the names stay here for the size tests.
_CHAFF_SIZE_PERTURB_UP_P: float = tuncore.CHAFF_PERTURB_UP_P
_CHAFF_SIZE_PERTURB_DOWN_P: float = tuncore.CHAFF_PERTURB_DOWN_P

# set_size_class_ceiling crosses the FFI as a u16.
_MAX_U16 = 0xFFFF


def _min_outer(payload_len: int) -> int:
    """Smallest outer packet that carries ``payload_len`` payload bytes."""
    return OUTER_HEADER_SIZE + INNER_HEADER_SIZE + payload_len + GCM_TAG_SIZE


class TrafficShaper:
    """Python side of the tier shaper: builds packet bytes, asks Rust for
    sizes and send slots. Holds no timing state of its own."""

    def __init__(
        self,
        padding_min: int = 128,
        padding_max: int = 1400,
        *,
        clock: Callable[[], float] = time.monotonic,
        tiers_pps: Sequence[float] = DEFAULT_SHAPER_TIERS_PPS,
        latency_budget_ms: int = DEFAULT_SHAPER_LATENCY_BUDGET_MS,
        decoy_interval_s: float = DEFAULT_SHAPER_DECOY_INTERVAL_S,
        linger_s: Sequence[float] = DEFAULT_SHAPER_LINGER_S,
    ) -> None:
        linger_min, linger_max = linger_s
        self._core = tuncore.Shaper(
            [float(t) for t in tiers_pps],
            latency_budget_ms / 1000.0,
            float(decoy_interval_s),
            (float(linger_min), float(linger_max)),
            padding_min,
            padding_max,
            clock(),
        )

    @classmethod
    def from_config(
        cls, config: Config, *, clock: Callable[[], float] = time.monotonic
    ) -> TrafficShaper:
        """Build the shaper from config. Client and server both use this, so
        both ends shape what they send from the same settings."""
        return cls(
            config.padding_min,
            config.padding_max,
            clock=clock,
            tiers_pps=config.shaper_tiers_pps,
            latency_budget_ms=config.shaper_latency_budget_ms,
            decoy_interval_s=config.shaper_decoy_interval_s,
            linger_s=config.shaper_linger_s,
        )

    @property
    def _active_classes(self) -> tuple[int, ...]:
        """Size classes in use now (public information, not a secret)."""
        return tuple(self._core.active_classes())

    def poll(
        self, now: float, queue_len: int, oldest_wait: float, real_sent: int
    ) -> tuple[int, float]:
        """Advance the schedule to ``now``; return ``(slots_due, next_wake)``.

        ``queue_len``: real packets waiting. ``oldest_wait``: seconds the
        oldest sendable one has waited (0 if none). ``real_sent``: real
        packets sent since the previous poll.
        """
        return self._core.poll(now, queue_len, oldest_wait, real_sent)

    def set_size_class_ceiling(self, max_outer: int) -> None:
        """Cap padded sizes at ``max_outer`` bytes (path MTU minus IP + UDP).

        Never above ``padding_max``; at least one class always stays usable,
        so an absurdly low ceiling degrades gracefully.
        """
        self._core.set_size_class_ceiling(min(max(max_outer, 0), _MAX_U16))

    def _sample_chaff_wire_class(self) -> int:
        """Chaff size class: a fixed-mix draw plus the one-class nudge."""
        return self._core.chaff_size_class()

    def pad_packet(self, inner: InnerPacket) -> tuple[bytes, int]:
        """Serialize and pad a REAL inner packet.

        Returns ``(inner_plaintext_with_padding, target_outer_size)``. The
        core draws the class from the fixed mix and bumps it up to fit the
        payload: padding only ever grows a packet.
        """
        payload_len = len(inner.payload)
        if payload_len > MAX_INNER_PAYLOAD:
            raise ValueError(f"payload too large: {payload_len} > {MAX_INNER_PAYLOAD}")
        target_outer = self._core.real_size_class(payload_len)
        return self._serialize_padded(inner, target_outer)

    def pad_chaff_to_class(
        self, inner: InnerPacket, target_outer: int
    ) -> tuple[bytes, int]:
        """Pad a chaff packet to a class the core picked.

        Raises ``ValueError`` if ``target_outer`` is not an active class or
        the payload does not fit in it.
        """
        if target_outer not in self._core.active_classes():
            raise ValueError(f"{target_outer} is not an active size class")
        if _min_outer(len(inner.payload)) > target_outer:
            raise ValueError(f"payload does not fit size class {target_outer}")
        return self._serialize_padded(inner, target_outer)

    def make_chaff_padded(self, epoch_id: int = 0) -> tuple[bytes, int]:
        """Build a padded chaff packet from ONE size draw, used for both the
        payload budget and the wire size."""
        size_class = self._sample_chaff_wire_class()
        chaff = self._chaff_for_class(epoch_id, size_class)
        return self._serialize_padded(chaff, size_class)

    @staticmethod
    def _serialize_padded(inner: InnerPacket, target_outer: int) -> tuple[bytes, int]:
        """Build header + payload + random inner padding for ``target_outer``
        in one pre-sized buffer. The caller guarantees the payload fits."""
        payload_len = len(inner.payload)
        serialized_len = INNER_HEADER_SIZE + payload_len
        target_ct = target_outer - OUTER_HEADER_SIZE
        inner_pad_len = max(0, target_ct - GCM_TAG_SIZE - serialized_len)

        buf = bytearray(serialized_len + inner_pad_len)
        flags = (inner.epoch_id & 0x0F) << 4
        INNER_STRUCT.pack_into(buf, 0, inner.ptype, flags, payload_len)
        buf[INNER_HEADER_SIZE : INNER_HEADER_SIZE + payload_len] = inner.payload
        if inner_pad_len > 0:
            buf[INNER_HEADER_SIZE + payload_len :] = os.urandom(inner_pad_len)
        return bytes(buf), target_outer

    @staticmethod
    def _chaff_for_class(epoch_id: int, size_class: int) -> InnerPacket:
        """A chaff ``InnerPacket`` whose payload fits ``size_class``.

        The payload length is uniform in [0, max] so a chaff packet's
        inner_length field looks like real DATA's variable length; inner
        padding fills the rest of the class.
        """
        max_payload = max(0, size_class - _min_outer(0))
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

    When packets leave is the tier shaper's job (``poll``); this only builds a
    size-class-matched chaff packet for the scheduler to send in a free slot.
    """
    return shaper.make_chaff_padded(epoch_id)
