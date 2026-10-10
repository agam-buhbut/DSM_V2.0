"""DSM packet format: serialization and deserialization.

Outer packet, wire v2 (what a watcher sees):
    [Header block: 16 bytes] AES-256 of seq(8) ‖ epoch(4) ‖ counter(4),
                             under this direction's header key
    [Nonce tail: 4 bytes]    the random part of the AES-GCM nonce
    [Ciphertext + GCM Tag: variable]
Only tuncore builds and reads it (``SessionKeyManager.seal_packet`` /
``open_packet``). The AES-GCM nonce is epoch ‖ counter ‖ tail; AAD = seq
(8 bytes). Size-class padding sits inside the AEAD (inner padding).

Inner plaintext (after AEAD decryption):
    [Type: 1 byte][Epoch|Flags: 1 byte][Inner Length: 2 bytes][Payload][Inner Padding]

Inner types: every version drops an inner packet whose type it does not
know, quietly (one DEBUG line, no error count, no teardown). Newer versions
rely on this rule to add a type without a version bump, so changes to
``InnerPacket.deserialize`` must keep it.

LINK_REPORT (0x0A) payload, for the sender's slow-link auto cap:
    [highest_seq: 8 bytes][received: 8 bytes]
Unsigned 64-bit big-endian totals since the session started: the highest
authenticated seq received, and how many authenticated packets arrived.
Readers take the first 16 bytes and ignore the rest, so later versions can
append fields; a shorter payload is dropped.
"""

from __future__ import annotations

import logging
import struct
import time
from dataclasses import dataclass, field
from enum import IntEnum

import tuncore

log = logging.getLogger(__name__)

# Outer header: 16 (protected block) + 4 (random nonce tail) = 20 bytes
OUTER_HEADER_SIZE = 20
# Inner header: 1 (type) + 1 (flags) + 2 (inner_length) = 4 bytes
INNER_HEADER_SIZE = 4
# AES-GCM authentication tag
GCM_TAG_SIZE = 16
# Maximum inner payload size (MTU-based practical limit)
MAX_INNER_PAYLOAD = 1500

# Packet size classes for padding (bytes) and their draw weights (a typical
# web-traffic mix: smaller packets likelier). The Rust shaper core owns the
# one copy; these names re-export it for the rest of dsm.
SIZE_CLASSES: tuple[int, ...] = tuncore.SIZE_CLASSES
SIZE_CLASS_WEIGHTS: tuple[int, ...] = tuncore.SIZE_CLASS_WEIGHTS

# Module-level Struct instances — avoid per-packet format-string parsing on
# the hot path. `pack_into` writes into a caller-owned buffer, saving an
# intermediate bytes allocation per serialize.
INNER_STRUCT = struct.Struct("!BBH")
SEQ_STRUCT = struct.Struct("!Q")
FRAG_STRUCT = struct.Struct("!HBB")

# The wire version in the Noise prologue: builds of different versions refuse
# each other at the handshake. tuncore owns the one copy.
WIRE_VERSION: int = tuncore.WIRE_VERSION


class PacketType(IntEnum):
    DATA = 0x00
    REKEY_INIT = 0x02
    REKEY_ACK = 0x03
    CHAFF = 0x04
    KEEPALIVE = 0x05
    SESSION_CLOSE = 0x06
    FRAGMENT = 0x07
    # QUIC-style return-routability check for server egress roaming.
    # Both authenticated (inside AEAD); each carries a 16-byte token.
    PATH_CHALLENGE = 0x08
    PATH_RESPONSE = 0x09
    # Receiver loss report for the sender's slow-link auto cap
    # (dsm/traffic/autocap.py); layout in the module docstring. 0x01 stays
    # unused: it was the old HANDSHAKE type, and reusing it could confuse a
    # very old build.
    LINK_REPORT = 0x0A


# Return-routability token: 128 bits of CSPRNG entropy is unguessable by an
# on-path attacker who must echo it back from a spoofed (and unreachable to
# them) source address. The token rides inside the AEAD envelope.
PATH_TOKEN_SIZE = 16

# LINK_REPORT payload: highest_seq, received (see the module docstring).
LINK_REPORT_STRUCT = struct.Struct("!QQ")


@dataclass(slots=True, frozen=True)
class LinkReport:
    """What the receiver has seen so far in this session."""

    highest_seq: int
    received: int

    def serialize(self) -> bytes:
        return LINK_REPORT_STRUCT.pack(self.highest_seq, self.received)

    @classmethod
    def deserialize(cls, payload: bytes) -> LinkReport:
        """Read the first 16 bytes of ``payload``; later bytes are ignored.

        Raises:
            ValueError: ``payload`` is shorter than 16 bytes.
        """
        if len(payload) < LINK_REPORT_STRUCT.size:
            raise ValueError(f"link report too short: {len(payload)} bytes")
        highest_seq, received = LINK_REPORT_STRUCT.unpack_from(payload)
        return cls(highest_seq=highest_seq, received=received)


@dataclass(slots=True)
class InnerPacket:
    """Decrypted inner packet."""

    ptype: PacketType
    epoch_id: int  # 4-bit epoch identifier (0-15) — extended from 2-bit
    payload: bytes

    def serialize(self) -> bytes:
        """Serialize to inner plaintext format.

        epoch_id occupies the top nibble of the flags byte (4 bits, 16
        rotations ~= 2.6 h at default cadence). A 2-bit field would recycle
        every 4 rotations, so a captured packet could land in the same
        epoch_id slot again within one session.
        """
        flags = (self.epoch_id & 0x0F) << 4
        inner_len = len(self.payload)
        if inner_len > MAX_INNER_PAYLOAD:
            raise ValueError(f"payload too large: {inner_len} > {MAX_INNER_PAYLOAD}")
        buf = bytearray(INNER_HEADER_SIZE + inner_len)
        INNER_STRUCT.pack_into(buf, 0, self.ptype, flags, inner_len)
        buf[INNER_HEADER_SIZE:] = self.payload
        return bytes(buf)

    @classmethod
    def deserialize(cls, data: bytes) -> InnerPacket:
        if len(data) < INNER_HEADER_SIZE:
            raise ValueError("inner packet too short")
        ptype_raw, flags, inner_len = INNER_STRUCT.unpack_from(data)
        try:
            ptype = PacketType(ptype_raw)
        except ValueError:
            raise ValueError(f"unknown packet type: {ptype_raw:#x}")
        epoch_id = (flags >> 4) & 0x0F
        if flags & 0x0F:
            raise ValueError(f"reserved flag bits set: {flags:#x}")
        if inner_len > MAX_INNER_PAYLOAD:
            raise ValueError(
                f"inner payload too large: {inner_len} > {MAX_INNER_PAYLOAD}"
            )
        payload_end = INNER_HEADER_SIZE + inner_len
        if payload_end > len(data):
            raise ValueError("inner length exceeds data")
        payload = data[INNER_HEADER_SIZE:payload_end]
        # Remaining bytes are inner padding — ignored
        return cls(ptype=ptype, epoch_id=epoch_id, payload=payload)


# Fragment format within inner payload (Type=FRAGMENT):
# [Fragment ID: 2 bytes][Fragment Index: 1 byte][Total Fragments: 1 byte][Fragment Data]

FRAGMENT_HEADER_SIZE = 4
MAX_FRAGMENTS = 16


@dataclass(slots=True)
class Fragment:
    fragment_id: int  # 16-bit
    index: int  # 0-based
    total: int
    data: bytes

    def serialize(self) -> bytes:
        buf = bytearray(FRAGMENT_HEADER_SIZE + len(self.data))
        FRAG_STRUCT.pack_into(buf, 0, self.fragment_id, self.index, self.total)
        buf[FRAGMENT_HEADER_SIZE:] = self.data
        return bytes(buf)

    @classmethod
    def deserialize(cls, payload: bytes) -> Fragment:
        if len(payload) < FRAGMENT_HEADER_SIZE:
            raise ValueError("fragment too short")
        fid, idx, total = FRAG_STRUCT.unpack_from(payload)
        if total == 0 or total > MAX_FRAGMENTS:
            raise ValueError(f"invalid total fragments: {total}")
        if idx >= total:
            raise ValueError(f"fragment index {idx} >= total {total}")
        data = payload[FRAGMENT_HEADER_SIZE:]
        return cls(fragment_id=fid, index=idx, total=total, data=data)


# Largest inner payload that fits on the wire inside the MAX size class
# without spilling past a 1400B outer packet. Used both to decide when a
# packet MUST be fragmented and as the per-fragment chunk size bound.
#
#     max outer (1400) - outer header (20) - GCM tag (16) - inner header (4)
#   = 1360 bytes of inner payload.
MAX_INNER_PAYLOAD_ON_WIRE = (
    SIZE_CLASSES[-1] - OUTER_HEADER_SIZE - GCM_TAG_SIZE - INNER_HEADER_SIZE
)

# Per-fragment data budget: one more header (the Fragment struct) shaves
# 4 bytes off the inner budget.
MAX_FRAGMENT_DATA = MAX_INNER_PAYLOAD_ON_WIRE - FRAGMENT_HEADER_SIZE

# Max IP packet the send side can handle: 16 fragments × max fragment data.
MAX_FRAGMENTABLE_PACKET = MAX_FRAGMENTS * MAX_FRAGMENT_DATA


def fragment_ip_packet(
    packet: bytes,
    epoch_id: int,
    fragment_id: int,
) -> list[InnerPacket]:
    """Split an IP packet into FRAGMENT inner packets if it doesn't fit
    on the wire in a single size-class outer. Packets that fit are
    returned as a single DATA inner — no fragment envelope overhead on
    the common path.

    The receiver reassembles via ``ReassemblyBuffer``. All fragments
    carry the same ``fragment_id`` and sequential ``index`` values
    (0..total-1).

    Raises ``ValueError`` when the packet is larger than the protocol's
    max fragmentable size (see ``MAX_FRAGMENTABLE_PACKET``).
    """
    if len(packet) <= MAX_INNER_PAYLOAD_ON_WIRE:
        return [InnerPacket(ptype=PacketType.DATA, epoch_id=epoch_id, payload=packet)]

    total = (len(packet) + MAX_FRAGMENT_DATA - 1) // MAX_FRAGMENT_DATA
    if total > MAX_FRAGMENTS:
        raise ValueError(
            f"packet too large to fragment: {len(packet)} bytes "
            f"({total} fragments > cap {MAX_FRAGMENTS})"
        )

    fid = fragment_id & 0xFFFF
    out: list[InnerPacket] = []
    for i in range(total):
        chunk = packet[i * MAX_FRAGMENT_DATA : (i + 1) * MAX_FRAGMENT_DATA]
        frag = Fragment(fragment_id=fid, index=i, total=total, data=chunk)
        out.append(
            InnerPacket(
                ptype=PacketType.FRAGMENT,
                epoch_id=epoch_id,
                payload=frag.serialize(),
            )
        )
    return out


REASSEMBLY_MAX_PENDING = 256
REASSEMBLY_TIMEOUT_S = 5.0


@dataclass
class _PendingReassembly:
    total: int
    received: dict[int, bytes] = field(default_factory=lambda: {})
    first_seen: float = field(default_factory=time.monotonic)


class ReassemblyBuffer:
    """Fragment reassembly with timeout and capacity limits.

    Prevents memory exhaustion from incomplete fragment sets (DoS) by
    capping pending entries and expiring stale ones.
    """

    def __init__(
        self,
        max_pending: int = REASSEMBLY_MAX_PENDING,
        timeout_s: float = REASSEMBLY_TIMEOUT_S,
    ) -> None:
        self._pending: dict[int, _PendingReassembly] = {}
        self._max_pending = max_pending
        self._timeout_s = timeout_s

    def add_fragment(self, frag: Fragment) -> bytes | None:
        """Add a fragment. Returns reassembled payload if complete, else None."""
        self._cleanup_expired()

        fid = frag.fragment_id

        if fid not in self._pending:
            if len(self._pending) >= self._max_pending:
                log.debug("reassembly buffer full, dropping fragment_id=%d", fid)
                return None
            self._pending[fid] = _PendingReassembly(total=frag.total)

        entry = self._pending[fid]

        if entry.total != frag.total:
            log.debug(
                "fragment total mismatch for id=%d: %d != %d",
                fid,
                frag.total,
                entry.total,
            )
            return None

        if frag.index in entry.received:
            return None

        # Defensive: an out-of-range index would later KeyError the
        # range(total) reassembly join below (a {0,1,5}-for-total-3 set can
        # reach len == total). Unreachable from the wire (deserialize bounds
        # index < total), but guard explicitly so a malformed in-process
        # fragment fails closed (drop) rather than raising.
        if not 0 <= frag.index < entry.total:
            return None

        entry.received[frag.index] = frag.data

        if len(entry.received) == entry.total:
            payload = b"".join(entry.received[i] for i in range(entry.total))
            del self._pending[fid]
            return payload

        return None

    def _cleanup_expired(self) -> None:
        now = time.monotonic()
        expired = [
            fid
            for fid, e in self._pending.items()
            if now - e.first_seen > self._timeout_s
        ]
        for fid in expired:
            log.debug("reassembly timeout for fragment_id=%d", fid)
            del self._pending[fid]
