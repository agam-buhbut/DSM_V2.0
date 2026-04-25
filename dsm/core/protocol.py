"""DSM packet format: serialization and deserialization.

Outer packet (visible to observer):
    [Sequence Number: 8 bytes][Nonce: 12 bytes][Ciphertext + GCM Tag: variable][Random Padding]

Inner plaintext (after AEAD decryption):
    [Type: 1 byte][Epoch|Flags: 1 byte][Inner Length: 2 bytes][Payload][Inner Padding]

AAD = sequence number (8 bytes).  Nonce is bound as the GCM IV.
"""

from __future__ import annotations

import logging
import secrets
import struct
import time
from dataclasses import dataclass, field
from enum import IntEnum

log = logging.getLogger(__name__)

# Outer header: 8 (seq) + 12 (nonce) = 20 bytes
OUTER_HEADER_SIZE = 20
# Inner header: 1 (type) + 1 (flags) + 2 (inner_length) = 4 bytes
INNER_HEADER_SIZE = 4
# AES-GCM authentication tag
GCM_TAG_SIZE = 16
# Maximum inner payload size (MTU-based practical limit)
MAX_INNER_PAYLOAD = 1500

# Packet size classes for padding (bytes) — more classes reduce fingerprinting
SIZE_CLASSES = (128, 256, 384, 512, 640, 768, 896, 1024, 1152, 1280, 1400)

# Module-level Struct instances — avoid per-packet format-string parsing on
# the hot path. `pack_into` writes into a caller-owned buffer, saving an
# intermediate bytes allocation per serialize.
INNER_STRUCT = struct.Struct("!BBH")
SEQ_STRUCT = struct.Struct("!Q")
FRAG_STRUCT = struct.Struct("!HBB")


class PacketType(IntEnum):
    DATA = 0x00
    HANDSHAKE = 0x01
    REKEY_INIT = 0x02
    REKEY_ACK = 0x03
    CHAFF = 0x04
    KEEPALIVE = 0x05
    SESSION_CLOSE = 0x06
    FRAGMENT = 0x07


@dataclass(slots=True)
class InnerPacket:
    """Decrypted inner packet."""

    ptype: PacketType
    epoch_id: int  # 2-bit epoch identifier (0-3), replaces single bool
    payload: bytes

    def serialize(self) -> bytes:
        """Serialize to inner plaintext format."""
        flags = (self.epoch_id & 0x03) << 6  # 2 MSBs = epoch_id
        inner_len = len(self.payload)
        if inner_len > MAX_INNER_PAYLOAD:
            raise ValueError(f"payload too large: {inner_len} > {MAX_INNER_PAYLOAD}")
        buf = bytearray(INNER_HEADER_SIZE + inner_len)
        INNER_STRUCT.pack_into(buf, 0, self.ptype, flags, inner_len)
        buf[INNER_HEADER_SIZE:] = self.payload
        return bytes(buf)

    @classmethod
    def deserialize(cls, data: bytes) -> InnerPacket:
        """Deserialize from inner plaintext."""
        if len(data) < INNER_HEADER_SIZE:
            raise ValueError("inner packet too short")
        ptype_raw, flags, inner_len = INNER_STRUCT.unpack_from(data)
        try:
            ptype = PacketType(ptype_raw)
        except ValueError:
            raise ValueError(f"unknown packet type: {ptype_raw:#x}")
        epoch_id = (flags >> 6) & 0x03
        # Reserved bits (lower 6) must be zero
        if flags & 0x3F:
            raise ValueError(f"reserved flag bits set: {flags:#x}")
        if inner_len > MAX_INNER_PAYLOAD:
            raise ValueError(f"inner payload too large: {inner_len} > {MAX_INNER_PAYLOAD}")
        payload_end = INNER_HEADER_SIZE + inner_len
        if payload_end > len(data):
            raise ValueError("inner length exceeds data")
        payload = data[INNER_HEADER_SIZE:payload_end]
        # Remaining bytes are inner padding — ignored
        return cls(ptype=ptype, epoch_id=epoch_id, payload=payload)


@dataclass(slots=True)
class OuterPacket:
    """Wire-format outer packet."""

    seq: int  # 64-bit sequence number
    nonce: bytes  # 12 bytes
    ciphertext: bytes  # includes GCM tag

    def serialize(self, target_size: int | None = None) -> bytes:
        """Serialize to wire format: header || ciphertext.

        Callers that want size-class shaping must size the ciphertext (via
        inner padding inside the AEAD envelope) so the wire output lands on
        the desired size. Outer padding is never added here because it would
        be unauthenticated and would be included by the receiver in the
        ciphertext passed to AEAD, breaking tag validation.

        If `target_size` is supplied, the final wire length must equal it;
        any mismatch means inner-padding sizing is wrong and is reported as
        a programming error rather than silently papered over.
        """
        wire_size = OUTER_HEADER_SIZE + len(self.ciphertext)

        if target_size is not None and target_size != wire_size:
            raise ValueError(
                f"ciphertext sizing mismatch: wire={wire_size}, target={target_size}"
            )
        buf = bytearray(wire_size)
        SEQ_STRUCT.pack_into(buf, 0, self.seq)
        buf[8:OUTER_HEADER_SIZE] = self.nonce
        buf[OUTER_HEADER_SIZE:] = self.ciphertext
        return bytes(buf)

    @classmethod
    def deserialize(cls, data: bytes, ciphertext_len: int) -> OuterPacket:
        """Deserialize from wire format.

        ciphertext_len is needed because outer padding is unauthenticated
        and we need to know where ciphertext ends.
        The ciphertext length = inner_plaintext_size + GCM_TAG_SIZE.
        In practice, this is total_packet_size - OUTER_HEADER_SIZE - outer_padding.
        The receiver computes this from the encrypted inner_length field after
        decryption, or uses the full remaining bytes and lets GCM reject if wrong.
        """
        if len(data) < OUTER_HEADER_SIZE:
            raise ValueError("outer packet too short")
        seq = SEQ_STRUCT.unpack_from(data)[0]
        nonce = data[8:20]
        ct_end = OUTER_HEADER_SIZE + ciphertext_len
        if ct_end > len(data):
            raise ValueError("ciphertext_len exceeds packet")
        ciphertext = data[OUTER_HEADER_SIZE:ct_end]
        return cls(seq=seq, nonce=nonce, ciphertext=ciphertext)

    def aad(self) -> bytes:
        """Return the Additional Authenticated Data for this packet.

        AAD = sequence number (8 bytes).  The nonce is NOT included
        because it is inherently bound as the GCM IV — including it
        in AAD would be redundant.  This matches the actual AAD
        construction in session.py encrypt/decrypt paths.
        """
        return SEQ_STRUCT.pack(self.seq)


def pick_random_size_class() -> int:
    """Pick a random size class weighted toward smaller packets."""
    # Weights approximate typical web traffic distribution (11 classes)
    weights = (20, 15, 12, 10, 8, 7, 6, 6, 5, 6, 5)
    if len(weights) != len(SIZE_CLASSES):
        raise ValueError("weights must match SIZE_CLASSES")
    total = sum(weights)
    r = secrets.randbelow(total)
    cumulative = 0
    for sc, w in zip(SIZE_CLASSES, weights):
        cumulative += w
        if r < cumulative:
            return sc
    return SIZE_CLASSES[-1]


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
MAX_INNER_PAYLOAD_ON_WIRE = SIZE_CLASSES[-1] - OUTER_HEADER_SIZE - GCM_TAG_SIZE - INNER_HEADER_SIZE

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
        out.append(InnerPacket(
            ptype=PacketType.FRAGMENT,
            epoch_id=epoch_id,
            payload=frag.serialize(),
        ))
    return out


# ── Fragment reassembly ──

REASSEMBLY_MAX_PENDING = 256
REASSEMBLY_TIMEOUT_S = 5.0


@dataclass
class _PendingReassembly:
    """Tracks fragments for a single fragment_id."""
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

        # Validate consistency
        if entry.total != frag.total:
            log.debug("fragment total mismatch for id=%d: %d != %d", fid, frag.total, entry.total)
            return None

        # Duplicate check
        if frag.index in entry.received:
            return None

        entry.received[frag.index] = frag.data

        # Check if complete
        if len(entry.received) == entry.total:
            payload = b"".join(entry.received[i] for i in range(entry.total))
            del self._pending[fid]
            return payload

        return None

    def _cleanup_expired(self) -> None:
        """Remove entries that have timed out."""
        now = time.monotonic()
        expired = [
            fid for fid, e in self._pending.items()
            if now - e.first_seen > self._timeout_s
        ]
        for fid in expired:
            log.debug("reassembly timeout for fragment_id=%d", fid)
            del self._pending[fid]
