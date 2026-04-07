"""DSM packet format: serialization and deserialization.

Outer packet (visible to observer):
    [Sequence Number: 8 bytes][Nonce: 12 bytes][Ciphertext + GCM Tag: variable][Random Padding]

Inner plaintext (after AEAD decryption):
    [Type: 1 byte][Epoch|Flags: 1 byte][Inner Length: 2 bytes][Payload][Inner Padding]

AAD = outer header (seq + nonce, 20 bytes).
"""

from __future__ import annotations

import logging
import os
import struct
from dataclasses import dataclass
from enum import IntEnum

log = logging.getLogger(__name__)

# Outer header: 8 (seq) + 12 (nonce) = 20 bytes
OUTER_HEADER_SIZE = 20
# Inner header: 1 (type) + 1 (flags) + 2 (inner_length) = 4 bytes
INNER_HEADER_SIZE = 4
# AES-GCM authentication tag
GCM_TAG_SIZE = 16

# Packet size classes for padding (bytes) — more classes reduce fingerprinting
SIZE_CLASSES = (128, 256, 384, 512, 640, 768, 896, 1024, 1152, 1280, 1400)


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
        if inner_len > 0xFFFF:
            raise ValueError(f"payload too large: {inner_len}")
        header = struct.pack("!BBH", self.ptype, flags, inner_len)
        return header + self.payload

    @classmethod
    def deserialize(cls, data: bytes) -> InnerPacket:
        """Deserialize from inner plaintext."""
        if len(data) < INNER_HEADER_SIZE:
            raise ValueError("inner packet too short")
        ptype_raw, flags, inner_len = struct.unpack("!BBH", data[:INNER_HEADER_SIZE])
        try:
            ptype = PacketType(ptype_raw)
        except ValueError:
            raise ValueError(f"unknown packet type: {ptype_raw:#x}")
        epoch_id = (flags >> 6) & 0x03
        # Reserved bits (lower 6) must be zero
        if flags & 0x3F:
            raise ValueError(f"reserved flag bits set: {flags:#x}")
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
        """Serialize with random outer padding to target_size.

        If target_size is None, picks the smallest size class that fits.
        """
        header = struct.pack("!Q", self.seq) + self.nonce
        min_size = len(header) + len(self.ciphertext)

        if target_size is None:
            target_size = _pick_size_class(min_size)

        if target_size < min_size:
            raise ValueError(
                f"target_size {target_size} too small for {min_size} bytes"
            )

        pad_len = target_size - min_size
        # Invariant: inner padding should size ciphertext to exactly fill the
        # target, leaving no outer padding. If pad_len > 0, the receiver will
        # pass ciphertext+padding to decrypt, which breaks GCM tag validation.
        if pad_len > 0:
            log.warning("outer padding %d bytes — inner padding sizing mismatch", pad_len)
        padding = os.urandom(pad_len)
        return header + self.ciphertext + padding

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
        seq = struct.unpack("!Q", data[:8])[0]
        nonce = data[8:20]
        ct_end = OUTER_HEADER_SIZE + ciphertext_len
        if ct_end > len(data):
            raise ValueError("ciphertext_len exceeds packet")
        ciphertext = data[OUTER_HEADER_SIZE:ct_end]
        return cls(seq=seq, nonce=nonce, ciphertext=ciphertext)

    def aad(self) -> bytes:
        """Return the Additional Authenticated Data (outer header).

        NOTE: Currently unused — snow's transport mode does not accept AAD.
        The outer header (seq + nonce) is not bound to the AEAD ciphertext.
        Noise's internal nonce tracking provides replay protection independently.
        Retained for future use if transport switches to raw AES-GCM with AAD.
        """
        return struct.pack("!Q", self.seq) + self.nonce


def _pick_size_class(min_size: int) -> int:
    """Pick the smallest size class that can hold the data."""
    for sc in SIZE_CLASSES:
        if sc >= min_size:
            return sc
    return max(min_size, SIZE_CLASSES[-1])


def pick_random_size_class() -> int:
    """Pick a random size class weighted toward smaller packets."""
    # Weights approximate typical web traffic distribution (11 classes)
    weights = (20, 15, 12, 10, 8, 7, 6, 6, 5, 6, 5)
    if len(weights) != len(SIZE_CLASSES):
        raise ValueError("weights must match SIZE_CLASSES")
    total = sum(weights)
    r = int.from_bytes(os.urandom(4), "big") % total
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
        return struct.pack("!HBB", self.fragment_id, self.index, self.total) + self.data

    @classmethod
    def deserialize(cls, payload: bytes) -> Fragment:
        if len(payload) < FRAGMENT_HEADER_SIZE:
            raise ValueError("fragment too short")
        fid, idx, total = struct.unpack("!HBB", payload[:FRAGMENT_HEADER_SIZE])
        if total == 0 or total > MAX_FRAGMENTS:
            raise ValueError(f"invalid total fragments: {total}")
        if idx >= total:
            raise ValueError(f"fragment index {idx} >= total {total}")
        data = payload[FRAGMENT_HEADER_SIZE:]
        return cls(fragment_id=fid, index=idx, total=total, data=data)
