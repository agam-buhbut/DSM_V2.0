"""Tests for dsm.core.protocol — packet serialization, deserialization, fragments."""

import os
import struct
import unittest

from dsm.core.protocol import (
    OUTER_HEADER_SIZE,
    SIZE_CLASSES,
    Fragment,
    InnerPacket,
    OuterPacket,
    PacketType,
    pick_random_size_class,
)


class TestInnerPacket(unittest.TestCase):
    def test_roundtrip_data(self) -> None:
        pkt = InnerPacket(ptype=PacketType.DATA, epoch_id=0, payload=b"hello")
        raw = pkt.serialize()
        got = InnerPacket.deserialize(raw)
        self.assertEqual(got.ptype, PacketType.DATA)
        self.assertEqual(got.epoch_id, 0)
        self.assertEqual(got.payload, b"hello")

    def test_roundtrip_all_types(self) -> None:
        for pt in PacketType:
            pkt = InnerPacket(ptype=pt, epoch_id=2, payload=b"\x00\x01\x02")
            raw = pkt.serialize()
            got = InnerPacket.deserialize(raw)
            self.assertEqual(got.ptype, pt)
            self.assertEqual(got.epoch_id, 2)
            self.assertEqual(got.payload, b"\x00\x01\x02")

    def test_epoch_id_bits(self) -> None:
        # Audit M3: epoch_id widened to 4 bits (16 distinct values, was 4).
        for epoch_id in range(16):
            pkt = InnerPacket(ptype=PacketType.DATA, epoch_id=epoch_id, payload=b"x")
            raw = pkt.serialize()
            got = InnerPacket.deserialize(raw)
            self.assertEqual(got.epoch_id, epoch_id)

    def test_empty_payload(self) -> None:
        pkt = InnerPacket(ptype=PacketType.CHAFF, epoch_id=0, payload=b"")
        raw = pkt.serialize()
        got = InnerPacket.deserialize(raw)
        self.assertEqual(got.payload, b"")

    def test_inner_padding_ignored(self) -> None:
        pkt = InnerPacket(ptype=PacketType.DATA, epoch_id=0, payload=b"abc")
        raw = pkt.serialize() + os.urandom(50)  # trailing padding
        got = InnerPacket.deserialize(raw)
        self.assertEqual(got.payload, b"abc")

    def test_too_short_raises(self) -> None:
        with self.assertRaises(ValueError):
            InnerPacket.deserialize(b"\x00\x00")

    def test_unknown_type_raises(self) -> None:
        raw = struct.pack("!BBH", 0xFF, 0, 0)
        with self.assertRaises(ValueError):
            InnerPacket.deserialize(raw)

    def test_reserved_bits_raises(self) -> None:
        raw = struct.pack("!BBH", 0x00, 0x01, 0)  # reserved bit set
        with self.assertRaises(ValueError):
            InnerPacket.deserialize(raw)

    def test_inner_length_exceeds_data(self) -> None:
        raw = struct.pack("!BBH", 0x00, 0x00, 100)  # claims 100 bytes, has 0
        with self.assertRaises(ValueError):
            InnerPacket.deserialize(raw)

    def test_payload_too_large(self) -> None:
        pkt = InnerPacket(ptype=PacketType.DATA, epoch_id=0, payload=b"\x00" * 1501)
        with self.assertRaises(ValueError):
            pkt.serialize()

    def test_deserialize_payload_too_large(self) -> None:
        # Craft a raw packet with inner_len = 1501 (exceeds MAX_INNER_PAYLOAD)
        raw = struct.pack("!BBH", 0x00, 0x00, 1501) + b"\x00" * 1501
        with self.assertRaises(ValueError):
            InnerPacket.deserialize(raw)


class TestOuterPacket(unittest.TestCase):
    def test_serialize_roundtrip_length(self) -> None:
        ct = os.urandom(48)
        pkt = OuterPacket(seq=42, nonce=os.urandom(12), ciphertext=ct)
        wire = pkt.serialize()
        self.assertEqual(len(wire), OUTER_HEADER_SIZE + len(ct))

    def test_serialize_matches_explicit_target(self) -> None:
        ct = os.urandom(48)
        pkt = OuterPacket(seq=1, nonce=os.urandom(12), ciphertext=ct)
        wire = pkt.serialize(target_size=OUTER_HEADER_SIZE + len(ct))
        self.assertEqual(len(wire), OUTER_HEADER_SIZE + len(ct))

    def test_target_size_mismatch_raises(self) -> None:
        # Sizing is the shaper's responsibility; OuterPacket must not silently
        # pad with unauthenticated bytes to reach a larger target.
        ct = os.urandom(200)
        pkt = OuterPacket(seq=1, nonce=os.urandom(12), ciphertext=ct)
        with self.assertRaises(ValueError):
            pkt.serialize(target_size=10)
        with self.assertRaises(ValueError):
            pkt.serialize(target_size=OUTER_HEADER_SIZE + len(ct) + 32)


class TestFragment(unittest.TestCase):
    def test_roundtrip(self) -> None:
        frag = Fragment(fragment_id=1234, index=2, total=5, data=b"frag data")
        raw = frag.serialize()
        got = Fragment.deserialize(raw)
        self.assertEqual(got.fragment_id, 1234)
        self.assertEqual(got.index, 2)
        self.assertEqual(got.total, 5)
        self.assertEqual(got.data, b"frag data")

    def test_too_short(self) -> None:
        with self.assertRaises(ValueError):
            Fragment.deserialize(b"\x00\x01")

    def test_zero_total(self) -> None:
        raw = struct.pack("!HBB", 1, 0, 0) + b"data"
        with self.assertRaises(ValueError):
            Fragment.deserialize(raw)

    def test_index_ge_total(self) -> None:
        raw = struct.pack("!HBB", 1, 5, 5) + b"data"
        with self.assertRaises(ValueError):
            Fragment.deserialize(raw)


class TestSizeClasses(unittest.TestCase):
    def test_random_size_class_in_range(self) -> None:
        for _ in range(100):
            sc = pick_random_size_class()
            self.assertIn(sc, SIZE_CLASSES)


if __name__ == "__main__":
    unittest.main()
