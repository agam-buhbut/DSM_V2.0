"""Tests for dsm.core.protocol — packet serialization, deserialization, fragments."""

import os
import struct
import unittest

from dsm.core.protocol import (
    FRAGMENT_HEADER_SIZE,
    GCM_TAG_SIZE,
    INNER_HEADER_SIZE,
    OUTER_HEADER_SIZE,
    SIZE_CLASSES,
    Fragment,
    InnerPacket,
    OuterPacket,
    PacketType,
    _pick_size_class,
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
        for epoch_id in range(4):
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
    def test_roundtrip(self) -> None:
        ct = os.urandom(48)
        pkt = OuterPacket(seq=42, nonce=os.urandom(12), ciphertext=ct)
        wire = pkt.serialize()
        got = OuterPacket.deserialize(wire, ciphertext_len=len(ct))
        self.assertEqual(got.seq, 42)
        self.assertEqual(got.nonce, pkt.nonce)
        self.assertEqual(got.ciphertext, ct)

    def test_serialize_picks_size_class(self) -> None:
        ct = os.urandom(20)
        pkt = OuterPacket(seq=1, nonce=os.urandom(12), ciphertext=ct)
        wire = pkt.serialize()
        self.assertIn(len(wire), SIZE_CLASSES)

    def test_target_size_too_small(self) -> None:
        ct = os.urandom(200)
        pkt = OuterPacket(seq=1, nonce=os.urandom(12), ciphertext=ct)
        with self.assertRaises(ValueError):
            pkt.serialize(target_size=10)

    def test_too_short_deserialize(self) -> None:
        with self.assertRaises(ValueError):
            OuterPacket.deserialize(b"\x00" * 10, ciphertext_len=5)

    def test_aad_format(self) -> None:
        pkt = OuterPacket(seq=123, nonce=b"\x00" * 12, ciphertext=b"")
        aad = pkt.aad()
        self.assertEqual(len(aad), 8)  # AAD = seq only (nonce bound as GCM IV)
        seq_from_aad = struct.unpack("!Q", aad)[0]
        self.assertEqual(seq_from_aad, 123)


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
    def test_pick_smallest(self) -> None:
        self.assertEqual(_pick_size_class(50), 128)

    def test_pick_exact(self) -> None:
        self.assertEqual(_pick_size_class(256), 256)

    def test_pick_larger_than_all(self) -> None:
        result = _pick_size_class(2000)
        self.assertGreaterEqual(result, 2000)

    def test_random_size_class_in_range(self) -> None:
        for _ in range(100):
            sc = pick_random_size_class()
            self.assertIn(sc, SIZE_CLASSES)


if __name__ == "__main__":
    unittest.main()
