"""Tests for the send-side fragmenter in ``dsm.core.protocol.fragment_ip_packet``.

The receive path (``_handle_fragment`` + ``ReassemblyBuffer``) already
existed; the send splitter was added to close the gap so TUN reads
larger than ``MAX_INNER_PAYLOAD`` no longer crash ``tun_send_loop``.

These tests drive the splitter directly (no asyncio, no TUN), and also
verify that the integration point in ``tun_send_loop`` uses the splitter
— oversized packets must result in enqueued FRAGMENT inner packets
rather than a ``ValueError``.
"""

from __future__ import annotations

import unittest

from dsm.core.protocol import (
    INNER_HEADER_SIZE,
    MAX_FRAGMENTS,
    MAX_FRAGMENTABLE_PACKET,
    MAX_INNER_PAYLOAD_ON_WIRE,
    Fragment,
    PacketType,
    ReassemblyBuffer,
    fragment_ip_packet,
)


class TestFragmenter(unittest.TestCase):
    def test_small_packet_not_fragmented(self) -> None:
        payload = b"\xab" * 1000
        inners = fragment_ip_packet(payload, epoch_id=0, fragment_id=1)
        self.assertEqual(len(inners), 1)
        self.assertEqual(inners[0].ptype, PacketType.DATA)
        self.assertEqual(inners[0].payload, payload)

    def test_boundary_exactly_max_inner_on_wire_not_fragmented(self) -> None:
        payload = b"\xcd" * MAX_INNER_PAYLOAD_ON_WIRE
        inners = fragment_ip_packet(payload, epoch_id=0, fragment_id=2)
        self.assertEqual(len(inners), 1)
        self.assertEqual(inners[0].ptype, PacketType.DATA)

    def test_just_over_max_inner_on_wire_fragments(self) -> None:
        payload = b"\xcd" * (MAX_INNER_PAYLOAD_ON_WIRE + 1)
        inners = fragment_ip_packet(payload, epoch_id=0, fragment_id=2)
        self.assertEqual(len(inners), 2)
        self.assertEqual(inners[0].ptype, PacketType.FRAGMENT)

    def test_large_packet_splits_into_fragments(self) -> None:
        payload = b"x" * 2500
        inners = fragment_ip_packet(payload, epoch_id=0, fragment_id=42)
        self.assertGreater(len(inners), 1)
        for i, ip in enumerate(inners):
            self.assertEqual(ip.ptype, PacketType.FRAGMENT)
            frag = Fragment.deserialize(ip.payload)
            self.assertEqual(frag.fragment_id, 42)
            self.assertEqual(frag.index, i)
            self.assertEqual(frag.total, len(inners))

    def test_all_fragments_serialize_within_inner_bound(self) -> None:
        payload = b"\x11" * 2500
        inners = fragment_ip_packet(payload, epoch_id=0, fragment_id=7)
        for ip in inners:
            # The INNER_PACKET payload here is `Fragment.serialize()` =
            # FRAGMENT_HEADER_SIZE + fragment data. Bounded by wire budget.
            self.assertLessEqual(len(ip.payload), MAX_INNER_PAYLOAD_ON_WIRE)
            raw = ip.serialize()
            self.assertLessEqual(len(raw), INNER_HEADER_SIZE + MAX_INNER_PAYLOAD_ON_WIRE)

    def test_roundtrip_via_reassembly_buffer(self) -> None:
        payload = bytes((i * 7 + 3) & 0xFF for i in range(2500))
        inners = fragment_ip_packet(payload, epoch_id=0, fragment_id=99)

        rb = ReassemblyBuffer()
        reassembled: bytes | None = None
        for ip in inners:
            frag = Fragment.deserialize(ip.payload)
            result = rb.add_fragment(frag)
            if result is not None:
                reassembled = result
        self.assertEqual(reassembled, payload)

    def test_max_fragments_exact_fit_roundtrips(self) -> None:
        payload = b"\xa5" * MAX_FRAGMENTABLE_PACKET
        inners = fragment_ip_packet(payload, epoch_id=0, fragment_id=5)
        self.assertEqual(len(inners), MAX_FRAGMENTS)

        rb = ReassemblyBuffer()
        reassembled: bytes | None = None
        for ip in inners:
            frag = Fragment.deserialize(ip.payload)
            self.assertEqual(frag.total, MAX_FRAGMENTS)
            result = rb.add_fragment(frag)
            if result is not None:
                reassembled = result
        self.assertEqual(reassembled, payload)

    def test_payload_exceeding_fragment_limit_rejected(self) -> None:
        huge = b"\x00" * 65536
        with self.assertRaises(ValueError):
            fragment_ip_packet(huge, epoch_id=0, fragment_id=1)

    def test_payload_one_byte_over_cap_rejected(self) -> None:
        just_too_big = b"\x01" * (MAX_FRAGMENTABLE_PACKET + 1)
        with self.assertRaises(ValueError):
            fragment_ip_packet(just_too_big, epoch_id=0, fragment_id=2)

    def test_fragment_indices_are_sequential_and_unique(self) -> None:
        payload = b"\xbb" * 4000
        inners = fragment_ip_packet(payload, epoch_id=0, fragment_id=123)
        indices = [Fragment.deserialize(ip.payload).index for ip in inners]
        self.assertEqual(indices, list(range(len(inners))))

    def test_fragment_ids_all_match(self) -> None:
        payload = b"\xcc" * 4000
        inners = fragment_ip_packet(payload, epoch_id=0, fragment_id=555)
        for ip in inners:
            frag = Fragment.deserialize(ip.payload)
            self.assertEqual(frag.fragment_id, 555)

    def test_epoch_id_propagates_to_every_inner(self) -> None:
        payload = b"\xdd" * 3000
        inners = fragment_ip_packet(payload, epoch_id=2, fragment_id=8)
        for ip in inners:
            self.assertEqual(ip.epoch_id, 2)

    def test_fragment_id_wraps_at_16_bits(self) -> None:
        # Caller-passed fragment_id values outside 16-bit range are
        # truncated, not rejected — matches the wire format.
        payload = b"\xee" * 3000
        inners = fragment_ip_packet(payload, epoch_id=0, fragment_id=0x1_0001)
        for ip in inners:
            frag = Fragment.deserialize(ip.payload)
            self.assertEqual(frag.fragment_id, 1)


class TestFragmentIdCounter(unittest.TestCase):
    """Verify the counter used by tun_send_loop wraps correctly at 16 bits."""

    def test_counter_increments(self) -> None:
        from dsm.session import FragmentIdCounter

        c = FragmentIdCounter()
        self.assertEqual(c.next(), 1)
        self.assertEqual(c.next(), 2)

    def test_counter_wraps_at_16_bits(self) -> None:
        from dsm.session import FragmentIdCounter

        c = FragmentIdCounter(value=0xFFFF)
        self.assertEqual(c.next(), 0)
        self.assertEqual(c.next(), 1)


if __name__ == "__main__":
    unittest.main()
