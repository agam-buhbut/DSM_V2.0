"""Tests for dsm.crypto.handshake framing helpers."""

import unittest

from dsm.crypto.handshake import (
    HANDSHAKE_FRAME_SIZE,
    HandshakeError,
    _pad_handshake,
    _unpad_handshake,
)


class TestHandshakePadding(unittest.TestCase):
    def test_pad_produces_fixed_size(self) -> None:
        for n in (0, 1, 32, 96, 1398):
            framed = _pad_handshake(b"x" * n)
            self.assertEqual(len(framed), HANDSHAKE_FRAME_SIZE)

    def test_round_trip(self) -> None:
        for payload in (b"", b"abc", b"\x00" * 64, b"y" * 1398):
            self.assertEqual(_unpad_handshake(_pad_handshake(payload)), payload)

    def test_oversize_payload_rejected(self) -> None:
        too_big = b"z" * (HANDSHAKE_FRAME_SIZE - 1)
        with self.assertRaises(HandshakeError):
            _pad_handshake(too_big)

    def test_wrong_frame_size_rejected(self) -> None:
        with self.assertRaises(HandshakeError):
            _unpad_handshake(b"x" * (HANDSHAKE_FRAME_SIZE - 1))
        with self.assertRaises(HandshakeError):
            _unpad_handshake(b"x" * (HANDSHAKE_FRAME_SIZE + 1))

    def test_length_prefix_out_of_range_rejected(self) -> None:
        bad = (HANDSHAKE_FRAME_SIZE).to_bytes(2, "big") + b"\x00" * (HANDSHAKE_FRAME_SIZE - 2)
        with self.assertRaises(HandshakeError):
            _unpad_handshake(bad)


if __name__ == "__main__":
    unittest.main()
