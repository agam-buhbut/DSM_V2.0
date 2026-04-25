"""Tests for dsm.crypto.handshake framing helpers.

Noise XX messages are pre-padded by the Rust side; the Python helpers
tested here only frame the *bootstrap* messages (post-handshake ephemeral
DH exchange), which are ciphertexts of a fixed, protocol-known size.
"""

import unittest

from dsm.crypto.handshake import (
    BOOTSTRAP_CIPHERTEXT_SIZE,
    HANDSHAKE_FRAME_SIZE,
    HandshakeError,
    _pad_to_frame,
    _unpad_from_frame,
)


class TestHandshakeFraming(unittest.TestCase):
    def test_pad_produces_fixed_size(self) -> None:
        ct = b"x" * BOOTSTRAP_CIPHERTEXT_SIZE
        framed = _pad_to_frame(ct, BOOTSTRAP_CIPHERTEXT_SIZE)
        self.assertEqual(len(framed), HANDSHAKE_FRAME_SIZE)

    def test_pad_preserves_prefix(self) -> None:
        ct = b"y" * BOOTSTRAP_CIPHERTEXT_SIZE
        framed = _pad_to_frame(ct, BOOTSTRAP_CIPHERTEXT_SIZE)
        self.assertEqual(framed[:BOOTSTRAP_CIPHERTEXT_SIZE], ct)

    def test_round_trip(self) -> None:
        ct = bytes(range(BOOTSTRAP_CIPHERTEXT_SIZE))
        framed = _pad_to_frame(ct, BOOTSTRAP_CIPHERTEXT_SIZE)
        self.assertEqual(_unpad_from_frame(framed, BOOTSTRAP_CIPHERTEXT_SIZE), ct)

    def test_wrong_payload_size_rejected(self) -> None:
        # Caller passed a ct that's a different size than the protocol expects.
        with self.assertRaises(HandshakeError):
            _pad_to_frame(b"x" * (BOOTSTRAP_CIPHERTEXT_SIZE - 1), BOOTSTRAP_CIPHERTEXT_SIZE)
        with self.assertRaises(HandshakeError):
            _pad_to_frame(b"x" * (BOOTSTRAP_CIPHERTEXT_SIZE + 1), BOOTSTRAP_CIPHERTEXT_SIZE)

    def test_wrong_frame_size_rejected(self) -> None:
        with self.assertRaises(HandshakeError):
            _unpad_from_frame(b"x" * (HANDSHAKE_FRAME_SIZE - 1), BOOTSTRAP_CIPHERTEXT_SIZE)
        with self.assertRaises(HandshakeError):
            _unpad_from_frame(b"x" * (HANDSHAKE_FRAME_SIZE + 1), BOOTSTRAP_CIPHERTEXT_SIZE)


if __name__ == "__main__":
    unittest.main()
