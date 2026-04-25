"""Tests for the post-handshake ephemeral DH bootstrap primitives.

The bootstrap derives session keys from a SECRET ephemeral DH shared secret
(not the public handshake hash). These tests exercise the Rust primitives
``tuncore.bootstrap_session_from_dh`` and ``tuncore.generate_ephemeral``
plus the security checks on input (low-order point rejection, length checks).

The full end-to-end handshake (msg1..msg3 + bootstrap exchange over UDP)
is covered separately in ``tests/test_handshake_integration.py``.
"""

from __future__ import annotations

import unittest

try:
    import tuncore
    _HAS_TUNCORE = True
except ImportError:
    tuncore = None  # type: ignore[assignment]
    _HAS_TUNCORE = False


@unittest.skipUnless(_HAS_TUNCORE, "tuncore (Rust crypto core) not built; run `maturin develop` in rust/tuncore/")
class TestBootstrapSessionDH(unittest.TestCase):
    """Exercise tuncore.bootstrap_session_from_dh directly."""

    def test_bootstrap_roundtrip_encrypt_decrypt(self) -> None:
        """The core property: when both sides call bootstrap_session_from_dh
        with matching inputs (their own secret + peer's public) the resulting
        SessionKeyManagers produce interoperable encrypt/decrypt."""
        a_secret, a_public = tuncore.generate_ephemeral()
        b_secret, b_public = tuncore.generate_ephemeral()

        a_keys = tuncore.bootstrap_session_from_dh(
            bytes(a_secret), bytes(b_public), True
        )
        b_keys = tuncore.bootstrap_session_from_dh(
            bytes(b_secret), bytes(a_public), False
        )

        # A (initiator) sends -> B (responder) decrypts with is_prev_epoch=False.
        # tuncore.encrypt returns list[int] for Vec<u8>; decrypt wants PyBytes.
        # Seq starts at 1 to satisfy the replay window (see Rust test_from_handshake_hash_roundtrip).
        aad = b"\x00" * 8
        nonce, ct, _epoch = a_keys.encrypt(b"hello from initiator", aad)
        pt = b_keys.decrypt(bytes(nonce), bytes(ct), aad, 1, False)
        self.assertEqual(bytes(pt), b"hello from initiator")

        # B (responder) sends -> A (initiator) decrypts
        nonce2, ct2, _epoch2 = b_keys.encrypt(b"hello back", aad)
        pt2 = a_keys.decrypt(bytes(nonce2), bytes(ct2), aad, 1, False)
        self.assertEqual(bytes(pt2), b"hello back")

    def test_bootstrap_keys_differ_from_noise_transport(self) -> None:
        """Regression guard: verify that the bootstrap DH key material is
        different from whatever would come out of the Noise handshake hash
        alone. We can't directly compare keys (they're in mlock'd heap) but
        we can check that ciphertext produced with bootstrap keys cannot be
        decrypted with a SessionKeyManager derived from handshake hash."""
        a_secret, _a_public = tuncore.generate_ephemeral()
        _b_secret, b_public = tuncore.generate_ephemeral()

        bootstrap_keys = tuncore.bootstrap_session_from_dh(
            bytes(a_secret), bytes(b_public), True
        )

        # Build a SessionKeyManager the old way from some handshake hash.
        # from_handshake_hash requires 32+ bytes.
        fake_hash = b"\xAB" * 32
        hash_keys = tuncore.SessionKeyManager.from_handshake_hash(
            fake_hash, is_initiator=False
        )

        aad = b"\x00" * 8
        nonce, ct, _epoch = bootstrap_keys.encrypt(b"secret", aad)

        # The hash-based peer should NOT be able to decrypt the bootstrap
        # ciphertext. decrypt raises RuntimeError on auth failure.
        with self.assertRaises(Exception):
            hash_keys.decrypt(bytes(nonce), bytes(ct), aad, 1, False)

    def test_low_order_point_rejected(self) -> None:
        """A peer public key of all-zeros is a well-known low-order point that
        yields a zero shared secret; bootstrap_keys_from_dh must reject it to
        prevent a silent downgrade to a contributory-zero key."""
        # The peer_public is what actually matters for the "non-contributory"
        # check (the shared secret becomes zero). secret=0 with zero peer_pub
        # is the canonical low-order case.
        with self.assertRaises(Exception) as ctx:
            tuncore.bootstrap_session_from_dh(b"\x00" * 32, b"\x00" * 32, True)
        msg = str(ctx.exception).lower()
        self.assertTrue(
            "non-contributory" in msg or "low-order" in msg or "contrib" in msg,
            f"expected rejection message about non-contributory/low-order, got: {msg!r}",
        )

    def test_wrong_size_secret_rejected(self) -> None:
        _, peer_pub = tuncore.generate_ephemeral()
        with self.assertRaises(Exception):
            tuncore.bootstrap_session_from_dh(b"\x00" * 31, bytes(peer_pub), True)
        with self.assertRaises(Exception):
            tuncore.bootstrap_session_from_dh(b"\x00" * 33, bytes(peer_pub), True)
        with self.assertRaises(Exception):
            tuncore.bootstrap_session_from_dh(b"", bytes(peer_pub), True)

    def test_wrong_size_peer_public_rejected(self) -> None:
        our_secret, _ = tuncore.generate_ephemeral()
        with self.assertRaises(Exception):
            tuncore.bootstrap_session_from_dh(bytes(our_secret), b"\x00" * 31, True)
        with self.assertRaises(Exception):
            tuncore.bootstrap_session_from_dh(bytes(our_secret), b"\x00" * 33, True)
        with self.assertRaises(Exception):
            tuncore.bootstrap_session_from_dh(bytes(our_secret), b"", True)

    def test_generate_ephemeral_shapes(self) -> None:
        """generate_ephemeral returns (32-byte secret, 32-byte public) and
        successive calls return different material."""
        s1, p1 = tuncore.generate_ephemeral()
        s2, p2 = tuncore.generate_ephemeral()
        self.assertEqual(len(bytes(s1)), 32)
        self.assertEqual(len(bytes(p1)), 32)
        self.assertEqual(len(bytes(s2)), 32)
        self.assertEqual(len(bytes(p2)), 32)
        self.assertNotEqual(bytes(s1), bytes(s2))
        self.assertNotEqual(bytes(p1), bytes(p2))


if __name__ == "__main__":
    unittest.main()
