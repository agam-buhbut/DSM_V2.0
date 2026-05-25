"""Tests for the post-handshake ephemeral DH bootstrap primitives.

The bootstrap derives session keys from a SECRET ephemeral DH shared secret
(not the public handshake hash). These tests exercise the Rust primitives
``tuncore.BootstrapEphemeral`` and ``tuncore.complete_bootstrap`` plus the
security checks on input (low-order point rejection, length checks).

The earlier insecure variants ``tuncore.generate_ephemeral`` and
``tuncore.bootstrap_session_from_dh`` — which exposed the X25519 secret
through Python ``bytes`` — were removed during the audit. Their length-
validation coverage now lives in the Rust unit tests for
``SessionKeyManager::from_bootstrap_shared_secret``.

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
    """Exercise tuncore.complete_bootstrap directly."""

    def test_bootstrap_roundtrip_encrypt_decrypt(self) -> None:
        """The core property: when both sides call complete_bootstrap with
        matching inputs (their own BootstrapEphemeral + peer's public) the
        resulting SessionKeyManagers produce interoperable encrypt/decrypt."""
        a_eph = tuncore.BootstrapEphemeral.generate()
        b_eph = tuncore.BootstrapEphemeral.generate()
        a_public = bytes(a_eph.public_key_bytes)
        b_public = bytes(b_eph.public_key_bytes)

        a_keys = tuncore.complete_bootstrap(a_eph, b_public, is_initiator=True)
        b_keys = tuncore.complete_bootstrap(b_eph, a_public, is_initiator=False)

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

    def test_bootstrap_keys_specific_to_inputs(self) -> None:
        """Regression guard: bootstrap DH key material is specific to its
        secret+peer inputs. Ciphertext produced with one bootstrap session
        cannot be decrypted with a session built from different DH inputs."""
        # First bootstrap pair: keys derived from (a_secret, b_public)
        a_eph = tuncore.BootstrapEphemeral.generate()
        b_eph = tuncore.BootstrapEphemeral.generate()
        bootstrap_keys = tuncore.complete_bootstrap(
            a_eph, bytes(b_eph.public_key_bytes), is_initiator=True,
        )

        # Second, unrelated bootstrap pair (different secrets/publics).
        # Used to be derived from a public handshake hash; the Python binding
        # for that path was dropped (audit M2) since it derives keys from
        # public material. A fresh independent DH covers the same regression.
        c_eph = tuncore.BootstrapEphemeral.generate()
        d_eph = tuncore.BootstrapEphemeral.generate()
        unrelated_keys = tuncore.complete_bootstrap(
            c_eph, bytes(d_eph.public_key_bytes), is_initiator=False,
        )

        aad = b"\x00" * 8
        nonce, ct, _epoch = bootstrap_keys.encrypt(b"secret", aad)

        # The unrelated peer should NOT be able to decrypt the bootstrap
        # ciphertext. decrypt raises RuntimeError on auth failure.
        with self.assertRaises(Exception):
            unrelated_keys.decrypt(bytes(nonce), bytes(ct), aad, 1, False)

    def test_low_order_point_rejected(self) -> None:
        """A peer public key of all-zeros is a well-known low-order point that
        yields a zero shared secret; complete_bootstrap must reject it to
        prevent a silent downgrade to a contributory-zero key."""
        eph = tuncore.BootstrapEphemeral.generate()
        with self.assertRaises(Exception) as ctx:
            tuncore.complete_bootstrap(eph, b"\x00" * 32, is_initiator=True)
        msg = str(ctx.exception).lower()
        self.assertTrue(
            "non-contributory" in msg or "low-order" in msg or "contrib" in msg,
            f"expected rejection message about non-contributory/low-order, got: {msg!r}",
        )

    def test_wrong_size_peer_public_rejected(self) -> None:
        """complete_bootstrap must reject any peer_public that isn't 32 bytes."""
        for bad in (b"\x00" * 31, b"\x00" * 33, b""):
            eph = tuncore.BootstrapEphemeral.generate()
            with self.assertRaises(Exception):
                tuncore.complete_bootstrap(eph, bad, is_initiator=True)

    def test_bootstrap_ephemeral_shapes(self) -> None:
        """BootstrapEphemeral.generate yields a fresh 32-byte public key per call
        and is_live reports True until consumed."""
        e1 = tuncore.BootstrapEphemeral.generate()
        e2 = tuncore.BootstrapEphemeral.generate()
        p1 = bytes(e1.public_key_bytes)
        p2 = bytes(e2.public_key_bytes)
        self.assertEqual(len(p1), 32)
        self.assertEqual(len(p2), 32)
        self.assertNotEqual(p1, p2)
        self.assertTrue(e1.is_live)
        self.assertTrue(e2.is_live)

    def test_bootstrap_ephemeral_consumed_after_use(self) -> None:
        """complete_bootstrap consumes the ephemeral; a second call fails and
        is_live flips to False. This is the property that justifies removing
        the older ``bootstrap_session_from_dh`` — the secret never reaches
        Python and cannot be replayed by re-passing it."""
        eph = tuncore.BootstrapEphemeral.generate()
        peer_eph = tuncore.BootstrapEphemeral.generate()
        peer_pub = bytes(peer_eph.public_key_bytes)

        self.assertTrue(eph.is_live)
        tuncore.complete_bootstrap(eph, peer_pub, is_initiator=True)
        self.assertFalse(eph.is_live)

        # Second call against the same (now-consumed) ephemeral must fail.
        with self.assertRaises(Exception):
            tuncore.complete_bootstrap(eph, peer_pub, is_initiator=True)

    def test_session_key_manager_encrypt_decrypt_return_bytes(self) -> None:
        """H-PERF-3 contract: ``SessionKeyManager.encrypt`` returns a
        ``(bytes, bytes, int)`` tuple and ``SessionKeyManager.decrypt``
        returns ``bytes``. The Rust side returns ``PyBytes`` directly so
        Python callers can drop the historical ``bytes(...)`` coercion on
        the AEAD hot path. Regression guard: if a future Rust change
        reverts to ``Vec<u8>``, this test trips and ``struct.unpack_from``
        downstream of decrypt starts failing in production.
        """
        a_eph = tuncore.BootstrapEphemeral.generate()
        b_eph = tuncore.BootstrapEphemeral.generate()
        a_pub = bytes(a_eph.public_key_bytes)
        b_pub = bytes(b_eph.public_key_bytes)
        a_keys = tuncore.complete_bootstrap(a_eph, b_pub, is_initiator=True)
        b_keys = tuncore.complete_bootstrap(b_eph, a_pub, is_initiator=False)

        aad = b"\x00" * 8
        nonce, ct, epoch = a_keys.encrypt(b"payload", aad)
        self.assertIsInstance(nonce, bytes)
        self.assertIsInstance(ct, bytes)
        self.assertIsInstance(epoch, int)
        self.assertEqual(len(nonce), 12)

        pt = b_keys.decrypt(nonce, ct, aad, 1, False)
        self.assertIsInstance(pt, bytes)
        self.assertEqual(pt, b"payload")


if __name__ == "__main__":
    unittest.main()
