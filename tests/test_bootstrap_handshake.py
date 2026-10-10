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


@unittest.skipUnless(
    _HAS_TUNCORE,
    "tuncore (Rust crypto core) not built; run `maturin develop` in rust/tuncore/",
)
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

        # A (initiator) seals -> B (responder) opens, then the other way.
        opened = b_keys.open_packet(a_keys.seal_packet(1, b"hello from initiator"))
        assert opened is not None
        self.assertEqual(opened[1], b"hello from initiator")
        opened2 = a_keys.open_packet(b_keys.seal_packet(1, b"hello back"))
        assert opened2 is not None
        self.assertEqual(opened2[1], b"hello back")

    def test_bootstrap_keys_specific_to_inputs(self) -> None:
        """Regression guard: bootstrap DH key material is specific to its
        secret+peer inputs. Ciphertext produced with one bootstrap session
        cannot be decrypted with a session built from different DH inputs."""
        # First bootstrap pair: keys derived from (a_secret, b_public)
        a_eph = tuncore.BootstrapEphemeral.generate()
        b_eph = tuncore.BootstrapEphemeral.generate()
        bootstrap_keys = tuncore.complete_bootstrap(
            a_eph,
            bytes(b_eph.public_key_bytes),
            is_initiator=True,
        )

        # Second, unrelated bootstrap pair (different secrets/publics).
        # Used to be derived from a public handshake hash; the Python binding
        # for that path was dropped (audit M2) since it derives keys from
        # public material. A fresh independent DH covers the same regression.
        c_eph = tuncore.BootstrapEphemeral.generate()
        d_eph = tuncore.BootstrapEphemeral.generate()
        unrelated_keys = tuncore.complete_bootstrap(
            c_eph,
            bytes(d_eph.public_key_bytes),
            is_initiator=False,
        )

        wire = bootstrap_keys.seal_packet(1, b"secret")

        # The unrelated peer must NOT be able to open the bootstrap packet.
        # open_packet returns None for anything that does not open.
        self.assertIsNone(unrelated_keys.open_packet(wire))

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
            f"expected rejection message about non-contributory/low-order, got: {msg!r}",  # noqa: E501  # assertion failure message; not splitting to avoid touching test logic
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
        """H-PERF-3 contract, now on the wire v2 calls: ``seal_packet``
        returns the whole wire packet as ``bytes`` and ``open_packet`` returns
        ``(int, bytes, bool)``. The Rust side returns ``PyBytes`` directly so
        Python callers need no ``bytes(...)`` copy on the hot path. (Named for
        the calls it replaced.)
        """
        a_eph = tuncore.BootstrapEphemeral.generate()
        b_eph = tuncore.BootstrapEphemeral.generate()
        a_pub = bytes(a_eph.public_key_bytes)
        b_pub = bytes(b_eph.public_key_bytes)
        a_keys = tuncore.complete_bootstrap(a_eph, b_pub, is_initiator=True)
        b_keys = tuncore.complete_bootstrap(b_eph, a_pub, is_initiator=False)

        wire = a_keys.seal_packet(1, b"payload")
        self.assertIsInstance(wire, bytes)
        self.assertEqual(len(wire), 20 + len(b"payload") + 16)

        opened = b_keys.open_packet(wire)
        assert opened is not None
        seq, pt, used_prev = opened
        self.assertIsInstance(seq, int)
        self.assertIsInstance(pt, bytes)
        self.assertIsInstance(used_prev, bool)
        self.assertEqual((seq, pt, used_prev), (1, b"payload", False))


if __name__ == "__main__":
    unittest.main()
