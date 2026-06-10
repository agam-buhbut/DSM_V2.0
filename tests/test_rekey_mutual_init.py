"""DSM-003 regression lock: SessionKeyManager.abort_rotation().

On a mutual-init rekey tie-break the yielding side has already called
``initiate_rotation`` (setting the Rust-side ``pending_rotation``) but never
calls ``complete_rotation_initiator``. Before the fix there was no way to drop
that pending init, so the next ``initiate_rotation`` raised "rotation already
in progress" and tore down a healthy session. ``abort_rotation`` discards it.

Exercised at the tuncore boundary (the bug lives in the PyO3 wrapper's
pending_rotation handling), so it needs the built extension.
"""

from __future__ import annotations

import unittest

try:
    import tuncore

    _HAS_TUNCORE = True
except ImportError:
    tuncore = None  # type: ignore[assignment]
    _HAS_TUNCORE = False


def _make_session_keys() -> tuncore.SessionKeyManager:
    """Build an initiator SessionKeyManager via the only public path."""
    ours = tuncore.BootstrapEphemeral.generate()
    peer = tuncore.BootstrapEphemeral.generate()
    return tuncore.complete_bootstrap(ours, peer.public_key_bytes, True)


@unittest.skipUnless(_HAS_TUNCORE, "tuncore extension not built")
class AbortRotation(unittest.TestCase):
    def test_abort_clears_pending_so_next_initiate_succeeds(self) -> None:
        km = _make_session_keys()

        # First initiation sets pending_rotation.
        km.initiate_rotation()
        # A second initiation without completing must be rejected...
        with self.assertRaises(Exception):
            km.initiate_rotation()
        # ...until we abort the pending one.
        self.assertTrue(km.abort_rotation())

        # A fresh rotation now starts cleanly (the DSM-003 teardown is gone).
        km.initiate_rotation()
        self.assertTrue(km.abort_rotation())

    def test_abort_is_idempotent_and_false_when_nothing_pending(self) -> None:
        km = _make_session_keys()
        # Nothing pending yet.
        self.assertFalse(km.abort_rotation())
        km.initiate_rotation()
        self.assertTrue(km.abort_rotation())
        # Second abort with nothing pending returns False, does not raise.
        self.assertFalse(km.abort_rotation())


if __name__ == "__main__":
    unittest.main()
