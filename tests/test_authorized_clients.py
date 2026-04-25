"""Tests for dsm.crypto.authorized_clients — HMAC-protected client pubkey allowlist."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

try:
    import tuncore
    _HAS_TUNCORE = True
except ImportError:
    tuncore = None  # type: ignore[assignment]
    _HAS_TUNCORE = False

from dsm.crypto.authorized_clients import AuthorizedClients


def _harden(path: Path) -> None:
    """Ensure sensitive files satisfy check_user_file_permissions."""
    os.chmod(path, 0o600)


@unittest.skipUnless(_HAS_TUNCORE, "tuncore (Rust crypto core) not built; run `maturin develop` in rust/tuncore/")
class TestAuthorizedClients(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.mkdtemp()
        self.path = Path(self._tmpdir) / "authorized_clients.json"
        self.identity = tuncore.IdentityKeyPair.generate()

    def tearDown(self) -> None:
        if self.path.exists():
            try:
                self.path.unlink()
            except OSError:
                pass
        try:
            os.rmdir(self._tmpdir)
        except OSError:
            # Swallow cleanup errors so test results aren't masked
            pass

    # --- Round-trip ---
    def test_save_load_roundtrip(self) -> None:
        ac = AuthorizedClients(self.path, self.identity)
        keys = [os.urandom(32) for _ in range(3)]
        for k in keys:
            ac.add(k)
        ac.save()
        _harden(self.path)

        ac2 = AuthorizedClients(self.path, self.identity)
        ac2.load()
        for k in keys:
            self.assertTrue(ac2.is_authorized(k), f"expected {k.hex()[:8]} authorized")
        # Unrelated key must not be authorized
        self.assertFalse(ac2.is_authorized(os.urandom(32)))
        self.assertEqual(len(ac2), 3)

    # --- Tamper detection ---
    def test_hmac_tamper_detection(self) -> None:
        ac = AuthorizedClients(self.path, self.identity)
        keys = [os.urandom(32) for _ in range(3)]
        for k in keys:
            ac.add(k)
        ac.save()
        _harden(self.path)

        # Corrupt the HMAC on the first entry.
        blob = json.loads(self.path.read_text())
        tampered_pubkey_hex = blob["entries"][0]["pubkey_hex"]
        original_hmac = blob["entries"][0]["hmac"]
        # Flip the first hex nibble.
        tampered_first = "0" if original_hmac[0] != "0" else "1"
        blob["entries"][0]["hmac"] = tampered_first + original_hmac[1:]
        self.path.write_text(json.dumps(blob, indent=2))
        _harden(self.path)

        ac2 = AuthorizedClients(self.path, self.identity)
        with self.assertLogs("dsm.crypto.authorized_clients", level="WARNING") as cm:
            ac2.load()
        # Check a warning about the skipped entry was emitted
        self.assertTrue(
            any("skipping" in msg.lower() or "hmac" in msg.lower() for msg in cm.output),
            f"expected warning about skipped/HMAC, got: {cm.output}",
        )

        tampered_pubkey = bytes.fromhex(tampered_pubkey_hex)
        self.assertFalse(ac2.is_authorized(tampered_pubkey))
        # The other two entries still load.
        self.assertEqual(len(ac2), 2)

    # --- Wrong identity rejects all ---
    def test_wrong_identity_rejects_all(self) -> None:
        ac = AuthorizedClients(self.path, self.identity)
        for _ in range(3):
            ac.add(os.urandom(32))
        ac.save()
        _harden(self.path)

        other_identity = tuncore.IdentityKeyPair.generate()
        ac2 = AuthorizedClients(self.path, other_identity)
        # All entries should fail HMAC under the other identity; warnings expected.
        with self.assertLogs("dsm.crypto.authorized_clients", level="WARNING"):
            ac2.load()
        self.assertEqual(len(ac2), 0)

    # --- Corrupted JSON raises ---
    def test_corrupted_json_raises(self) -> None:
        self.path.write_bytes(b"not a json at all {{{")
        _harden(self.path)
        ac = AuthorizedClients(self.path, self.identity)
        with self.assertRaises(RuntimeError):
            ac.load()

    # --- Bad version raises ---
    def test_bad_version_raises(self) -> None:
        self.path.write_text(json.dumps({"version": 2, "entries": []}))
        _harden(self.path)
        ac = AuthorizedClients(self.path, self.identity)
        with self.assertRaises(RuntimeError):
            ac.load()

    # --- add() enforces 32 bytes ---
    def test_add_enforces_pubkey_length(self) -> None:
        ac = AuthorizedClients(self.path, self.identity)
        with self.assertRaises(ValueError):
            ac.add(b"\x00" * 16)
        with self.assertRaises(ValueError):
            ac.add(b"\x00" * 33)
        with self.assertRaises(ValueError):
            ac.add(b"")
        # 32 bytes is fine.
        ac.add(b"\x00" * 32)
        self.assertEqual(len(ac), 1)

    # --- Missing file is not an error ---
    def test_missing_file_is_not_error(self) -> None:
        missing = Path(self._tmpdir) / "does_not_exist.json"
        ac = AuthorizedClients(missing, self.identity)
        # Must not raise.
        ac.load()
        self.assertEqual(len(ac), 0)


if __name__ == "__main__":
    unittest.main()
