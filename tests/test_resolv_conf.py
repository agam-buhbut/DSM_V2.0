"""DSM-008 — byte/target-exact capture & restore of ResolvConfManager.

The only thing mocked is the I/O boundary: the module-level ``RESOLV_CONF``
constant is redirected into a tmp dir. The real ``ResolvConfManager`` (and
the real ``atomic_write`` it calls) operate on actual files we control.

Locks exact restore for all three prior states plus idempotency:
  (1) prior regular file -> bytes restored exactly,
  (2) prior symlink     -> symlink target restored exactly,
  (3) absent            -> apply creates, remove unlinks,
  (4) double apply / double remove are no-ops,
  and that apply() never raises regardless of M-NET-1 host detection.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dsm.net import resolv_conf
from dsm.net.resolv_conf import ResolvConfManager

NAMESERVER = "10.8.0.1"


class ResolvConfManagerTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

        # Redirect the managed path into our tmp tree. apply()/remove() read
        # this module global directly and hand it to atomic_write, so the
        # real code path is exercised end-to-end against a file we own.
        self.resolv = self.root / "resolv.conf"
        patcher = patch.object(resolv_conf, "RESOLV_CONF", self.resolv)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _managed(self) -> ResolvConfManager:
        return ResolvConfManager(NAMESERVER)

    def test_prior_regular_file_restored_byte_exact(self) -> None:
        # remove() must restore the original bytes EXACTLY, not a normalized copy.
        original = b"nameserver 1.1.1.1\noptions timeout:1\n# user comment\n"
        self.resolv.write_bytes(original)

        mgr = self._managed()
        mgr.apply()
        applied = self.resolv.read_bytes()
        self.assertIn(f"nameserver {NAMESERVER}".encode(), applied)
        self.assertNotEqual(applied, original)
        self.assertFalse(self.resolv.is_symlink())

        mgr.remove()
        self.assertEqual(self.resolv.read_bytes(), original)
        self.assertFalse(self.resolv.is_symlink())

    def test_prior_symlink_restored_to_same_target(self) -> None:
        # remove() must leave a symlink whose readlink matches the original target.
        sentinel = self.root / "stub-resolv.conf"
        sentinel.write_bytes(b"nameserver 127.0.0.53\n")
        target = str(sentinel)
        os.symlink(target, self.resolv)

        mgr = self._managed()
        mgr.apply()
        # After apply the managed path is a concrete file (atomic rename
        # over the symlink), holding our nameserver block.
        self.assertFalse(self.resolv.is_symlink())
        self.assertIn(f"nameserver {NAMESERVER}".encode(), self.resolv.read_bytes())

        mgr.remove()
        self.assertTrue(self.resolv.is_symlink())
        self.assertEqual(os.readlink(self.resolv), target)
        # The sentinel target is untouched.
        self.assertEqual(sentinel.read_bytes(), b"nameserver 127.0.0.53\n")

    def test_absent_file_created_then_unlinked(self) -> None:
        self.assertFalse(self.resolv.exists())

        mgr = self._managed()
        mgr.apply()
        self.assertTrue(self.resolv.exists())
        self.assertIn(f"nameserver {NAMESERVER}".encode(), self.resolv.read_bytes())

        mgr.remove()
        self.assertFalse(self.resolv.exists())
        self.assertFalse(self.resolv.is_symlink())

    def test_double_apply_and_double_remove_are_noops(self) -> None:
        original = b"nameserver 9.9.9.9\n"
        self.resolv.write_bytes(original)

        mgr = self._managed()
        mgr.apply()
        after_first = self.resolv.read_bytes()
        mgr.apply()  # _applied guard -> no-op
        self.assertEqual(self.resolv.read_bytes(), after_first)

        mgr.remove()
        self.assertEqual(self.resolv.read_bytes(), original)
        mgr.remove()  # _applied is False -> no-op, must not raise
        self.assertEqual(self.resolv.read_bytes(), original)

    def test_apply_does_not_raise_regardless_of_mnet1_detection(self) -> None:
        # M-NET-1 detection reads /run/systemd/... and /run/NetworkManager.
        # apply() must only warn, never raise, whether or not those exist.
        self.resolv.write_bytes(b"nameserver 8.8.8.8\n")

        # Force the "detected" branch: make the host-state probe report
        # present, and confirm apply() completes and only logs a warning.
        real_exists = Path.exists

        def fake_exists(self_path: Path) -> bool:
            if str(self_path).startswith("/run/"):
                return True
            return real_exists(self_path)

        mgr = self._managed()
        with patch.object(Path, "exists", fake_exists):
            with self.assertLogs(resolv_conf.log, level="WARNING") as cm:
                mgr.apply()  # must not raise
        self.assertTrue(any("M-NET-1" in m for m in cm.output))
        self.assertTrue(self.resolv.exists())
        mgr.remove()


if __name__ == "__main__":
    unittest.main()
