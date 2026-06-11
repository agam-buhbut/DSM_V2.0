"""Phase 1.5: a crash (apply twice without restore) must NOT clobber the
real original. The persistent backup preserves it, and a self-captured
managed file is never treated as the original.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dsm.net import resolv_conf
from dsm.net.resolv_conf import ResolvConfManager

NAMESERVER = "10.8.0.1"


class ResolvConfCrashSafety(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self.resolv = self.root / "resolv.conf"
        self.backup = self.root / "var" / "resolv.conf.orig"
        self._p1 = patch.object(resolv_conf, "RESOLV_CONF", self.resolv)
        self._p2 = patch.object(resolv_conf, "RESOLV_BACKUP", self.backup)
        self._p1.start()
        self._p2.start()
        self.addCleanup(self._p1.stop)
        self.addCleanup(self._p2.stop)

    def test_crash_then_restart_preserves_real_original(self) -> None:
        original = b"nameserver 1.1.1.1\noptions timeout:1\n"
        self.resolv.write_bytes(original)

        # First apply: captures the real original + writes the backup.
        ResolvConfManager(NAMESERVER).apply()
        self.assertIn(b"nameserver 10.8.0.1", self.resolv.read_bytes())
        self.assertTrue(self.backup.exists())
        self.assertEqual(self.backup.read_bytes(), original)
        # Backup is written with 0o600 (atomic_write mode) inside a dir the
        # atomic_write created at 0o700 — no world-readable secret leak.
        self.assertEqual(self.backup.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.backup.parent.stat().st_mode & 0o777, 0o700)

        # CRASH: no remove() ran. Simulate restart -> a NEW manager applies
        # again over the dsm-managed file.
        mgr2 = ResolvConfManager(NAMESERVER)
        mgr2.apply()  # current file IS dsm-managed -> must NOT capture it

        # Clean teardown now must restore the REAL original, not dsm's payload.
        mgr2.remove()
        self.assertEqual(self.resolv.read_bytes(), original)

    def test_read_race_oserror_does_not_empty_resolv_or_poison_backup(self) -> None:
        # A read OSError between exists() and read_bytes() must be treated as
        # "no original" (remove() unlinks our override), NOT captured as b""
        # — which would write an empty resolv.conf on restore AND poison the
        # write-once persistent backup with b"".
        original = b"nameserver 8.8.8.8\n"
        self.resolv.write_bytes(original)
        mgr = ResolvConfManager(NAMESERVER)
        with patch.object(type(self.resolv), "read_bytes", side_effect=OSError("EIO")):
            mgr.apply()
        # No backup was poisoned with b"".
        self.assertFalse(self.backup.exists())
        # Our managed override is present; teardown removes it (no empty file).
        mgr.remove()
        self.assertFalse(self.resolv.exists())

    def test_first_apply_of_managed_file_uses_backup_if_present(self) -> None:
        # No live original, but a backup exists from a prior run.
        original = b"nameserver 9.9.9.9\n"
        self.backup.parent.mkdir(parents=True, exist_ok=True)
        self.backup.write_bytes(original)
        self.resolv.write_bytes(
            b"# Managed by dsm while the VPN is up\nnameserver 10.8.0.1\n"
        )
        mgr = ResolvConfManager(NAMESERVER)
        mgr.apply()
        mgr.remove()
        self.assertEqual(self.resolv.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
