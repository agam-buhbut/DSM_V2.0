"""DSM-007 — capture/override/restore semantics of SysctlOverride.

These exercise the real :class:`dsm.core.sysctl.SysctlOverride` against a
fake ``/proc/sys`` tree. The only thing mocked is the I/O boundary: the
module-level ``sysctl_path`` translator is redirected into a tmp dir, so
``set`` / ``restore_all`` read and write real files we control.

Locks the fail-closed-relevant invariants:
  (a) no-op when current already equals the requested value,
  (b) capture-ONCE (re-setting a key restores the *first* original),
  (c) restore writes every captured original then clears state,
  (d) OSError on an unreadable/unwritable key is swallowed to a WARNING
      and records nothing.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dsm.core import sysctl
from dsm.core.sysctl import SysctlOverride


class SysctlOverrideTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

        # Redirect the dotted-key -> path translation into our tmp tree.
        # SysctlOverride.set/restore_all look ``sysctl_path`` up by module
        # global, so the real class honors this patch for the test's life.
        patcher = patch.object(sysctl, "sysctl_path", self._fake_path)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _fake_path(self, key: str) -> Path:
        """Mirror the real translation but rooted in the tmp tree."""
        return self.root / key.replace(".", "/")

    def _seed(self, key: str, value: str) -> Path:
        """Create a fake /proc/sys/<key> file pre-populated with ``value``."""
        path = self._fake_path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"{value}\n")
        return path

    def test_noop_when_current_equals_value(self) -> None:
        # A no-op set captures nothing, so restore_all must not rewrite the file.
        key = "net.ipv4.ip_forward"
        path = self._seed(key, "1")
        before = path.read_bytes()

        ovr = SysctlOverride()
        self.assertEqual(ovr.set(key, "1"), "1")  # returns current, no write
        self.assertEqual(ovr._original, {})  # nothing captured

        ovr.restore_all()
        self.assertEqual(path.read_bytes(), before)  # byte-identical

    def test_set_records_only_first_capture(self) -> None:
        # set('1') then set('2'); restore writes back the FIRST original.
        key = "net.ipv4.conf.all.rp_filter"
        path = self._seed(key, "2")  # original on disk

        ovr = SysctlOverride()
        self.assertEqual(ovr.set(key, "1"), "2")  # captures '2'
        self.assertEqual(path.read_text().strip(), "1")

        # Second override of the SAME key must NOT overwrite the captured
        # original — capture-once is what makes restore correct.
        self.assertEqual(ovr.set(key, "0"), "1")  # current is now '1'
        self.assertEqual(path.read_text().strip(), "0")
        self.assertEqual(ovr._original[key], "2")  # still the first value

        ovr.restore_all()
        self.assertEqual(path.read_text().strip(), "2")

    def test_restore_all_writes_all_then_clears(self) -> None:
        # Every captured original is restored; a second restore is a no-op.
        k1 = "net.ipv4.conf.all.send_redirects"
        k2 = "net.ipv4.conf.default.send_redirects"
        p1 = self._seed(k1, "1")
        p2 = self._seed(k2, "1")

        ovr = SysctlOverride()
        ovr.set(k1, "0")
        ovr.set(k2, "0")
        self.assertEqual(p1.read_text().strip(), "0")
        self.assertEqual(p2.read_text().strip(), "0")

        ovr.restore_all()
        self.assertEqual(p1.read_text().strip(), "1")
        self.assertEqual(p2.read_text().strip(), "1")
        self.assertEqual(ovr._original, {})  # state cleared

        # Mutate the files post-restore; a second restore_all must do nothing.
        p1.write_text("9\n")
        p2.write_text("9\n")
        ovr.restore_all()
        self.assertEqual(p1.read_text().strip(), "9")
        self.assertEqual(p2.read_text().strip(), "9")

    def test_oserror_on_unreadable_key_is_logged_and_records_nothing(self) -> None:
        # A key whose path does not exist -> read_text raises OSError; set() must
        # return None, log a WARNING, and capture nothing.
        key = "net.ipv4.conf.nonexistent.value"  # never seeded -> ENOENT

        ovr = SysctlOverride()
        with self.assertLogs(sysctl.log, level="WARNING") as cm:
            self.assertIsNone(ovr.set(key, "1"))
        self.assertTrue(any("could not read" in m for m in cm.output))
        self.assertEqual(ovr._original, {})

        # restore_all with nothing captured is a clean no-op.
        ovr.restore_all()
        self.assertEqual(ovr._original, {})


if __name__ == "__main__":
    unittest.main()
