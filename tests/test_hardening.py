"""Regression: set_process_nondumpable() clears PR_SET_DUMPABLE so a
post-hardening crash cannot dump key material to a core file. Runs in a
subprocess so the test runner itself stays dumpable."""

from __future__ import annotations

import subprocess
import sys
import unittest


class TestNondumpableBackstop(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux prctl only")
    def test_set_process_nondumpable_clears_flag(self) -> None:
        code = (
            "import ctypes, ctypes.util\n"
            "from dsm.core.hardening import set_process_nondumpable\n"
            "set_process_nondumpable()\n"
            "libc = ctypes.CDLL(ctypes.util.find_library('c') or 'libc.so.6',"
            " use_errno=True)\n"
            "print(libc.prctl(3, 0, 0, 0, 0))\n"  # PR_GET_DUMPABLE == 3
        )
        proc = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(proc.stdout.strip(), "0")

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux prctl only")
    def test_idempotent_second_call_is_noop(self) -> None:
        code = (
            "import ctypes, ctypes.util\n"
            "from dsm.core.hardening import set_process_nondumpable\n"
            "set_process_nondumpable()\n"
            "set_process_nondumpable()\n"  # must not raise on the second call
            "libc = ctypes.CDLL(ctypes.util.find_library('c') or 'libc.so.6',"
            " use_errno=True)\n"
            "print(libc.prctl(3, 0, 0, 0, 0))\n"
        )
        proc = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(proc.stdout.strip(), "0")


if __name__ == "__main__":
    unittest.main()
