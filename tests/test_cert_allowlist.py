"""Tests for ``dsm.crypto.cert_allowlist``."""

from __future__ import annotations

import os
import secrets
import unittest
from pathlib import Path

from dsm.crypto.cert_allowlist import CNAllowlist, CNAllowlistError


class TestCNAllowlist(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(os.environ.get("TMPDIR", "/tmp")) / (
            f"dsm-allowlist-{os.getpid()}-{secrets.token_hex(4)}.txt"
        )

    def tearDown(self) -> None:
        try:
            self.tmp.unlink()
        except FileNotFoundError:
            pass

    def _write(self, text: str, mode: int = 0o600) -> None:
        self.tmp.write_text(text, encoding="utf-8")
        os.chmod(self.tmp, mode)

    def test_load_simple_list(self) -> None:
        self._write(
            "dsm-a3f29c81-client\n"
            "dsm-9f001122-client\n"
        )
        al = CNAllowlist.from_file(self.tmp)
        self.assertEqual(len(al), 2)
        self.assertTrue(al.is_allowed("dsm-a3f29c81-client"))
        self.assertTrue(al.is_allowed("dsm-9f001122-client"))
        self.assertFalse(al.is_allowed("dsm-deadbeef-client"))

    def test_comments_and_blank_lines_ignored(self) -> None:
        self._write(
            "# this is the allowlist\n"
            "\n"
            "dsm-a3f29c81-client\n"
            "  \n"
            "# trailing comment\n"
            "dsm-9f001122-client\n"
        )
        al = CNAllowlist.from_file(self.tmp)
        self.assertEqual(len(al), 2)

    def test_whitespace_trimmed(self) -> None:
        self._write("  dsm-a3f29c81-client  \n")
        al = CNAllowlist.from_file(self.tmp)
        self.assertTrue(al.is_allowed("dsm-a3f29c81-client"))

    def test_internal_whitespace_rejected(self) -> None:
        self._write("dsm a3 client\n")
        with self.assertRaises(CNAllowlistError):
            CNAllowlist.from_file(self.tmp)

    def test_world_readable_rejected(self) -> None:
        self._write("dsm-x\n", mode=0o644)
        with self.assertRaises(CNAllowlistError):
            CNAllowlist.from_file(self.tmp)

    def test_missing_file_rejected(self) -> None:
        with self.assertRaises(CNAllowlistError):
            CNAllowlist.from_file(
                Path("/nonexistent/path/should/not/exist")
            )

    def test_empty_allowlist(self) -> None:
        self._write("# nobody allowed\n")
        al = CNAllowlist.from_file(self.tmp)
        self.assertEqual(len(al), 0)
        self.assertFalse(al.is_allowed("anyone"))

    def test_duplicate_entries_collapse(self) -> None:
        self._write(
            "dsm-a3f29c81-client\n"
            "dsm-a3f29c81-client\n"
        )
        al = CNAllowlist.from_file(self.tmp)
        self.assertEqual(len(al), 1)


if __name__ == "__main__":
    unittest.main()
