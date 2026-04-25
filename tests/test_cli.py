"""Tests for dsm CLI entry point and config directory resolution.

Covers:
    1. DSM_CONFIG_DIR env var precedence in dsm.core.config.load
    2. `reset-trust --yes` deletes the known_hosts file
    3. `reset-trust` on missing file is a no-op
    4. `reset-trust` without --yes and without a tty exits with code 2
"""

from __future__ import annotations

import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest import mock

import dsm.__main__ as dsm_main
import dsm.crypto.handshake as handshake_mod
from dsm.core.config import load as config_load


_VALID_TOML = b"""\
mode = "client"
server_ip = "10.0.0.1"
server_port = 51820
listen_port = 51821
key_file = "/tmp/test.key"
transport = "udp"
"""


class TestConfigDirPrecedence(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.mkdtemp()
        self.config_path = Path(self._tmpdir) / "config.toml"
        self.config_path.write_bytes(_VALID_TOML)
        # Preserve and clear DSM_CONFIG_DIR for predictable starting state.
        self._prev_env = os.environ.get("DSM_CONFIG_DIR")
        if "DSM_CONFIG_DIR" in os.environ:
            del os.environ["DSM_CONFIG_DIR"]

    def tearDown(self) -> None:
        if self._prev_env is not None:
            os.environ["DSM_CONFIG_DIR"] = self._prev_env
        elif "DSM_CONFIG_DIR" in os.environ:
            del os.environ["DSM_CONFIG_DIR"]
        if self.config_path.exists():
            self.config_path.unlink()
        try:
            os.rmdir(self._tmpdir)
        except OSError:
            pass

    def test_env_var_unset_uses_config_parent(self) -> None:
        self.assertNotIn("DSM_CONFIG_DIR", os.environ)
        cfg = config_load(self.config_path)
        self.assertEqual(Path(cfg.config_dir), Path(self._tmpdir))

    def test_env_var_overrides_config_parent(self) -> None:
        other = tempfile.mkdtemp()
        try:
            os.environ["DSM_CONFIG_DIR"] = other
            cfg = config_load(self.config_path)
            # Env-var wins even though config parent is self._tmpdir.
            self.assertEqual(Path(cfg.config_dir), Path(other))
            self.assertNotEqual(Path(cfg.config_dir), Path(self._tmpdir))
        finally:
            if "DSM_CONFIG_DIR" in os.environ:
                del os.environ["DSM_CONFIG_DIR"]
            os.rmdir(other)

    def test_env_var_is_restored_in_teardown(self) -> None:
        """Sanity test that our setUp/tearDown correctly isolates env state
        across sub-tests — uses explicit try/finally as required."""
        prev = os.environ.get("DSM_CONFIG_DIR")
        os.environ["DSM_CONFIG_DIR"] = "/tmp/xxx"
        try:
            self.assertEqual(os.environ["DSM_CONFIG_DIR"], "/tmp/xxx")
        finally:
            if prev is None:
                del os.environ["DSM_CONFIG_DIR"]
            else:
                os.environ["DSM_CONFIG_DIR"] = prev


class TestResetTrust(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.mkdtemp()
        self.known_hosts = Path(self._tmpdir) / "known_hosts.json"
        # Monkeypatch DEFAULT_KNOWN_HOSTS_PATH so _run_reset_trust imports
        # our temp path. The CLI re-imports it inside the function, so
        # patching at module scope on dsm.crypto.handshake works.
        self._orig_path = handshake_mod.DEFAULT_KNOWN_HOSTS_PATH
        handshake_mod.DEFAULT_KNOWN_HOSTS_PATH = self.known_hosts

    def tearDown(self) -> None:
        handshake_mod.DEFAULT_KNOWN_HOSTS_PATH = self._orig_path
        if self.known_hosts.exists():
            try:
                self.known_hosts.unlink()
            except OSError:
                pass
        try:
            os.rmdir(self._tmpdir)
        except OSError:
            pass

    def test_reset_trust_yes_deletes_file(self) -> None:
        self.known_hosts.write_text("{}")
        self.assertTrue(self.known_hosts.exists())
        buf = io.StringIO()
        with redirect_stdout(buf):
            dsm_main._run_reset_trust(assume_yes=True)
        self.assertFalse(self.known_hosts.exists())
        self.assertIn("Deleted", buf.getvalue())

    def test_reset_trust_missing_file_no_op(self) -> None:
        self.assertFalse(self.known_hosts.exists())
        buf = io.StringIO()
        with redirect_stdout(buf):
            # Should just return without error.
            result = dsm_main._run_reset_trust(assume_yes=True)
        self.assertIsNone(result)
        self.assertIn("does not exist", buf.getvalue())

    def test_reset_trust_without_yes_non_tty_exits_2(self) -> None:
        self.known_hosts.write_text("{}")
        err_buf = io.StringIO()
        fake_stdin = mock.MagicMock()
        fake_stdin.isatty.return_value = False
        with mock.patch.object(sys, "stdin", fake_stdin):
            with redirect_stderr(err_buf):
                with self.assertRaises(SystemExit) as ctx:
                    dsm_main._run_reset_trust(assume_yes=False)
        self.assertEqual(ctx.exception.code, 2)
        # File must still exist — we refused to delete it.
        self.assertTrue(self.known_hosts.exists())


if __name__ == "__main__":
    unittest.main()
