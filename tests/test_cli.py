"""Tests for dsm CLI entry point and config directory resolution."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from dsm.core.config import load as config_load


_VALID_TOML = b"""\
mode = "client"
server_ip = "10.0.0.1"
server_port = 51820
listen_port = 51821
key_file = "/tmp/test.key"
cert_file = "/tmp/test.crt"
ca_root_file = "/tmp/test-ca.pem"
attest_key_file = "/tmp/test-attest.key"
expected_server_cn = "dsm-test-server"
transport = "udp"
"""


class TestConfigDirPrecedence(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.mkdtemp()
        self.config_path = Path(self._tmpdir) / "config.toml"
        self.config_path.write_bytes(_VALID_TOML)
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


if __name__ == "__main__":
    unittest.main()
