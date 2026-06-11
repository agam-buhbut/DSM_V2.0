"""Regression: config.toml itself must be permission-checked at load —
it pins the CA root + crl_strict, so a group/world-accessible or
foreign-owned config is a trust-anchor-substitution hole (config.py:406)."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from dsm.core.config import ConfigError, load

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


class TestConfigPermissions(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = Path(tempfile.mkdtemp())
        self.cfg = self._dir / "config.toml"
        self.cfg.write_bytes(_VALID_TOML)

    def tearDown(self) -> None:
        try:
            self.cfg.unlink()
        except FileNotFoundError:
            pass
        try:
            self._dir.rmdir()
        except OSError:
            pass

    def test_secure_mode_loads(self) -> None:
        os.chmod(self.cfg, 0o600)
        cfg = load(self.cfg)
        self.assertEqual(cfg.mode, "client")

    def test_group_readable_rejected(self) -> None:
        os.chmod(self.cfg, 0o640)
        with self.assertRaises(ConfigError):
            load(self.cfg)

    def test_world_readable_rejected(self) -> None:
        os.chmod(self.cfg, 0o644)
        with self.assertRaises(ConfigError):
            load(self.cfg)

    def test_missing_file_says_not_found_not_chmod(self) -> None:
        # A missing config must report "not found", not the permission
        # check's misleading "chmod 600" message.
        self.cfg.unlink()
        with self.assertRaises(ConfigError) as ctx:
            load(self.cfg)
        msg = str(ctx.exception)
        self.assertIn("not found", msg)
        self.assertNotIn("chmod", msg)
