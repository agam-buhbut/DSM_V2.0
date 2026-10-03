"""Regression guard: UDP is the pinned default transport.

UDP avoids the TCP-in-TCP throughput meltdown that occurs when carrying
TCP traffic over a TCP-based VPN tunnel. This test pins the default so a
future refactor cannot silently change it. It guards only the Config
default value and the shipped example config.
"""

from __future__ import annotations

import tomllib
import unittest
from dataclasses import fields
from pathlib import Path
from typing import Any

from dsm.core.config import Config

REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = REPO_ROOT / "config.example.toml"


def _minimal(**overrides: Any) -> dict[str, Any]:
    """Return the minimal set of required fields for a Config, without transport."""
    base: dict[str, Any] = {
        "mode": "client",
        "server_ip": "10.0.0.1",
        "server_port": 51820,
        "listen_port": 51821,
        "key_file": "/tmp/test.key",
        "cert_file": "/tmp/test.crt",
        "ca_root_file": "/tmp/test-ca.pem",
        "attest_key_file": "/tmp/test-attest.key",
        "expected_server_cn": "dsm-test-server",
    }
    base.update(overrides)
    return base


class TransportDefaultIsUdp(unittest.TestCase):
    """Pin that Config's default transport is 'udp'."""

    def test_config_default_transport_is_udp(self) -> None:
        """Constructing Config without specifying transport yields 'udp'."""
        cfg = Config(**_minimal())
        self.assertEqual(cfg.transport, "udp")

    def test_config_field_default_is_udp(self) -> None:
        """The dataclass field default for transport is 'udp'."""
        transport_field = next(f for f in fields(Config) if f.name == "transport")
        self.assertEqual(transport_field.default, "udp")

    def test_explicit_udp_accepted(self) -> None:
        """Explicitly passing transport='udp' is accepted."""
        cfg = Config(**_minimal(transport="udp"))
        self.assertEqual(cfg.transport, "udp")

    def test_explicit_tcp_accepted(self) -> None:
        """TCP is a valid fallback transport for networks that block UDP."""
        cfg = Config(**_minimal(transport="tcp"))
        self.assertEqual(cfg.transport, "tcp")


class ExampleConfigTransportIsUdp(unittest.TestCase):
    """Pin that config.example.toml ships transport = 'udp'."""

    def test_example_toml_transport_is_udp(self) -> None:
        """config.example.toml must ship with transport = 'udp'."""
        with EXAMPLE.open("rb") as fh:
            data = tomllib.load(fh)
        self.assertEqual(
            data.get("transport"),
            "udp",
            "config.example.toml must ship transport = 'udp' (regression guard)",
        )


if __name__ == "__main__":
    unittest.main()
