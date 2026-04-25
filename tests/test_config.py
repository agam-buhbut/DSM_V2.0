"""Tests for dsm.core.config — Config validation."""

import unittest
from typing import Any

from dsm.core.config import Config


def _base(**overrides: Any) -> dict[str, Any]:
    """Return a valid base config dict, with optional overrides."""
    defaults: dict[str, Any] = {
        "mode": "client",
        "server_ip": "10.0.0.1",
        "server_port": 51820,
        "listen_port": 51821,
        "key_file": "/tmp/test.key",
        "transport": "udp",
    }
    defaults.update(overrides)
    return defaults


class TestConfigValidation(unittest.TestCase):
    def test_valid_client(self) -> None:
        c = Config(**_base())
        self.assertEqual(c.mode, "client")

    def test_valid_server(self) -> None:
        c = Config(**_base(
            mode="server",
            dns_providers=["8.8.8.8"],
            dns_provider_pins={"8.8.8.8": ["a" * 64]},
        ))
        self.assertEqual(c.mode, "server")

    def test_server_requires_pin_for_each_provider(self) -> None:
        with self.assertRaises(ValueError):
            Config(**_base(mode="server", dns_providers=["8.8.8.8"]))

    def test_pin_must_be_hex(self) -> None:
        with self.assertRaises(ValueError):
            Config(**_base(
                mode="server",
                dns_providers=["8.8.8.8"],
                dns_provider_pins={"8.8.8.8": ["nothex" * 10 + "abcd"]},
            ))

    def test_pin_must_be_64_chars(self) -> None:
        with self.assertRaises(ValueError):
            Config(**_base(
                mode="server",
                dns_providers=["8.8.8.8"],
                dns_provider_pins={"8.8.8.8": ["deadbeef"]},
            ))

    def test_known_hosts_path_must_be_absolute(self) -> None:
        with self.assertRaises(ValueError):
            Config(**_base(known_hosts_path="relative/path"))

    def test_known_hosts_path_optional(self) -> None:
        c = Config(**_base(known_hosts_path="/opt/mtun/kh.json"))
        self.assertEqual(c.known_hosts_path, "/opt/mtun/kh.json")

    def test_invalid_mode(self) -> None:
        with self.assertRaises(ValueError):
            Config(**_base(mode="invalid"))

    def test_invalid_server_ip(self) -> None:
        with self.assertRaises(ValueError):
            Config(**_base(server_ip="not-an-ip"))

    def test_port_zero(self) -> None:
        with self.assertRaises(ValueError):
            Config(**_base(server_port=0))

    def test_port_too_large(self) -> None:
        with self.assertRaises(ValueError):
            Config(**_base(listen_port=70000))

    def test_empty_key_file(self) -> None:
        with self.assertRaises(ValueError):
            Config(**_base(key_file=""))

    def test_invalid_transport(self) -> None:
        with self.assertRaises(ValueError):
            Config(**_base(transport="websocket"))

    def test_server_requires_dns(self) -> None:
        with self.assertRaises(ValueError):
            Config(**_base(mode="server"))

    def test_padding_inverted(self) -> None:
        with self.assertRaises(ValueError):
            Config(**_base(padding_min=1400, padding_max=128))

    def test_padding_too_small(self) -> None:
        with self.assertRaises(ValueError):
            Config(**_base(padding_min=10))

    def test_jitter_inverted(self) -> None:
        with self.assertRaises(ValueError):
            Config(**_base(jitter_ms_min=100, jitter_ms_max=10))

    def test_rotation_packets_too_low(self) -> None:
        with self.assertRaises(ValueError):
            Config(**_base(rotation_packets=50))

    def test_rotation_seconds_too_low(self) -> None:
        with self.assertRaises(ValueError):
            Config(**_base(rotation_seconds=30))

    def test_defaults(self) -> None:
        c = Config(**_base())
        self.assertEqual(c.transport, "udp")
        self.assertEqual(c.tun_name, "mtun0")
        self.assertEqual(c.log_level, "warning")
        self.assertEqual(c.padding_min, 128)
        self.assertEqual(c.padding_max, 1400)
        self.assertEqual(c.jitter_ms_min, 1)
        self.assertEqual(c.jitter_ms_max, 50)
        self.assertEqual(c.mtu, 1400)
        self.assertFalse(c.pmtu_discover)

    def test_mtu_too_small(self) -> None:
        with self.assertRaises(ValueError):
            Config(**_base(mtu=100))

    def test_mtu_too_large(self) -> None:
        with self.assertRaises(ValueError):
            Config(**_base(mtu=9000))

    def test_mtu_custom_valid(self) -> None:
        c = Config(**_base(mtu=1280))
        self.assertEqual(c.mtu, 1280)

    def test_pmtu_discover_flag(self) -> None:
        c = Config(**_base(pmtu_discover=True))
        self.assertTrue(c.pmtu_discover)


if __name__ == "__main__":
    unittest.main()
