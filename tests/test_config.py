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
        "cert_file": "/tmp/test.crt",
        "ca_root_file": "/tmp/test-ca.pem",
        "attest_key_file": "/tmp/test-attest.key",
        "expected_server_cn": "dsm-test-server",
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
            allowed_cns_file="/tmp/test-allowed-cns.txt",
            expected_server_cn=None,
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

    def test_cert_file_must_be_absolute(self) -> None:
        with self.assertRaises(ValueError):
            Config(**_base(cert_file="relative/path.crt"))

    def test_ca_root_file_must_be_absolute(self) -> None:
        with self.assertRaises(ValueError):
            Config(**_base(ca_root_file="not/absolute.pem"))

    def test_attest_key_file_must_be_absolute(self) -> None:
        with self.assertRaises(ValueError):
            Config(**_base(attest_key_file="rel.key"))

    def test_crl_file_optional_when_absent(self) -> None:
        c = Config(**_base())
        self.assertIsNone(c.crl_file)

    def test_crl_file_must_be_absolute(self) -> None:
        with self.assertRaises(ValueError):
            Config(**_base(crl_file="rel.crl"))

    def test_client_requires_expected_server_cn(self) -> None:
        with self.assertRaises(ValueError):
            Config(**_base(expected_server_cn=None))

    def test_server_requires_allowed_cns_file(self) -> None:
        with self.assertRaises(ValueError):
            Config(**_base(
                mode="server",
                dns_providers=["8.8.8.8"],
                dns_provider_pins={"8.8.8.8": ["a" * 64]},
                expected_server_cn=None,
                allowed_cns_file=None,
            ))

    def test_server_allowed_cns_file_must_be_absolute(self) -> None:
        with self.assertRaises(ValueError):
            Config(**_base(
                mode="server",
                dns_providers=["8.8.8.8"],
                dns_provider_pins={"8.8.8.8": ["a" * 64]},
                expected_server_cn=None,
                allowed_cns_file="rel.txt",
            ))

    def test_invalid_mode(self) -> None:
        with self.assertRaises(ValueError):
            Config(**_base(mode="invalid"))

    def test_invalid_server_ip(self) -> None:
        with self.assertRaises(ValueError):
            Config(**_base(server_ip="not-an-ip"))

    def test_server_port_zero_rejected(self) -> None:
        # server_port is the public service port, must be a real port
        with self.assertRaises(ValueError):
            Config(**_base(server_port=0))

    def test_listen_port_zero_rejected_in_server_mode(self) -> None:
        # In server mode listen_port is the bind, must be a real port
        with self.assertRaises(ValueError):
            Config(**_base(
                mode="server",
                listen_port=0,
                dns_providers=["8.8.8.8"],
                dns_provider_pins={"8.8.8.8": ["a" * 64]},
                allowed_cns_file="/tmp/allowed.txt",
                expected_server_cn=None,
            ))

    def test_listen_port_zero_allowed_in_client_mode(self) -> None:
        # 0 means "kernel picks an ephemeral source port" — standard for clients
        c = Config(**_base(mode="client", listen_port=0))
        self.assertEqual(c.listen_port, 0)

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
        self.assertEqual(c.log_level, "info")
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
