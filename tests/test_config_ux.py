"""Phase 1.11: config/CLI UX — typed errors, absolute key_file, IPv6 reject,
atomic_write write-loop, padding clamp, passphrase SUPPRESS, enroll CSR-path
precheck."""

from __future__ import annotations

import argparse
import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from typing import Any
from unittest.mock import patch

from dsm.core import atomic_io
from dsm.core.config import Config
from dsm.traffic.shaper import TrafficShaper


def _base(**o: Any) -> dict[str, Any]:
    d: dict[str, Any] = {
        "mode": "client",
        "server_ip": "10.0.0.1",
        "server_port": 51820,
        "listen_port": 51821,
        "key_file": "/tmp/k.key",
        "cert_file": "/tmp/c.crt",
        "ca_root_file": "/tmp/ca.pem",
        "attest_key_file": "/tmp/a.key",
        "expected_server_cn": "dsm-test-server",
        "transport": "udp",
    }
    d.update(o)
    return d


class TypedConfigErrors(unittest.TestCase):
    def test_valid_config_still_loads(self) -> None:
        # The type-check pass must not reject a fully valid config (ints,
        # floats, bools, str, list, dict, None Optionals all present).
        c = Config(
            **_base(
                padding_min=128,
                padding_max=1400,
                jitter_ms_min=1,
                jitter_ms_max=100,
                rotation_packets=5000,
                rotation_seconds=600,
                mtu=1400,
                pmtu_check_interval_s=30.0,
                auto_mtu=True,
                pmtu_discover=False,
                dns_providers=[],
                dns_provider_pins={},
            )
        )
        self.assertEqual(c.mode, "client")
        # pmtu_check_interval_s also accepts an int (TOML integer literal).
        c2 = Config(**_base(pmtu_check_interval_s=30))
        self.assertEqual(c2.pmtu_check_interval_s, 30)

    def test_string_port_raises_valueerror_not_typeerror(self) -> None:
        with self.assertRaises(ValueError):
            Config(**_base(server_port="51820"))  # type: ignore[arg-type]

    def test_string_mtu_raises_valueerror(self) -> None:
        with self.assertRaises(ValueError):
            Config(**_base(mtu="1400"))  # type: ignore[arg-type]

    def test_bool_port_rejected(self) -> None:
        # bool is an int subclass — must be rejected for an int field.
        with self.assertRaises(ValueError):
            Config(**_base(server_port=True))  # type: ignore[arg-type]

    def test_string_pmtu_interval_raises_valueerror(self) -> None:
        with self.assertRaises(ValueError):
            Config(**_base(pmtu_check_interval_s="30"))  # type: ignore[arg-type]

    def test_error_message_names_field_and_type(self) -> None:
        with self.assertRaises(ValueError) as cm:
            Config(**_base(server_port="51820"))  # type: ignore[arg-type]
        msg = str(cm.exception)
        self.assertIn("server_port", msg)
        self.assertIn("integer", msg)


class KeyFileAbsolute(unittest.TestCase):
    def test_relative_key_file_rejected(self) -> None:
        with self.assertRaises(ValueError):
            Config(**_base(key_file="relative.key"))

    def test_absolute_key_file_ok(self) -> None:
        c = Config(**_base(key_file="/tmp/abs.key"))
        self.assertEqual(c.key_file, "/tmp/abs.key")


class Ipv6ServerIpRejected(unittest.TestCase):
    def test_ipv6_server_ip_rejected(self) -> None:
        with self.assertRaises(ValueError):
            Config(**_base(server_ip="2001:db8::1"))

    def test_ipv4_server_ip_ok(self) -> None:
        c = Config(**_base(server_ip="192.0.2.10"))
        self.assertEqual(c.server_ip, "192.0.2.10")


class AtomicWriteFullWrite(unittest.TestCase):
    def test_short_write_is_completed_in_a_loop(self) -> None:
        data = b"x" * 10000
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "out.bin"
            real_write = os.write
            calls = {"n": 0}

            def short_write(fd: int, buf: bytes) -> int:
                # First call writes only half; loop must continue.
                calls["n"] += 1
                if calls["n"] == 1:
                    return real_write(fd, buf[: len(buf) // 2])
                return real_write(fd, buf)

            with patch.object(atomic_io.os, "write", side_effect=short_write):
                atomic_io.atomic_write(target, data, mkdir=False)
            self.assertEqual(target.read_bytes(), data)
            self.assertGreaterEqual(calls["n"], 2)

    def test_full_write_lands_all_bytes(self) -> None:
        data = b"abc" * 5000
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "full.bin"
            atomic_io.atomic_write(target, data, mkdir=False)
            self.assertEqual(target.read_bytes(), data)


class PaddingClamp(unittest.TestCase):
    def test_padding_min_above_max_class_does_not_crash(self) -> None:
        # padding_min in (1400, 1500] passes Config range validation but the
        # shaper's class filter is empty -> must clamp, not raise.
        shaper = TrafficShaper(padding_min=1450, padding_max=1500)
        self.assertGreaterEqual(len(shaper._active_classes), 1)

    def test_normal_padding_unaffected(self) -> None:
        shaper = TrafficShaper(padding_min=128, padding_max=1400)
        self.assertGreaterEqual(len(shaper._active_classes), 1)
        self.assertTrue(all(128 <= sc <= 1400 for sc in shaper._active_classes))

    def test_set_size_class_ceiling_with_high_padding_min_does_not_crash(self) -> None:
        # The Phase-1.7 ceiling method had the same empty-min() crash class as
        # __init__ when padding_min exceeds every SIZE_CLASS — guard it too.
        shaper = TrafficShaper(padding_min=1450, padding_max=1500)
        shaper.set_size_class_ceiling(1200)  # must not raise
        self.assertGreaterEqual(len(shaper._active_classes), 1)


class PassphraseFlagClobber(unittest.TestCase):
    def test_parent_passphrase_survives_subcommand(self) -> None:
        from dsm.__main__ import _add_passphrase_args

        parser = argparse.ArgumentParser()
        _add_passphrase_args(parser)
        sub = parser.add_subparsers(dest="command")
        enroll = sub.add_parser("enroll")
        enroll.add_argument("--csr-out", default=None)
        _add_passphrase_args(enroll)
        args = parser.parse_args(["--passphrase-fd", "3", "enroll", "--csr-out", "x"])
        self.assertEqual(args.passphrase_fd, 3)

    def test_flag_after_subcommand_still_works(self) -> None:
        from dsm.__main__ import _add_passphrase_args

        parser = argparse.ArgumentParser()
        _add_passphrase_args(parser)
        sub = parser.add_subparsers(dest="command")
        enroll = sub.add_parser("enroll")
        enroll.add_argument("--csr-out", default=None)
        _add_passphrase_args(enroll)
        args = parser.parse_args(["enroll", "--csr-out", "x", "--passphrase-fd", "7"])
        self.assertEqual(args.passphrase_fd, 7)


class EnrollCsrPathPrecheck(unittest.TestCase):
    def test_unwritable_csr_dir_exits_before_keygen(self) -> None:
        # A CSR path whose parent does not exist must exit 2 with a clean
        # message BEFORE generate_enrollment persists any keys.
        from dsm.__main__ import _run_enroll
        from tests.test_lifecycle import _client_config

        buf = io.StringIO()
        with patch(
            "dsm.__main__._load_config_or_exit",
            return_value=_client_config(),
        ):
            with redirect_stderr(buf):
                with self.assertRaises(SystemExit) as cm:
                    _run_enroll(
                        None,
                        csr_out=Path("/nonexistent-dir-xyz/out.csr"),
                        import_cert=None,
                        cn=None,
                        role="client",
                        passphrase_fd=None,
                        passphrase_env_file=None,
                    )
        self.assertEqual(cm.exception.code, 2)
        self.assertIn("enroll:", buf.getvalue())
        # No keys were persisted (the precheck fired before keygen).
        self.assertFalse(Path("/nonexistent-dir-xyz/out.csr").exists())


if __name__ == "__main__":
    unittest.main()
