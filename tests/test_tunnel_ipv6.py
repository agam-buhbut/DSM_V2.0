"""Tests for IPv6 state save/restore in dsm.net.tunnel.TunDevice.

These tests must NOT require root and MUST NOT modify host sysctls.
All host-touching surfaces (_run_commands, /sys/class/net iteration,
and the on-disk state path) are patched.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dsm.net import tunnel
from dsm.net.tunnel import TunDevice


class TestSaveIpv6State(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.state_path = Path(self._tmpdir.name) / "ipv6_state.json"

    def test_save_writes_json_with_mode_0600(self) -> None:
        with patch.object(TunDevice, "_IPV6_STATE_PATH", self.state_path):
            tun = TunDevice(name="mtun0")
            tun._save_ipv6_state({"eth0": True, "wlan0": False})

        self.assertTrue(self.state_path.exists())
        with open(self.state_path, "r") as f:
            got = json.load(f)
        self.assertEqual(got, {"eth0": True, "wlan0": False})
        mode = os.stat(self.state_path).st_mode & 0o777
        self.assertEqual(mode, 0o600)


class TestRestoreIpv6State(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.state_path = Path(self._tmpdir.name) / "ipv6_state.json"

    def test_restore_noop_if_file_missing(self) -> None:
        # File intentionally does not exist.
        self.assertFalse(self.state_path.exists())
        with patch.object(TunDevice, "_IPV6_STATE_PATH", self.state_path), \
             patch.object(tunnel, "_run_commands") as run_mock:
            tun = TunDevice(name="mtun0")
            tun._restore_ipv6_state()
            run_mock.assert_not_called()

    def test_restore_issues_correct_sysctl_commands(self) -> None:
        # Write a well-formed state file.
        with open(self.state_path, "w") as f:
            json.dump({"eth0": True, "wlan0": False}, f)

        with patch.object(TunDevice, "_IPV6_STATE_PATH", self.state_path), \
             patch.object(tunnel, "_run_commands") as run_mock:
            tun = TunDevice(name="mtun0")
            tun._restore_ipv6_state()

            self.assertEqual(run_mock.call_count, 1)
            args, kwargs = run_mock.call_args
            cmds = args[0]
            expected = [
                ["sysctl", "-w", "net.ipv6.conf.eth0.disable_ipv6=1"],
                ["sysctl", "-w", "net.ipv6.conf.wlan0.disable_ipv6=0"],
            ]
            # Order may vary since it comes from a dict iteration; compare as sorted.
            self.assertEqual(sorted(cmds), sorted(expected))
            # Must be invoked best-effort (strict=False) so one failing iface
            # doesn't abort the restore of the rest.
            self.assertEqual(kwargs.get("strict"), False)

    def test_restore_unlinks_file_after_success(self) -> None:
        with open(self.state_path, "w") as f:
            json.dump({"eth0": True}, f)

        with patch.object(TunDevice, "_IPV6_STATE_PATH", self.state_path), \
             patch.object(tunnel, "_run_commands"):
            tun = TunDevice(name="mtun0")
            tun._restore_ipv6_state()

        self.assertFalse(self.state_path.exists())

    def test_restore_survives_corrupted_json(self) -> None:
        # Not valid JSON — method must swallow the exception (logged as warning).
        with open(self.state_path, "w") as f:
            f.write("{not valid json")

        with patch.object(TunDevice, "_IPV6_STATE_PATH", self.state_path), \
             patch.object(tunnel, "_run_commands") as run_mock:
            tun = TunDevice(name="mtun0")
            # Should not raise.
            tun._restore_ipv6_state()
            # With corrupted JSON we never reach the _run_commands call.
            run_mock.assert_not_called()


class TestDeconfigureGuard(unittest.TestCase):
    """The _configured guard prevents restoring a stale state file left by a
    crashed earlier process run."""

    def test_deconfigure_skips_restore_when_not_configured(self) -> None:
        with patch.object(tunnel, "_run_commands"), \
             patch.object(TunDevice, "_restore_ipv6_state") as restore_mock:
            tun = TunDevice(name="mtun0")
            self.assertFalse(tun._configured)
            tun.deconfigure()
            restore_mock.assert_not_called()

    def test_deconfigure_calls_restore_when_configured(self) -> None:
        with patch.object(tunnel, "_run_commands"), \
             patch.object(TunDevice, "_restore_ipv6_state") as restore_mock:
            tun = TunDevice(name="mtun0")
            tun._configured = True  # simulate a successful configure()
            tun.deconfigure()
            restore_mock.assert_called_once()
            # After deconfigure the flag must be cleared so a subsequent
            # deconfigure() is a no-op.
            self.assertFalse(tun._configured)


class TestCloseTryFinally(unittest.TestCase):
    """close() must always close the fd, even if deconfigure() raises."""

    def test_close_propagates_exception_but_still_closes_fd(self) -> None:
        tun = TunDevice(name="mtun0")
        # Set an obviously-fake fd; os.close is patched so no real close runs.
        tun._fd = 12345

        class Boom(RuntimeError):
            pass

        with patch.object(tun, "deconfigure", side_effect=Boom("deconfig failed")), \
             patch("dsm.net.tunnel.os.close") as close_mock:
            with self.assertRaises(Boom):
                tun.close()
            close_mock.assert_called_once_with(12345)

        # After the try/finally, _fd should be cleared so re-close is a no-op.
        self.assertIsNone(tun._fd)

    def test_close_is_noop_if_fd_never_opened(self) -> None:
        tun = TunDevice(name="mtun0")
        self.assertIsNone(tun._fd)
        with patch("dsm.net.tunnel.os.close") as close_mock, \
             patch.object(tun, "deconfigure") as deconfig_mock:
            tun.close()
            close_mock.assert_not_called()
            deconfig_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
