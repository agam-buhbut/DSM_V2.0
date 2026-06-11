"""Phase 1.9: `dsm cleanup` removes all dsm host state idempotently. Only the
subprocess boundary is mocked.
"""

from __future__ import annotations

import shutil
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from dsm.net import cleanup


class CleanupHostState(unittest.TestCase):
    def test_cleanup_deletes_all_dsm_nft_tables(self) -> None:
        runs: list[list[str]] = []

        def fake_run(cmd, *a, **k):  # type: ignore[no-untyped-def]
            runs.append(list(cmd))

            class _R:
                returncode = 0

            return _R()

        with patch.object(cleanup.subprocess, "run", side_effect=fake_run):
            cleanup.cleanup_host_state()

        flat = [" ".join(c) for c in runs]
        for table in (
            "dsm_killswitch_pre",
            "dsm_killswitch",
            "dsm_dns_leak",
            "dsm_server_ratelimit",
            "dsm_server_nat",
        ):
            self.assertTrue(
                any(f"delete table inet {table}" in f for f in flat),
                f"cleanup must delete table {table}",
            )
        # Flushes table 100 + deletes the priority-10 ip rule.
        self.assertTrue(any("flush table 100" in f for f in flat))
        self.assertTrue(
            any(
                "rule del" in f and "priority" in f and "10" in c
                for f, c in zip(flat, runs)
            )
        )

    def test_cleanup_is_idempotent_swallows_missing(self) -> None:
        # Every subprocess call fails (nothing exists) — cleanup must not raise.
        def boom(cmd, *a, **k):  # type: ignore[no-untyped-def]
            raise subprocess.CalledProcessError(1, cmd)

        with patch.object(cleanup.subprocess, "run", side_effect=boom):
            cleanup.cleanup_host_state()  # must not raise

    def test_cleanup_restores_safe_default_sysctls(self) -> None:
        # The coarse crash-path restore re-enables IPv6 + disables forwarding.
        runs: list[list[str]] = []

        def fake_run(cmd, *a, **k):  # type: ignore[no-untyped-def]
            runs.append(list(cmd))

            class _R:
                returncode = 0

            return _R()

        with patch.object(cleanup.subprocess, "run", side_effect=fake_run):
            cleanup.cleanup_host_state()

        flat = [" ".join(c) for c in runs]
        for kv in (
            "net.ipv6.conf.all.disable_ipv6=0",
            "net.ipv6.conf.default.disable_ipv6=0",
            "net.ipv4.ip_forward=0",
        ):
            self.assertTrue(
                any("sysctl" in f and kv in f for f in flat),
                f"cleanup must restore {kv}",
            )


class CleanupResolvConf(unittest.TestCase):
    """The resolv.conf restore reuses the persistent backup written by
    Task 1.5's ResolvConfManager. cleanup must restore from it and drop it.
    """

    def setUp(self) -> None:
        import tempfile

        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.resolv = self.root / "resolv.conf"
        self.backup = self.root / "var" / "resolv.conf.orig"
        # cleanup imports RESOLV_CONF / RESOLV_BACKUP into its own namespace.
        self._p1 = patch.object(cleanup, "RESOLV_CONF", self.resolv)
        self._p2 = patch.object(cleanup, "RESOLV_BACKUP", self.backup)
        self._p1.start()
        self._p2.start()
        self.addCleanup(self._p1.stop)
        self.addCleanup(self._p2.stop)

    def _noop_run(self):  # type: ignore[no-untyped-def]
        def fake_run(cmd, *a, **k):  # type: ignore[no-untyped-def]
            class _R:
                returncode = 0

            return _R()

        return fake_run

    def test_restore_from_backup_overwrites_managed_file(self) -> None:
        original = b"nameserver 1.1.1.1\n"
        self.backup.parent.mkdir(parents=True, exist_ok=True)
        self.backup.write_bytes(original)
        self.resolv.write_bytes(b"# Managed by dsm\nnameserver 10.8.0.1\n")

        with patch.object(cleanup.subprocess, "run", side_effect=self._noop_run()):
            cleanup.cleanup_host_state()

        self.assertEqual(self.resolv.read_bytes(), original)
        # Backup consumed so a later genuine apply captures a fresh original.
        self.assertFalse(self.backup.exists())

    def test_no_backup_removes_only_managed_file(self) -> None:
        self.resolv.write_bytes(b"# Managed by dsm\nnameserver 10.8.0.1\n")
        with patch.object(cleanup.subprocess, "run", side_effect=self._noop_run()):
            cleanup.cleanup_host_state()
        # No backup -> dsm-managed file is removed (host falls back to DHCP/NM).
        self.assertFalse(self.resolv.exists())

    def test_no_backup_leaves_genuine_file_untouched(self) -> None:
        genuine = b"nameserver 9.9.9.9\n"
        self.resolv.write_bytes(genuine)
        with patch.object(cleanup.subprocess, "run", side_effect=self._noop_run()):
            cleanup.cleanup_host_state()
        # Not dsm-managed and no backup -> must NOT touch the operator's file.
        self.assertEqual(self.resolv.read_bytes(), genuine)


class CleanupCliDispatch(unittest.TestCase):
    """`dsm cleanup` dispatches to cleanup_host_state and exits 0 without a
    config (no passphrase, no store unlock).
    """

    def test_cli_cleanup_dispatches_and_exits_zero(self) -> None:
        from dsm import __main__ as cli

        called: dict[str, bool] = {"ran": False}

        def fake_cleanup() -> None:
            called["ran"] = True

        argv = ["dsm", "cleanup"]
        with patch.object(cli.sys, "argv", argv):
            with patch("dsm.net.cleanup.cleanup_host_state", fake_cleanup):
                # No SystemExit expected: main() returns for the cleanup branch.
                cli.main()
        self.assertTrue(called["ran"])


class UnitFile(unittest.TestCase):
    @unittest.skipUnless(shutil.which("systemd-analyze"), "systemd-analyze absent")
    def test_unit_verifies(self) -> None:
        unit = Path(__file__).resolve().parent.parent / "deploy" / "dsm.service"
        # `verify` warns on unknown keys; StartLimitIntervalSec in [Service]
        # would warn — after the move it must not.
        proc = subprocess.run(
            ["systemd-analyze", "verify", str(unit)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotIn("StartLimitIntervalSec", proc.stderr)


if __name__ == "__main__":
    unittest.main()
