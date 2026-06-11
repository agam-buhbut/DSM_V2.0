"""Phase 1.4: IPv6 state is restored even when configure() fails partway,
and the global all/default disable_ipv6 sysctls are captured + restored.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dsm.net import tunnel
from dsm.net.tunnel import TunDevice


class _Boom(RuntimeError):
    pass


class Ipv6PartialConfigureRestore(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.state_path = Path(self._tmp.name) / "ipv6_state.json"

    def test_restore_runs_after_partial_configure_failure(self) -> None:
        # _run_commands raises after IPv6 was already disabled mid-sequence.
        # The stub honours `strict` exactly as the real _run_commands does:
        # configure() calls it with strict=True (default) so the failure
        # propagates, but deconfigure()'s leak-safe teardown batch uses
        # strict=False, which the real function swallows — so the stub must
        # not raise there, otherwise it would mask the restore path under test.
        def fake_run_commands(cmds: object, *, strict: bool = True) -> None:
            if strict:
                raise _Boom("cmd failed")

        with (
            patch.object(TunDevice, "_IPV6_STATE_PATH", self.state_path),
            patch.object(
                TunDevice, "_capture_ipv6_state", return_value={"eth0": False}
            ),
            patch.object(tunnel, "_run_commands", side_effect=fake_run_commands),
            patch.object(tunnel.subprocess, "run"),
            patch.object(TunDevice, "_restore_ipv6_state") as restore_mock,
        ):
            tun = TunDevice(name="mtun0")
            with self.assertRaises(_Boom):
                tun.configure(local_ip="10.8.0.2")
            self.assertFalse(tun._configured)  # never fully configured
            # ...but the IPv6 mutation flag IS set, so deconfigure restores.
            tun.deconfigure()
            restore_mock.assert_called_once()

    def test_capture_includes_global_all_and_default(self) -> None:
        # _capture_ipv6_state must include net.ipv6.conf.all/default.
        fake_proc = {
            "all": "0",
            "default": "0",
            "eth0": "0",
        }

        real_read_text = Path.read_text

        def fake_read_text(self_path: Path, *a: object, **k: object) -> str:
            name = self_path.parent.name  # .../conf/<name>/disable_ipv6
            if name in fake_proc:
                return fake_proc[name] + "\n"
            return real_read_text(self_path, *a, **k)  # type: ignore[arg-type]

        with (
            patch.object(Path, "read_text", fake_read_text),
            patch.object(
                Path,
                "iterdir",
                return_value=[Path("/sys/class/net/eth0")],
            ),
            patch.object(Path, "exists", return_value=True),
        ):
            tun = TunDevice(name="mtun0")
            state = tun._capture_ipv6_state()
        self.assertIn("all", state)
        self.assertIn("default", state)


if __name__ == "__main__":
    unittest.main()
