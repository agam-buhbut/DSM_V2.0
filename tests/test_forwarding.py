"""Server forwarding/NAT setup: dsm.net.forwarding.

``IPForwardingManager`` and ``MasqueradeManager`` had no tests. They run as
root in production, so these exercise the real apply()/remove() logic with
only the I/O boundary mocked:

  * IPForwardingManager writes /proc/sys via SysctlOverride; we redirect
    the module-level ``sysctl_path`` into a tmp tree (same technique as
    tests/test_sysctl.py) so the real set/restore runs against files we
    control. No root, no real kernel state touched.
  * MasqueradeManager shells out to ``nft``; we patch
    ``forwarding.subprocess.run`` and assert the argv + ruleset, and that
    remove() reverses apply() and is best-effort/idempotent.

KEY properties proved: apply() turns ip_forward ON and tightens the
redirect/rp_filter sysctls; remove() restores every original; MASQUERADE
emits the correct delete-table teardown and is idempotent when never
applied.
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dsm.core import sysctl
from dsm.net import forwarding
from dsm.net.forwarding import IPForwardingManager, MasqueradeManager


class IPForwardingApplyRemoveTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        patcher = patch.object(sysctl, "sysctl_path", self._fake_path)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _fake_path(self, key: str) -> Path:
        return self.root / key.replace(".", "/")

    def _seed(self, key: str, value: str) -> Path:
        path = self._fake_path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"{value}\n")
        return path

    def _read(self, key: str) -> str:
        return self._fake_path(key).read_text().strip()

    def test_apply_enables_forwarding_and_hardens_redirects(self) -> None:
        # Seed kernel defaults: forwarding off, redirects on, strict rp_filter.
        ip_forward = self._seed("net.ipv4.ip_forward", "0")
        self._seed("net.ipv4.conf.all.send_redirects", "1")
        self._seed("net.ipv4.conf.default.send_redirects", "1")
        self._seed("net.ipv4.conf.all.accept_redirects", "1")
        self._seed("net.ipv4.conf.default.accept_redirects", "1")
        self._seed("net.ipv4.conf.all.secure_redirects", "1")
        self._seed("net.ipv4.conf.all.rp_filter", "1")

        mgr = IPForwardingManager()
        mgr.apply()

        # The load-bearing security flip: forwarding is now ON.
        self.assertEqual(ip_forward.read_text().strip(), "1")
        # ICMP-redirect bypass surface is closed on both all/default.
        self.assertEqual(self._read("net.ipv4.conf.all.send_redirects"), "0")
        self.assertEqual(self._read("net.ipv4.conf.default.send_redirects"), "0")
        self.assertEqual(self._read("net.ipv4.conf.all.accept_redirects"), "0")
        self.assertEqual(self._read("net.ipv4.conf.default.accept_redirects"), "0")
        self.assertEqual(self._read("net.ipv4.conf.all.secure_redirects"), "0")
        # Loose reverse-path filtering for asymmetric tunnel paths.
        self.assertEqual(self._read("net.ipv4.conf.all.rp_filter"), "2")

    def test_remove_restores_every_touched_value(self) -> None:
        ip_forward = self._seed("net.ipv4.ip_forward", "0")
        send_all = self._seed("net.ipv4.conf.all.send_redirects", "1")
        rp_all = self._seed("net.ipv4.conf.all.rp_filter", "1")
        self._seed("net.ipv4.conf.default.send_redirects", "1")
        self._seed("net.ipv4.conf.all.accept_redirects", "1")
        self._seed("net.ipv4.conf.default.accept_redirects", "1")
        self._seed("net.ipv4.conf.all.secure_redirects", "1")

        mgr = IPForwardingManager()
        mgr.apply()
        self.assertEqual(ip_forward.read_text().strip(), "1")

        mgr.remove()
        # Originals are back: the manager leaves no kernel state behind.
        self.assertEqual(ip_forward.read_text().strip(), "0")
        self.assertEqual(send_all.read_text().strip(), "1")
        self.assertEqual(rp_all.read_text().strip(), "1")

    def test_apply_sets_per_iface_keys_when_tun_named(self) -> None:
        self._seed("net.ipv4.ip_forward", "0")
        self._seed("net.ipv4.conf.all.send_redirects", "1")
        self._seed("net.ipv4.conf.default.send_redirects", "1")
        self._seed("net.ipv4.conf.all.accept_redirects", "1")
        self._seed("net.ipv4.conf.default.accept_redirects", "1")
        self._seed("net.ipv4.conf.all.secure_redirects", "1")
        self._seed("net.ipv4.conf.all.rp_filter", "1")
        # Per-iface keys default to the insecure direction.
        self._seed("net.ipv4.conf.mtun0.send_redirects", "1")
        self._seed("net.ipv4.conf.mtun0.accept_redirects", "1")
        self._seed("net.ipv4.conf.mtun0.rp_filter", "1")
        self._seed("net.ipv4.conf.mtun0.accept_local", "0")

        IPForwardingManager(tun_name="mtun0").apply()

        self.assertEqual(self._read("net.ipv4.conf.mtun0.send_redirects"), "0")
        self.assertEqual(self._read("net.ipv4.conf.mtun0.accept_redirects"), "0")
        self.assertEqual(self._read("net.ipv4.conf.mtun0.rp_filter"), "2")
        self.assertEqual(self._read("net.ipv4.conf.mtun0.accept_local"), "1")

    def test_invalid_tun_name_rejected(self) -> None:
        # Injection guard: a tun_name that escapes the sysctl-key grammar
        # must be refused before it is spliced into a /proc path.
        for bad in ("eth0; rm -rf", "a" * 32, "bad name"):
            with self.subTest(tun_name=bad):
                with self.assertRaises(ValueError):
                    IPForwardingManager(tun_name=bad)


class _RecordingRun:
    """Records subprocess.run calls; optional side effects per call."""

    def __init__(self, side_effects: list[object] | None = None) -> None:
        self._side_effects = list(side_effects or [])
        self.calls: list[dict[str, object]] = []

    def __call__(self, *args: object, **kwargs: object) -> object:
        self.calls.append({"args": args, "kwargs": kwargs})
        if self._side_effects:
            effect = self._side_effects.pop(0)
            if isinstance(effect, BaseException):
                raise effect
            return effect
        return subprocess.CompletedProcess(
            args=args, returncode=0, stdout=b"", stderr=b""
        )


class MasqueradeManagerTest(unittest.TestCase):
    TUN = "mtun0"

    def _argv(self, call: dict[str, object]) -> list[str]:
        return list(call["args"][0])  # type: ignore[index]

    def test_apply_loads_masquerade_ruleset_via_nft(self) -> None:
        fake = _RecordingRun()
        mgr = MasqueradeManager(self.TUN)
        with patch.object(forwarding.subprocess, "run", fake):
            mgr.apply()

        self.assertTrue(mgr._applied)
        self.assertEqual(len(fake.calls), 1)
        self.assertEqual(self._argv(fake.calls[0]), ["nft", "-f", "-"])
        ruleset = fake.calls[0]["kwargs"]["input"].decode()  # type: ignore[union-attr,index]
        self.assertIn(f"table inet {MasqueradeManager.TABLE}", ruleset)
        self.assertIn("type nat hook postrouting", ruleset)
        self.assertIn("masquerade", ruleset)
        # SNAT is scoped to traffic that arrived via the TUN and leaves
        # elsewhere — not a blanket masquerade.
        self.assertIn(f'iifname "{self.TUN}"', ruleset)
        self.assertIn(f'oifname != "{self.TUN}"', ruleset)

    def test_remove_deletes_the_table(self) -> None:
        fake = _RecordingRun()
        mgr = MasqueradeManager(self.TUN)
        with patch.object(forwarding.subprocess, "run", fake):
            mgr.apply()
            mgr.remove()

        self.assertFalse(mgr._applied)
        self.assertEqual(len(fake.calls), 2)
        self.assertEqual(
            self._argv(fake.calls[1]),
            ["nft", "delete", "table", "inet", MasqueradeManager.TABLE],
        )

    def test_remove_is_noop_when_never_applied(self) -> None:
        # Idempotent/best-effort: remove() without a prior apply() must not
        # shell out at all (nothing to tear down).
        fake = _RecordingRun()
        mgr = MasqueradeManager(self.TUN)
        with patch.object(forwarding.subprocess, "run", fake):
            mgr.remove()
        self.assertEqual(fake.calls, [])
        self.assertFalse(mgr._applied)

    def test_apply_failure_is_best_effort_not_fatal(self) -> None:
        # nft missing -> apply logs and leaves _applied False, never raises.
        fake = _RecordingRun([FileNotFoundError("nft")])
        mgr = MasqueradeManager(self.TUN)
        with patch.object(forwarding.subprocess, "run", fake):
            with self.assertLogs(forwarding.log, level="WARNING"):
                mgr.apply()  # must not raise
        self.assertFalse(mgr._applied)

    def test_apply_called_process_error_logged_not_raised(self) -> None:
        err = subprocess.CalledProcessError(
            returncode=1, cmd=["nft"], stderr=b"syntax error"
        )
        fake = _RecordingRun([err])
        mgr = MasqueradeManager(self.TUN)
        with patch.object(forwarding.subprocess, "run", fake):
            with self.assertLogs(forwarding.log, level="WARNING") as cm:
                mgr.apply()
        self.assertFalse(mgr._applied)
        self.assertTrue(any("syntax error" in m for m in cm.output))

    def test_invalid_tun_name_rejected(self) -> None:
        for bad in ("eth0; drop", "way-too-long-interface-name", "bad name", ""):
            with self.subTest(tun_name=bad):
                with self.assertRaises(ValueError):
                    MasqueradeManager(bad)


if __name__ == "__main__":
    unittest.main()
