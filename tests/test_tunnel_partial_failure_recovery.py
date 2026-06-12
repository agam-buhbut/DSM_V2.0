"""Partial-failure recovery for ``TunDevice.configure``.

When a mid-sequence ``ip``/``link``/``sysctl`` command fails, ``configure``
must:

  * stop issuing the *remaining* commands (no successor step runs),
  * raise a TYPED ``RuntimeError`` (the wrapped "TUN configure failed: …"),
    never the raw ``subprocess.CalledProcessError``, and
  * leave the device recoverable: ``_configured`` stays False but
    ``_ipv6_mutated`` is set, so a subsequent ``deconfigure()`` rolls the
    already-applied IPv6-disable back to the captured pre-mutation state.

DISCREPANCY (documented, not invented): ``configure()`` does NOT perform an
inline per-step undo loop. The rollback is two-phase by design — the failing
``configure()`` raises, and recovery (restoring the captured IPv6 sysctls and
best-effort tearing down route/rule/link) happens when the caller invokes
``deconfigure()`` (which ``close()`` does in its ``finally``). These tests
exercise that real contract.

The tests must NOT require root and MUST NOT touch host sysctls: the only
patched surfaces are the subprocess I/O boundary (``tunnel.subprocess.run``),
the deterministic pre-state source (``_capture_ipv6_state``), and the on-disk
state path (``_IPV6_STATE_PATH``).
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from dsm.net import tunnel
from dsm.net.tunnel import TunDevice

# configure(server_mode=True) issues exactly this sequence of commands
# through tunnel.subprocess.run (no client route/rule). Indices used below
# select the mid-sequence step at which the I/O boundary is made to fail.
_SERVER_SEQUENCE: list[list[str]] = [
    ["ip", "addr", "replace", "10.8.0.2/24", "dev", "mtun0"],
    ["ip", "link", "set", "mtun0", "mtu", "1400"],
    ["ip", "link", "set", "mtun0", "up"],
    ["sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"],
    ["sysctl", "-w", "net.ipv6.conf.mtun0.disable_ipv6=0"],
]


class _FakeRun:
    """Stub for ``subprocess.run`` that records argv and fails at step N.

    Every invocation's argv is appended to ``self.calls``. The call whose
    *strict* index (count of strict, ``check=True`` calls so far) equals
    ``fail_at`` raises ``CalledProcessError`` exactly as a real failing
    ``ip``/``sysctl`` would — but only when invoked with ``check=True``,
    so the best-effort ``ip rule del`` / teardown calls (``check`` absent
    or False) never spuriously fail.
    """

    def __init__(self, fail_at: int | None) -> None:
        self.fail_at = fail_at
        self.calls: list[list[str]] = []
        self._strict_seen = 0

    def __call__(self, cmd: object, **kwargs: object) -> MagicMock:
        argv = list(cmd)  # type: ignore[call-overload]
        self.calls.append(argv)
        if kwargs.get("check"):
            idx = self._strict_seen
            self._strict_seen += 1
            if self.fail_at is not None and idx == self.fail_at:
                raise subprocess.CalledProcessError(
                    returncode=2, cmd=argv, stderr=b"RTNETLINK answers: boom"
                )
        completed = MagicMock()
        completed.returncode = 0
        return completed


class PartialConfigureRecovery(unittest.TestCase):
    """A mid-sequence configure() failure is typed, halted, and recoverable."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.state_path = Path(self._tmp.name) / "ipv6_state.json"
        # Deterministic captured pre-state: two interfaces that were NOT
        # disabled before configure() ran. After rollback they must be put
        # back to that value (disable_ipv6=0).
        self._pre_state = {"eth0": False, "all": False}

    def _run_configure_failing_at(self, fail_at: int) -> _FakeRun:
        """Run configure(server_mode=True) with the boundary failing at step
        ``fail_at``; return the boundary stub for assertions. Asserts the
        wrapped RuntimeError propagated."""
        fake = _FakeRun(fail_at=fail_at)
        with (
            patch.object(TunDevice, "_IPV6_STATE_PATH", self.state_path),
            patch.object(
                TunDevice, "_capture_ipv6_state", return_value=dict(self._pre_state)
            ),
            patch.object(tunnel.subprocess, "run", side_effect=fake),
        ):
            tun = TunDevice(name="mtun0")
            with self.assertRaises(RuntimeError) as ctx:
                tun.configure(local_ip="10.8.0.2", server_mode=True)
            # Typed, wrapped error — NOT the raw CalledProcessError.
            self.assertNotIsInstance(ctx.exception, subprocess.CalledProcessError)
            self.assertIn("TUN configure failed", str(ctx.exception))
            self.assertIn(" ".join(_SERVER_SEQUENCE[fail_at]), str(ctx.exception))
            # Never marked fully configured; but mutation flag set so the
            # subsequent deconfigure() will restore.
            self.assertFalse(tun._configured)
            self.assertTrue(tun._ipv6_mutated)
        self._tun = tun  # for the recovery half of the test
        return fake

    def test_failure_halts_sequence_and_applies_only_prior_steps(self) -> None:
        # Fail at step 2 ("ip link set up"): the two prior steps must have
        # been issued to the boundary, the failing step is the last one
        # issued, and NO successor step (the sysctls) runs.
        fail_at = 2
        fake = self._run_configure_failing_at(fail_at)

        self.assertEqual(fake.calls, _SERVER_SEQUENCE[: fail_at + 1])
        for prior in _SERVER_SEQUENCE[:fail_at]:
            self.assertIn(prior, fake.calls)
        for successor in _SERVER_SEQUENCE[fail_at + 1 :]:
            self.assertNotIn(successor, fake.calls)

    def test_recovery_rolls_back_applied_ipv6_disable(self) -> None:
        """KEY discriminating property: after a mid-sequence failure, the
        already-applied IPv6-disable is rolled back to the captured
        pre-mutation state on deconfigure() — issued best-effort through the
        same I/O boundary."""
        # Fail at step 3 (sysctl all.disable_ipv6=1): steps 0..2 applied,
        # the IPv6-disable step is where it dies.
        self._run_configure_failing_at(fail_at=3)
        tun = self._tun

        recover = _FakeRun(fail_at=None)
        with (
            patch.object(TunDevice, "_IPV6_STATE_PATH", self.state_path),
            patch.object(tunnel.subprocess, "run", side_effect=recover),
        ):
            tun.deconfigure()

        # The captured pre-state (eth0=False, all=False) must be written back
        # as disable_ipv6=0 — i.e. the disable step is undone. A build that
        # forgot to set _ipv6_mutated on partial failure would skip restore
        # entirely and these would be absent.
        self.assertIn(
            ["sysctl", "-w", "net.ipv6.conf.eth0.disable_ipv6=0"], recover.calls
        )
        self.assertIn(
            ["sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=0"], recover.calls
        )
        # Nothing should ever be RE-disabled (=1) during recovery.
        self.assertFalse(
            any(c[-1].endswith("disable_ipv6=1") for c in recover.calls),
            f"recovery must not re-disable IPv6: {recover.calls}",
        )
        # Flags cleared so a second deconfigure() is a no-op.
        self.assertFalse(tun._configured)
        self.assertFalse(tun._ipv6_mutated)

    def test_recovery_is_idempotent_after_partial_failure(self) -> None:
        # After the first recovery clears the flags, a second deconfigure()
        # must not re-issue the IPv6 restore (state file already consumed).
        self._run_configure_failing_at(fail_at=1)
        tun = self._tun

        first = _FakeRun(fail_at=None)
        with (
            patch.object(TunDevice, "_IPV6_STATE_PATH", self.state_path),
            patch.object(tunnel.subprocess, "run", side_effect=first),
        ):
            tun.deconfigure()
        self.assertFalse(self.state_path.exists())

        second = _FakeRun(fail_at=None)
        with (
            patch.object(TunDevice, "_IPV6_STATE_PATH", self.state_path),
            patch.object(tunnel.subprocess, "run", side_effect=second),
        ):
            tun.deconfigure()
        # Best-effort link/route/rule teardown may repeat, but no sysctl
        # restore is issued the second time.
        self.assertFalse(
            any(c[0] == "sysctl" for c in second.calls),
            f"second deconfigure must not re-restore IPv6: {second.calls}",
        )


if __name__ == "__main__":
    unittest.main()
