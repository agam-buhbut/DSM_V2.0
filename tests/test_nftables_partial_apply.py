"""Idempotent failure-recovery surface of ``dsm.net.nftables``.

Companion to ``tests/test_nftables.py``. That file proves the fail-closed
apply contract; this file proves the *teardown* side of a partially-applied
kill switch: when ``NFTablesManager.apply()`` raises (the full-table commit
fails after the pre-handshake table was already torn down), the rollback path
``remove()`` must be **best-effort and idempotent** — it must never raise, even

  * when the kill-switch tables were never successfully installed, and
  * when an underlying ``nft delete table`` itself errors (missing table,
    ``nft`` not installed, or a transient subprocess failure), and
  * when ``remove()`` is invoked more than once.

The only thing mocked is the I/O boundary: ``dsm.net.nftables.subprocess.run``
(the single place the module shells out to ``nft``). The real templates under
``nftables/`` are loaded unmodified.
"""

from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

from dsm.net import nftables
from dsm.net.nftables import NFTablesManager, PreHandshakeKillSwitch

V4_IP = "203.0.113.7"
PORT = 51820

# The two inet tables the full kill switch installs and tears down.
_FULL_TABLES = ("dsm_killswitch", "dsm_dns_leak")
_DELETE_PREFIX = ("nft", "delete", "table", "inet")


class _ScriptedRun:
    """Stand-in for ``subprocess.run`` driven by a per-argv script.

    Two channels:
      * ``apply_effects`` is consumed one entry per ``nft -f -`` call (the
        apply path). An exception instance is raised; anything else is
        returned. When exhausted, a benign success object is returned.
      * ``delete_effects`` is consumed one entry per ``nft delete table``
        call (the remove path), with the same raise-or-return semantics.

    Every call's full argv is captured in ``calls`` so the rollback path can
    be asserted on (which tables were targeted, and in what order).
    """

    def __init__(
        self,
        *,
        apply_effects: list[object] | None = None,
        delete_effects: list[object] | None = None,
    ) -> None:
        self._apply = list(apply_effects or [])
        self._delete = list(delete_effects or [])
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, args: object, *_: object, **__: object) -> object:
        argv = tuple(str(a) for a in args)  # type: ignore[arg-type]
        self.calls.append(argv)
        queue = self._delete if argv[:4] == _DELETE_PREFIX else self._apply
        if queue:
            effect = queue.pop(0)
            if isinstance(effect, BaseException):
                raise effect
            return effect
        return subprocess.CompletedProcess(args=argv, returncode=0, stdout=b"")

    def delete_targets(self) -> list[str]:
        """The inet-table names passed to ``nft delete table inet <name>``."""
        return [c[4] for c in self.calls if c[:4] == _DELETE_PREFIX and len(c) > 4]


def _called_process_error(stderr: bytes) -> subprocess.CalledProcessError:
    return subprocess.CalledProcessError(returncode=1, cmd=["nft"], stderr=stderr)


class PartialApplyRollbackTest(unittest.TestCase):
    def test_apply_raises_when_full_commit_fails_both_attempts(self) -> None:
        """Precondition for the rollback tests: a full-table commit that fails
        on both the delete-prefixed transaction AND the fallback propagates a
        ``RuntimeError`` (fail-closed). This is the "partial apply" state the
        rollback must recover from."""
        fake = _ScriptedRun(
            apply_effects=[
                _called_process_error(b"commit failed near line 9"),
                _called_process_error(b"commit failed near line 9"),
            ]
        )
        with patch.object(nftables.subprocess, "run", fake):
            with self.assertRaises(RuntimeError):
                NFTablesManager(V4_IP, PORT).apply()

    def test_remove_after_failed_apply_does_not_raise(self) -> None:
        """KEY: after a failed/partial apply, ``remove()`` is best-effort. The
        underlying ``nft delete table`` reports the missing table via a
        ``CalledProcessError`` (or even ``nft`` is absent), yet ``remove()``
        must swallow it and complete — leaving no leaked tables behind and no
        exception propagated to the teardown path."""
        fake = _ScriptedRun(
            apply_effects=[
                _called_process_error(b"boom"),
                _called_process_error(b"boom"),
            ],
            # Both delete calls fail (table was never committed / nft errors).
            delete_effects=[
                _called_process_error(b"No such file or directory: table"),
                _called_process_error(b"No such file or directory: table"),
            ],
        )
        mgr = NFTablesManager(V4_IP, PORT)
        with patch.object(nftables.subprocess, "run", fake):
            with self.assertRaises(RuntimeError):
                mgr.apply()
            # Must NOT raise despite both delete calls erroring.
            mgr.remove()

        # Rollback attempted teardown of *both* full-killswitch tables.
        self.assertEqual(fake.delete_targets(), list(_FULL_TABLES))

    def test_remove_is_idempotent_across_repeated_calls(self) -> None:
        """Calling ``remove()`` twice (e.g. an explicit teardown followed by an
        atexit/shutdown handler) must not raise the second time and must keep
        issuing best-effort deletes — there is no ``_applied`` latch on
        ``NFTablesManager.remove()`` that could turn the repeat into a no-op,
        so the property under test is genuine idempotent safety, not a guard."""
        fake = _ScriptedRun(
            delete_effects=[
                # First teardown: tables present, both deletes succeed.
                subprocess.CompletedProcess(args=[], returncode=0, stdout=b""),
                subprocess.CompletedProcess(args=[], returncode=0, stdout=b""),
                # Second teardown: tables already gone -> nft errors, swallowed.
                _called_process_error(b"No such table"),
                _called_process_error(b"No such table"),
            ]
        )
        mgr = NFTablesManager(V4_IP, PORT)
        with patch.object(nftables.subprocess, "run", fake):
            mgr.remove()
            mgr.remove()  # idempotent: must not raise on the second call

        # Four delete attempts total: two tables x two teardowns.
        self.assertEqual(
            fake.delete_targets(),
            [*_FULL_TABLES, *_FULL_TABLES],
        )

    def test_remove_swallows_nft_not_installed(self) -> None:
        """Best-effort teardown also covers the ``nft`` binary being absent
        (``FileNotFoundError`` from the subprocess layer): ``remove()`` must
        still complete cleanly so shutdown is never blocked on a missing tool."""
        fake = _ScriptedRun(
            delete_effects=[
                FileNotFoundError("nft"),
                FileNotFoundError("nft"),
            ]
        )
        mgr = NFTablesManager(V4_IP, PORT)
        with patch.object(nftables.subprocess, "run", fake):
            mgr.remove()  # must not raise
        # It attempted both tables before giving up on each.
        self.assertEqual(fake.delete_targets(), list(_FULL_TABLES))

    def test_prehandshake_remove_after_failed_apply_is_safe(self) -> None:
        """The pre-handshake table is the *other* half of the partial-apply
        window. If its apply() raised (fatal), ``_applied`` stayed False, so
        remove() is a guarded no-op and must not shell out at all — and even a
        defensive double-remove stays silent."""
        fake = _ScriptedRun(apply_effects=[_called_process_error(b"nope")])
        ks = PreHandshakeKillSwitch(V4_IP, PORT)
        with patch.object(nftables.subprocess, "run", fake):
            with self.assertRaises(RuntimeError):
                ks.apply()
            ks.remove()  # guarded no-op (never applied)
            ks.remove()  # idempotent

        # apply() shelled out (and failed); remove() issued no delete because
        # the table was never successfully installed.
        self.assertEqual(fake.delete_targets(), [])


if __name__ == "__main__":
    unittest.main()
