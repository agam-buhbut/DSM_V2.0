"""B2 regression tests for resolv.conf backup durability.

Two bugs are covered here:

  (a) remove() used to unconditionally drop the persistent backup and clear
      the captured original inside its ``finally`` — even when the restore
      write raised — permanently losing the operator's real resolv.conf. The
      fix gates that teardown on a ``restored`` flag set only after a restore
      branch completes cleanly. See ``test_failed_restore_keeps_backup``.

  (b) When the original resolv.conf was a SYMLINK (systemd-resolved /
      NetworkManager hosts) apply() recorded the target only in memory. A
      crash then lost the original and the coarse cleanup path deleted
      resolv.conf. The fix persists the symlink target to the backup via a
      sentinel line and reconstructs the symlink on restore. See
      ``test_symlink_crash_recovery_via_cleanup`` and
      ``test_symlink_crash_recovery_via_manager``.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from dsm.net import cleanup, resolv_conf
from dsm.net.resolv_conf import DSM_MARKER, ResolvConfManager

NAMESERVER = "10.8.0.1"


@pytest.fixture
def paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    """Redirect the managed globals into ``tmp_path`` for both modules."""
    resolv = tmp_path / "etc" / "resolv.conf"
    backup = tmp_path / "var" / "lib" / "dsm" / "resolv.conf.orig"
    resolv.parent.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(resolv_conf, "RESOLV_CONF", resolv)
    monkeypatch.setattr(resolv_conf, "RESOLV_BACKUP", backup)
    # cleanup imported the names directly — patch its copies too.
    monkeypatch.setattr(cleanup, "RESOLV_CONF", resolv)
    monkeypatch.setattr(cleanup, "RESOLV_BACKUP", backup)
    return resolv, backup


def _managed() -> ResolvConfManager:
    return ResolvConfManager(NAMESERVER)


def test_failed_restore_keeps_backup(
    paths: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    resolv, backup = paths
    original = b"nameserver 203.0.113.9\noptions timeout:1\n"
    resolv.write_bytes(original)

    mgr = _managed()
    mgr.apply()
    assert backup.read_bytes() == original

    # Make the restore write blow up part-way through remove().
    def _boom(*_a: object, **_k: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(resolv_conf, "atomic_write", _boom)
    mgr.remove()

    # KEY: the persistent backup and the captured original must survive a
    # failed restore so the crash-path cleanup (or a retry) can still recover.
    assert backup.read_bytes() == original
    assert mgr._original_contents == original  # noqa: SLF001

    # And the coarse cleanup path can now finish the job from that backup.
    cleanup._restore_resolv_conf()  # noqa: SLF001
    assert resolv.read_bytes() == original
    assert not backup.exists()


def test_apply_over_symlink_persists_target(paths: tuple[Path, Path]) -> None:
    resolv, backup = paths
    sentinel = resolv.parent / "stub-resolv.conf"
    sentinel.write_bytes(b"nameserver 127.0.0.53\n")
    target = str(sentinel)
    os.symlink(target, resolv)

    _managed().apply()

    # The symlink target is now durable on disk, not just in memory.
    data = backup.read_bytes()
    assert resolv_conf.parse_symlink_backup(data) == target


def test_symlink_crash_recovery_via_cleanup(paths: tuple[Path, Path]) -> None:
    resolv, _backup = paths
    sentinel = resolv.parent / "stub-resolv.conf"
    sentinel.write_bytes(b"nameserver 127.0.0.53\n")
    target = str(sentinel)
    os.symlink(target, resolv)

    # Session 1: apply, then crash — the dsm-managed file and the symlink
    # backup are on disk; the in-memory manager is gone.
    mgr = _managed()
    mgr.apply()
    assert resolv.read_bytes().startswith(DSM_MARKER)
    del mgr

    # The systemd ExecStopPost coarse cleanup runs.
    cleanup.cleanup_host_state()

    # KEY: the original symlink comes back as a symlink to the exact target,
    # not deleted and not replaced by a plain file of the resolved contents.
    assert resolv.is_symlink()
    assert os.readlink(resolv) == target


def test_symlink_crash_recovery_via_manager(paths: tuple[Path, Path]) -> None:
    resolv, backup = paths
    sentinel = resolv.parent / "stub-resolv.conf"
    sentinel.write_bytes(b"nameserver 127.0.0.53\n")
    target = str(sentinel)
    os.symlink(target, resolv)

    # Session 1: apply then crash.
    _managed().apply()

    # Session 2: a fresh manager applies over the dsm-managed file and must
    # recover the symlink target from the backup, then restore it on teardown.
    mgr2 = _managed()
    mgr2.apply()
    mgr2.remove()

    assert resolv.is_symlink()
    assert os.readlink(resolv) == target
    assert not backup.exists()
