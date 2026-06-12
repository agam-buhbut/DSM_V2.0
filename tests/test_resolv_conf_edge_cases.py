"""Edge cases for :class:`dsm.net.resolv_conf.ResolvConfManager`.

Complements ``tests/test_resolv_conf.py`` (which locks the three happy-path
states) by exercising the crash-recovery machinery that the happy-path tests
never touch:

  * the write-once persistent backup (``RESOLV_BACKUP``) and its guard against
    being overwritten by a later (possibly dsm-managed) capture,
  * the ``_DSM_MARKER`` guard — apply() reading back OUR OWN file after a crash
    must recover the *real* original from the backup, never adopt the managed
    file as the original,
  * the Phase-1.5 OSError fix — if the file disappears between ``exists()`` and
    ``read_bytes()``, apply() must NOT poison the persistent backup with ``b""``
    (which would later restore an empty resolv.conf, breaking DNS),
  * remove() preferring the persistent backup when nothing was captured
    in-memory (a fresh manager that took over after a crash),
  * restore when the prior file was a symlink, owned-by-other, or missing.

The ONLY thing mocked is the I/O boundary: the module globals ``RESOLV_CONF``
and ``RESOLV_BACKUP`` are redirected into ``tmp_path``. The real
``ResolvConfManager`` and the real ``atomic_write`` it calls run end-to-end
against files we own.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from dsm.net import resolv_conf
from dsm.net.resolv_conf import _DSM_MARKER, ResolvConfManager

NAMESERVER = "10.8.0.1"


@pytest.fixture
def paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    """Redirect both managed globals into ``tmp_path``.

    Returns ``(resolv, backup)``. Both are patched on the module object so the
    production code reads them directly and hands them to ``atomic_write``.
    """
    resolv = tmp_path / "etc" / "resolv.conf"
    backup = tmp_path / "var" / "lib" / "dsm" / "resolv.conf.orig"
    resolv.parent.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(resolv_conf, "RESOLV_CONF", resolv)
    monkeypatch.setattr(resolv_conf, "RESOLV_BACKUP", backup)
    return resolv, backup


def _managed() -> ResolvConfManager:
    return ResolvConfManager(NAMESERVER)


def _crash(mgr: ResolvConfManager) -> None:
    """Simulate a process crash after apply(): the on-disk dsm file and the
    persistent backup survive, but the in-memory manager state is gone."""
    del mgr


# ── write-once persistent backup ─────────────────────────────────────────────


def test_apply_over_genuine_file_persists_backup(paths: tuple[Path, Path]) -> None:
    resolv, backup = paths
    original = b"nameserver 1.1.1.1\noptions timeout:1\n"
    resolv.write_bytes(original)

    _managed().apply()

    # The real original is captured into the persistent backup, byte-exact.
    assert backup.read_bytes() == original


def test_backup_is_write_once_not_clobbered_by_later_genuine_file(
    paths: tuple[Path, Path],
) -> None:
    resolv, backup = paths
    # The real original the operator authored.
    original = b"nameserver 1.1.1.1\n# the real original\n"
    # A DIFFERENT, also-genuine (non-marker) file that a DNS-managing service
    # (NetworkManager / systemd-resolved) writes over resolv.conf after a crash
    # but before the next session starts. This is the scenario the write-once
    # guard exists for: apply() will reach _save_backup() with non-marker
    # contents a SECOND time and must refuse to overwrite the good backup.
    decoy = b"nameserver 5.5.5.5\n# NetworkManager DHCP renew\n"
    resolv.write_bytes(original)

    # Session 1 applies (captures the real original into the backup) and then
    # CRASHES before remove().
    s1 = _managed()
    s1.apply()
    assert backup.read_bytes() == original
    _crash(s1)

    # Between sessions a DNS-managing service overwrites resolv.conf with its
    # own genuine (non-marker) file.
    resolv.write_bytes(decoy)

    # Session 2 starts and applies. Because the on-disk file is a genuine
    # non-marker file, apply() calls _save_backup() again.
    s2 = _managed()
    s2.apply()

    # KEY: the backup still holds the REAL original. If _save_backup were not
    # write-once, the backup would now be the decoy and the true original would
    # be lost forever — teardown would then "restore" the wrong nameserver.
    assert backup.read_bytes() == original
    assert backup.read_bytes() != decoy


# ── _DSM_MARKER guard (crash recovery) ───────────────────────────────────────


def test_crash_restart_restores_real_original_not_managed_file(
    paths: tuple[Path, Path],
) -> None:
    resolv, backup = paths
    original = b"nameserver 9.9.9.9\nsearch corp.example\n"
    resolv.write_bytes(original)

    # Session 1: apply, then crash (managed file + backup on disk).
    s1 = _managed()
    s1.apply()
    managed_bytes = resolv.read_bytes()
    assert managed_bytes.startswith(_DSM_MARKER)
    _crash(s1)

    # Session 2: a fresh manager finds the dsm-managed file. apply() must read
    # the marker, refuse to treat the managed file as the original, and recover
    # the true original from the persistent backup instead.
    s2 = _managed()
    s2.apply()
    s2.remove()

    # KEY: teardown restores the REAL original from the backup — not the
    # dsm-managed file. A broken marker guard would round-trip the managed file
    # (with our nameserver) back as if it were the operator's config, silently
    # pinning DNS at the VPN server forever after the VPN is gone.
    assert resolv.read_bytes() == original
    assert not resolv.read_bytes().startswith(_DSM_MARKER)


def test_remove_prefers_persistent_backup_when_nothing_captured(
    paths: tuple[Path, Path],
) -> None:
    resolv, backup = paths
    original = b"nameserver 8.8.4.4\n"
    backup.parent.mkdir(parents=True, exist_ok=True)
    backup.write_bytes(original)

    # Manager with no in-memory original (both capture fields None), but marked
    # applied as a crash-restart takeover would leave it.
    mgr = _managed()
    resolv.write_bytes(_DSM_MARKER + b" placeholder\n")
    mgr._applied = True  # type: ignore[attr-defined]

    mgr.remove()

    # KEY: with nothing captured in-memory, remove() falls back to the
    # persistent backup and restores it exactly.
    assert resolv.read_bytes() == original


# ── Phase-1.5 OSError fix: do not poison the backup with b"" ──────────────────


def test_disappearing_file_does_not_poison_backup_with_empty(
    paths: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    resolv, backup = paths
    original = b"nameserver 1.0.0.1\n# precious\n"
    resolv.write_bytes(original)

    # Force the race: is_symlink()/exists() see the file, but read_bytes()
    # raises as if it vanished between the checks. apply() must treat this as
    # "no original to restore" and must NOT write a b"" backup.
    real_read_bytes = Path.read_bytes

    def flaky_read_bytes(self_path: Path) -> bytes:
        if self_path == resolv:
            raise OSError("vanished between exists() and read")
        return real_read_bytes(self_path)

    monkeypatch.setattr(Path, "read_bytes", flaky_read_bytes)

    mgr = _managed()
    mgr.apply()
    # Stop the read flakiness so the assertions below read real bytes.
    monkeypatch.setattr(Path, "read_bytes", real_read_bytes)

    # KEY: the persistent backup was NOT created with empty contents. A b""
    # backup would, on a later crash-restart, restore an EMPTY resolv.conf and
    # silently break DNS resolution for the host.
    assert not backup.exists()
    # The managed file is still installed (apply completed).
    assert resolv.read_bytes().startswith(_DSM_MARKER)


def test_disappearing_file_restore_removes_override_no_empty_write(
    paths: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    resolv, backup = paths
    resolv.write_bytes(b"nameserver 1.0.0.1\n")

    real_read_bytes = Path.read_bytes

    def flaky_read_bytes(self_path: Path) -> bytes:
        if self_path == resolv:
            raise OSError("vanished")
        return real_read_bytes(self_path)

    monkeypatch.setattr(Path, "read_bytes", flaky_read_bytes)

    mgr = _managed()
    mgr.apply()
    # Stop the read flakiness so remove()'s own reads (if any) behave.
    monkeypatch.setattr(Path, "read_bytes", real_read_bytes)
    mgr.remove()

    # Captured nothing and no backup -> remove() unlinks our override rather
    # than writing an empty file back.
    assert not resolv.exists()


# ── restore when prior state is unusual ──────────────────────────────────────


def test_restore_symlink_target_exactly(paths: tuple[Path, Path]) -> None:
    resolv, _backup = paths
    sentinel = resolv.parent / "stub-resolv.conf"
    sentinel.write_bytes(b"nameserver 127.0.0.53\n")
    target = str(sentinel)
    os.symlink(target, resolv)

    mgr = _managed()
    mgr.apply()
    assert not resolv.is_symlink()  # replaced by a concrete file
    mgr.remove()

    # KEY: the original symlink (and its exact target) is restored, not a copy
    # of the resolved contents. systemd-resolved's stub symlink must come back
    # as a symlink so resolved keeps managing it after teardown.
    assert resolv.is_symlink()
    assert os.readlink(resolv) == target
    assert sentinel.read_bytes() == b"nameserver 127.0.0.53\n"


def test_restore_missing_original_unlinks_override(
    paths: tuple[Path, Path],
) -> None:
    resolv, backup = paths
    assert not resolv.exists()

    mgr = _managed()
    mgr.apply()
    assert resolv.read_bytes().startswith(_DSM_MARKER)
    mgr.remove()

    # No original existed -> the override is unlinked, leaving the path absent
    # exactly as it was before apply(). No backup is left behind either.
    assert not resolv.exists()
    assert not backup.exists()


def test_owned_by_other_original_restored_byte_exact(
    paths: tuple[Path, Path],
) -> None:
    # We cannot chown to another uid without privileges, so model the
    # owned-by-other property that actually matters to the restore path: the
    # file's BYTES are preserved verbatim through capture+restore regardless of
    # ownership, because remove() rewrites the captured bytes via atomic_write
    # rather than editing in place.
    resolv, _backup = paths
    original = b"# operator-authored, owned by root\nnameserver 192.0.2.53\n"
    resolv.write_bytes(original)

    mgr = _managed()
    mgr.apply()
    mgr.remove()

    assert resolv.read_bytes() == original


def test_backup_dropped_after_successful_restore(
    paths: tuple[Path, Path],
) -> None:
    resolv, backup = paths
    original = b"nameserver 198.51.100.1\n"
    resolv.write_bytes(original)

    mgr = _managed()
    mgr.apply()
    assert backup.read_bytes() == original
    mgr.remove()

    # After a clean restore the backup is removed so the NEXT session's apply()
    # captures a fresh original rather than restoring a stale one.
    assert not backup.exists()
    assert resolv.read_bytes() == original
