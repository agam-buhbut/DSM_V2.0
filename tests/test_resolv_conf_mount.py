"""resolv.conf on a mount point (containers, ``ip netns exec``).

There /etc/resolv.conf is a bind mount, and rename(2) onto it fails with
EBUSY. The swap must then write the file in place, the restore and the crash
cleanup must do the same, and if the in-place write fails too the client
must exit with one ERROR line (no traceback) after unwinding as usual.
"""

from __future__ import annotations

import asyncio
import errno
import logging
import os
from collections.abc import Callable
from contextlib import ExitStack
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from dsm.core.config import Config
from dsm.net import cleanup, resolv_conf
from dsm.net.resolv_conf import DSM_MARKER, ResolvConfError, ResolvConfManager

NAMESERVER = "10.8.0.1"
ORIGINAL = b"nameserver 203.0.113.9\noptions timeout:1\n"


@pytest.fixture
def paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    """Redirect the managed globals into ``tmp_path`` for both modules."""
    resolv = tmp_path / "etc" / "resolv.conf"
    backup = tmp_path / "var" / "lib" / "dsm" / "resolv.conf.orig"
    resolv.parent.mkdir(parents=True)
    resolv.write_bytes(ORIGINAL)
    resolv.chmod(0o644)
    monkeypatch.setattr(resolv_conf, "RESOLV_CONF", resolv)
    monkeypatch.setattr(resolv_conf, "RESOLV_BACKUP", backup)
    monkeypatch.setattr(cleanup, "RESOLV_CONF", resolv)
    monkeypatch.setattr(cleanup, "RESOLV_BACKUP", backup)
    return resolv, backup


def _busy_rename(monkeypatch: pytest.MonkeyPatch, target: Path) -> Callable[[], int]:
    """Make rename onto ``target`` fail with EBUSY, as for a mount point.

    Returns a counter of the refused renames.
    """
    real_rename = os.rename
    refused = 0

    def fake_rename(src: Any, dst: Any, *a: Any, **k: Any) -> None:
        nonlocal refused
        if Path(dst) == target:
            refused += 1
            raise OSError(errno.EBUSY, os.strerror(errno.EBUSY), str(dst))
        real_rename(src, dst, *a, **k)

    monkeypatch.setattr(os, "rename", fake_rename)
    return lambda: refused


def _readonly_open(monkeypatch: pytest.MonkeyPatch, target: Path) -> None:
    """Make opening ``target`` for writing fail with EROFS."""
    real_open = os.open

    def fake_open(path: Any, flags: int, *a: Any, **k: Any) -> int:
        if Path(path) == target and flags & (os.O_WRONLY | os.O_RDWR):
            raise OSError(errno.EROFS, os.strerror(errno.EROFS), str(path))
        return real_open(path, flags, *a, **k)

    monkeypatch.setattr(os, "open", fake_open)


def _no_temp_left(resolv: Path) -> bool:
    return sorted(p.name for p in resolv.parent.iterdir()) == ["resolv.conf"]


def test_apply_and_remove_write_in_place_on_mount_point(
    paths: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    resolv, backup = paths
    inode = resolv.stat().st_ino
    refused = _busy_rename(monkeypatch, resolv)

    mgr = ResolvConfManager(NAMESERVER)
    mgr.apply()

    assert refused() == 1
    data = resolv.read_bytes()
    assert data.startswith(DSM_MARKER)
    assert f"nameserver {NAMESERVER}\n".encode() in data
    # Written through the existing file, not replaced by a new one.
    assert resolv.stat().st_ino == inode
    assert resolv.stat().st_mode & 0o777 == 0o644
    assert _no_temp_left(resolv)
    assert backup.read_bytes() == ORIGINAL

    mgr.remove()

    assert refused() == 2
    assert resolv.read_bytes() == ORIGINAL
    assert resolv.stat().st_ino == inode
    assert _no_temp_left(resolv)
    assert not backup.exists()


def test_crash_cleanup_restores_in_place_on_mount_point(
    paths: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    resolv, backup = paths
    refused = _busy_rename(monkeypatch, resolv)
    ResolvConfManager(NAMESERVER).apply()  # then "crash": no remove()

    cleanup._restore_resolv_conf()  # noqa: SLF001

    assert refused() == 2
    assert resolv.read_bytes() == ORIGINAL
    assert _no_temp_left(resolv)
    assert not backup.exists()


def test_other_rename_errors_are_not_masked(
    paths: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    resolv, _backup = paths

    def fake_rename(*_a: Any, **_k: Any) -> None:
        raise OSError(errno.EXDEV, os.strerror(errno.EXDEV))

    monkeypatch.setattr(os, "rename", fake_rename)

    with pytest.raises(ResolvConfError):
        ResolvConfManager(NAMESERVER).apply()
    # No in-place fallback for anything but EBUSY.
    assert resolv.read_bytes() == ORIGINAL


def test_apply_fails_with_one_line_error_when_in_place_fails(
    paths: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    resolv, _backup = paths
    _busy_rename(monkeypatch, resolv)
    _readonly_open(monkeypatch, resolv)

    mgr = ResolvConfManager(NAMESERVER)
    with pytest.raises(ResolvConfError) as info:
        mgr.apply()

    msg = str(info.value)
    assert msg == f"cannot write {resolv}: {os.strerror(errno.EROFS)}"
    assert "\n" not in msg
    assert resolv.read_bytes() == ORIGINAL
    assert _no_temp_left(resolv)
    # Not applied, so remove() has nothing to undo.
    mgr.remove()
    assert resolv.read_bytes() == ORIGINAL


# --------------------------------------------------------------------------- #
# Client: one ERROR line, host state unwound
# --------------------------------------------------------------------------- #


def _client_config() -> Config:
    return Config(
        mode="client",
        server_ip="10.0.0.1",
        server_port=51820,
        listen_port=0,
        key_file="/tmp/dsm-test.key",
        cert_file="/tmp/dsm-test.crt",
        ca_root_file="/tmp/dsm-test-ca.pem",
        attest_key_file="/tmp/dsm-test-attest.key",
        expected_server_cn="dsm-test-server",
        transport="udp",
    )


async def test_client_exits_with_one_line_when_resolv_conf_cannot_be_written(
    caplog: pytest.LogCaptureFixture,
) -> None:
    events: list[str] = []
    failure = ResolvConfError(Path("/etc/resolv.conf"), "Read-only file system")

    def recorder(name: str) -> type:
        class _Rec:
            def __init__(self, *_a: object, **_k: object) -> None:
                pass

            def apply(self) -> None:
                events.append(f"{name}.apply")
                if name == "resolv":
                    raise failure

            def remove(self) -> None:
                events.append(f"{name}.remove")

            def open(self) -> None:
                pass

            def configure(self, *_a: object, **_k: object) -> None:
                events.append(f"{name}.configure")

            def close(self) -> None:
                events.append(f"{name}.close")

        return _Rec

    class _Materials:
        cert_der = b""
        ca_root = object()
        crl = None

    class _Identity:
        public_key = b"\x01" * 32

    class _FakeStore:
        def __init__(self, *_a: object, **_k: object) -> None:
            self.identity = _Identity()
            self.attest_key = object()

        def unload(self) -> None:
            pass

    class _FakeTransport:
        async def bind(self, *_a: object, **_k: object) -> int:
            return 0

        async def aclose(self) -> None:
            events.append("transport.aclose")

    class _FakeKeys:
        epoch = 0

    async def _handshake(*_a: object, **_k: object) -> tuple[Any, bytes, bytes]:
        return _FakeKeys(), b"", b"\x02" * 32

    patches = [
        patch("tuncore.harden_process"),
        patch("dsm.core.hardening.set_process_nondumpable"),
        patch("dsm.crypto.attest_gate.enforce_attest_backend_policy"),
        patch("dsm.client.setup_signal_handlers"),
        patch("dsm.client.load_cert_materials", return_value=_Materials()),
        patch("dsm.client.verify_cert_matches_identity"),
        patch("dsm.crypto._stores.load_daemon_stores", return_value=True),
        patch("dsm.client.KeyStore", _FakeStore),
        patch("dsm.client.AttestStore", _FakeStore),
        patch("dsm.client.PreHandshakeKillSwitch", recorder("pre")),
        patch("dsm.client.check_clock_sync", return_value=None),
        patch("dsm.client.UDPTransport", _FakeTransport),
        patch("dsm.crypto.handshake.client_handshake", _handshake),
        patch("dsm.client.TcpTimestampsDisabler", recorder("tcp_ts")),
        patch("dsm.client.SrcValidMarkEnabler", recorder("svm")),
        patch("dsm.client.TunDevice", recorder("tun")),
        patch("dsm.client.NFTablesManager", recorder("nft")),
        patch("dsm.client.ResolvConfManager", recorder("resolv")),
    ]
    caplog.set_level(logging.ERROR)
    with ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)
        from dsm.client import run_client

        rc = await asyncio.wait_for(run_client(_client_config()), timeout=10)

    assert rc == 1
    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert len(errors) == 1
    assert errors[0].getMessage() == (
        "cannot write /etc/resolv.conf: Read-only file system; exiting"
    )
    assert errors[0].exc_info is None
    # Everything applied before resolv.conf is undone: full kill switch, TUN,
    # then the rest of the stack (pre-handshake kill switch last).
    for step in ("nft.remove", "tun.close", "svm.remove", "tcp_ts.remove"):
        assert step in events
    assert events.index("nft.remove") < events.index("tun.close")
    assert events[-1] == "pre.remove"
