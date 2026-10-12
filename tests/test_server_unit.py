"""The server's systemd unit must leave /proc/sys visible: the server writes its
network settings there when a client connects."""

from __future__ import annotations

from pathlib import Path

SERVER_UNIT = Path(__file__).resolve().parent.parent / "deploy" / "dsm.service"


def test_the_server_unit_can_write_proc_sys() -> None:
    code = [
        line.strip()
        for line in SERVER_UNIT.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    assert not any(line.startswith("ProcSubset=") for line in code)
    assert not any(line.startswith("ProtectKernelTunables=") for line in code)
    assert "ProtectProc=invisible" in code
