"""The server's systemd unit: it must leave /proc/sys visible (the server writes
its network settings there), and its stop step runs `dsm cleanup` only after a
crash."""

from __future__ import annotations

import shlex
import subprocess
from pathlib import Path

import pytest

from tests.test_client_unit import _code

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


_STOP_POST = (
    "ExecStopPost=/bin/sh -c "
    "'[ \"$$EXIT_CODE\" = exited ] || exec /usr/local/bin/dsm cleanup'"
)


def _stop_post() -> str:
    lines = [line for line in _code(SERVER_UNIT) if line.startswith("ExecStopPost=")]
    assert len(lines) == 1, lines
    return lines[0]


def _run_stop_step(tmp_path: Path, exit_code: str | None) -> list[str]:
    """Run the unit's ExecStopPost the way systemd hands it over, with a fake
    dsm in place of /usr/local/bin/dsm. Returns the fake dsm's calls."""
    fake = tmp_path / "dsm"
    fake.write_text('#!/bin/sh\necho "$*" >>"$FAKE_DSM_LOG"\n')
    fake.chmod(0o755)
    log = tmp_path / "dsm.log"
    log.touch()
    # systemd turns $$ into $ and splits the line on shell-style quotes.
    command = _stop_post().removeprefix("ExecStopPost=").replace("$$", "$")
    argv = [
        arg.replace("/usr/local/bin/dsm", str(fake)) for arg in shlex.split(command)
    ]
    env = {"PATH": str(tmp_path / "no-bin"), "FAKE_DSM_LOG": str(log)}
    if exit_code is not None:
        env["EXIT_CODE"] = exit_code
    proc = subprocess.run(
        argv, env=env, capture_output=True, text=True, timeout=30, check=False
    )
    assert proc.returncode == 0, proc.stderr
    return log.read_text().splitlines()


def test_the_server_stop_step_line() -> None:
    assert _stop_post() == _STOP_POST


@pytest.mark.parametrize(
    ("exit_code", "calls"),
    [
        ("exited", []),  # stop, restart, start error or Python error: stack unwound
        ("killed", ["cleanup"]),  # SIGKILL, OOM, stop timeout, early SIGTERM
        ("dumped", ["cleanup"]),
        (None, ["cleanup"]),  # not set: cannot tell, clean up
    ],
)
def test_the_server_stop_step_cleans_up_only_after_a_crash(
    tmp_path: Path, exit_code: str | None, calls: list[str]
) -> None:
    assert _run_stop_step(tmp_path, exit_code) == calls
