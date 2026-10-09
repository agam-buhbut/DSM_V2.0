"""`--stop-keeps-block`: a stop leaves the start-up kill switch up.

dsm-client.service passes this flag, and its ExecStopPost takes the kill
switch down only when systemd holds a `stop` job for the unit; a restart, an
exit no stop caused or a failed check keeps it, so none of them opens the
host. Covers the flag in ``main()`` and in
``run_client`` (with the faked host of tests/test_client_fail_closed.py) and
the unit's two lines. The ExecStopPost script runs under ``/bin/sh`` with
fake ``systemctl`` and ``nft`` programs in ``tmp_path``, never the real ones.
"""

from __future__ import annotations

import functools
import logging
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import dsm.__main__ as entry
import dsm.client as client_mod
from dsm.crypto.handshake import HandshakeError
from dsm.net.resolv_conf import ResolvConfError
from tests.test_client_fail_closed import _config, _Run, _tables_after
from tests.test_client_unit import CLIENT_UNIT, _code

_DELETED = [
    "delete table inet dsm_killswitch_pre",
    "delete table inet dsm_killswitch",
    "delete table inet dsm_dns_leak",
]
_STOP_POST = (
    "ExecStopPost=/bin/sh -c '"
    'if [ "$$SERVICE_RESULT" = success ]; then '
    "queued=$$(systemctl list-jobs --no-legend --plain dsm-client.service "
    '2>/dev/null) || queued=""; '
    'case "$$queued" in *" stop "*) '
    '[ "$$(systemctl is-system-running 2>/dev/null)" = stopping ] || '
    "for t in dsm_killswitch_pre dsm_killswitch dsm_dns_leak; do "
    'nft delete table inet "$$t" 2>/dev/null; done ;; esac; fi; '
    "exit 0'"
)


async def _run_with_flag(run: _Run) -> int:
    # _Run calls client_mod.run_client; hand it the flag on the way.
    with_flag = functools.partial(client_mod.run_client, stop_keeps_block=True)
    with patch.object(client_mod, "run_client", with_flag):
        return await run.run()


async def test_a_stop_in_a_session_with_the_flag_keeps_the_pre_table(
    caplog: pytest.LogCaptureFixture,
) -> None:
    run = _Run()
    run.stop_in_session = [True]
    caplog.set_level(logging.INFO, logger="dsm")

    rc = await _run_with_flag(run)

    assert rc == 0
    # The session ends with the swap back to the pre table, and it stays.
    assert run.events.count("pre.apply") == 2
    assert "pre.remove" not in run.events
    assert "nft.remove" not in run.events
    assert _tables_after(run.events) == {"pre"}
    kept = [r for r in caplog.records if "--stop-keeps-block" in r.getMessage()]
    assert len(kept) == 1


async def test_a_stop_during_a_wait_with_the_flag_keeps_the_pre_table() -> None:
    run = _Run()
    run.handshakes = [HandshakeError("lost")]
    run.stop_at_wait = 1

    rc = await _run_with_flag(run)

    assert rc == 0
    assert "pre.remove" not in run.events
    assert _tables_after(run.events) == {"pre"}


async def test_a_stop_without_the_flag_takes_the_kill_switch_down() -> None:
    run = _Run()
    run.stop_in_session = [True]

    rc = await run.run()

    assert rc == 0
    assert run.events[-1] == "pre.remove"
    assert _tables_after(run.events) == set()


async def test_a_setup_error_with_the_flag_still_takes_it_down() -> None:
    # The flag is about stops only: a read-only resolv.conf at the first try
    # is still a setup error that removes the kill switch and exits 1. (A
    # UDP port in use is not one under the flag: see
    # tests/test_client_port_taken_under_unit.py.)
    run = _Run()
    run.raise_on = {
        "resolv": {
            "apply": ResolvConfError(Path("/etc/resolv.conf"), "Read-only file system")
        }
    }

    rc = await _run_with_flag(run)

    assert rc == 1
    assert run.events[-1] == "pre.remove"


@pytest.mark.parametrize(
    ("flags", "keeps"), [(["--stop-keeps-block"], True), ([], False)]
)
def test_main_hands_the_flag_to_run_client(flags: list[str], keeps: bool) -> None:
    with (
        patch.object(entry.sys, "argv", ["dsm", "--mode", "client", *flags]),
        patch.object(entry, "_load_config_or_exit", return_value=_config()),
        patch("dsm.core.log.configure"),
        patch("dsm.core.netaudit.configure"),
        # A plain MagicMock: asyncio.run is faked, so nothing awaits
        # run_client, and an AsyncMock would leave a coroutine never awaited.
        patch("dsm.client.run_client", new_callable=MagicMock) as run_client,
        patch.object(entry.asyncio, "run", return_value=0),
        pytest.raises(SystemExit),
    ):
        entry.main()

    assert run_client.call_args.kwargs["stop_keeps_block"] is keeps


def _unit_line(key: str) -> str:
    lines = [line for line in _code(CLIENT_UNIT) if line.startswith(f"{key}=")]
    assert len(lines) == 1, lines
    return lines[0]


def test_the_unit_passes_the_flag() -> None:
    assert _unit_line("ExecStart").startswith(
        "ExecStart=/opt/dsm/venv/bin/dsm --mode client --stop-keeps-block "
    )


def test_the_stop_step_line_checks_for_a_stop_job() -> None:
    assert _unit_line("ExecStopPost") == _STOP_POST


def _stop_step(
    tmp_path: Path,
    service_result: str | None,
    jobs: str,
    systemctl_rc: int | None,
    state: str = "running",
) -> list[str]:
    """Run the unit's ExecStopPost script with fake systemctl and nft.

    ``service_result`` None leaves SERVICE_RESULT unset; ``systemctl_rc`` None
    leaves systemctl off PATH (the shell then fails with 127). ``state`` is
    what ``systemctl is-system-running`` prints. Returns the nft calls it
    made.
    """
    head = "ExecStopPost=/bin/sh -c '"
    line = _unit_line("ExecStopPost")
    assert line.startswith(head) and line.endswith("'")
    script = line[len(head) : -1].replace("$$", "$")  # what systemd hands sh
    fakes = tmp_path / "bin"
    fakes.mkdir()
    if systemctl_rc is not None:
        (fakes / "systemctl").write_text(
            "#!/bin/sh\n"
            'case "$1" in\n'
            '  list-jobs) printf "%s\\n" "$FAKE_JOBS" ;;\n'
            '  is-system-running) printf "%s\\n" "${FAKE_STATE:-running}" ;;\n'
            "esac\n"
            'exit "$FAKE_SYSTEMCTL_RC"\n'
        )
    (fakes / "nft").write_text('#!/bin/sh\necho "$*" >>"$FAKE_NFT_LOG"\n')
    for fake in fakes.iterdir():
        fake.chmod(0o755)
    nft_log = tmp_path / "nft.log"
    nft_log.touch()
    proc = subprocess.run(
        ["/bin/sh", "-c", script],
        # Only the fakes on PATH: the script must never reach the real nft.
        env={
            "PATH": str(fakes),
            **({} if service_result is None else {"SERVICE_RESULT": service_result}),
            "FAKE_JOBS": jobs,
            "FAKE_STATE": state,
            "FAKE_SYSTEMCTL_RC": str(systemctl_rc),
            "FAKE_NFT_LOG": str(nft_log),
        },
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    return nft_log.read_text().splitlines()


@pytest.mark.parametrize(
    ("service_result", "jobs", "systemctl_rc", "deleted"),
    [
        # systemctl stop: the only case that takes the block down.
        ("success", "42 dsm-client.service stop running", 0, _DELETED),
        # systemctl restart: keep it; the new start replaces it.
        ("success", "41 dsm-client.service restart running", 0, []),
        # A clean exit no stop caused (a signal sent straight to DSM,
        # SIGHUP/SIGQUIT): no job, keep it; Restart=always brings DSM back.
        ("success", "", 0, []),
        # The check fails: keep it, even if it printed a stop job.
        ("success", "", 1, []),
        ("success", "42 dsm-client.service stop running", 1, []),
        # A crash, a kill or a stop timeout: keep it (fail closed).
        ("exit-code", "42 dsm-client.service stop running", 0, []),
        ("signal", "42 dsm-client.service stop running", 0, []),
        # The result is not set, or systemctl is not on PATH (rc 127): the
        # check cannot say "stop", so keep it.
        (None, "42 dsm-client.service stop running", 0, []),
        ("success", "42 dsm-client.service stop running", None, []),
    ],
)
def test_the_stop_step_takes_the_block_down_only_for_a_stop_job(
    tmp_path: Path,
    service_result: str | None,
    jobs: str,
    systemctl_rc: int | None,
    deleted: list[str],
) -> None:
    assert _stop_step(tmp_path, service_result, jobs, systemctl_rc) == deleted


@pytest.mark.parametrize(
    ("state", "deleted"),
    [
        # Shutdown or reboot: the stop job is part of it. Keep the block up
        # until the host is gone (nft tables do not survive a boot).
        ("stopping", []),
        # A `systemctl stop` on a running host takes it down.
        ("running", _DELETED),
        # Any other state behaves as before.
        ("degraded", _DELETED),
    ],
)
def test_the_stop_step_keeps_the_block_while_the_host_shuts_down(
    tmp_path: Path, state: str, deleted: list[str]
) -> None:
    jobs = "42 dsm-client.service stop running"
    assert _stop_step(tmp_path, "success", jobs, 0, state) == deleted
