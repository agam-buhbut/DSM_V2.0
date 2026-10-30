"""The client's boot block (#11): a oneshot unit loads the start-up kill
switch before any network comes up, so nothing leaves the host in the
clear between boot and DSM's start, and an error before DSM's own block
leaves a block up. Text checks, as the other unit and install.sh tests do;
one kernel check loads the rules in a throwaway user+net namespace and is
skipped where nft, ip or unprivileged namespaces are missing.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

from dsm import init
from dsm.net.cleanup import _DSM_TABLES
from dsm.net.nftables import PreHandshakeKillSwitch
from tests.test_client_unit import _code
from tests.test_units_and_release import Install, _calls
from tests.test_units_and_release import _install as _install  # noqa: F401

REPO = Path(__file__).resolve().parent.parent
BOOT = "dsm-client-boot-block.service"
BOOT_UNIT = REPO / "deploy" / BOOT
CLIENT_UNIT = REPO / "deploy" / "dsm-client.service"
SERVER_UNIT = REPO / "deploy" / "dsm.service"
INSTALL = (REPO / "install.sh").read_text()
RELEASE = (REPO / ".github" / "workflows" / "release.yml").read_text()

_SBIN = os.pathsep.join([os.environ.get("PATH", ""), "/usr/sbin", "/sbin"])
_NFT = shutil.which("nft", path=_SBIN)
_IP = shutil.which("ip", path=_SBIN)
_UNSHARE = shutil.which("unshare")


def _rule_lines(text: str) -> list[str]:
    lines = (line.strip() for line in text.splitlines())
    return [line for line in lines if line and not line.startswith("#")]


def _boot_rules() -> str:
    """The text systemd hands nft on stdin: each StandardInputText= value,
    stripped, one per line."""
    values = [
        line.removeprefix("StandardInputText=")
        for line in _code(BOOT_UNIT)
        if line.startswith("StandardInputText=")
    ]
    # systemd expands % and \\ in these values; the rules must have neither.
    assert not [v for v in values if "%" in v or "\\" in v], values
    return "".join(f"{v}\n" for v in values)


def test_the_boot_block_is_the_start_up_table_with_no_openings() -> None:
    rules = _rule_lines(_boot_rules())
    assert rules == _rule_lines(PreHandshakeKillSwitch(None, 1)._ruleset())
    assert "table inet dsm_killswitch_pre {" in rules
    assert not [line for line in rules if "daddr" in line or "skuid" in line]
    # The same table name, so DSM's first start, the client unit's stop
    # step and `dsm cleanup` all remove it.
    assert PreHandshakeKillSwitch.TABLE_NAME in _DSM_TABLES


def test_the_boot_block_runs_before_any_network() -> None:
    code = _code(BOOT_UNIT)
    for line in (
        "DefaultDependencies=no",
        "Before=network-pre.target",
        "Wants=network-pre.target",
        "After=nftables.service",
        "PartOf=dsm-client.service",
        "Type=oneshot",
        "RemainAfterExit=yes",
        "StandardInput=data",
        "ExecStart=/usr/sbin/nft -f -",
    ):
        assert line in code, line
    # Nothing in it takes the block down, and only the client unit pulls it
    # in: no [Install], so it is never enabled on its own.
    assert not [line for line in code if line.startswith(("ExecStop", "ExecReload"))]
    assert "[Install]" not in code


def test_the_boot_block_skips_itself_while_a_tunnel_is_up() -> None:
    assert (
        "ExecCondition=/bin/sh -c '! /usr/sbin/nft list table inet dsm_killswitch"
        " >/dev/null 2>&1'"
    ) in _code(BOOT_UNIT)


def test_only_the_client_unit_pulls_in_the_boot_block() -> None:
    code = _code(CLIENT_UNIT)
    assert f"Wants=network-online.target {BOOT}" in code
    assert f"After=network-online.target {BOOT}" in code
    assert BOOT not in SERVER_UNIT.read_text()


def test_the_client_unit_only_wants_the_boot_block() -> None:
    code = _code(CLIENT_UNIT)
    assert not [
        line
        for line in code
        if line.startswith(("Requires=", "BindsTo=", "Requisite=")) and BOOT in line
    ]


def test_install_sh_and_the_release_ship_the_boot_block_for_a_client_only() -> None:
    assert f'UNIT_FILES="dsm-client.service {BOOT}"' in INSTALL
    server = INSTALL.index('if [ "$SYSTEMD" = 1 ] && [ "$CLIENT" = 0 ]; then')
    client = INSTALL.index('elif [ "$SYSTEMD" = 1 ] && [ "$CLIENT" = 1 ]; then')
    end = INSTALL.index('elif [ "$SYSTEMD" = 1 ]; then', client)
    assert BOOT not in INSTALL[server:client]
    server_files = [x for x in INSTALL.splitlines() if 'UNIT_FILES="dsm.service ' in x]
    assert len(server_files) == 1 and BOOT not in server_files[0]
    assert f"/etc/systemd/system/{BOOT}" in INSTALL[client:end]
    cp_line = RELEASE[RELEASE.index("cp deploy/dsm.service") :].split("dist/\n", 1)[0]
    assert f"deploy/{BOOT}" in cp_line


def test_a_client_install_stops_when_the_sums_lack_the_boot_block(
    install: Install,
) -> None:
    # The real install.sh, run against the fakes of test_units_and_release:
    # their signed sums have no line for the boot block, so a client install
    # must stop at the unit check, before anything is installed. apt_fails
    # stops a run that gets past the check (the code before the fix) at the
    # first step after it, so that run changes nothing either.
    done, logs = install("--systemd", "--client", apt_fails=True)
    assert done.returncode != 0, done.stderr
    assert f"signed SHA256SUMS has no single entry for {BOOT}" in done.stderr
    assert _calls(logs) == ""


def test_dsm_init_installs_the_boot_block_with_the_client_unit_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    units = tmp_path / "units"
    units.mkdir()
    monkeypatch.setattr(init, "_DEPLOY_DIR", REPO / "deploy")
    monkeypatch.setattr(init, "_SYSTEMD_DIR", units)
    run = mock.MagicMock()
    monkeypatch.setattr(init.subprocess, "run", run)

    init._install_unit("server")
    assert sorted(p.name for p in units.iterdir()) == ["dsm.service"]

    (units / "dsm.service").unlink()
    run.reset_mock()
    init._install_unit("client")
    assert sorted(p.name for p in units.iterdir()) == [BOOT, "dsm-client.service"]
    assert (units / BOOT).read_bytes() == BOOT_UNIT.read_bytes()
    run.assert_called_once_with(["systemctl", "daemon-reload"], check=True)
    assert f"Installed dsm-client.service and {BOOT}." in capsys.readouterr().out


def _in_namespace(script: str, *args: str) -> subprocess.CompletedProcess[str]:
    assert _NFT and _IP and _UNSHARE  # the kernel test skips without them
    return subprocess.run(
        [_UNSHARE, "-rn", "sh", "-c", script, "sh", _NFT, _IP, *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )


# $1 nft, $2 ip, $3 python, $4 the boot rules, $5 the rules DSM's first
# start loads (a server at 10.9.0.2).
_KERNEL = r"""
nft=$1 ip=$2 py=$3
"$ip" link set lo up && "$ip" link add d0 type dummy &&
  "$ip" addr add 10.9.0.1/24 dev d0 && "$ip" link set d0 up || exit 1
send='
import socket, sys
for addr in sys.argv[1:]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.sendto(b"x", (addr, 9))
        print(addr, "sent")
    except PermissionError:
        print(addr, "blocked")
'
printf '%s' "$4" | "$nft" -f - || exit 1
"$py" -I -c "$send" 10.9.0.2 127.0.0.1
printf '%s' "$5" | "$nft" -f - || exit 1
"$nft" list tables
"$nft" list table inet dsm_killswitch_pre | grep -c 10.9.0.2
"""


@pytest.mark.skipif(not (_NFT and _IP and _UNSHARE), reason="nft, ip or unshare absent")
def test_the_kernel_blocks_all_but_loopback_until_dsm_replaces_the_table() -> None:
    probe = _in_namespace('"$1" list ruleset && "$2" link add d0 type dummy')
    if probe.returncode != 0:
        pytest.skip(f"no nft or dummy link in a user+net namespace: {probe.stderr}")
    dsm_first_start = PreHandshakeKillSwitch("10.9.0.2", 51820)._ruleset()
    proc = _in_namespace(_KERNEL, sys.executable, _boot_rules(), dsm_first_start)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.splitlines() == [
        "10.9.0.2 blocked",
        "127.0.0.1 sent",
        # DSM's own start-up table took the boot block's place, in one commit.
        "table inet dsm_killswitch_pre",
        "2",
    ]
