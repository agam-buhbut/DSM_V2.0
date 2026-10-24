"""The systemd units run the dsm both install paths make, and a release
ships them, checked, for `install.sh --systemd` (QA B1, M11). Text checks,
as the other unit and install.sh tests do."""

from __future__ import annotations

from pathlib import Path

from tests.test_client_unit import _code

REPO = Path(__file__).resolve().parent.parent
UNITS = [REPO / "deploy" / "dsm.service", REPO / "deploy" / "dsm-client.service"]
INSTALL = (REPO / "install.sh").read_text()
RELEASE = (REPO / ".github" / "workflows" / "release.yml").read_text()
SHIPPED = (
    "dsm.service",
    "dsm-client.service",
    "dsm-blocklist-update.sh",
    "dsm-blocklist-update.service",
    "dsm-blocklist-update.timer",
)


def test_the_units_run_usr_local_bin_dsm() -> None:
    for unit in UNITS:
        execs = [
            line
            for line in _code(unit)
            if line.startswith(("ExecStart=", "ExecStopPost="))
        ]
        dsm_execs = [line for line in execs if "dsm " in line and "/bin/sh" not in line]
        assert dsm_execs, unit
        for line in dsm_execs:
            assert "=/usr/local/bin/dsm " in line, line
        assert "/opt/dsm/venv" not in "\n".join(_code(unit)), unit


def test_the_release_ships_the_units() -> None:
    for name in SHIPPED:
        assert f"deploy/{name}" in RELEASE, name
    for pattern in ("dist/*.service", "dist/*.timer", "dist/dsm-blocklist-update.sh"):
        assert pattern in RELEASE, pattern
    # Staged before the checksums are made, so the signed list covers them.
    assert RELEASE.index("deploy/dsm.service") < RELEASE.index(
        "sha256sum * > SHA256SUMS"
    )


def test_install_sh_fetches_and_checks_the_units_before_installing() -> None:
    block_start = INSTALL.index('mkdir -p "$WORK/deploy"')
    gate = INSTALL.index("VERIFIED-ARTIFACT GATE PASSED")
    verify = INSTALL.index('minisign -V -p "$WORK/pubkey.pub"')
    assert verify < block_start < gate
    block = INSTALL[block_start:gate]
    assert '"$BASE/$f" -o "$WORK/deploy/$f"' in block
    assert "curl -fsSL --proto '=https'" in block
    assert "sha256sum -c" in block
    assert 'awk -v w="$f" \'$2 == w' in block
    for name in SHIPPED:
        assert name in INSTALL[INSTALL.index("UNIT_FILES=") : gate], name
    # The copies just checked win over an older /opt/dsm/deploy.
    assert "for c in ./deploy/dsm.service /opt/dsm/deploy/dsm.service;" in INSTALL
    assert (
        "for c in ./deploy/dsm-client.service /opt/dsm/deploy/dsm-client.service;"
        in INSTALL
    )
    # The server is enabled, not started, before init (QA M2), and both
    # branches name --install-unit (QA M1).
    assert 'enable --now dsm"' not in INSTALL
    assert INSTALL.count("Give --install-unit to the first dsm init command") == 2
