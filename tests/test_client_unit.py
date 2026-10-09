"""A client gets the client unit, never the server's.

Covers deploy/dsm-client.service, `install.sh --systemd --client` and
`dsm init client --install-unit`. install.sh is read as text, as the other
install.sh tests do; `dsm init` copies into a temporary folder.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from dsm import init

REPO = Path(__file__).resolve().parent.parent
CLIENT_UNIT = REPO / "deploy" / "dsm-client.service"
INSTALL = REPO / "install.sh"


def _code(path: Path) -> list[str]:
    """Unit lines without comments, with backslash continuations joined."""
    out: list[str] = []
    pending: list[str] = []
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.endswith("\\"):
            pending.append(stripped[:-1].strip())
            continue
        out.append(" ".join([*pending, stripped]))
        pending = []
    return out


def test_the_client_unit_runs_dsm_as_a_client() -> None:
    starts = [line for line in _code(CLIENT_UNIT) if line.startswith("ExecStart=")]
    assert len(starts) == 1
    assert starts[0].startswith("ExecStart=/opt/dsm/venv/bin/dsm --mode client ")
    assert "--passphrase-env-file=${CREDENTIALS_DIRECTORY}/passphrase" in starts[0]
    assert not any("--mode server" in line for line in _code(CLIENT_UNIT))


def test_the_kill_switch_comes_down_only_after_a_stop_you_asked_for() -> None:
    # Checked by parts, not as one exact line: Task 5 adds a stop-job check
    # inside the same `if`, and this must hold before and after it.
    posts = [line for line in _code(CLIENT_UNIT) if line.startswith("ExecStopPost=")]
    assert len(posts) == 1
    post = posts[0]
    check = post.index('if [ "$$SERVICE_RESULT" = success ]; then ')
    delete = post.index(
        "for t in dsm_killswitch_pre dsm_killswitch dsm_dns_leak; do "
        'nft delete table inet "$$t" 2>/dev/null; done'
    )
    assert check < delete < post.index("fi; exit 0'")
    assert post.endswith("fi; exit 0'")
    assert "dsm cleanup" not in post


def test_the_client_unit_restarts_after_a_crash() -> None:
    code = _code(CLIENT_UNIT)
    assert "Restart=always" in code
    assert "RestartSec=5s" in code
    assert "TimeoutStopSec=30" in code
    unit_section = CLIENT_UNIT.read_text().split("[Service]")[0]
    assert "StartLimitIntervalSec=10min" in unit_section
    assert "StartLimitBurst=5" in unit_section


def test_the_client_unit_can_write_proc_sys_and_has_no_dns_port_cap() -> None:
    code = _code(CLIENT_UNIT)
    assert "CapabilityBoundingSet=CAP_NET_ADMIN CAP_IPC_LOCK" in code
    assert not any(line.startswith("ProcSubset=") for line in code)
    assert "LoadCredential=passphrase:/etc/dsm/passphrase" in code
    assert "SupplementaryGroups=tss" in code


@pytest.mark.skipif(
    shutil.which("systemd-analyze") is None, reason="systemd-analyze absent"
)
def test_the_client_unit_verifies() -> None:
    proc = subprocess.run(
        ["systemd-analyze", "verify", str(CLIENT_UNIT)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert "Unknown" not in proc.stderr
    assert "StartLimitIntervalSec" not in proc.stderr


def test_install_sh_puts_only_the_client_unit_on_a_client() -> None:
    text = INSTALL.read_text()
    assert "--client)  CLIENT=1 ;;" in text
    server = text.index('if [ "$SYSTEMD" = 1 ] && [ "$CLIENT" = 0 ]; then')
    server_unit = text.index(
        'install -m 0644 "$UNIT_SRC" /etc/systemd/system/dsm.service'
    )
    start = text.index('elif [ "$SYSTEMD" = 1 ] && [ "$CLIENT" = 1 ]; then')
    end = text.index('elif [ "$SYSTEMD" = 1 ]; then', start)
    assert server < server_unit < start < end
    block = text[start:end]
    assert 'install -m 0644 "$UNIT_SRC" /etc/systemd/system/dsm-client.service' in block
    assert "/etc/systemd/system/dsm.service" not in block
    assert "dsm-blocklist-update" not in block
    assert "sudo systemctl enable --now dsm-client" in block


def test_install_sh_names_the_client_steps() -> None:
    text = INSTALL.read_text()
    assert "supported: --eval, --systemd, --client, --help" in text
    assert "Install complete. Next: sudo dsm init client" in text


def _point_init_at(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    deploy = tmp_path / "deploy"
    deploy.mkdir()
    (deploy / "dsm.service").write_text("server unit\n")
    (deploy / "dsm-client.service").write_text("client unit\n")
    (tmp_path / "units").mkdir()
    monkeypatch.setattr(init, "_DEPLOY_DIR", deploy)
    monkeypatch.setattr(init, "_SYSTEMD_DIR", tmp_path / "units")
    monkeypatch.setattr(init, "_CRED_FILE", tmp_path / "etc-dsm" / "passphrase")
    runs: list[list[str]] = []

    def fake_run(cmd: list[str], **_k: object) -> None:
        runs.append(cmd)

    monkeypatch.setattr(init.subprocess, "run", fake_run)
    return runs


def test_dsm_init_client_installs_the_client_unit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    runs = _point_init_at(tmp_path, monkeypatch)

    init._install_unit("client")

    units = tmp_path / "units"
    assert (units / "dsm-client.service").read_text() == "client unit\n"
    assert not (units / "dsm.service").exists()
    assert runs == [["systemctl", "daemon-reload"]]
    assert (tmp_path / "etc-dsm" / "passphrase").stat().st_mode & 0o777 == 0o600
    assert "sudo systemctl enable --now dsm-client" in capsys.readouterr().out


def test_dsm_init_server_still_installs_the_server_unit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _point_init_at(tmp_path, monkeypatch)

    init._install_unit()

    assert (tmp_path / "units" / "dsm.service").read_text() == "server unit\n"
    assert not (tmp_path / "units" / "dsm-client.service").exists()


def test_unit_names_by_role() -> None:
    assert init._unit_name("client") == "dsm-client"
    assert init._unit_name("server") == "dsm"
