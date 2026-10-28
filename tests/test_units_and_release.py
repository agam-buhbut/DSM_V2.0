"""The systemd units run the dsm both install paths make, and a release
ships them, checked, for `install.sh --systemd` (QA B1, M11). Text checks,
as the other unit and install.sh tests do."""

from __future__ import annotations

import hashlib
import os
import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

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
    files_block = RELEASE.split("files: |", 1)[1].split("\n\n", 1)[0]
    for pattern in ("dist/*.service", "dist/*.timer", "dist/dsm-blocklist-update.sh"):
        assert pattern in files_block, pattern
    cp_line = RELEASE[RELEASE.index("cp deploy/dsm.service") :].split("dist/\n", 1)[0]
    for name in SHIPPED:
        assert f"deploy/{name}" in cp_line, name
    # Staged before the checksums are made, so the signed list covers them.
    assert RELEASE.index("deploy/dsm.service") < RELEASE.index(
        "sha256sum * > SHA256SUMS"
    )


def test_install_sh_fetches_and_checks_the_units_before_installing() -> None:
    block_start = INSTALL.index('mkdir -p "$WORK/deploy"')
    gate = INSTALL.index("VERIFIED-ARTIFACT GATE PASSED")
    verify = INSTALL.index('minisign -V -P "$MINISIGN_PUBKEY" -m "$WORK/SHA256SUMS"')
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


def test_install_sh_guards_the_fetch_and_checks_inside_deploy() -> None:
    assert 'if [ "$SYSTEMD" = 1 ] && [ "$EVAL" = 0 ]; then' in INSTALL
    assert '( cd "$WORK/deploy" && sha256sum -c "$WORK/expected.sha256" )' in INSTALL


# --- run install.sh against fakes -------------------------------------------

_FAKE_CURL = """#!/bin/sh
# fake curl: copy $SERVED/<name> to the -o file; fail for names in $CURL_FAIL.
out=""; url=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift ;;
    http*) url="$1" ;;
  esac
  shift
done
name="${url##*/}"
echo "$name" >> "$FAKE_LOG_DIR/curl.log"
case " $CURL_FAIL " in *" $name "*) exit 22 ;; esac
cp "$SERVED/$name" "$out"
"""
_RECORDER = """#!/bin/sh
echo "$0 $*" >> "$FAKE_LOG_DIR/calls.log"
"""
_WHEEL = "dsm-0.1.0-cp311-abi3-manylinux_2_35_x86_64.whl"
_SOFT_WHEEL = "dsm-0.1.0+soft-cp311-abi3-manylinux_2_35_x86_64.whl"
_UNIT_FILES = [n for n in SHIPPED if n != "dsm-client.service"]

Install = Callable[..., "tuple[subprocess.CompletedProcess[str], Path]"]


def _sums(served: Path, names: list[str]) -> None:
    lines = [
        f"{hashlib.sha256((served / n).read_bytes()).hexdigest()}  {n}\n" for n in names
    ]
    (served / "SHA256SUMS").write_text("".join(lines))


@pytest.fixture(name="install")
def _install(tmp_path: Path) -> Install:
    fakebin = tmp_path / "fakebin"
    fakebin.mkdir()
    for name, body in (
        ("curl", _FAKE_CURL),
        ("minisign", "#!/bin/sh\nexit 0\n"),
        ("id", "#!/bin/sh\necho 0\n"),
        ("uname", "#!/bin/sh\necho x86_64\n"),
        ("apt-get", _RECORDER),
        ("install", _RECORDER),
        ("pip", _RECORDER),
        ("python3", _RECORDER),
        ("systemctl", _RECORDER),
    ):
        (fakebin / name).write_text(body)
        (fakebin / name).chmod(0o755)
    tpm = tmp_path / "tpmrm0"
    tpm.write_text("")
    # The copy looks for a stand-in TPM node, so nothing on the host is read.
    script = tmp_path / "install.sh"
    script.write_text(INSTALL.replace("/dev/tpmrm0", str(tpm)))
    tmp = tmp_path / "tmp"
    tmp.mkdir()

    def run(
        *args: str,
        tamper: str | None = None,
        drop: str | None = None,
        curl_fail: str = "",
        wheel: str = _WHEEL,
        apt_fails: bool = False,
    ) -> tuple[subprocess.CompletedProcess[str], Path]:
        served = tmp_path / "served"
        served.mkdir(exist_ok=True)
        for name in (wheel, *SHIPPED):
            (served / name).write_text(f"content of {name}\n")
        names = [wheel, *(n for n in SHIPPED if n != drop)]
        if apt_fails:
            # The first step past the gate fails: the run stops there,
            # before anything is installed.
            (fakebin / "apt-get").write_text("#!/bin/sh\nexit 1\n")
        _sums(served, names)
        (served / "SHA256SUMS.minisig").write_text("sig\n")
        if tamper:
            (served / tamper).write_text("tampered\n")
        logs = tmp_path / "logs"
        logs.mkdir(exist_ok=True)
        env = {
            "PATH": f"{fakebin}:{os.environ['PATH']}",
            "TMPDIR": str(tmp),
            "SERVED": str(served),
            "CURL_FAIL": curl_fail,
            "FAKE_LOG_DIR": str(logs),
            "DSM_RELEASE_BASE_URL": "https://example.invalid/rel",
        }
        done = subprocess.run(
            ["/bin/sh", str(script), *args],
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        return done, logs

    return run


def _calls(logs: Path) -> str:
    path = logs / "calls.log"
    return path.read_text() if path.exists() else ""


def test_a_unit_file_that_does_not_match_the_signed_sums_stops_the_install(
    install: Install,
) -> None:
    done, logs = install("--systemd", tamper="dsm.service")
    assert done.returncode != 0, done.stderr
    assert "checksum mismatch for dsm.service" in done.stderr
    assert _calls(logs) == ""


def test_sums_without_the_unit_line_stop_the_install(install: Install) -> None:
    done, logs = install("--systemd", drop="dsm.service")
    assert done.returncode != 0, done.stderr
    assert "no single entry for dsm.service" in done.stderr
    assert _calls(logs) == ""


def test_a_failed_unit_download_stops_the_install(install: Install) -> None:
    done, logs = install("--systemd", curl_fail="dsm.service")
    assert done.returncode != 0, done.stderr
    assert "cannot fetch dsm.service" in done.stderr
    assert _calls(logs) == ""


def test_the_client_install_checks_its_unit_too(install: Install) -> None:
    done, logs = install("--systemd", "--client", tamper="dsm-client.service")
    assert done.returncode != 0, done.stderr
    assert "checksum mismatch for dsm-client.service" in done.stderr
    assert _calls(logs) == ""


def test_eval_fetches_no_unit_file(install: Install) -> None:
    done, logs = install("--eval", "--systemd", wheel=_SOFT_WHEEL, apt_fails=True)
    assert "apt-get update failed" in done.stderr  # the gate was passed
    fetched = (logs / "curl.log").read_text().split()
    assert _SOFT_WHEEL in fetched
    assert not [n for n in fetched if n in SHIPPED], fetched


# --- supported systems and the TPM runtime ----------------------------------


def test_the_tpm_runtime_falls_back_to_debian_12s_package() -> None:
    assert "apt-get install -y libtss2-esys-3.0.2-0 libtss2-tcti-device0" in INSTALL
    # No release ships a package named plain libtss2-esys.
    assert "libtss2-esys libtss2-tcti-device0" not in INSTALL


def test_install_sh_names_ubuntu_24_04_everywhere() -> None:
    # DSM needs Python 3.11; Ubuntu 22.04's python3 is 3.10.
    assert "22.04" not in INSTALL
    assert "(Debian 12+ / Ubuntu 24.04+ / x86_64 / TPM 2.0)" in INSTALL
    assert "supported targets are Debian 12+/Ubuntu 24.04+." in INSTALL


def _distro_warning(tmp_path: Path, os_release: str) -> str:
    start = INSTALL.index("if [ -r /etc/os-release ]; then")
    end = INSTALL.index("# TPM presence gate")
    release = tmp_path / "os-release"
    release.write_text(os_release)
    snippet = INSTALL[start:end].replace("/etc/os-release", str(release))
    done = subprocess.run(
        ["/bin/sh", "-c", snippet],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    return done.stderr


@pytest.mark.parametrize(
    ("version", "warned"),
    [("22.04", True), ("23.10", True), ("24.04", False), ("26.04", False)],
)
def test_ubuntu_below_24_04_gets_a_warning(
    tmp_path: Path, version: str, warned: bool
) -> None:
    err = _distro_warning(tmp_path, f'ID=ubuntu\nVERSION_ID="{version}"\n')
    assert ("below the supported Ubuntu 24.04+ baseline" in err) is warned, err
