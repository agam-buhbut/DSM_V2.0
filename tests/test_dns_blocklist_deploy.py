"""The block list download script, its systemd units and the install step.

The script runs for real against a temporary config folder, with stand-ins
for `curl` (no network) and `id` (so it believes it runs as root).
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "deploy" / "dsm-blocklist-update.sh"
SERVICE = REPO / "deploy" / "dsm-blocklist-update.service"
TIMER = REPO / "deploy" / "dsm-blocklist-update.timer"
INSTALL = REPO / "install.sh"
DEFAULT_URL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"

_FAKE_CURL = """#!/bin/sh
out=""
url=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output) out="$2"; shift ;;
    --proto|--proto-redir|--max-filesize|--max-time) shift ;;
    -*) ;;
    *) url="$1" ;;
  esac
  shift
done
echo "$url" >>"$FAKE_CURL_LOG"
[ -z "${FAKE_CURL_FAIL:-}" ] || exit 22
cat "$FAKE_CURL_BODY" >"$out"
"""

Run = Callable[..., subprocess.CompletedProcess[str]]


def _fetched(url: str) -> str:
    return "fetched-" + hashlib.sha256(url.encode()).hexdigest()[:16] + ".txt"


def _mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


@pytest.fixture
def config_dir(tmp_path: Path) -> Path:
    path = tmp_path / "cfg"
    path.mkdir(mode=0o700)
    return path


@pytest.fixture
def run(tmp_path: Path, config_dir: Path) -> Run:
    fakebin = tmp_path / "bin"
    fakebin.mkdir()
    (fakebin / "curl").write_text(_FAKE_CURL)
    (fakebin / "id").write_text("#!/bin/sh\necho 0\n")
    for tool in fakebin.iterdir():
        tool.chmod(0o755)
    body = tmp_path / "body.txt"
    body.write_text("0.0.0.0 ads.example.com\n")
    log = tmp_path / "curl.log"
    log.touch()

    def _run(*, fail: bool = False) -> subprocess.CompletedProcess[str]:
        env = {
            "PATH": f"{fakebin}:{os.environ['PATH']}",
            "FAKE_CURL_LOG": str(log),
            "FAKE_CURL_BODY": str(body),
        }
        if fail:
            env["FAKE_CURL_FAIL"] = "1"
        return subprocess.run(
            ["sh", str(SCRIPT), str(config_dir)],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

    return _run


def _curl_log(config_dir: Path) -> list[str]:
    return (config_dir.parent / "curl.log").read_text().splitlines()


def test_the_first_run_writes_the_default_source_and_fetches_it(
    config_dir: Path, run: Run
) -> None:
    result = run()
    assert result.returncode == 0, result.stderr
    dns_dir = config_dir / "dns"
    sources = dns_dir / "sources.txt"
    assert DEFAULT_URL in sources.read_text().splitlines()
    assert _mode(sources) == 0o600
    assert _mode(dns_dir) == 0o700
    assert _mode(dns_dir / "block") == 0o700
    fetched = dns_dir / "block" / _fetched(DEFAULT_URL)
    assert fetched.read_text() == "0.0.0.0 ads.example.com\n"
    assert _mode(fetched) == 0o600
    assert sorted(p.name for p in (dns_dir / "block").iterdir()) == [fetched.name]
    assert _curl_log(config_dir) == [DEFAULT_URL]


def test_a_failed_download_keeps_the_old_copy_and_fails_the_run(
    config_dir: Path, run: Run
) -> None:
    assert run().returncode == 0
    result = run(fail=True)
    assert result.returncode == 1
    assert "could not download" in result.stderr
    block = config_dir / "dns" / "block"
    assert sorted(p.name for p in block.iterdir()) == [_fetched(DEFAULT_URL)]
    assert (block / _fetched(DEFAULT_URL)).read_text() == "0.0.0.0 ads.example.com\n"


def test_a_source_taken_out_takes_its_list_but_never_your_own_files(
    config_dir: Path, run: Run
) -> None:
    assert run().returncode == 0
    other = "https://lists.example/a.txt"
    (config_dir / "dns" / "sources.txt").write_text(f"# {DEFAULT_URL}\n{other}\n")
    own = config_dir / "dns" / "block" / "mine.txt"
    own.write_text("own.example.com\n")
    assert run().returncode == 0
    names = sorted(p.name for p in (config_dir / "dns" / "block").iterdir())
    assert names == sorted([_fetched(other), "mine.txt"])


def test_only_https_sources_are_fetched(config_dir: Path, run: Run) -> None:
    (config_dir / "dns").mkdir(mode=0o700)
    (config_dir / "dns" / "sources.txt").write_text(
        "http://plain.example/list.txt\n# a comment\n   \n"
        "https://lists.example/a.txt # a note\r\n"
    )
    result = run()
    assert result.returncode == 1
    assert "https://" in result.stderr
    assert _curl_log(config_dir) == ["https://lists.example/a.txt"]


def _code(path: Path) -> str:
    return "\n".join(
        line
        for line in path.read_text().splitlines()
        if not line.lstrip().startswith("#")
    )


def test_the_script_downloads_safely_and_never_signals_dsm() -> None:
    code = _code(SCRIPT)
    curl = re.search(r"if curl .*?--output \"\$tmp\" \"\$url\"", code, re.S)
    assert curl is not None
    for flag in (
        "--fail",
        "--proto '=https'",
        "--proto-redir '=https'",
        '--max-filesize "$MAX_BYTES"',
    ):
        assert flag in curl.group(0)
    assert "MAX_BYTES=67108864" in code
    assert 'wc -c <"$tmp"' in code
    assert 'chmod 600 "$tmp"' in code
    assert 'mv -f "$tmp" "$BLOCK_DIR/$name"' in code
    assert f'DEFAULT_SOURCE="{DEFAULT_URL}"' in code
    assert re.search(r"\b(kill|pkill|killall|systemctl|SIGHUP)\b", code) is None


def test_the_timer_runs_the_script_daily_at_a_random_time() -> None:
    timer = TIMER.read_text()
    for line in (
        "OnCalendar=daily",
        "RandomizedDelaySec=1h",
        "Persistent=true",
        "WantedBy=timers.target",
    ):
        assert line in timer.splitlines()
    service = SERVICE.read_text().splitlines()
    for line in (
        "Type=oneshot",
        "ExecStart=/usr/local/sbin/dsm-blocklist-update /opt/mtun",
        "ProtectSystem=strict",
        "ReadWritePaths=-/opt/mtun/dns",
    ):
        assert line in service


def test_install_sh_sets_up_the_timer_and_fetches_once_without_failing() -> None:
    text = INSTALL.read_text()
    unit = text.index('install -m 0644 "$UNIT_SRC" /etc/systemd/system/dsm.service')
    script = text.index(
        'install -m 0755 "$DEPLOY_DIR/dsm-blocklist-update.sh" '
        "/usr/local/sbin/dsm-blocklist-update"
    )
    enable = text.index("systemctl enable --now dsm-blocklist-update.timer")
    fetch = re.search(
        r"\n\s*/usr/local/sbin/dsm-blocklist-update /opt/mtun \\\n"
        r"\s*\|\| echo \"install\.sh: WARNING",
        text,
    )
    assert fetch is not None
    assert unit < script < enable < fetch.start()


_CAP_CURL = """#!/bin/sh
# Writes FAKE_CURL_BYTES bytes, like a server that sends no length, then notes
# how many bytes reached the disk.
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output) out="$2"; shift ;;
  esac
  shift
done
head -c "$FAKE_CURL_BYTES" /dev/zero >"$out"
status=$?
wc -c <"$out" >"$FAKE_CURL_SIZE"
exit "$status"
"""


def test_a_download_past_the_cap_is_stopped_while_it_is_written(
    tmp_path: Path, config_dir: Path
) -> None:
    cap = 4096
    script = tmp_path / "capped-update.sh"
    text = SCRIPT.read_text()
    assert "MAX_BYTES=67108864" in text
    script.write_text(text.replace("MAX_BYTES=67108864", f"MAX_BYTES={cap}"))
    fakebin = tmp_path / "capbin"
    fakebin.mkdir()
    (fakebin / "curl").write_text(_CAP_CURL)
    (fakebin / "id").write_text("#!/bin/sh\necho 0\n")
    for tool in fakebin.iterdir():
        tool.chmod(0o755)
    size_log = tmp_path / "size.log"

    def _run(nbytes: int) -> subprocess.CompletedProcess[str]:
        env = {
            "PATH": f"{fakebin}:{os.environ['PATH']}",
            "FAKE_CURL_BYTES": str(nbytes),
            "FAKE_CURL_SIZE": str(size_log),
        }
        return subprocess.run(
            ["sh", str(script), str(config_dir)],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

    assert _run(100).returncode == 0
    block = config_dir / "dns" / "block"
    kept = block / _fetched(DEFAULT_URL)
    assert kept.stat().st_size == 100

    result = _run(200_000)
    assert result.returncode == 1
    assert "could not download" in result.stderr
    # The limit stopped the writer, so the disk never held the whole body
    # (a size check only after the download would see all 200000 bytes).
    assert 0 < int(size_log.read_text()) < 2 * cap + 512
    assert sorted(p.name for p in block.iterdir()) == [kept.name]
    assert kept.stat().st_size == 100
