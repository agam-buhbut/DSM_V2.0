"""Pytest session configuration for the DSM test suite.

DSM-022 — make a tuncore-unbuilt LOCAL run loud instead of silently
green.

Some tests still gate themselves behind ``@unittest.skipUnless(
_HAS_TUNCORE, ...)``, but that no longer lets the suite run without the
Rust extension: the size list lives in tuncore, so ``dsm.core.protocol``,
and every test module that imports it, fails to import. Without tuncore,
pytest stops with collection errors and runs no tests.

This hook splits the two intents:

  * ``DSM_REQUIRE_TUNCORE`` set (truthy) — the caller asserts tuncore
    MUST be importable (e.g. the CI lane that builds it). If the import
    fails, fail the whole session at configure time with one clear
    message instead of a page of collection errors.

  * Unset (the default, local-dev) — when tuncore is missing, emit ONE
    warning line that says why the collection errors follow.

When tuncore IS importable, this hook is a no-op.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

_REQUIRE_ENV = "DSM_REQUIRE_TUNCORE"
# Values that mean "off" when the env var is present. Anything else
# (including "1", "true", "yes") is treated as truthy.
_FALSEY = frozenset({"", "0", "false", "no", "off"})


class DsmTuncoreSkipWarning(pytest.PytestWarning):
    """tuncore is not built, so most test modules cannot be collected."""


def _require_tuncore() -> bool:
    value = os.environ.get(_REQUIRE_ENV)
    if value is None:
        return False
    return value.strip().lower() not in _FALSEY


def _tuncore_importable() -> bool:
    try:
        import tuncore  # noqa: F401
    except ImportError:
        return False
    return True


def pytest_configure(config: pytest.Config) -> None:
    if _tuncore_importable():
        return

    if _require_tuncore():
        raise pytest.UsageError(
            f"{_REQUIRE_ENV} is set but the Rust extension 'tuncore' is not "
            "importable. Build it first: run `maturin develop` in "
            "rust/tuncore/. Without it, every test module that imports "
            "dsm.core.protocol fails at collection."
        )

    config.issue_config_time_warning(
        DsmTuncoreSkipWarning(
            "tuncore (Rust crypto core) is not built, so every test module "
            "that imports dsm.core.protocol fails at collection and no tests "
            "run. Build it with `maturin develop` in rust/tuncore/, or set "
            f"{_REQUIRE_ENV}=1 to make this a hard error in CI."
        ),
        stacklevel=2,
    )


# TPM backend test support: per-test swtpm over TCP (mirrors
# rust/tuncore/tests/tpm_swtpm.rs). The fixture points the Rust attest backend
# at it via the TCTI env var and self-skips under the soft wheel, so the normal
# soft suite is unaffected.

_SWTPM_READINESS_TIMEOUT_S = 5.0
_SWTPM_POLL_S = 0.02


def _free_port_pair() -> int:
    """Pick a loopback port P such that P and P+1 are both bindable now.

    swtpm listens on P and on P+1 (control channel) without SO_REUSEADDR, so
    P+1 must also be free: Linux hands out odd ports for bind(0) and even ones
    for connect(), so P+1 is often a recent client port still in TIME_WAIT.
    """
    while True:
        port = _free_port()
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.bind(("127.0.0.1", port + 1))
        except OSError:
            continue
        finally:
            probe.close()
        return port


def _free_port() -> int:
    """Pick a free loopback TCP port. swtpm also claims port+1 for its control
    channel; the small race window between release and re-bind is tolerated as
    in the Rust harness (tests are serial enough)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])
    finally:
        s.close()


@pytest.fixture
def swtpm_tcti(monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    """Per-test swtpm over TCP; yields its ``swtpm:host=…,port=…`` TCTI.

    Skips unless the installed tuncore is the TPM build (so soft-wheel runs
    skip TPM tests) and swtpm/swtpm_setup are present. Sets the ``TCTI`` env
    var (restored on teardown via monkeypatch) so the Rust backend talks to
    this instance. Kills swtpm and removes its state dir on teardown.
    """
    try:
        import tuncore
    except ImportError:
        pytest.skip("tuncore not built")
    if bool(getattr(tuncore, "ATTEST_BACKEND_IS_SOFTWARE", True)):
        pytest.skip("not the TPM backend build")
    if shutil.which("swtpm") is None or shutil.which("swtpm_setup") is None:
        pytest.skip("swtpm / swtpm_setup not installed")

    state = Path(tempfile.mkdtemp(prefix="dsm-swtpm-"))

    def _teardown(proc: subprocess.Popen[bytes] | None) -> None:
        if proc is not None:
            proc.kill()
            proc.wait()
        shutil.rmtree(state, ignore_errors=True)

    # Author fresh TPM2 state (PCR banks etc.); --create-ek-cert is omitted
    # (needs a localca and is irrelevant here), matching the Rust harness.
    setup = subprocess.run(
        ["swtpm_setup", "--tpm2", "--tpmstate", str(state)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if setup.returncode != 0:
        _teardown(None)
        pytest.skip("swtpm_setup failed to author TPM state")

    port = _free_port_pair()
    ctrl = port + 1
    proc = subprocess.Popen(
        [
            "swtpm",
            "socket",
            "--tpm2",
            # State is pre-authored; startup-clear self-runs TPM2_Startup(CLEAR).
            "--flags",
            "not-need-init,startup-clear",
            "--tpmstate",
            f"dir={state}",
            "--server",
            f"type=tcp,port={port},bindaddr=127.0.0.1",
            "--ctrl",
            f"type=tcp,port={ctrl},bindaddr=127.0.0.1",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    deadline = time.monotonic() + _SWTPM_READINESS_TIMEOUT_S
    while True:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            if time.monotonic() > deadline:
                _teardown(proc)
                pytest.fail(f"swtpm did not start accepting on 127.0.0.1:{port}")
            time.sleep(_SWTPM_POLL_S)

    tcti = f"swtpm:host=127.0.0.1,port={port}"
    monkeypatch.setenv("TCTI", tcti)
    try:
        yield tcti
    finally:
        _teardown(proc)


@pytest.fixture(autouse=True)
def isolate_src_valid_mark(
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Keep client tests off the host's real src_valid_mark state.

    Points ``SrcValidMarkEnabler.STATE_PATH`` and the sysctl knob for its
    key at files in a fresh temp dir (not the test's own ``tmp_path``), so a
    test run as root never writes ``/run/dsm`` or ``/proc/sys``. Other
    sysctl keys keep the real translator. Tests that patch these themselves
    (e.g. ``fake_proc`` in test_rp_filter_strict.py) still win, as their
    patch is applied later.
    """
    from dsm.core import sysctl
    from dsm.net.tunnel import SrcValidMarkEnabler

    root = tmp_path_factory.mktemp("svm-isolated")
    knob = root / "src_valid_mark"
    knob.write_text("0\n")
    real_sysctl_path = sysctl.sysctl_path

    def fake_sysctl_path(key: str) -> Path:
        return knob if key == SrcValidMarkEnabler.KEY else real_sysctl_path(key)

    monkeypatch.setattr(sysctl, "sysctl_path", fake_sysctl_path)
    monkeypatch.setattr(
        SrcValidMarkEnabler,
        "STATE_PATH",
        root / "run" / "dsm" / "src_valid_mark.orig",
    )


class _NoBlocklist:
    """Stand-in for ``DnsBlocklist``: takes the dns dir, does nothing."""

    def __init__(self, dns_dir: Path) -> None:
        self.dns_dir = dns_dir

    def start(self) -> None:
        pass

    async def stop(self) -> None:
        pass

    def is_blocked(self, qname: str) -> bool:
        del qname
        return False


@pytest.fixture(autouse=True)
def isolate_dns_blocklist(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep server tests off the real blocklist folder.

    ``run_server`` builds a ``DnsBlocklist`` on ``<config_dir>/dns`` (by
    default ``/opt/mtun/dns``) and starts its reload task. Swap in a no-op
    stub for ``dsm.server.DnsBlocklist`` so a test that never mentions the
    blocklist cannot read that folder or leave a background task running.
    Tests that patch ``dsm.server.DnsBlocklist`` themselves (e.g.
    test_dns_blocklist_server.py) still win, as their patch is applied
    later; tests that import the real class from ``dsm.net.dns_blocklist``
    are not affected.
    """
    from dsm import server

    monkeypatch.setattr(server, "DnsBlocklist", _NoBlocklist)
