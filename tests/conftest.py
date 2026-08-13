"""Pytest session configuration for the DSM test suite.

DSM-022 — make a tuncore-unbuilt LOCAL run loud instead of silently
green.

Many tests gate themselves behind ``@unittest.skipUnless(_HAS_TUNCORE,
...)`` so that contributors without the Rust extension built can still
run the pure-Python suite. The hazard is that those skips are easy to
miss: a CI lane (or a developer) can run the suite, see all-green, and
never notice that the entire crypto-core-backed half was skipped.

This hook splits the two intents:

  * ``DSM_REQUIRE_TUNCORE`` set (truthy) — the caller asserts tuncore
    MUST be importable (e.g. the CI lane that builds it). If the import
    fails, fail the whole session at configure time with a clear message
    rather than reporting a misleading pass.

  * Unset (the default, local-dev) — behave exactly as before (skips are
    allowed), but when tuncore is missing emit ONE warning line so the
    skip is visible in the run summary.

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
    """The tuncore-gated portion of the suite is being skipped."""


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
            "rust/tuncore/. Refusing to run a suite that would silently skip "
            "every tuncore-gated test and report a misleading pass."
        )

    config.issue_config_time_warning(
        DsmTuncoreSkipWarning(
            "tuncore (Rust crypto core) is not built; tuncore-gated tests "
            "will be SKIPPED (not failed). Build it with `maturin develop` "
            f"in rust/tuncore/, or set {_REQUIRE_ENV}=1 to make this a hard "
            "error in CI."
        ),
        stacklevel=2,
    )


# TPM backend test support: per-test swtpm over TCP (mirrors
# rust/tuncore/tests/tpm_swtpm.rs). The fixture points the Rust attest backend
# at it via the TCTI env var and self-skips under the soft wheel, so the normal
# soft suite is unaffected.

_SWTPM_READINESS_TIMEOUT_S = 5.0
_SWTPM_POLL_S = 0.02


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

    port = _free_port()
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
