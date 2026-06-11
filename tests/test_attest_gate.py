"""Tests for dsm.crypto.attest_gate — Phase-0 startup gate that refuses
to run on the extractable software attestation backend unless the operator
sets ``allow_soft_attest``.

The gate reads ``tuncore.ATTEST_BACKEND_IS_SOFTWARE`` (a compile-time
constant). Tests 1-2 force that flag in setUp/tearDown so they are
deterministic regardless of which backend the installed wheel was built
with. Test 3 checks the *real* constant in a fresh subprocess, because a
PyO3 module's init runs once per process and cannot be re-run by reloading.
"""

from __future__ import annotations

import io
import json
import logging
import subprocess
import sys
import unittest

from dsm.core import netaudit
from dsm.core.config import Config

try:
    import tuncore

    _HAS_TUNCORE = True
except ImportError:
    tuncore = None  # type: ignore[assignment]
    _HAS_TUNCORE = False


def _client_config(*, allow_soft_attest: bool) -> Config:
    """Minimal valid client Config with the gate flag set as requested."""
    return Config(
        mode="client",
        server_ip="10.0.0.1",
        server_port=51820,
        listen_port=51821,
        key_file="/tmp/test.key",
        cert_file="/tmp/test.crt",
        ca_root_file="/tmp/test-ca.pem",
        attest_key_file="/tmp/test-attest.key",
        expected_server_cn="dsm-test-server",
        allow_soft_attest=allow_soft_attest,
    )


class _Capture:
    """Replace netaudit's handler with a StringIO sink, restore on exit.

    Mirrors tests/test_netaudit.py's capture helper so audit events emitted
    by the gate can be asserted without touching real stderr.
    """

    def __init__(self) -> None:
        self.buf = io.StringIO()
        self._previous_handlers: list[logging.Handler] = []

    def __enter__(self) -> _Capture:
        log = logging.getLogger(netaudit.LOGGER_NAME)
        self._previous_handlers = list(log.handlers)
        for h in self._previous_handlers:
            log.removeHandler(h)
        netaudit.configure(True)
        for h in log.handlers:
            if isinstance(h, logging.StreamHandler):
                h.stream = self.buf
                break
        return self

    def __exit__(self, *exc: object) -> None:
        log = logging.getLogger(netaudit.LOGGER_NAME)
        netaudit.configure(False)
        for h in list(log.handlers):
            log.removeHandler(h)
        for h in self._previous_handlers:
            log.addHandler(h)

    def events(self) -> list[dict[str, object]]:
        return [json.loads(ln) for ln in self.buf.getvalue().splitlines() if ln.strip()]


@unittest.skipUnless(_HAS_TUNCORE, "requires tuncore")
class TestAttestGate(unittest.TestCase):
    def setUp(self) -> None:
        # Force the software flag so the gate's behavior is deterministic
        # regardless of which backend the installed wheel was built with.
        self._orig = getattr(tuncore, "ATTEST_BACKEND_IS_SOFTWARE", None)
        tuncore.ATTEST_BACKEND_IS_SOFTWARE = True  # type: ignore[attr-defined]

    def tearDown(self) -> None:
        if self._orig is None:
            try:
                delattr(tuncore, "ATTEST_BACKEND_IS_SOFTWARE")
            except AttributeError:
                pass
        else:
            tuncore.ATTEST_BACKEND_IS_SOFTWARE = self._orig  # type: ignore[attr-defined]

    def test_refuses_without_flag(self) -> None:
        from dsm.crypto.attest_gate import (
            SoftAttestNotAllowedError,
            enforce_attest_backend_policy,
        )

        config = _client_config(allow_soft_attest=False)
        with _Capture() as cap:
            with self.assertRaises(SoftAttestNotAllowedError) as ctx:
                enforce_attest_backend_policy(config)
        # The refusal message must name the exact config key to flip so the
        # operator has an actionable next step.
        self.assertIn("allow_soft_attest", str(ctx.exception))
        events = cap.events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event"], "soft_attest_acknowledged")
        self.assertEqual(events[0]["action"], "refused_start")

    def test_malformed_build_missing_constant_refused(self) -> None:
        from dsm.crypto.attest_gate import (
            MalformedAttestBuildError,
            enforce_attest_backend_policy,
        )

        # Simulate a stale wheel that predates the gate: drop the constant.
        delattr(tuncore, "ATTEST_BACKEND_IS_SOFTWARE")
        try:
            config = _client_config(allow_soft_attest=True)
            with _Capture() as cap:
                with self.assertRaises(MalformedAttestBuildError) as ctx:
                    enforce_attest_backend_policy(config)
        finally:
            # setUp's tearDown restores via self._orig; ensure the attr is
            # back even though tearDown also handles it.
            tuncore.ATTEST_BACKEND_IS_SOFTWARE = True  # type: ignore[attr-defined]
        # Even with allow_soft_attest=True, a missing constant fails closed
        # with a build-specific diagnostic (not the soft-backend message).
        self.assertIn("ATTEST_BACKEND_IS_SOFTWARE", str(ctx.exception))
        events = cap.events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event"], "soft_attest_acknowledged")
        self.assertEqual(events[0]["action"], "malformed_build")

    def test_allows_with_flag_warns_and_audits(self) -> None:
        from dsm.crypto.attest_gate import enforce_attest_backend_policy

        config = _client_config(allow_soft_attest=True)
        with _Capture() as cap:
            with self.assertLogs("dsm.crypto.attest_gate", level="WARNING") as logs:
                # Must not raise.
                enforce_attest_backend_policy(config)
        messages = [r.getMessage() for r in logs.records]
        self.assertTrue(
            any("extractable" in m.lower() for m in messages),
            f"expected an 'extractable' WARNING, got {messages}",
        )
        events = cap.events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event"], "soft_attest_acknowledged")
        self.assertEqual(events[0]["action"], "warned")


@unittest.skipUnless(_HAS_TUNCORE, "requires tuncore")
class TestConstantExposed(unittest.TestCase):
    def test_constant_exposed_by_tuncore(self) -> None:
        # Check the real (compile-time) constant in a fresh process: a
        # PyO3 module's init runs once per interpreter and is not re-run by
        # importlib.reload, so in-process mutation in other tests cannot
        # affect this.
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import tuncore; "
                "print(type(tuncore.ATTEST_BACKEND_IS_SOFTWARE).__name__)",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(result.stdout.strip(), "bool")


if __name__ == "__main__":
    unittest.main()
