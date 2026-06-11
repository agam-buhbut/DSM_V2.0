"""Regression: the failed-handshake netaudit event must carry only the
exception class name, never str(e) — otherwise --debug-net re-leaks the
cert-auth detail the human log deliberately hides (finding: server.py:268
emitted message=str(e), enabling CN-allowlist / CRL enumeration via the
journald audit stream)."""

from __future__ import annotations

import io
import json
import logging
import unittest

from dsm.client import _emit_handshake_failure as _emit_client_failure
from dsm.core import netaudit
from dsm.crypto.handshake import CNNotAllowedError
from dsm.server import _emit_handshake_failure


class _AuditCapture:
    """Capture netaudit JSON lines without disturbing other handlers."""

    def __init__(self) -> None:
        self.buf = io.StringIO()
        self._prev: list[logging.Handler] = []

    def __enter__(self) -> _AuditCapture:
        log = logging.getLogger(netaudit.LOGGER_NAME)
        self._prev = list(log.handlers)
        for h in self._prev:
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
        for h in self._prev:
            log.addHandler(h)

    def text(self) -> str:
        return self.buf.getvalue()

    def events(self) -> list[dict[str, object]]:
        return [json.loads(ln) for ln in self.buf.getvalue().splitlines() if ln.strip()]


class TestHandshakeFailureNoLeak(unittest.TestCase):
    def test_server_failed_event_coarsens_cert_auth_class(self) -> None:
        # Phase 1.13: the SERVER must not distinguish allowlist-miss
        # (CNNotAllowedError) from CRL-hit (CertRevokedError) in the audit
        # stream — both map to a single "cert_auth" family label so a
        # journald reader cannot enumerate the allowlist / CRL.
        secret = "client CN 'dsm-secret-victim-client' not in allowlist"
        with _AuditCapture() as cap:
            _emit_handshake_failure(CNNotAllowedError(secret))
        events = cap.events()
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["event"], "handshake_end")
        self.assertEqual(ev["outcome"], "failed")
        self.assertEqual(ev["error"], "cert_auth")  # coarse family label
        self.assertNotIn("message", ev)
        self.assertNotIn("dsm-secret-victim-client", cap.text())

    def test_server_non_cert_handshake_error_keeps_class(self) -> None:
        # A non-cert HandshakeError keeps its precise class (no enumeration
        # risk — it doesn't reveal allowlist/CRL membership).
        from dsm.crypto.handshake import HandshakeError

        with _AuditCapture() as cap:
            _emit_handshake_failure(HandshakeError("malformed msg1"))
        ev = cap.events()[0]
        self.assertEqual(ev["error"], "HandshakeError")

    def test_client_failed_event_omits_message(self) -> None:
        secret = "server CN 'dsm-secret-server' mismatch"
        with _AuditCapture() as cap:
            _emit_client_failure(CNNotAllowedError(secret))
        events = cap.events()
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["event"], "handshake_end")
        self.assertEqual(ev["role"], "client")
        self.assertEqual(ev["outcome"], "failed")
        self.assertEqual(ev["error"], "CNNotAllowedError")
        self.assertNotIn("message", ev)
        self.assertNotIn("dsm-secret-server", cap.text())


if __name__ == "__main__":
    unittest.main()
