"""Tests for dsm.core.netaudit — structured JSON event stream.

Locks the schema (every event has ``ts`` ISO-8601 UTC + ``event``) and
the disabled-by-default behavior. Live emission paths (handshake / nft /
tun / session) are exercised end-to-end via the integration tests, which
already capture stderr and would catch a regression in the wiring.
"""

from __future__ import annotations

import datetime
import io
import json
import logging
import re
import unittest

from dsm.core import netaudit


class _Capture:
    """Replace netaudit's stderr handler with a StringIO sink, restore on exit."""

    def __init__(self) -> None:
        self.buf = io.StringIO()
        self._handler: logging.Handler | None = None
        self._previous_handlers: list[logging.Handler] = []

    def __enter__(self) -> _Capture:
        log = logging.getLogger(netaudit.LOGGER_NAME)
        # Save and detach existing handlers so test output is clean.
        self._previous_handlers = list(log.handlers)
        for h in self._previous_handlers:
            log.removeHandler(h)
        netaudit.configure(True)
        # Redirect: swap the StreamHandler's stream to our buffer.
        for h in log.handlers:
            if isinstance(h, logging.StreamHandler):
                h.stream = self.buf
                self._handler = h
                break
        return self

    def __exit__(self, *exc: object) -> None:
        log = logging.getLogger(netaudit.LOGGER_NAME)
        netaudit.configure(False)
        for h in list(log.handlers):
            log.removeHandler(h)
        for h in self._previous_handlers:
            log.addHandler(h)

    def lines(self) -> list[str]:
        return [ln for ln in self.buf.getvalue().splitlines() if ln.strip()]

    def events(self) -> list[dict[str, object]]:
        return [json.loads(ln) for ln in self.lines()]


class TestNetAuditEnabled(unittest.TestCase):
    def test_emits_json_with_required_fields(self) -> None:
        with _Capture() as cap:
            netaudit.emit("test_event", role="client", value=42)
        events = cap.events()
        self.assertEqual(len(events), 1)
        ev = events[0]
        # Required keys
        self.assertIn("ts", ev)
        self.assertEqual(ev["event"], "test_event")
        # Caller fields preserved
        self.assertEqual(ev["role"], "client")
        self.assertEqual(ev["value"], 42)

    def test_ts_is_iso8601_utc(self) -> None:
        with _Capture() as cap:
            netaudit.emit("t")
        ev = cap.events()[0]
        # Parse and verify UTC timezone.
        ts = ev["ts"]
        self.assertIsInstance(ts, str)
        parsed = datetime.datetime.fromisoformat(ts)  # type: ignore[arg-type]
        self.assertIsNotNone(parsed.tzinfo)
        self.assertEqual(parsed.utcoffset(), datetime.timedelta(0))

    def test_each_emit_produces_one_line(self) -> None:
        with _Capture() as cap:
            for i in range(5):
                netaudit.emit("e", n=i)
        events = cap.events()
        self.assertEqual(len(events), 5)
        for i, ev in enumerate(events):
            self.assertEqual(ev["n"], i)

    def test_idempotent_configure(self) -> None:
        # Calling configure(True) twice must not double the handler set.
        log = logging.getLogger(netaudit.LOGGER_NAME)
        before = len(log.handlers)
        netaudit.configure(True)
        netaudit.configure(True)
        after = len(log.handlers)
        try:
            self.assertEqual(after - before, 1)
        finally:
            netaudit.configure(False)
            for h in list(log.handlers):
                if getattr(h, "_dsm_netaudit", False):
                    log.removeHandler(h)


class TestNetAuditDisabled(unittest.TestCase):
    def test_disabled_by_default(self) -> None:
        # Module-level state should be disabled at import.
        self.assertFalse(netaudit.is_enabled())

    def test_disabled_emit_is_noop(self) -> None:
        # Make sure we're disabled, and emit nothing comes out.
        netaudit.configure(False)
        with self.assertNoLogs(netaudit.LOGGER_NAME, level="INFO"):
            netaudit.emit("e", x=1)

    def test_configure_round_trip(self) -> None:
        netaudit.configure(True)
        self.assertTrue(netaudit.is_enabled())
        netaudit.configure(False)
        self.assertFalse(netaudit.is_enabled())


class TestNetAuditSerialization(unittest.TestCase):
    def test_non_serializable_value_falls_back_to_repr(self) -> None:
        class Weird:
            def __repr__(self) -> str:
                return "<weird>"

        with _Capture() as cap:
            netaudit.emit("e", obj=Weird())
        ev = cap.events()[0]
        self.assertEqual(ev["obj"], "<weird>")

    def test_bytes_value_falls_back_to_repr(self) -> None:
        # Plain bytes aren't JSON-serializable; ensure we don't crash.
        with _Capture() as cap:
            netaudit.emit("e", payload=b"\x01\x02\x03")
        events = cap.events()
        self.assertEqual(len(events), 1)
        # repr(b"...") is something like "b'\\x01\\x02\\x03'".
        self.assertIsInstance(events[0]["payload"], str)
        self.assertIn("\\x01", events[0]["payload"])


class TestSchemaLock(unittest.TestCase):
    """Regression lock for the event names runtime callers emit. If you
    rename one of these, the captured demo JSON from Phase 2B will no
    longer parse with downstream tooling — bump deliberately."""

    EXPECTED_EVENT_NAMES = {
        "handshake_start",
        "handshake_end",
        "nft_apply",
        "nft_remove",
        "tun_configure",
        "tun_deconfigure",
        "rekey_epoch",
        "liveness_fire",
        "shutdown_signal",
        "auto_mtu_change",
    }

    def test_call_sites_in_repo(self) -> None:
        """grep for `netaudit.emit("…")` across dsm/ and check the literal
        first arg of each call against the expected schema. Catches
        accidental rename / typo."""
        import pathlib

        root = pathlib.Path(__file__).resolve().parent.parent / "dsm"
        pattern = re.compile(r'netaudit\.emit\(\s*"([a-zA-Z_][a-zA-Z0-9_]*)"')
        seen: set[str] = set()
        for py in root.rglob("*.py"):
            text = py.read_text()
            for m in pattern.finditer(text):
                seen.add(m.group(1))

        # Every emitted name must be in the expected set (catches typos).
        unexpected = seen - self.EXPECTED_EVENT_NAMES
        self.assertFalse(
            unexpected,
            f"unexpected event names emitted in repo: {sorted(unexpected)}. "
            f"Either fix the typo or update EXPECTED_EVENT_NAMES.",
        )
        # Every expected name must be emitted somewhere (catches dropped wiring).
        missing = self.EXPECTED_EVENT_NAMES - seen
        self.assertFalse(
            missing,
            f"expected event names with no emit() call: {sorted(missing)}",
        )


if __name__ == "__main__":
    unittest.main()
