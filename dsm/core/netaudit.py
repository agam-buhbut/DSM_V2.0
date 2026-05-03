"""Structured network-event audit log (JSON to stderr / journalctl).

Disabled by default. When `--debug-net` is set or `debug_net = true` is in
config, ``configure(True)`` attaches a stderr handler to the
``dsm.netaudit`` logger and ``emit(event, **fields)`` writes one JSON
line per event:

    {"ts": "2026-05-03T18:42:11.123456+00:00",
     "event": "handshake_end",
     "role": "client",
     "peer_cn": "dsm-a3f29c81-server",
     "outcome": "ok",
     "duration_s": 0.84}

The emit() function is the only public API for runtime callers. Tests
use ``configure(True)`` + ``logging`` capture machinery to assert events.

Why a separate logger from ``dsm`` (instead of just calling ``log.info``):
- Audit events should be machine-parseable JSON. Mixing them into the
  human-formatted dsm log would break grep-based ops.
- ``dsm.netaudit`` is configured with ``propagate=False`` so audit events
  do NOT bleed into the human log even when the root ``dsm`` logger is
  noisy at debug level.
- The `dsm.netaudit` logger name is preserved by journalctl as the
  ``LOGGER`` field, so consumers can filter:
      journalctl -u dsm | grep dsm.netaudit
      journalctl -u dsm SYSLOG_IDENTIFIER=dsm | jq 'select(.LOGGER=="dsm.netaudit")'
"""

from __future__ import annotations

import datetime
import json
import logging
import sys
from typing import Any

LOGGER_NAME = "dsm.netaudit"

_log = logging.getLogger(LOGGER_NAME)
# Don't bubble events up to the root dsm logger — they would otherwise
# show up as INFO lines in the human stream.
_log.propagate = False
# Default: muted. configure(True) raises level + attaches a handler.
_log.setLevel(logging.CRITICAL + 1)

_enabled = False


def is_enabled() -> bool:
    return _enabled


def configure(enabled: bool) -> None:
    """Enable or disable structured event emission.

    Idempotent: calling configure(True) twice attaches at most one
    handler. configure(False) restores the muted-by-default state but
    leaves any previously-attached handler in place — this is fine
    because the level filter alone is enough to suppress emission.
    """
    global _enabled
    _enabled = enabled
    if enabled:
        if not any(getattr(h, "_dsm_netaudit", False) for h in _log.handlers):
            handler = logging.StreamHandler(sys.stderr)
            handler.setFormatter(logging.Formatter("%(message)s"))
            handler._dsm_netaudit = True  # type: ignore[attr-defined]
            _log.addHandler(handler)
        _log.setLevel(logging.INFO)
    else:
        _log.setLevel(logging.CRITICAL + 1)


def _json_default(obj: Any) -> str:
    """Best-effort fallback for non-JSON-serializable values.

    We never want emit() to crash a real session over a logging detail,
    so anything we don't know how to serialize falls back to repr().
    """
    return repr(obj)


def emit(event: str, **fields: Any) -> None:
    """Emit one structured event as a JSON line on the audit logger.

    No-op when ``configure(False)`` (the default). Safe to call from
    any code path; the cost of a disabled call is one bool check.

    ``ts`` (ISO-8601 UTC with microseconds) and ``event`` are always
    set; caller-provided keys must not collide with them.
    """
    if not _enabled:
        return
    payload = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "event": event,
        **fields,
    }
    try:
        line = json.dumps(payload, default=_json_default)
    except (TypeError, ValueError):
        # Last-ditch: even the default fallback failed. Drop a sentinel
        # event so the operator can see the audit had a hole.
        line = json.dumps(
            {
                "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "event": "audit_serialization_error",
                "original_event": event,
            }
        )
    _log.info(line)
