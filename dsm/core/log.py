"""Logging configuration for DSM, and a limit for lines that can repeat per
packet."""

from __future__ import annotations

import contextlib
import contextvars
import logging
import sys
import time
from collections.abc import Callable, Iterator

_configured = (
    False  # pylint: disable=invalid-name  # module-private flag, not a constant
)

# Events that can repeat once per packet log at most one line per this many
# seconds. The shaper sends 8-12 packets/s at idle and up to ~960/s at the top
# tier, so one line per packet would flood the log; one line per 10 s still
# shows within seconds that a problem started, and every 10 s that it goes on.
REPEAT_LOG_INTERVAL_S = 10.0

# The running server session's number, as text ("7"); "" outside a session.
# Each session's task sets it at its start, and asyncio copies it into every
# task that session starts (multi-client spec §2.13).
SESSION_LABEL: contextvars.ContextVar[str] = contextvars.ContextVar(
    "dsm_session_label", default=""
)


class _SessionLabel(logging.Filter):
    """Puts ``"[s7] "`` in ``record.session`` inside session 7, ``""``
    elsewhere, for the human log format."""

    def filter(self, record: logging.LogRecord) -> bool:
        label = SESSION_LABEL.get()
        # LogRecord has no such field; the formatter reads it from __dict__.
        record.__dict__["session"] = f"[s{label}] " if label else ""
        return True


class RepeatLog:
    """Log the first of a run of repeated events, then at most one line per
    ``interval_s`` that adds how many more happened since the line before.

    For events that can happen once per packet. A count still pending when
    the events stop is logged with the next event of the same kind.
    """

    def __init__(
        self,
        logger: logging.Logger,
        level: int,
        *,
        interval_s: float = REPEAT_LOG_INTERVAL_S,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._logger = logger
        self._level = level
        self._interval_s = interval_s
        self._clock = clock
        self._last_line: float | None = None
        self._skipped = 0

    def log(self, msg: str, *args: object, exc_info: bool = False) -> None:
        """Log ``msg % args`` now, or count it if a line went out less than
        ``interval_s`` ago.

        With ``exc_info``, a line about a single event carries the current
        exception's traceback; a line with a count does not, so a repeating
        error prints its traceback once.
        """
        now = self._clock()
        last = self._last_line
        if last is not None and now - last < self._interval_s:
            self._skipped += 1
            return
        if last is not None and self._skipped:
            self._logger.log(
                self._level,
                msg + " (%d more in the last %.0f s)",
                *args,
                self._skipped,
                now - last,
            )
        else:
            self._logger.log(self._level, msg, *args, exc_info=exc_info)
        self._last_line = now
        self._skipped = 0


def _stderr_handler() -> logging.Handler:
    handler = logging.StreamHandler(sys.stderr)
    handler.addFilter(_SessionLabel())
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s %(levelname)s %(name)s: %(session)s%(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    return handler


def configure(level: str = "warning") -> None:
    """Configure logging. Call once at startup."""
    global _configured
    if _configured:
        return

    numeric = getattr(logging, level.upper(), logging.WARNING)
    root = logging.getLogger("dsm")
    root.setLevel(numeric)
    root.addHandler(_stderr_handler())
    _configured = True


@contextlib.contextmanager
def until_configured() -> Iterator[None]:
    """Inside, a line logged before :func:`configure` (a warning about the
    config that holds ``log_level``, while it loads) goes to stderr in the
    normal format, not as Python's bare last-resort line (QA2 box Nit 1).
    A no-op once logging is configured."""
    if _configured:
        yield
        return
    handler = _stderr_handler()
    root = logging.getLogger("dsm")
    root.addHandler(handler)
    try:
        yield
    finally:
        root.removeHandler(handler)
