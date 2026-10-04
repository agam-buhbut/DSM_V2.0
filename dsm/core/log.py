"""Logging configuration for DSM, and a limit for lines that can repeat per
packet."""

from __future__ import annotations

import logging
import sys
import time
from collections.abc import Callable

_configured = (
    False  # pylint: disable=invalid-name  # module-private flag, not a constant
)

# Events that can repeat once per packet log at most one line per this many
# seconds. The shaper sends 8-12 packets/s at idle and up to ~960/s at the top
# tier, so one line per packet would flood the log; one line per 10 s still
# shows within seconds that a problem started, and every 10 s that it goes on.
REPEAT_LOG_INTERVAL_S = 10.0


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

    def log(self, msg: str, *args: object) -> None:
        """Log ``msg % args`` now, or count it if a line went out less than
        ``interval_s`` ago."""
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
            self._logger.log(self._level, msg, *args)
        self._last_line = now
        self._skipped = 0


def configure(level: str = "warning") -> None:
    """Configure logging. Call once at startup."""
    global _configured
    if _configured:
        return

    numeric = getattr(logging, level.upper(), logging.WARNING)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s %(levelname)s %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    root = logging.getLogger("dsm")
    root.setLevel(numeric)
    root.addHandler(handler)
    _configured = True
