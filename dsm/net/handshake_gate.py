"""Limits on starting server handshake attempts.

Each admitted msg1 costs the server an attest-key signature (a TPM call on
TPM builds) and holds one of ``max_inflight_handshakes`` slots for up to
12 s. These limits stop one address, or a burst of new ones, from taking all
of that. They live on the server only and change nothing on the wire.

Limits are keyed by source IP, not port: a client gets a new port each time
it restarts. The server binds IPv4 only; an IPv6 listener would need to key
by /64.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass

from dsm.core.log import RepeatLog

log = logging.getLogger(__name__)

# One client needs one attempt at a time. The second covers a client that
# restarts while its old attempt still holds a slot.
PER_SOURCE_INFLIGHT = 2
# New attempts per address: one every 4 s, up to 3 saved up. A client that
# systemd restarts every 10 s stays well inside this.
PER_SOURCE_RATE = 0.25  # tokens per second
PER_SOURCE_BURST = 3.0
# New attempts from all addresses together: a safety net for signing time.
# Measured on the server box's TPM (2026-10-09): about 0.21 s a signature.
# Keeping the parent key loaded saves only about 40 ms of that; the real win
# is that signing no longer blocks the event loop (its longest stall went
# from 219 ms to 6 ms).
GLOBAL_START_RATE = 4.0  # tokens per second
GLOBAL_START_BURST = 8.0
# New attempts from all addresses together while a session runs, on top of
# the limits above (owner decision 2026-10-09). Each admitted attempt costs
# a TPM signature; this caps that work while a session is live.
IN_SESSION_START_RATE = 1.0  # tokens per second
IN_SESSION_START_BURST = 1.0
# Addresses remembered at once. When full, the idle address that started an
# attempt longest ago is forgotten; one with an attempt running never is.
MAX_TRACKED_SOURCES = 4096


class TokenBucket:
    """``rate`` tokens a second, holding at most ``burst``; starts full."""

    def __init__(self, rate: float, burst: float, now: float) -> None:
        self._rate = rate
        self._burst = burst
        self._tokens = burst
        self._stamp = now

    def ready(self, now: float) -> bool:
        """Refill up to ``now``; True if a whole token can be taken."""
        # A clock that steps back adds nothing and is not counted twice.
        if now > self._stamp:
            self._tokens = min(
                self._burst, self._tokens + (now - self._stamp) * self._rate
            )
            self._stamp = now
        return self._tokens >= 1.0

    def take(self) -> None:
        """Spend one token. Call only after ``ready`` returned True."""
        self._tokens -= 1.0


@dataclass
class _Source:
    inflight: int
    bucket: TokenBucket


class SourceLimiter:
    """Per-address and overall limits on new handshake attempts.

    ``run_server`` makes one per run and hands it to every accept cycle, so
    the limits hold across cycles. ``try_start`` and ``finish`` never await:
    a check and the slot it admits happen in one step on the event loop.
    Refusals are logged at INFO, at most one line per 10 s per reason, never
    with the address.
    """

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_sources: int = MAX_TRACKED_SOURCES,
    ) -> None:
        self._clock = clock
        self._max_sources = max_sources
        # Oldest start first: try_start moves an address to the end.
        self._sources: dict[str, _Source] = {}
        now = clock()
        self._overall = TokenBucket(GLOBAL_START_RATE, GLOBAL_START_BURST, now)
        self._in_session = TokenBucket(
            IN_SESSION_START_RATE, IN_SESSION_START_BURST, now
        )
        self._busy_log = RepeatLog(log, logging.INFO, clock=clock)
        self._rate_log = RepeatLog(log, logging.INFO, clock=clock)
        self._overall_log = RepeatLog(log, logging.INFO, clock=clock)
        self._in_session_log = RepeatLog(log, logging.INFO, clock=clock)

    def __len__(self) -> int:
        """How many addresses are remembered now."""
        return len(self._sources)

    def try_start(self, ip: str, *, in_session: bool = False) -> bool:
        """Admit a new attempt from ``ip`` if every limit allows it.

        All or nothing: a refusal spends no token and remembers nothing.
        Pair every True with exactly one ``finish(ip)``. ``in_session`` is
        True for the accept that runs while a session is live: such a start
        also needs the in-session budget (one a second).
        """
        now = self._clock()
        src = self._sources.get(ip)
        if src is not None and src.inflight >= PER_SOURCE_INFLIGHT:
            self._busy_log.log(
                "new handshake refused: that address already has %d running",
                PER_SOURCE_INFLIGHT,
            )
            return False
        if src is not None and not src.bucket.ready(now):
            self._rate_log.log(
                "new handshake refused: that address started too many lately"
            )
            return False
        if not self._overall.ready(now):
            self._overall_log.log(
                "new handshake refused: too many new handshakes overall"
            )
            return False
        if in_session and not self._in_session.ready(now):
            self._in_session_log.log(
                "new handshake refused: too many new handshakes while a session runs"
            )
            return False
        if src is None:
            if len(self._sources) >= self._max_sources and not self._forget_one_idle():
                self._overall_log.log(
                    "new handshake refused: too many new handshakes overall"
                )
                return False
            src = _Source(
                inflight=0,
                bucket=TokenBucket(PER_SOURCE_RATE, PER_SOURCE_BURST, now),
            )
        else:
            del self._sources[ip]  # added back below, as the newest
        src.bucket.take()
        self._overall.take()
        if in_session:
            self._in_session.take()
        src.inflight += 1
        self._sources[ip] = src
        return True

    def finish(self, ip: str) -> None:
        """End one attempt that ``try_start(ip)`` admitted.

        Callers must pair each True from ``try_start`` with exactly one
        ``finish``; a missed ``finish`` is the caller's to prevent.

        Raises:
            RuntimeError: ``ip`` has no running attempt to end. Nothing
                changes, so one extra call cannot let an address run more
                than its share.
        """
        src = self._sources.get(ip)
        if src is None or src.inflight <= 0:
            raise RuntimeError("finish without a matching try_start")
        src.inflight -= 1

    def _forget_one_idle(self) -> bool:
        """Forget the idle address that started longest ago, if there is one."""
        idle = next(
            (ip for ip, src in self._sources.items() if src.inflight == 0), None
        )
        if idle is None:
            return False
        del self._sources[idle]
        return True
