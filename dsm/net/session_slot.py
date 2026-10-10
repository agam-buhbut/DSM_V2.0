"""Who holds the server's one session, and who may take it over.

The server serves one client at a time. While a session runs it still
accepts handshakes, so a client that crashed and came back does not wait
for the old session's dead-peer timer. After a handshake passed every check
(certificate chain, attest signature, allowlist, CRL) and before the server
sends the last handshake frame, this module decides whether that client may
have the session:

* Only one handshake at a time may sit between this check and becoming the
  next session.
* While a session runs, only a client with the same CN (the name in its
  certificate) may take it over: that is the same client coming back.
  Another client is refused, as it always was; it gets in once the session
  ends.
* Each CN may take its session over 3 times at once, then once a minute.
  Two devices that share one CN would otherwise push each other off
  forever. When the budget is spent, the old session stays.

Nothing here touches the wire.
"""

from __future__ import annotations

import hashlib
import logging
import time
from collections.abc import Callable

from dsm.core.log import RepeatLog
from dsm.crypto.handshake import ClientRefusedError, VerifiedClient
from dsm.net.handshake_gate import TokenBucket

log = logging.getLogger(__name__)

# Session takeovers per CN: 3 at once, then 1 a minute (owner decision
# 2026-10-09). A client that crashes more often than that waits for the old
# session's dead-peer timer, as it did before a session could be taken over.
REPLACE_BURST = 3.0
REPLACE_RATE = 1.0 / 60.0  # tokens per second


def _key_hash(noise_static: bytes) -> str:
    """The 16-hex key hash the server already logs when a client connects."""
    return hashlib.sha256(noise_static).hexdigest()[:16]


class SessionSlot:
    """The server's one session: who holds it, and who may take it over.

    ``run_server`` makes one per run and hands it to every accept. Nothing
    here awaits, so a check and the mark it sets happen in one step on the
    event loop.
    """

    def __init__(self, *, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._holder: VerifiedClient | None = None
        self._admitted: tuple[object, VerifiedClient] | None = None
        # One budget per CN that ever took its session over. Only CNs on the
        # allowlist get that far, so the allowlist bounds this table.
        self._budgets: dict[str, TokenBucket] = {}
        self._other_client_log = RepeatLog(log, logging.INFO, clock=clock)
        self._too_often_log = RepeatLog(log, logging.WARNING, clock=clock)

    @property
    def holder(self) -> VerifiedClient | None:
        """The client of the live session (or of the next one), or None."""
        return self._holder

    @property
    def admitted(self) -> object | None:
        """The attempt that passed :meth:`admit` and has not ended, or None."""
        return None if self._admitted is None else self._admitted[0]

    def admit(
        self, attempt: object, client: VerifiedClient, *, session_live: bool
    ) -> None:
        """Let ``client`` have the last handshake frame, or refuse it.

        ``attempt`` marks the handshake; pass the same object to
        :meth:`confirm` or :meth:`release`. ``session_live`` is True for the
        accept that runs during a session. A takeover spends one token of the
        CN's budget here, after every check passed.

        Raises:
            ClientRefusedError: another attempt is finishing; or a session
                runs and its client is unknown, has another CN, or this CN
                took its session over too often lately.
        """
        if self._admitted is not None:
            raise ClientRefusedError("another handshake is finishing")
        if session_live:
            holder = self._holder
            if holder is None:
                # Cannot happen: a session starts only after confirm() set
                # the holder. Refuse rather than guess.
                raise ClientRefusedError("the live session's client is unknown")
            if client.cn != holder.cn:
                self._other_client_log.log(
                    "handshake refused: another client is connected (client_cn=%s)",
                    client.cn,
                )
                raise ClientRefusedError("another client holds the session")
            now = self._clock()
            budget = self._budgets.get(client.cn)
            if budget is None:
                budget = TokenBucket(REPLACE_RATE, REPLACE_BURST, now)
                self._budgets[client.cn] = budget
            if not budget.ready(now):
                self._too_often_log.log(
                    "client_cn=%s reconnected too often; keeping its current "
                    "session (two devices with one name?)",
                    client.cn,
                )
                raise ClientRefusedError("this client took its session over too often")
            budget.take()
        self._admitted = (attempt, client)

    def confirm(self, attempt: object) -> None:
        """``attempt`` won: its client holds the session from now on.

        Logs a takeover when another client held the session before, and a
        warning when the device key changed.

        Raises:
            RuntimeError: ``attempt`` did not pass :meth:`admit`.
        """
        if self._admitted is None or self._admitted[0] is not attempt:
            raise RuntimeError("confirm without a matching admit")
        _, client = self._admitted
        self._admitted = None
        old = self._holder
        self._holder = client
        if old is None:
            return
        log.info("client reconnected (client_cn=%s); ending its old session", client.cn)
        if old.noise_static != client.noise_static:
            log.warning(
                "client_cn=%s reconnected with a different device key "
                "(noise_static_sha256=%s, was %s); if this repeats, two devices "
                "share this name",
                client.cn,
                _key_hash(client.noise_static),
                _key_hash(old.noise_static),
            )

    def release(self, attempt: object) -> None:
        """``attempt`` ended without winning. Does nothing if it holds nothing."""
        if self._admitted is not None and self._admitted[0] is attempt:
            self._admitted = None

    def clear(self) -> None:
        """The session ended with no client waiting to take it over.

        Runs only after the accept drained every attempt, so an attempt still
        marked here is a bug; it is forgotten too, or every later handshake
        would be refused until a restart. Should it end later, it cannot
        win: it is no longer marked, so :meth:`confirm` raises for it.
        """
        self._holder = None
        self._admitted = None
