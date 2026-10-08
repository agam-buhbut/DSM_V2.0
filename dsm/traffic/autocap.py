"""Slow-link auto cap: receiver counts.

The receiver counts the genuine packets it gets from its peer
(``LinkStats``); the session sends those totals to the peer in a
LINK_REPORT. Nothing here logs seq numbers or report totals.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class LinkStats:
    """Receiver totals for one session: genuine packets from the peer."""

    received: int = 0
    highest_seq: int = 0

    def note(self, seq: int) -> None:
        """Count one packet that passed AEAD with a seq not seen before."""
        self.received += 1
        self.highest_seq = max(self.highest_seq, seq)
