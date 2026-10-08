"""Slow-link auto cap.

On a link slower than the top tier, the shaper floods it. The receiver can
count lost packets exactly (gaps in the seq), and the sender holds the knob:

* Receiver side: ``LinkStats`` holds two totals for the session, the highest
  authenticated seq and how many authenticated packets arrived. About once a
  second the session sends them to the peer in a LINK_REPORT.
* Sender side: ``AutoCap`` compares two reports, so it knows how many packets
  it sent in that stretch (every packet takes the next seq) and how many
  arrived, and its tier log tells which tier they left at. Two bad stretches
  in a row at a tier k of 2 or more cap the shaper at k - 1; after a wait the
  cap is lifted one tier. The loss check (tier log, intervals) is kept apart
  from the reaction (cap and lift), so a later rule can replace the reaction
  alone. Once the cap is at tier 1, the floor, loss that lasts there logs a
  warning instead (nothing is left to cap).

Nothing here logs seq numbers or report totals. Every method runs on the
session's asyncio thread and never awaits.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from fractions import Fraction
from typing import TYPE_CHECKING, Protocol

from dsm.core import netaudit
from dsm.core.log import RepeatLog

if TYPE_CHECKING:
    from dsm.core.protocol import LinkReport

log = logging.getLogger(__name__)

# How often, on average, the session sends a report and runs the lift timer
# (s). Each wait is drawn at random from half to one and a half times this.
REPORT_INTERVAL_S = 1.0
# An interval is bad when at least this share of what was sent was lost.
LOSS_THRESHOLD = 0.05
# Smaller intervals are not judged: a bad one then needs at least 5 lost
# packets, so one or two random losses never count.
MIN_INTERVAL_PACKETS = 100
# Bad intervals in a row, at the same tier, that cap the shaper.
BAD_INTERVALS_TO_CAP = 2
# The cap never goes below this tier.
MIN_CAP_TIER = 1
# Wait before the cap is lifted one tier. It doubles each time loss comes
# back after a lift, up to the maximum.
FIRST_LIFT_WAIT_S = 300.0
MAX_LIFT_WAIT_S = 3600.0
# Clean intervals in a row at the tier the last lift opened, or higher, that
# set the wait back to FIRST_LIFT_WAIT_S.
CLEAN_INTERVALS_TO_RESET = 30
# Most tier log entries kept, for a peer that never reports.
TIER_LOG_MAX = 64
# Loss that lasts at tier 1 (nothing left to cap) logs a warning at most
# this often (s).
FLOOR_WARN_INTERVAL_S = 600.0

# LOSS_THRESHOLD as an exact ratio, so the check is an integer one
# (lost * 20 >= sent at 5%) and exactly 5% is bad for any packet count.
_LOSS = Fraction(LOSS_THRESHOLD).limit_denominator(1000)

_IGNORED_REPORT = "auto cap: ignored a short or nonsensical link report"


@dataclass(slots=True)
class LinkStats:
    """Receiver totals for one session: genuine packets from the peer."""

    received: int = 0
    highest_seq: int = 0

    def note(self, seq: int) -> None:
        """Count one packet that passed AEAD with a seq not seen before."""
        self.received += 1
        self.highest_seq = max(self.highest_seq, seq)


class TierCapTarget(Protocol):
    """The one shaper call ``AutoCap`` makes."""

    def set_tier_cap(self, cap: int) -> None: ...


class AutoCap:
    """Caps the shaper's top tier on sustained loss, and lifts it later.

    One per session. ``note_tier`` is the shaper's tier listener,
    ``on_report`` takes the peer's reports, and ``tick`` runs once a second.
    Report content never makes it raise: a report that makes no sense is
    ignored with a rate-limited DEBUG line.
    """

    def __init__(
        self,
        shaper: TierCapTarget,
        *,
        tiers_pps: Sequence[float],
        start_tier: int,
        last_seq: Callable[[], int],
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """
        Args:
            shaper: gets ``set_tier_cap`` calls, nothing else.
            tiers_pps: the configured tier rates. Their count sets the top
                tier, which is the no-cap value and where lifts stop; the
                rates show in log lines.
            start_tier: the shaper's tier now.
            last_seq: our last used seq (``SequenceCounter.value``).
            clock: monotonic clock for the lift timer.
        """
        self._shaper = shaper
        self._tiers_pps = tuple(tiers_pps)
        self._top = len(self._tiers_pps) - 1
        self._last_seq = last_seq
        self._clock = clock
        # Loss check: (first seq, tier) at every tier change, oldest first,
        # and the last accepted report's (highest_seq, received).
        self._tier_log: list[tuple[int, int]] = [(last_seq() + 1, start_tier)]
        self._base: tuple[int, int] | None = None
        self._bad_run = 0
        self._bad_tier = -1
        # Reaction. A cap at the top tier means no cap.
        self._cap = self._top
        self._wait_s = FIRST_LIFT_WAIT_S
        self._lift_at: float | None = None
        self._lifted_since_cap = False
        self._opened_tier: int | None = None
        self._clean_run = 0
        self._ignored = RepeatLog(log, logging.DEBUG, clock=clock)
        # Tier-1 warning: pooled tier-1 intervals, bad pools in a row, and
        # when the last warning went out.
        self._floor_sent = 0
        self._floor_lost = 0
        self._floor_bad_run = 0
        self._floor_warned_at: float | None = None

    def note_tier(self, tier: int) -> None:
        """Shaper listener: the last poll changed the tier to ``tier``.

        Every packet sent after that poll takes the next seq, so the new tier
        starts at ``last_seq() + 1``. Runs inside the send loop: it must not
        raise, so it only does integer and list work.
        """
        first = self._last_seq() + 1
        if self._tier_log[-1][0] == first:
            # No packet left at the tier before: it never carried one.
            self._tier_log[-1] = (first, tier)
        else:
            self._tier_log.append((first, tier))
        if len(self._tier_log) > TIER_LOG_MAX:
            del self._tier_log[0]

    def on_report(self, report: LinkReport) -> None:
        """Take the peer's LINK_REPORT: judge the stretch since the last one
        and cap the shaper when loss lasted."""
        high, received = report.highest_seq, report.received
        base = self._base
        # Ignore, and keep the starting point: a seq we never sent (the peer
        # cannot have seen it), an older or reordered report, a second with
        # only late packets (same highest seq), or fewer received.
        if high > self._last_seq() or (
            base is not None and (high <= base[0] or received < base[1])
        ):
            self._ignored.log(_IGNORED_REPORT)
            return
        self._base = (high, received)
        if base is not None:
            sent = high - base[0]
            # Late packets can make more arrive than were sent: no loss.
            lost = max(0, sent - (received - base[1]))
            self._judge(self._tier_of(base[0] + 1, high), sent, lost)
        self._prune(high)

    def note_short_report(self) -> None:
        """The peer sent a LINK_REPORT shorter than 16 bytes."""
        self._ignored.log(_IGNORED_REPORT)

    def tick(self) -> None:
        """Run once a second: lift the cap one tier when its wait is over.

        A lift only changes the cap; the rate rises only when the shaper's
        usual rules climb.
        """
        now = self._clock()
        if self._lift_at is None or now < self._lift_at:
            return
        self._cap = min(self._cap + 1, self._top)
        self._shaper.set_tier_cap(self._cap)
        self._opened_tier = self._cap
        self._clean_run = 0
        self._lifted_since_cap = True
        if self._cap < self._top:
            self._lift_at = now + self._wait_s
            log.info(
                "auto cap: top tier back up to %d (%s/s)",
                self._cap,
                self._rate(self._cap),
            )
            netaudit.emit(
                "auto_cap_change",
                direction="raise",
                tier=self._cap,
                cap=self._cap,
                loss_pct=None,
                wait_s=self._wait_s,
            )
        else:
            self._lift_at = None
            log.info("auto cap: lifted, no cap")
            netaudit.emit(
                "auto_cap_change",
                direction="raise",
                tier=self._cap,
                cap=None,
                loss_pct=None,
                wait_s=None,
            )

    def _tier_of(self, first: int, last: int) -> int | None:
        """The tier seqs ``first`` to ``last`` left at, or None when a tier
        change falls inside them or the log no longer reaches back to
        ``first``."""
        tier: int | None = None
        for start, entry_tier in self._tier_log:
            if start <= first:
                tier = entry_tier
            elif start <= last:
                return None
            else:
                break
        return tier

    def _prune(self, high: int) -> None:
        """Drop the tier log entries no later report can need: all but the
        newest one at or below ``high``, and everything after it."""
        keep = 0
        for i, (start, _) in enumerate(self._tier_log):
            if start <= high:
                keep = i
        del self._tier_log[:keep]

    def _judge(self, tier: int | None, sent: int, lost: int) -> None:
        """Judge one interval and fire the cap trigger.

        Not judged, and the run of bad intervals starts over: a mixed or
        unknown tier, fewer than MIN_INTERVAL_PACKETS sent, a tier above the
        cap (sent before the last cap, so stale), or the floor and below
        (nothing to cap there). An interval at the floor goes to the floor
        warning instead (``_note_floor``), but only while the cap is there.
        """
        # Pool tier-1 loss only once the cap is at the floor: auto cap
        # stepped down there because a higher tier lost packets, or the tier
        # list tops out at tier 1 (the cap starts at the top). Loss at tier 1
        # without that, for example in linger on a fast but lossy Wi-Fi, does
        # not show that the link is too slow.
        if tier == MIN_CAP_TIER and self._cap == MIN_CAP_TIER:
            self._note_floor(sent, lost)
        else:
            self._floor_sent = self._floor_lost = self._floor_bad_run = 0
        if (
            tier is None
            or sent < MIN_INTERVAL_PACKETS
            or tier > self._cap
            or tier <= MIN_CAP_TIER
        ):
            self._bad_run = 0
            return
        if lost * _LOSS.denominator < sent * _LOSS.numerator:
            self._bad_run = 0
            self._note_clean(tier)
            return
        loss_pct = lost * 100 // sent
        log.debug("auto cap: lost %d%% of %d packets at tier %d", loss_pct, sent, tier)
        if self._opened_tier is not None and tier >= self._opened_tier:
            self._clean_run = 0
        self._bad_run = self._bad_run + 1 if tier == self._bad_tier else 1
        self._bad_tier = tier
        if self._bad_run >= BAD_INTERVALS_TO_CAP:
            self._bad_run = 0
            self._cap_at(tier, loss_pct)

    def _note_floor(self, sent: int, lost: int) -> None:
        """Loss at tier 1 with the cap there: nothing left to cap, so warn
        when it lasts.

        One-second intervals at tier 1 hold fewer than MIN_INTERVAL_PACKETS
        packets at the default tiers (40-60 a second), so consecutive ones
        are pooled until they reach it. BAD_INTERVALS_TO_CAP bad pools in a
        row warn, at most every FLOOR_WARN_INTERVAL_S.
        """
        self._floor_sent += sent
        self._floor_lost += lost
        if self._floor_sent < MIN_INTERVAL_PACKETS:
            return
        bad = self._floor_lost * _LOSS.denominator >= self._floor_sent * _LOSS.numerator
        loss_pct = self._floor_lost * 100 // self._floor_sent
        self._floor_sent = self._floor_lost = 0
        self._floor_bad_run = self._floor_bad_run + 1 if bad else 0
        if self._floor_bad_run < BAD_INTERVALS_TO_CAP:
            return
        self._floor_bad_run = 0
        now = self._clock()
        warned_at = self._floor_warned_at
        if warned_at is not None and now - warned_at < FLOOR_WARN_INTERVAL_S:
            return
        self._floor_warned_at = now
        log.warning(
            "auto cap: link too slow even for tier 1 (about %d%% lost); "
            "lower shaper_tiers_pps by hand",
            loss_pct,
        )

    def _note_clean(self, tier: int) -> None:
        """A clean interval. CLEAN_INTERVALS_TO_RESET in a row at or above
        the tier the last lift opened show the link carries it: the wait
        starts over, and a pending lift comes within FIRST_LIFT_WAIT_S."""
        if self._opened_tier is None or tier < self._opened_tier:
            return
        self._clean_run += 1
        if self._clean_run < CLEAN_INTERVALS_TO_RESET:
            return
        self._wait_s = FIRST_LIFT_WAIT_S
        self._lifted_since_cap = False
        self._opened_tier = None
        self._clean_run = 0
        if self._lift_at is not None:
            self._lift_at = min(self._lift_at, self._clock() + FIRST_LIFT_WAIT_S)

    def _cap_at(self, tier: int, loss_pct: int) -> None:
        """Cap event: loss lasted at ``tier``, so the top tier becomes one
        lower. The shaper steps down at its next poll."""
        if self._lifted_since_cap:
            # Loss came back after a lift: wait longer before the next try.
            self._wait_s = min(2 * self._wait_s, MAX_LIFT_WAIT_S)
        self._cap = max(tier - 1, MIN_CAP_TIER)
        self._shaper.set_tier_cap(self._cap)
        self._lift_at = self._clock() + self._wait_s
        self._lifted_since_cap = False
        self._opened_tier = None
        self._clean_run = 0
        log.info(
            "auto cap: lost %d%% at tier %d (%s/s); top tier now %d (%s/s), "
            "next try in %d min",
            loss_pct,
            tier,
            self._rate(tier),
            self._cap,
            self._rate(self._cap),
            round(self._wait_s / 60),
        )
        netaudit.emit(
            "auto_cap_change",
            direction="lower",
            tier=tier,
            cap=self._cap,
            loss_pct=loss_pct,
            wait_s=self._wait_s,
        )

    def _rate(self, tier: int) -> str:
        """The configured rate of ``tier`` (public, from the config file)."""
        return f"{self._tiers_pps[tier]:g}"
