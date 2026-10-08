"""The tier-1 warning (owner answer 4).

Once auto cap has stepped down to tier 1, the floor where nothing can be
capped, because a higher tier lost packets, loss that lasts there logs a
warning at most every FLOOR_WARN_INTERVAL_S. A tier list that tops out at
tier 1 starts with the cap there. Loss at tier 1 without the cap there (for
example in linger after a download) never warns. At the default tiers one
second at tier 1 holds 40-60 packets, under MIN_INTERVAL_PACKETS, so
consecutive tier-1 intervals are pooled until they reach it; two bad pools
in a row warn. Nothing on the wire, no cap.
"""

from __future__ import annotations

import logging

import pytest

from dsm.core.protocol import LinkReport
from dsm.traffic.autocap import FLOOR_WARN_INTERVAL_S, AutoCap

_LOGGER = "dsm.traffic.autocap"
# The cap starts at the top, so with these tiers it is at the floor from the
# start; with the four tiers it gets there only after loss at tier 2.
TWO_TIERS = (10.0, 50.0)
FOUR_TIERS = (10.0, 50.0, 200.0, 800.0)


def _warning(pct: int) -> str:
    return (
        f"auto cap: link too slow even for tier 1 (about {pct}% lost); "
        "lower shaper_tiers_pps by hand"
    )


_WARNING = _warning(10)


class _Shaper:
    def __init__(self) -> None:
        self.caps: list[int] = []

    def set_tier_cap(self, cap: int) -> None:
        self.caps.append(cap)


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class _Link:
    """The sending side, as AutoCap sees it."""

    def __init__(
        self, *, tiers: tuple[float, ...] = TWO_TIERS, start_tier: int = 1
    ) -> None:
        self.seq = 0
        self.received = 0
        self.tier = start_tier
        self.clock = _Clock()
        self.shaper = _Shaper()
        self.auto = AutoCap(
            self.shaper,
            tiers_pps=tiers,
            start_tier=start_tier,
            last_seq=lambda: self.seq,
            clock=self.clock,
        )

    def set_tier(self, tier: int) -> None:
        if tier != self.tier:
            self.tier = tier
            self.auto.note_tier(tier)

    def interval(self, sent: int, lost: int = 0) -> None:
        self.seq += sent
        self.received += sent - lost
        self.clock.now += 1.0
        self.auto.tick()
        self.auto.on_report(LinkReport(highest_seq=self.seq, received=self.received))


def _warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == _LOGGER and r.levelno == logging.WARNING
    ]


def test_lasting_loss_at_tier_one_warns_at_most_every_ten_minutes(
    caplog: pytest.LogCaptureFixture,
) -> None:
    link = _Link(tiers=TWO_TIERS)
    link.interval(60)  # starting point
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger=_LOGGER):
        for _ in range(3):
            link.interval(60, 6)
        assert _warnings(caplog) == [], "warned after one pool"
        link.interval(60, 6)  # the second bad pool of 120 packets
        assert _warnings(caplog) == [_WARNING]
        for _ in range(100):
            link.interval(60, 6)
        assert len(_warnings(caplog)) == 1, "warned again within ten minutes"
        link.clock.now += FLOOR_WARN_INTERVAL_S
        for _ in range(4):
            link.interval(60, 6)
        assert len(_warnings(caplog)) == 2
    assert link.shaper.caps == [], "the floor was capped"


def test_light_loss_at_tier_one_never_warns(caplog: pytest.LogCaptureFixture) -> None:
    link = _Link(tiers=TWO_TIERS)
    link.interval(60)
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger=_LOGGER):
        for _ in range(100):
            link.interval(60, 2)  # 3.3% per pool
    assert _warnings(caplog) == []


def test_a_tier_change_starts_the_pool_over(caplog: pytest.LogCaptureFixture) -> None:
    link = _Link(tiers=TWO_TIERS)
    link.interval(60)
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger=_LOGGER):
        link.interval(60, 6)
        link.interval(60, 6)  # one bad pool
        link.set_tier(0)
        link.interval(30, 3)  # at tier 0: the pool and the run start over
        link.set_tier(1)
        link.interval(60, 6)
        link.interval(60, 6)  # one bad pool again
        assert _warnings(caplog) == []
        link.interval(60, 6)
        link.interval(60, 6)
        assert _warnings(caplog) == [_WARNING]


def test_a_half_full_pool_is_emptied_by_a_tier_change(
    caplog: pytest.LogCaptureFixture,
) -> None:
    link = _Link(tiers=TWO_TIERS)
    link.interval(60)
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger=_LOGGER):
        link.interval(60)  # half a pool, clean
        link.set_tier(0)
        link.interval(10)
        link.set_tier(1)
        # Kept, the clean half would make the next pool 120 packets with 4
        # lost (3.3%, clean), and no warning would come in these four.
        for _ in range(4):
            link.interval(60, 4)
        assert _warnings(caplog) == [_warning(6)]


def test_no_warning_at_tier_one_when_auto_cap_did_not_drop_there(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Linger after use: tier 1 with no cap. Loss there (a fast but lossy
    Wi-Fi) does not show that the link is too slow."""
    link = _Link(tiers=FOUR_TIERS, start_tier=3)
    link.interval(800)
    link.set_tier(1)
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger=_LOGGER):
        for _ in range(100):
            link.interval(60, 6)
    assert _warnings(caplog) == []
    assert link.shaper.caps == []


def test_warns_once_auto_cap_dropped_to_tier_one_and_stops_after_a_lift(
    caplog: pytest.LogCaptureFixture,
) -> None:
    link = _Link(tiers=FOUR_TIERS, start_tier=2)
    link.interval(200)
    link.interval(200, 20)
    link.interval(200, 20)  # two bad intervals at tier 2: cap at tier 1
    assert link.shaper.caps == [1]
    link.set_tier(1)
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger=_LOGGER):
        for _ in range(4):
            link.interval(60, 6)
        assert _warnings(caplog) == [_WARNING]
        # Past the lift (cap back at 2) and past the ten-minute limit: the
        # cap is no longer at the floor, so tier-1 loss warns no more.
        link.clock.now += FLOOR_WARN_INTERVAL_S
        for _ in range(8):
            link.interval(60, 6)
        assert link.shaper.caps == [1, 2]
        assert _warnings(caplog) == [_WARNING]


@pytest.mark.parametrize(
    ("since_warning", "warns"),
    [(FLOOR_WARN_INTERVAL_S - 0.001, False), (FLOOR_WARN_INTERVAL_S, True)],
)
def test_the_ten_minute_limit_ends_exactly_at_its_length(
    since_warning: float, warns: bool, caplog: pytest.LogCaptureFixture
) -> None:
    link = _Link(tiers=TWO_TIERS)
    link.interval(60)
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger=_LOGGER):
        for _ in range(4):
            link.interval(60, 6)
        assert _warnings(caplog) == [_WARNING]
        warned_at = link.clock.now
        for _ in range(3):
            link.interval(60, 6)
        # The next interval completes the second bad pool at this time.
        link.clock.now = warned_at + since_warning - 1.0
        link.interval(60, 6)
        assert link.clock.now - warned_at == pytest.approx(since_warning)
    assert len(_warnings(caplog)) == (2 if warns else 1)
