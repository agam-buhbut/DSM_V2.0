"""Only if the owner approves (spec, owner answer 4): the tier-1 warning.

Loss that lasts at tier 1, the floor where nothing can be capped, logs a
warning at most every FLOOR_WARN_INTERVAL_S. At the default tiers one second
at tier 1 holds 40-60 packets, under MIN_INTERVAL_PACKETS, so consecutive
tier-1 intervals are pooled until they reach it; two bad pools in a row
warn. Nothing on the wire, no cap.
"""

from __future__ import annotations

import logging

import pytest

from dsm.core.protocol import LinkReport
from dsm.traffic.autocap import FLOOR_WARN_INTERVAL_S, AutoCap

_LOGGER = "dsm.traffic.autocap"
_WARNING = (
    "auto cap: link too slow even for tier 1 (about 10% lost); "
    "lower shaper_tiers_pps by hand"
)


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
    """The sending side at tier 1, as AutoCap sees it."""

    def __init__(self) -> None:
        self.seq = 0
        self.received = 0
        self.tier = 1
        self.clock = _Clock()
        self.shaper = _Shaper()
        self.auto = AutoCap(
            self.shaper,
            tiers_pps=(10.0, 50.0, 200.0, 800.0),
            start_tier=1,
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
    link = _Link()
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
    link = _Link()
    link.interval(60)
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger=_LOGGER):
        for _ in range(100):
            link.interval(60, 2)  # 3.3% per pool
    assert _warnings(caplog) == []


def test_a_tier_change_starts_the_pool_over(caplog: pytest.LogCaptureFixture) -> None:
    link = _Link()
    link.interval(60)
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger=_LOGGER):
        link.interval(60, 6)
        link.interval(60, 6)  # one bad pool
        link.set_tier(2)
        link.interval(30, 3)  # at tier 2: the pool and the run start over
        link.set_tier(1)
        link.interval(60, 6)
        link.interval(60, 6)  # one bad pool again
        assert _warnings(caplog) == []
        link.interval(60, 6)
        link.interval(60, 6)
        assert _warnings(caplog) == [_WARNING]
