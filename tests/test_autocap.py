"""The slow-link auto cap's rules (``dsm.traffic.autocap.AutoCap``).

A scripted link stands in for the session: our seq counter, the tier the
shaper is on, and the peer's totals. The shaper is a fake that records every
``set_tier_cap`` call and has no other method, so any other call fails the
test. A fake clock drives the lift timer. Deterministic: no sleeps.
"""

from __future__ import annotations

import logging

import pytest

from dsm.core import netaudit
from dsm.core.protocol import LinkReport
from dsm.traffic.autocap import TIER_LOG_MAX, AutoCap

TIERS = (10.0, 50.0, 200.0, 800.0)
_LOGGER = "dsm.traffic.autocap"


class _Shaper:
    """Records every cap; has no other method."""

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
    """One session's sending side, as AutoCap sees it."""

    def __init__(
        self, *, tiers: tuple[float, ...] = TIERS, start_tier: int = 3, seq: int = 0
    ) -> None:
        self.seq = seq
        self.received = seq
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
        """The shaper moved to ``tier`` (its listener runs only on a change)."""
        if tier != self.tier:
            self.tier = tier
            self.auto.note_tier(tier)

    def send(self, sent: int, lost: int = 0, late: int = 0) -> None:
        """Send ``sent`` packets at the current tier: ``lost`` of them never
        arrive, and ``late`` packets from earlier arrive now."""
        self.seq += sent
        self.received += sent - lost + late

    def report(self) -> None:
        self.auto.on_report(LinkReport(highest_seq=self.seq, received=self.received))

    def interval(self, sent: int, lost: int = 0, late: int = 0) -> None:
        """One second: send, run the lift timer, then the report arrives."""
        self.send(sent, lost, late)
        self.clock.now += 1.0
        self.auto.tick()
        self.report()

    def flood(self, tier: int) -> float:
        """Two bad intervals (25% lost) at ``tier``; returns the time of the
        second report."""
        self.set_tier(tier)
        self.interval(800, 200)
        self.interval(800, 200)
        return self.clock.now

    def wait_until(self, at: float) -> None:
        self.clock.now = at
        self.auto.tick()


def _messages(caplog: pytest.LogCaptureFixture, level: int) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == _LOGGER and r.levelno == level
    ]


def test_the_first_report_is_only_a_starting_point() -> None:
    link = _Link()
    link.interval(800, 400)
    link.interval(800, 400)
    assert link.shaper.caps == [], "the first report was judged"
    link.interval(800, 400)
    assert link.shaper.caps == [2]


def test_two_bad_intervals_in_a_row_cap_one_tier_down() -> None:
    link = _Link()
    link.interval(800)
    link.interval(800, 100)
    assert link.shaper.caps == []
    link.interval(800, 100)
    assert link.shaper.caps == [2]


def test_bad_then_clean_never_caps() -> None:
    link = _Link()
    link.interval(800)
    for _ in range(20):
        link.interval(800, 100)
        link.interval(800)
    assert link.shaper.caps == []


@pytest.mark.parametrize(("lost", "caps"), [(50, [2]), (49, [])])
def test_exactly_five_percent_is_bad_and_just_under_is_clean(
    lost: int, caps: list[int]
) -> None:
    link = _Link()
    link.interval(1000)
    link.interval(1000, lost)
    link.interval(1000, lost)
    assert link.shaper.caps == caps


def test_fewer_than_100_packets_are_not_judged() -> None:
    link = _Link(start_tier=2)
    link.interval(500)
    for _ in range(5):
        link.interval(99, 50)
    assert link.shaper.caps == []
    link.interval(100, 5)
    link.interval(100, 5)
    assert link.shaper.caps == [1]


def test_an_interval_across_a_tier_change_is_skipped_and_resets_the_run() -> None:
    link = _Link()
    link.interval(800)
    link.interval(800, 100)  # bad at tier 3: one in a row
    link.send(400, 50)
    link.set_tier(2)  # the tier changed inside this interval
    link.send(400, 50)
    link.clock.now += 1.0
    link.report()  # mixed: skipped, and the run starts over
    link.set_tier(3)
    link.interval(800, 100)
    assert link.shaper.caps == [], "the mixed interval did not reset the run"
    link.interval(800, 100)
    assert link.shaper.caps == [2]


def test_loss_at_tier_one_never_caps() -> None:
    link = _Link(start_tier=1)
    link.interval(800)
    for _ in range(10):
        link.interval(800, 400)
    assert link.shaper.caps == []


def test_one_flood_caps_once() -> None:
    link = _Link()
    link.interval(800)
    link.flood(3)
    assert link.shaper.caps == [2]
    # Reports of packets that left at tier 3 before the step-down: stale.
    link.interval(800, 200)
    link.interval(800, 200)
    assert link.shaper.caps == [2]


def test_a_cascade_keeps_the_wait_and_stops_at_tier_one(
    caplog: pytest.LogCaptureFixture,
) -> None:
    link = _Link()
    link.interval(800)
    caplog.clear()
    with caplog.at_level(logging.INFO, logger=_LOGGER):
        link.flood(3)
        link.flood(2)
    assert link.shaper.caps == [2, 1]
    lines = _messages(caplog, logging.INFO)
    assert len(lines) == 2
    assert all(line.endswith("next try in 5 min") for line in lines), lines
    link.set_tier(1)
    for _ in range(10):
        link.interval(800, 400)
    assert link.shaper.caps == [2, 1], "capped below tier 1"


def test_the_lift_comes_at_exactly_the_wait_and_only_raises_the_cap() -> None:
    link = _Link()
    link.interval(800)
    capped_at = link.flood(3)
    link.wait_until(capped_at + 299.9)
    assert link.shaper.caps == [2]
    link.wait_until(capped_at + 300.0)
    # The fake shaper has no other method: the lift made exactly this call.
    assert link.shaper.caps == [2, 3]
    link.wait_until(capped_at + 100_000.0)
    assert link.shaper.caps == [2, 3], "lifted past the top"


def test_lifts_open_one_tier_at_a_time(caplog: pytest.LogCaptureFixture) -> None:
    link = _Link()
    link.interval(800)
    link.flood(3)
    capped_at = link.flood(2)
    caplog.clear()
    with caplog.at_level(logging.INFO, logger=_LOGGER):
        link.wait_until(capped_at + 300.0)
        assert link.shaper.caps == [2, 1, 2]
        link.wait_until(capped_at + 599.9)
        assert link.shaper.caps == [2, 1, 2]
        link.wait_until(capped_at + 600.0)
        assert link.shaper.caps == [2, 1, 2, 3]
    assert _messages(caplog, logging.INFO) == [
        "auto cap: top tier back up to 2 (200/s)",
        "auto cap: lifted, no cap",
    ]


def test_loss_after_a_lift_doubles_the_wait_up_to_an_hour() -> None:
    link = _Link()
    link.interval(800)
    for wait in (300.0, 600.0, 1200.0, 2400.0, 3600.0, 3600.0):
        capped_at = link.flood(3)
        assert link.shaper.caps[-1] == 2
        link.set_tier(2)
        link.wait_until(capped_at + wait - 0.1)
        assert link.shaper.caps[-1] == 2, f"lifted before {wait} s"
        link.wait_until(capped_at + wait)
        assert link.shaper.caps[-1] == 3, f"no lift at {wait} s"


def test_thirty_clean_intervals_at_the_opened_tier_reset_the_wait(
    caplog: pytest.LogCaptureFixture,
) -> None:
    link = _Link()
    link.interval(800)
    capped_at = link.flood(3)  # cap 2, wait 300
    link.wait_until(capped_at + 300.0)  # no cap; the lift opened tier 3
    link.flood(3)  # loss came back: cap 2, wait 600
    capped_at = link.flood(2)  # cascade: cap 1, the wait stays 600
    assert link.shaper.caps == [2, 3, 2, 1]
    link.wait_until(capped_at + 600.0)  # cap 2; the lift opened tier 2
    lifted_at = link.clock.now
    assert link.shaper.caps[-1] == 2
    for _ in range(29):
        link.interval(200)
    link.interval(200, 20)  # one bad interval starts the clean run over
    for _ in range(30):
        link.interval(200)
    # 30 clean in a row at lifted_at + 60 pull the next lift from
    # lifted_at + 600 to lifted_at + 360. Without the restart at the bad
    # interval it would have moved to lifted_at + 331.
    link.wait_until(lifted_at + 359.9)
    assert link.shaper.caps[-1] == 2
    link.wait_until(lifted_at + 360.0)
    assert link.shaper.caps[-1] == 3
    # The wait is back at 300: loss after this lift doubles it to 600 only.
    caplog.clear()
    with caplog.at_level(logging.INFO, logger=_LOGGER):
        link.flood(3)
    assert _messages(caplog, logging.INFO)[-1].endswith("next try in 10 min")


def test_reports_that_make_no_sense_are_ignored_and_keep_the_run(
    caplog: pytest.LogCaptureFixture,
) -> None:
    link = _Link()
    link.interval(800)
    link.interval(800, 100)  # bad: one in a row
    high, received = link.seq, link.received
    caplog.clear()
    with caplog.at_level(logging.DEBUG, logger=_LOGGER):
        for nonsense in (
            LinkReport(highest_seq=high, received=received + 5),
            LinkReport(highest_seq=high - 10, received=received),
            LinkReport(highest_seq=link.seq + 1, received=received + 1),
        ):
            link.auto.on_report(nonsense)
    assert len(_messages(caplog, logging.DEBUG)) == 1, "not rate-limited"
    link.interval(800, 100)  # bad: two in a row
    assert link.shaper.caps == [2]


def test_a_report_with_fewer_received_keeps_the_starting_point() -> None:
    link = _Link()
    link.interval(800)
    link.send(400)
    # Fewer received than the last report. Taken as the starting point, it
    # would make the next interval read 400 sent and 701 arrived: clean.
    link.auto.on_report(LinkReport(highest_seq=link.seq, received=link.received - 801))
    link.send(400, 100)
    link.clock.now += 1.0
    link.report()  # 800 sent since the kept starting point, 100 lost: bad
    link.interval(800, 100)
    assert link.shaper.caps == [2]


def test_late_packets_read_as_no_loss() -> None:
    link = _Link()
    link.interval(800)
    link.interval(800, 100)  # 100 missing: bad, one in a row
    link.interval(800, 0, late=100)  # they arrive late: clean, the run resets
    link.interval(800, 100)
    assert link.shaper.caps == []


def test_a_lost_report_leaves_a_longer_interval_that_is_still_judged() -> None:
    link = _Link()
    link.interval(800)
    link.send(800, 100)
    link.clock.now += 1.0  # this second's report was lost
    link.interval(800, 100)  # one report covers two seconds: bad
    link.interval(800, 100)
    assert link.shaper.caps == [2]


def test_with_no_reports_nothing_caps_and_the_log_stays_bounded() -> None:
    link = _Link(start_tier=0)
    for i in range(10_000):
        link.send(1)
        link.set_tier(i % 2)
        link.clock.now += 1.0
        link.auto.tick()
    assert link.shaper.caps == []
    assert len(link.auto._tier_log) <= TIER_LOG_MAX
    link.report()  # a report prunes what no later report can need
    assert [first for first, _ in link.auto._tier_log] == [10_000, 10_001]


def test_two_tier_changes_with_no_packet_between_leave_one_entry() -> None:
    link = _Link(start_tier=2)
    link.interval(800)
    link.set_tier(3)
    link.set_tier(1)  # no packet left at tier 3
    assert link.auto._tier_log == [(1, 2), (801, 1)]


def test_after_a_long_pause_one_tick_lifts_one_tier_only() -> None:
    link = _Link()
    link.interval(800)
    link.flood(3)
    capped_at = link.flood(2)  # cap 1
    link.wait_until(capped_at + 86_400.0)  # a day later
    assert link.shaper.caps == [2, 1, 2]
    link.wait_until(capped_at + 86_401.0)
    assert link.shaper.caps == [2, 1, 2], "the next lift did not wait"
    # The first report after the gap is judged like any other.
    link.interval(800, 200)
    link.interval(800, 200)
    assert link.shaper.caps == [2, 1, 2, 1]


def test_a_report_with_the_same_highest_seq_keeps_the_starting_point() -> None:
    link = _Link()
    link.interval(800)
    link.interval(800, 100)  # bad: one in a row
    # Only a late packet came in: same highest seq, one more received.
    link.received += 1
    link.report()
    link.interval(800, 100)  # still two in a row
    assert link.shaper.caps == [2]


def test_with_two_tiers_it_never_caps() -> None:
    link = _Link(tiers=(10.0, 50.0), start_tier=1)
    link.interval(800)
    for _ in range(10):
        link.interval(800, 400)
    link.wait_until(link.clock.now + 100_000.0)
    assert link.shaper.caps == []


def test_cap_and_lift_emit_auto_cap_change(monkeypatch: pytest.MonkeyPatch) -> None:
    events: list[tuple[str, dict[str, object]]] = []

    def record(event: str, **fields: object) -> None:
        events.append((event, fields))

    monkeypatch.setattr(netaudit, "emit", record)
    link = _Link()
    link.interval(800)
    capped_at = link.flood(3)
    link.wait_until(capped_at + 300.0)
    lower = {"direction": "lower", "tier": 3, "cap": 2, "loss_pct": 25, "wait_s": 300.0}
    lift = {
        "direction": "raise",
        "tier": 3,
        "cap": None,
        "loss_pct": None,
        "wait_s": None,
    }
    assert events == [("auto_cap_change", lower), ("auto_cap_change", lift)]


def test_log_lines_show_loss_and_configured_rates_but_no_seq_or_totals(
    caplog: pytest.LogCaptureFixture,
) -> None:
    link = _Link(seq=913_000_000)
    caplog.clear()
    with caplog.at_level(logging.DEBUG, logger=_LOGGER):
        link.interval(800)
        capped_at = link.flood(3)
        link.wait_until(capped_at + 300.0)
        link.auto.note_short_report()
        link.auto.note_short_report()
    messages = [r.getMessage() for r in caplog.records if r.name == _LOGGER]
    assert messages == [
        "auto cap: lost 25% of 800 packets at tier 3",
        "auto cap: lost 25% of 800 packets at tier 3",
        "auto cap: lost 25% at tier 3 (800/s); top tier now 2 (200/s), "
        "next try in 5 min",
        "auto cap: lifted, no cap",
        "auto cap: ignored a short or nonsensical link report",
    ]
    assert not any("913" in m for m in messages), "a seq or total was logged"
