"""The link report's slot in the send scheduler (``set_report``).

The report is not real traffic: the shaper sees the same queue_len,
oldest_wait and real_sent with and without one. It takes a slot that would
carry chaff, or a slot ahead of data once it has waited REPORT_OVERDUE_S;
control messages still go first. The scheduler is driven one tick at a time
with an injected clock; the shaper is a stand-in that gives a fixed number
of slots and records every poll.
"""

from __future__ import annotations

from dsm.traffic.scheduler import REPORT_OVERDUE_S, SendScheduler


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class _SlotShaper:
    """Gives ``slots`` slots at every poll; records what it was told."""

    def __init__(self, slots: int) -> None:
        self.slots = slots
        self.polls: list[tuple[int, float, int]] = []

    def poll(
        self, now: float, queue_len: int, oldest_wait: float, real_sent: int
    ) -> tuple[int, float]:
        self.polls.append((queue_len, oldest_wait, real_sent))
        return self.slots, now + 0.1


class _Rig:
    """A scheduler with a recording send function, chaff and a chaff gate."""

    def __init__(self, slots: int, *, gate_open: bool = True) -> None:
        self.clock = _Clock()
        self.shaper = _SlotShaper(slots)
        self.sent: list[bytes] = []
        self.gate_open = gate_open

        async def send_fn(data: bytes, target_size: int) -> None:
            self.sent.append(data)

        async def chaff_fn() -> tuple[bytes, int]:
            return b"chaff", 128

        self.sched = SendScheduler(
            send_fn,
            chaff_fn,
            lambda: self.gate_open,
            shaper=self.shaper,  # type: ignore[arg-type]
            clock=self.clock,
        )

    async def tick(self, after_s: float = 0.0) -> None:
        self.clock.now += after_s
        await self.sched._tick(self.clock.now)


async def test_the_shaper_sees_the_same_numbers_with_and_without_a_report() -> None:
    with_report, without = _Rig(2), _Rig(2)
    for rig in (with_report, without):
        await rig.tick()
        rig.sched.enqueue(b"data", 128)
    with_report.sched.set_report(b"report", 128)
    for rig in (with_report, without):
        await rig.tick(0.1)
        await rig.tick(0.1)
    assert with_report.shaper.polls == without.shaper.polls
    assert [p[2] for p in with_report.shaper.polls] == [0, 0, 1]
    assert with_report.sent == [
        b"chaff",
        b"chaff",
        b"data",
        b"report",
        b"chaff",
        b"chaff",
    ]
    assert without.sent == [b"chaff", b"chaff", b"data", b"chaff", b"chaff", b"chaff"]


async def test_a_waiting_report_is_not_in_queue_len_or_oldest_wait() -> None:
    rig = _Rig(0)
    rig.sched.set_report(b"report", 128)
    await rig.tick(5.0)
    assert rig.shaper.polls == [(0, 0.0, 0)]
    assert rig.sent == []


async def test_control_goes_before_even_an_overdue_report() -> None:
    rig = _Rig(1)
    rig.sched.set_report(b"report", 128)
    rig.sched.enqueue(b"control", 128, control=True)
    await rig.tick(REPORT_OVERDUE_S + 1.0)
    await rig.tick(0.1)
    assert rig.sent == [b"control", b"report"]
    assert [p[2] for p in rig.shaper.polls] == [0, 1]


async def test_a_fresh_report_waits_behind_data() -> None:
    rig = _Rig(1)
    rig.sched.set_report(b"report", 128)
    rig.sched.enqueue(b"data", 128)
    await rig.tick(REPORT_OVERDUE_S - 0.5)
    await rig.tick(0.1)
    assert rig.sent == [b"data", b"report"]


async def test_a_report_that_waited_its_overdue_time_goes_before_data() -> None:
    rig = _Rig(1)
    rig.sched.set_report(b"report", 128)
    rig.clock.now += REPORT_OVERDUE_S
    rig.sched.enqueue(b"data", 128)
    await rig.tick()
    await rig.tick(0.1)
    assert rig.sent == [b"report", b"data"]
    assert [p[2] for p in rig.shaper.polls] == [0, 0], "the report counted as real"


async def test_a_newer_report_replaces_a_waiting_one_and_keeps_its_wait() -> None:
    rig = _Rig(1)
    rig.sched.set_report(b"old", 128)
    rig.clock.now += 0.5
    rig.sched.set_report(b"new", 128)
    rig.sched.enqueue(b"data", 128)
    # 1.0 s after the old report was set: overdue only if the wait was kept.
    await rig.tick(0.5)
    await rig.tick(0.1)
    await rig.tick(0.1)
    assert rig.sent == [b"new", b"data", b"chaff"]


async def test_it_goes_out_through_send_fn_while_the_chaff_gate_is_closed() -> None:
    rig = _Rig(2, gate_open=False)
    rig.sched.set_report(b"report", 128)
    await rig.tick()
    assert rig.sent == [b"report"]
