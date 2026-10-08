"""The session side of the slow-link auto cap: the once-a-second report step
and loop, the LINK_REPORT handler, make_auto_cap, and the wiring in client,
server and the data loops.

Fakes stand in at the boundaries (keys, shaper, scheduler, auto cap); the
loop runs with a shrunk interval and stops on an event, never on a sleep.
"""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Callable
from typing import Any

import pytest

from dsm import client, server, session
from dsm.core.config import Config
from dsm.core.fsm import SessionFSM
from dsm.core.protocol import InnerPacket, LinkReport, PacketType
from dsm.net.transport.tcp import TCPTransport
from dsm.net.transport.udp import UDPTransport
from dsm.session import (
    DataPathContext,
    LivenessState,
    RekeyState,
    SequenceCounter,
    _link_report_step,
    dispatch_inner,
    link_report_loop,
    make_auto_cap,
)
from dsm.traffic.autocap import AutoCap, LinkStats


class _Keys:
    epoch = 0


class _Shaper:
    """Pads nothing, so a test can read the inner bytes back; records the
    tier listener and caps."""

    def __init__(self) -> None:
        self.tier = 0
        self.listener: Callable[[int], None] | None = None
        self.caps: list[int] = []

    def pad_packet(self, inner: InnerPacket) -> tuple[bytes, int]:
        return inner.serialize(), 128

    def set_tier_cap(self, cap: int) -> None:
        self.caps.append(cap)

    def watch_tier(self, listener: Callable[[int], None]) -> None:
        self.listener = listener


class _Scheduler:
    def __init__(self) -> None:
        self.reports: list[bytes] = []

    def set_report(self, data: bytes, target_size: int) -> None:
        self.reports.append(data)


class _AutoCap:
    """Counts ticks (sets ``stop`` at tick ``stop_at``) and keeps reports."""

    def __init__(self) -> None:
        self.ticks = 0
        self.reports: list[LinkReport] = []
        self.short = 0
        self.stop: asyncio.Event | None = None
        self.stop_at = 0

    def tick(self) -> None:
        self.ticks += 1
        if self.stop is not None and self.ticks == self.stop_at:
            self.stop.set()

    def on_report(self, report: LinkReport) -> None:
        self.reports.append(report)

    def note_short_report(self) -> None:
        self.short += 1


async def _no_send(data: bytes, target_size: int) -> None:
    return None


def _ctx(
    *, link_stats: LinkStats | None = None, autocap: _AutoCap | None = None
) -> tuple[DataPathContext, _Scheduler]:
    scheduler = _Scheduler()
    ctx = DataPathContext(
        tun=None,  # type: ignore[arg-type]
        session_keys=_Keys(),  # type: ignore[arg-type]
        fsm=SessionFSM(),
        shaper=_Shaper(),  # type: ignore[arg-type]
        send_fn=_no_send,
        scheduler=scheduler,  # type: ignore[arg-type]
        rekey=RekeyState(),
        liveness=LivenessState(),
        shutdown=asyncio.Event(),
        link_stats=link_stats,
        autocap=autocap,  # type: ignore[arg-type]
    )
    return ctx, scheduler


def _decode(data: bytes) -> LinkReport:
    inner = InnerPacket.deserialize(data)
    assert inner.ptype == PacketType.LINK_REPORT
    return LinkReport.deserialize(inner.payload)


def _config(**overrides: Any) -> Config:
    values: dict[str, Any] = {
        "mode": "client",
        "server_ip": "10.0.0.1",
        "server_port": 51820,
        "listen_port": 51821,
        "key_file": "/tmp/test.key",
        "cert_file": "/tmp/test.crt",
        "ca_root_file": "/tmp/test-ca.pem",
        "attest_key_file": "/tmp/test-attest.key",
        "expected_server_cn": "dsm-test-server",
        "transport": "udp",
    }
    values.update(overrides)
    return Config(**values)


def test_a_report_goes_out_only_when_packets_came_in() -> None:
    stats, auto = LinkStats(), _AutoCap()
    ctx, sched = _ctx(link_stats=stats, autocap=auto)
    reported = _link_report_step(ctx, stats, 0)
    assert sched.reports == [], "a report before any packet came in"
    for seq in (1, 2, 5):
        stats.note(seq)
    reported = _link_report_step(ctx, stats, reported)
    assert [_decode(d) for d in sched.reports] == [
        LinkReport(highest_seq=5, received=3)
    ]
    reported = _link_report_step(ctx, stats, reported)
    assert len(sched.reports) == 1, "a report although nothing came in"
    stats.note(9)
    _link_report_step(ctx, stats, reported)
    assert _decode(sched.reports[-1]) == LinkReport(highest_seq=9, received=4)
    assert auto.ticks == 4, "the lift timer did not run at every wake"


async def test_the_loop_returns_at_once_when_auto_cap_is_off() -> None:
    ctx, sched = _ctx()
    await asyncio.wait_for(link_report_loop(ctx), timeout=1.0)
    assert sched.reports == []


async def test_the_loop_runs_every_interval_until_shutdown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(session, "REPORT_INTERVAL_S", 0.001)
    stats, auto = LinkStats(), _AutoCap()
    stats.note(1)
    ctx, sched = _ctx(link_stats=stats, autocap=auto)
    auto.stop, auto.stop_at = ctx.shutdown, 3
    await asyncio.wait_for(link_report_loop(ctx), timeout=5.0)
    assert auto.ticks == 3
    assert [_decode(d) for d in sched.reports] == [
        LinkReport(highest_seq=1, received=1)
    ]


async def test_dispatch_passes_a_report_to_the_auto_cap() -> None:
    auto = _AutoCap()
    ctx, _ = _ctx(link_stats=LinkStats(), autocap=auto)
    payload = LinkReport(highest_seq=10, received=9).serialize() + b"later fields"
    inner = InnerPacket(ptype=PacketType.LINK_REPORT, epoch_id=0, payload=payload)
    await dispatch_inner(ctx, inner)
    assert auto.reports == [LinkReport(highest_seq=10, received=9)]


async def test_a_short_report_is_dropped() -> None:
    auto = _AutoCap()
    ctx, _ = _ctx(link_stats=LinkStats(), autocap=auto)
    inner = InnerPacket(ptype=PacketType.LINK_REPORT, epoch_id=0, payload=bytes(15))
    await dispatch_inner(ctx, inner)
    assert auto.reports == []
    assert auto.short == 1


async def test_reports_are_ignored_when_auto_cap_is_off() -> None:
    ctx, _ = _ctx()
    payload = LinkReport(highest_seq=1, received=1).serialize()
    inner = InnerPacket(ptype=PacketType.LINK_REPORT, epoch_id=0, payload=payload)
    await dispatch_inner(ctx, inner)  # no error, nothing to call


def test_make_auto_cap_builds_both_parts_for_udp_and_attaches_the_listener() -> None:
    shaper = _Shaper()
    stats, auto = make_auto_cap(
        _config(), UDPTransport(), shaper, SequenceCounter()  # type: ignore[arg-type]
    )
    assert isinstance(stats, LinkStats)
    assert isinstance(auto, AutoCap)
    assert shaper.listener == auto.note_tier


@pytest.mark.parametrize(("transport", "key_on"), [("tcp", True), ("udp", False)])
def test_make_auto_cap_is_off_in_tcp_mode_or_with_the_key_off(
    transport: str, key_on: bool
) -> None:
    shaper = _Shaper()
    link = TCPTransport() if transport == "tcp" else UDPTransport()
    config = _config(transport=transport, shaper_auto_cap=key_on)
    got = make_auto_cap(config, link, shaper, SequenceCounter())  # type: ignore[arg-type]
    assert got == (None, None)
    assert shaper.listener is None


def test_both_ends_wire_auto_cap_before_their_scheduler_starts() -> None:
    for name, src in (
        ("client", inspect.getsource(client.run_client)),
        ("server", inspect.getsource(server._run_one_session)),
    ):
        wired = src.find("make_auto_cap(config, transport, shaper, seq)")
        started = src.find("scheduler.start()")
        assert -1 < wired < started, f"{name}: wired after the scheduler started"
        assert "link_stats=link_stats" in src, name
        assert "autocap=autocap" in src, name


def test_the_data_loops_count_packets_and_run_the_report_loop() -> None:
    src = inspect.getsource(session.run_data_loops)
    assert "link_stats=ctx.link_stats" in src
    assert "link_report_loop(ctx)" in src
