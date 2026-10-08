"""Junk sent at a DSM host must not force the slow-link auto cap.

A flood of junk UDP at a host fills its receive queue, so genuine packets are
dropped before AEAD and would read as lost. So the receiver forgives (reports
as arrived) the packets missing since its last report whenever junk reached
it in that time: the receive queue overflowed, a packet was dropped before
AEAD passed (too short, a replay, AEAD failed), or, on the client, a packet
came from the wrong address. Reports still go out at every step; the totals
stay cumulative and ``received`` never exceeds ``highest_seq``.

Real session keys from tuncore for ``decrypt_packet``; fakes elsewhere. No
traffic is sent and nothing sleeps.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Iterable
from typing import Any
from unittest.mock import patch

import pytest

import tuncore
from dsm.core.config import Config
from dsm.core.fsm import SessionFSM, State
from dsm.core.protocol import (
    INNER_STRUCT,
    OUTER_HEADER_SIZE,
    SEQ_STRUCT,
    InnerPacket,
    LinkReport,
    OuterPacket,
    PacketType,
)
from dsm.net.transport.udp import RECV_QUEUE_SIZE, UDPTransport
from dsm.session import (
    DataPathContext,
    LivenessState,
    RekeyState,
    SequenceCounter,
    _link_report_step,
    decrypt_packet,
    make_auto_cap,
    run_data_loops,
)
from dsm.traffic.autocap import LOSS_THRESHOLD, MIN_INTERVAL_PACKETS, AutoCap, LinkStats

TIERS = (10.0, 50.0, 200.0, 800.0)
PEER = ("203.0.113.7", 40000)


# --- fakes -----------------------------------------------------------------


class _Keys:
    epoch = 0

    def needs_rotation(self) -> bool:
        return False

    def tick(self) -> None:
        return None


class _Shaper:
    """Pads nothing (so a report can be read back) and records caps."""

    tier = 3

    def __init__(self) -> None:
        self.caps: list[int] = []
        self.listener: Callable[[int], None] | None = None

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

    def enqueue(self, data: bytes, target_size: int, **_: object) -> None:
        return None


class _Never:
    async def read(self) -> bytes:
        await asyncio.Event().wait()
        return b""


async def _no_send(data: bytes, target_size: int) -> None:
    return None


def _ctx(stats: LinkStats, *, tun: object = None) -> tuple[DataPathContext, _Scheduler]:
    scheduler = _Scheduler()
    fsm = SessionFSM()
    for state in (State.CONNECTING, State.HANDSHAKING, State.ESTABLISHED):
        fsm.transition(state)
    ctx = DataPathContext(
        tun=tun,  # type: ignore[arg-type]
        session_keys=_Keys(),  # type: ignore[arg-type]
        fsm=fsm,
        shaper=_Shaper(),  # type: ignore[arg-type]
        send_fn=_no_send,
        scheduler=scheduler,  # type: ignore[arg-type]
        rekey=RekeyState(),
        liveness=LivenessState(),
        shutdown=asyncio.Event(),
        link_stats=stats,
    )
    return ctx, scheduler


def _decode(data: bytes) -> LinkReport:
    inner = InnerPacket.deserialize(data)
    assert inner.ptype == PacketType.LINK_REPORT
    return LinkReport.deserialize(inner.payload)


def _arrive(
    stats: LinkStats, first: int, last: int, missing: Iterable[int] = ()
) -> None:
    gone = set(missing)
    for seq in range(first, last + 1):
        if seq not in gone:
            stats.note(seq)


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


def _pair() -> tuple[tuncore.SessionKeyManager, tuncore.SessionKeyManager]:
    ours = tuncore.BootstrapEphemeral.generate()
    peer = tuncore.BootstrapEphemeral.generate()
    our_pub = ours.public_key_bytes
    peer_pub = peer.public_key_bytes
    sender = tuncore.complete_bootstrap(ours, peer_pub, True)
    receiver = tuncore.complete_bootstrap(peer, our_pub, False)
    return sender, receiver


def _wire(keys: tuncore.SessionKeyManager, seq: int, ptype: int) -> bytes:
    plaintext = INNER_STRUCT.pack(ptype, (keys.epoch & 0x0F) << 4, 1) + b"x"
    nonce, ct, _epoch = keys.encrypt(plaintext, SEQ_STRUCT.pack(seq))
    outer = OuterPacket(seq=seq, nonce=bytes(nonce), ciphertext=bytes(ct))
    return outer.serialize(OUTER_HEADER_SIZE + len(ct))


# --- the rule ----------------------------------------------------------------


def test_a_report_after_junk_forgives_the_missing_packets() -> None:
    stats = LinkStats()
    _arrive(stats, 1, 100)
    assert stats.report_totals() == (100, 100)
    _arrive(stats, 101, 200, missing=range(150, 170))
    stats.note_junk()
    assert stats.report_totals() == (200, 200)
    assert stats.forgiven == 20


def test_a_report_with_no_junk_since_the_last_one_keeps_the_loss() -> None:
    stats = LinkStats()
    _arrive(stats, 1, 100)
    stats.note_junk()  # junk before the first report only
    assert stats.report_totals() == (100, 100)
    _arrive(stats, 101, 200, missing=range(150, 170))
    assert stats.report_totals() == (200, 180)
    assert stats.forgiven == 0


def test_a_receive_queue_overflow_counts_as_junk() -> None:
    drops = [0]
    stats = LinkStats(queue_drops=lambda: drops[0])
    _arrive(stats, 1, 100)
    stats.report_totals()
    _arrive(stats, 101, 200, missing=range(150, 170))
    drops[0] += 3
    assert stats.report_totals() == (200, 200)


def test_received_never_exceeds_highest_seq() -> None:
    stats = LinkStats()
    _arrive(stats, 1, 100, missing=range(80, 90))
    stats.note_junk()
    assert stats.report_totals() == (100, 100)
    _arrive(stats, 80, 89)  # the forgiven packets arrive late after all
    high, received = stats.report_totals()
    assert received <= high
    assert (high, received) == (100, 100)


def test_the_step_sends_the_forgiven_totals() -> None:
    stats = LinkStats()
    ctx, sched = _ctx(stats)
    _arrive(stats, 1, 100)
    reported = _link_report_step(ctx, stats, 0)
    _arrive(stats, 101, 200, missing=range(150, 170))
    stats.note_junk()
    _link_report_step(ctx, stats, reported)
    assert [_decode(d) for d in sched.reports] == [
        LinkReport(highest_seq=100, received=100),
        LinkReport(highest_seq=200, received=200),
    ]


# --- where junk is counted ---------------------------------------------------


def test_packets_dropped_before_aead_passed_count_as_junk() -> None:
    sender, receiver = _pair()
    replay = tuncore.ReplayWindow()
    stats = LinkStats()
    wire = _wire(sender, 5, PacketType.DATA)
    assert decrypt_packet(wire, receiver, replay, link_stats=stats) is not None
    assert stats.junk == 0
    assert decrypt_packet(wire, receiver, replay, link_stats=stats) is None
    assert stats.junk == 1, "a replay did not count as junk"
    forged = bytearray(_wire(sender, 6, PacketType.DATA))
    forged[-1] ^= 0x01
    assert decrypt_packet(bytes(forged), receiver, replay, link_stats=stats) is None
    assert stats.junk == 2, "a forged packet did not count as junk"
    assert decrypt_packet(bytes(10), receiver, replay, link_stats=stats) is None
    assert stats.junk == 3, "a short packet did not count as junk"
    # Genuine, but dropped after AEAD (a type this build does not know).
    unknown = _wire(sender, 7, 0xFF)
    assert decrypt_packet(unknown, receiver, replay, link_stats=stats) is None
    assert stats.junk == 3
    assert stats.received == 2


async def test_the_transport_counts_overflows_on_every_socket() -> None:
    with patch("dsm.net.transport.udp.apply_so_mark", lambda sock: None):
        t = UDPTransport()
        await t.bind("127.0.0.1", 0)
        try:
            assert t._transport is not None
            protocol = t._transport.get_protocol()
            for _ in range(RECV_QUEUE_SIZE + 5):
                protocol.datagram_received(b"junk", PEER)  # type: ignore[attr-defined]
            assert t.recv_drops() == 5
            await t.rebind_to_fresh_port()
            t._transport.get_protocol().datagram_received(b"junk", PEER)  # type: ignore[attr-defined]
            assert t.recv_drops() == 6
            stats, _auto = make_auto_cap(
                _config(), t, _Shaper(), SequenceCounter()  # type: ignore[arg-type]
            )
            assert stats is not None
            assert stats.queue_drops() == 6
        finally:
            await t.aclose()


async def test_a_packet_from_the_wrong_address_counts_as_junk() -> None:
    stats = LinkStats()
    ctx, _ = _ctx(stats, tun=_Never())
    transport = UDPTransport()
    for _ in range(3):
        transport._recv_queue.put_nowait((b"junk", PEER))
    seen: list[tuple[str, int]] = []

    def only_the_server(addr: tuple[str, int]) -> bool:
        seen.append(addr)
        if len(seen) == 3:
            ctx.shutdown.set()
        return False

    await asyncio.wait_for(
        run_data_loops(
            ctx,
            transport,
            ctx.session_keys,
            None,  # type: ignore[arg-type]
            ctx.fsm,
            udp_addr_filter=only_the_server,
        ),
        timeout=5.0,
    )
    assert stats.junk == 3


# --- a pulsed flood at the sender's AutoCap ----------------------------------


class _Path:
    """One direction at tier 3: the sender's AutoCap, the receiver's
    LinkStats and report step. 800 packets leave each step."""

    def __init__(self, *, count_junk: bool) -> None:
        self.count_junk = count_junk
        self.seq = 0
        self.drops = 0
        self.stats = LinkStats(queue_drops=lambda: self.drops)
        self.ctx, self.sched = _ctx(self.stats)
        self.reported = 0
        self.shaper = _Shaper()
        self.auto = AutoCap(
            self.shaper, tiers_pps=TIERS, start_tier=3, last_seq=lambda: self.seq
        )
        self.delivered: list[LinkReport] = []

    def step(
        self, lost: Callable[[int], bool], *, aead: int = 0, queue: int = 0
    ) -> None:
        """Send 800 packets; packet i of the step is lost when ``lost(i)``.
        ``aead`` junk packets failed AEAD and ``queue`` overflowed the
        receive queue during the step."""
        for i in range(800):
            self.seq += 1
            if not lost(i):
                self.stats.note(self.seq)
        if self.count_junk:
            for _ in range(aead):
                self.stats.note_junk()
            self.drops += queue
        before = len(self.sched.reports)
        self.reported = _link_report_step(self.ctx, self.stats, self.reported)
        for data in self.sched.reports[before:]:
            report = _decode(data)
            self.delivered.append(report)
            self.auto.on_report(report)

    def bad_intervals(self) -> list[bool]:
        """Each interval between delivered reports: bad or not."""
        out: list[bool] = []
        for a, b in zip(self.delivered, self.delivered[1:]):
            sent = b.highest_seq - a.highest_seq
            lost = sent - (b.received - a.received)
            out.append(sent >= MIN_INTERVAL_PACKETS and lost >= LOSS_THRESHOLD * sent)
        return out


def _none(i: int) -> bool:
    return False


def _quarter_and_tail(i: int) -> bool:
    # A quarter lost, and the last 50 too: their gap shows only in the next
    # report, which the flood no longer touches.
    return i % 4 == 0 or i >= 750


def _all(i: int) -> bool:
    return True


def _pulsed_flood(path: _Path) -> None:
    path.step(_none)
    path.step(_none)
    for _ in range(10):
        path.step(_quarter_and_tail, aead=40)  # junk, part gets through
        path.step(_none)  # clean
        path.step(_all, queue=900)  # junk, nothing gets through: no report
        path.step(_none)  # clean


def test_a_pulsed_flood_never_gives_two_bad_intervals_in_a_row() -> None:
    path = _Path(count_junk=True)
    _pulsed_flood(path)
    bad = path.bad_intervals()
    assert not any(a and b for a, b in zip(bad, bad[1:])), bad
    assert path.shaper.caps == []
    assert all(r.received <= r.highest_seq for r in path.delivered)
    # Every step that got packets sent a report (32 of 42).
    assert len(path.delivered) == 32


def test_the_same_flood_caps_when_junk_is_not_counted() -> None:
    """Control: the pattern above is strong enough to force the cap."""
    path = _Path(count_junk=False)
    _pulsed_flood(path)
    assert path.shaper.caps == [2]


# --- logs ----------------------------------------------------------------------


def test_the_counters_are_never_logged(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    sender, receiver = _pair()
    replay = tuncore.ReplayWindow()
    drops = [7_770_000]
    stats = LinkStats(junk=5_550_000, queue_drops=lambda: drops[0])
    ctx, _ = _ctx(stats)
    _arrive(stats, 1, 2000)
    reported = _link_report_step(ctx, stats, 0)
    _arrive(stats, 2001, 4000, missing=range(2500, 2913))
    forged = bytearray(_wire(sender, 4001, PacketType.DATA))
    forged[-1] ^= 0x01
    decrypt_packet(bytes(forged), receiver, replay, link_stats=stats)
    drops[0] += 1
    _link_report_step(ctx, stats, reported)
    assert stats.forgiven == 413
    values = {
        str(v) for v in (stats.junk, drops[0], stats.junk + drops[0], stats.forgiven)
    }
    messages = [r.getMessage() for r in caplog.records]
    assert messages, "nothing was logged at all: the check means nothing"
    assert not [m for m in messages if any(v in m for v in values)]
