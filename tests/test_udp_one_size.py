"""Finding #55: every UDP packet, real or chaff, leaves at one size.

Over UDP a real packet used to take a draw from the size mix, raised until it
fit, so every full-size packet was 1400 B while chaff was 1400 B only about 5%
of the time. Counting 1428-byte datagrams per second then gave the real
full-size rate, the stop time and short bursts inside a tier. Now every packet
takes the largest class in use, as TCP mode already does, so its size says
nothing about whether it is real or how big its payload is. Over UDP a payload
too big for that size is dropped, never sent at its exact size. TCP pads every
frame to 1400 anyway, so there it still goes out.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import pytest

from dsm.client import _log_path_mtu
from dsm.core.config import Config
from dsm.core.fsm import SessionFSM, State
from dsm.core.protocol import (
    GCM_TAG_SIZE,
    INNER_HEADER_SIZE,
    INNER_STRUCT,
    OUTER_HEADER_SIZE,
    InnerPacket,
    PacketType,
)
from dsm.net.transport.tcp import TCPTransport
from dsm.net.transport.udp import UDPTransport
from dsm.session import (
    DataPathContext,
    LivenessState,
    RekeyState,
    SequenceCounter,
    make_send_fn,
    tun_send_loop,
)
from dsm.traffic.scheduler import SendScheduler
from dsm.traffic.shaper import TrafficShaper, _TooBigForOneSize

# Payload sizes from empty to full size (mtu 1360), across the class edges
# (88/89 is the 128-class edge).
PAYLOADS = (0, 40, 88, 89, 150, 600, 1112, 1240, 1360)


def _data(length: int) -> InnerPacket:
    return InnerPacket(ptype=PacketType.DATA, epoch_id=0, payload=b"x" * length)


def _real_sizes(shaper: TrafficShaper, payloads: tuple[int, ...]) -> set[int]:
    return {shaper.pad_packet(_data(n))[1] for n in payloads for _ in range(50)}


def _chaff_sizes(shaper: TrafficShaper, n: int = 500) -> set[int]:
    return {shaper.make_chaff_padded()[1] for _ in range(n)}


def test_real_and_chaff_take_the_largest_class() -> None:
    shaper = TrafficShaper(128, 1400)
    assert _real_sizes(shaper, PAYLOADS) == {1400}
    assert _chaff_sizes(shaper) == {1400}
    padded, target = shaper.pad_packet(_data(150))
    assert len(padded) == target - OUTER_HEADER_SIZE - GCM_TAG_SIZE


def test_the_one_size_follows_the_size_ceiling() -> None:
    shaper = TrafficShaper(128, 1400)
    shaper.set_size_class_ceiling(1300 - 28)  # path MTU 1300: classes up to 1152
    assert _real_sizes(shaper, (0, 150, 1112)) == {1152}
    assert _chaff_sizes(shaper) == {1152}
    shaper.set_size_class_ceiling(0xFFFF)
    assert _chaff_sizes(shaper) == {1400}


def test_the_one_size_is_the_top_of_the_padding_range() -> None:
    shaper = TrafficShaper(256, 1024)
    assert _real_sizes(shaper, (0, 150, 984)) == {1024}
    assert _chaff_sizes(shaper) == {1024}
    # Too big for the one size: dropped, never sent at its exact size (1040).
    with pytest.raises(_TooBigForOneSize, match="1024"):
        shaper.pad_packet(_data(1000))


def test_every_udp_packet_takes_the_one_size_or_is_dropped() -> None:
    for padding_max in (1400, 1024, 1000, 768, 300, 128):
        for ceiling in (0xFFFF, 1300 - 28, 1100 - 28, 650 - 28, 50):
            shaper = TrafficShaper(128, padding_max)
            shaper.set_size_class_ceiling(ceiling)
            one_size = shaper._active_classes[-1]
            case = f"padding_max {padding_max}, ceiling {ceiling}"
            for payload in range(1501):
                need = OUTER_HEADER_SIZE + INNER_HEADER_SIZE + payload + GCM_TAG_SIZE
                try:
                    padded, target = shaper.pad_packet(_data(payload))
                except _TooBigForOneSize:
                    assert need > one_size, f"{case}: payload {payload} dropped"
                    continue
                assert target == one_size, f"{case}: payload {payload}"
                assert len(padded) == one_size - OUTER_HEADER_SIZE - GCM_TAG_SIZE
            assert _chaff_sizes(shaper, 50) == {one_size}, case


def _config(transport: str, **overrides: Any) -> Config:
    fields: dict[str, Any] = {
        "mode": "client",
        "server_ip": "10.0.0.1",
        "server_port": 51820,
        "listen_port": 0,
        "key_file": "/tmp/dsm-test.key",
        "cert_file": "/tmp/dsm-test.crt",
        "ca_root_file": "/tmp/dsm-test-ca.pem",
        "attest_key_file": "/tmp/dsm-test-attest.key",
        "expected_server_cn": "dsm-test-server",
        "transport": transport,
    }
    fields.update(overrides)
    return Config(**fields)


class _Tun:
    """Hands out ``packets`` one read at a time and ends the session with the
    last one, so tun_send_loop handles every packet and then stops."""

    def __init__(self, packets: list[bytes], shutdown: asyncio.Event) -> None:
        self._packets = list(packets)
        self._shutdown = shutdown

    async def read(self, bufsize: int = 2048) -> bytes:
        packet = self._packets.pop(0)
        if not self._packets:
            self._shutdown.set()
        return packet


class _Keys:
    epoch = 0
    send_epoch = 0

    def needs_rotation(self) -> bool:
        return False

    def seal_packet(self, seq: int, data: bytes) -> bytes:
        # Header in front, GCM tag behind: the wire size of a real seal.
        del seq
        return bytes(OUTER_HEADER_SIZE) + data + bytes(GCM_TAG_SIZE)


class _Queue:
    def __init__(self) -> None:
        self.packets: list[tuple[bytes, int]] = []

    def enqueue(self, data: bytes, target_size: int, **_: object) -> None:
        self.packets.append((data, target_size))


class _UDP(UDPTransport):
    def __init__(self) -> None:
        super().__init__()
        self.sent: list[int] = []

    async def send(self, data: bytes, addr: tuple[str, int]) -> None:
        self.sent.append(len(data))


class _TCP(TCPTransport):
    def __init__(self) -> None:
        super().__init__()
        self.sent: list[int] = []

    async def send(self, data: bytes) -> None:
        self.sent.append(len(data))


async def _wire_sizes(
    shaper: TrafficShaper, transport: _UDP | _TCP, tun_packets: list[bytes]
) -> list[int]:
    """Run TUN packets through tun_send_loop and the session's send function,
    as the scheduler would, and return every wire size."""
    fsm = SessionFSM()
    for state in (State.CONNECTING, State.HANDSHAKING, State.ESTABLISHED):
        fsm.transition(state)
    shutdown = asyncio.Event()
    keys = _Keys()
    send_fn = make_send_fn(
        keys,  # type: ignore[arg-type]
        transport,
        lambda: ("10.0.0.1", 51820),
        SequenceCounter(),
    )
    queue = _Queue()
    ctx = DataPathContext(
        tun=_Tun(tun_packets, shutdown),  # type: ignore[arg-type]
        session_keys=keys,  # type: ignore[arg-type]
        fsm=fsm,
        shaper=shaper,
        send_fn=send_fn,
        scheduler=queue,  # type: ignore[arg-type]
        rekey=RekeyState(),
        liveness=LivenessState(),
        shutdown=shutdown,
    )
    await asyncio.wait_for(tun_send_loop(ctx), timeout=5)
    for data, target in queue.packets:
        await send_fn(data, target)
    return transport.sent


# TUN packets around the 1152 size (one fits it exactly, one is a byte over),
# a full-size one, and two the session splits into pieces.
_TUN_SIZES = (100, 1112, 1113, 1360, 1500, 3000)


def test_udp_drops_every_tun_packet_too_big_for_the_one_size(
    caplog: pytest.LogCaptureFixture,
) -> None:
    shaper = TrafficShaper.from_config(_config("udp"))
    shaper.set_size_class_ceiling(1300 - 28)  # the one size is now 1152
    caplog.set_level(logging.DEBUG, logger="dsm.session")
    sent = asyncio.run(_wire_sizes(shaper, _UDP(), [b"\x45" * n for n in _TUN_SIZES]))
    # Only the 100- and 1112-byte packets fit. A packet split in pieces goes
    # whole or not at all: its small last piece is not sent alone.
    assert sent == [1152, 1152]
    drops = [r for r in caplog.records if "too big for the one size" in r.message]
    assert drops and all(r.levelno == logging.DEBUG for r in drops)


def test_tcp_still_sends_a_payload_too_big_for_the_one_size() -> None:
    # TCP pads every frame to 1400 (make_send_fn), so a narrow padding range
    # drops nothing there.
    shaper = TrafficShaper.from_config(_config("tcp", padding_max=1024))
    sent = asyncio.run(_wire_sizes(shaper, _TCP(), [b"\x45" * n for n in _TUN_SIZES]))
    assert sent == [1400] * 9  # 1500 is two pieces, 3000 is three


class _FixedSlots(TrafficShaper):
    """The real shaper, sizes from the real core, with a poll that hands out
    ``slots`` slots, so one tick sends everything queued."""

    slots = 0

    def poll(
        self, now: float, queue_len: int, oldest_wait: float, real_sent: int
    ) -> tuple[int, float]:
        return self.slots, now + 1.0


def _inner(ptype: PacketType, payload: bytes) -> InnerPacket:
    return InnerPacket(ptype=ptype, epoch_id=0, payload=payload)


def _content(data: bytes) -> tuple[int, bytes]:
    """(type, payload) from a padded inner plaintext."""
    ptype, _, length = INNER_STRUCT.unpack_from(data)
    return ptype, data[INNER_HEADER_SIZE : INNER_HEADER_SIZE + length]


def _across_a_ceiling_change(
    shaper: _FixedSlots, after: int, payloads: tuple[int, ...]
) -> tuple[list[tuple[bytes, int]], list[tuple[int, bytes]], int]:
    """Queue data and a link report at the size in use, move the ceiling (as
    auto_mtu does), queue a control packet, then run one tick with a slot for
    every packet and two more. Returns what was sent, the (type, payload) of
    everything queued, and the number of slots."""
    sent: list[tuple[bytes, int]] = []

    async def send(data: bytes, size: int) -> None:
        sent.append((data, size))

    async def chaff() -> tuple[bytes, int]:
        return shaper.make_chaff_padded()

    sched = SendScheduler(send, chaff, shaper=shaper)
    queued = [_inner(PacketType.DATA, bytes([n % 251]) * n) for n in payloads]
    for inner in queued:
        sched.enqueue(*shaper.pad_packet(inner))
    report = _inner(PacketType.LINK_REPORT, b"r" * 16)
    sched.set_report(*shaper.pad_packet(report))
    shaper.set_size_class_ceiling(after)
    control = _inner(PacketType.PATH_RESPONSE, b"t" * 16)
    sched.enqueue(*shaper.pad_packet(control), control=True)
    slots = len(queued) + 4
    shaper.slots = slots
    asyncio.run(sched._tick(0.0))
    every = [(int(i.ptype), i.payload) for i in (*queued, report, control)]
    return sent, every, slots


def test_queued_packets_take_the_new_size_after_a_raise() -> None:
    # A control packet (padded after the raise) jumping ahead of data padded
    # before it marked every old-size packet between two new-size ones as
    # real and queued (review of #55: [1400, 1152 x 6, 1400, 1400]).
    shaper = _FixedSlots(128, 1400)
    shaper.set_size_class_ceiling(1300 - 28)  # the one size is 1152
    sent, every, slots = _across_a_ceiling_change(
        shaper, 0xFFFF, (0, 150, 600, 1000, 1112)
    )
    assert [size for _, size in sent] == [1400] * slots
    assert all(len(d) == 1400 - OUTER_HEADER_SIZE - GCM_TAG_SIZE for d, _ in sent)
    real = [_content(d) for d, _ in sent if _content(d)[0] != PacketType.CHAFF]
    assert sorted(real) == sorted(every)


def test_queued_packets_take_the_new_size_after_a_lower(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # A forged ICMP can lower the ceiling at will. Packets queued at the old
    # size must not leave at it (with DF they would be refused and leave
    # their slots empty): they take the new size, or chaff takes their slot.
    caplog.set_level(logging.DEBUG, logger="dsm.traffic.scheduler")
    shaper = _FixedSlots(128, 1400)
    sent, every, slots = _across_a_ceiling_change(
        shaper, 1300 - 28, (150, 600, 1112, 1113, 1360)
    )
    assert [size for _, size in sent] == [1152] * slots  # no slot left empty
    assert all(len(d) == 1152 - OUTER_HEADER_SIZE - GCM_TAG_SIZE for d, _ in sent)
    real = [_content(d) for d, _ in sent if _content(d)[0] != PacketType.CHAFF]
    too_big = [(PacketType.DATA, bytes([n % 251]) * n) for n in (1113, 1360)]
    assert sorted(real) == sorted(x for x in every if x not in too_big)
    drops = [r for r in caplog.records if "too big for the one size" in r.message]
    assert drops and all(r.levelno == logging.DEBUG for r in drops)


def test_tcp_queued_packets_keep_their_size() -> None:
    # TCP pads every frame to 1400 at send time, so the scheduler leaves a
    # packet too big for a narrow padding range as it is.
    shaper = TrafficShaper.from_config(_config("tcp", padding_max=1024))
    sent: list[int] = []

    async def send(data: bytes, size: int) -> None:
        sent.append(size)

    sched = SendScheduler(send, shaper=shaper)
    sched.enqueue(*shaper.pad_packet(_data(1300)))
    asyncio.run(sched._send_one(sched._queue[0]))
    assert sent == [1300 + 40]


_PREFIX = "padding_max ="


def _one_size_warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.levelno == logging.WARNING and r.getMessage().startswith(_PREFIX)
    ]


@pytest.mark.parametrize(
    ("padding_max", "mtu", "set_mtu"),
    [(1024, 1360, 984), (1000, 1360, 856), (1280, 1300, 1240), (1024, 985, 984)],
)
def test_a_udp_mtu_too_big_for_padding_max_warns_at_load(
    caplog: pytest.LogCaptureFixture, padding_max: int, mtu: int, set_mtu: int
) -> None:
    caplog.set_level(logging.WARNING, logger="dsm.core.config")
    _config("udp", padding_max=padding_max, mtu=mtu)
    lines = _one_size_warnings(caplog)
    assert len(lines) == 1
    assert "dropped" in lines[0]
    assert f"mtu = {set_mtu}" in lines[0]


def test_a_padding_max_too_small_for_any_mtu_says_to_raise_it(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # 512 - 40 = 472 is below the smallest mtu a config takes (576).
    caplog.set_level(logging.WARNING, logger="dsm.core.config")
    _config("udp", padding_max=600, mtu=576)
    lines = _one_size_warnings(caplog)
    assert len(lines) == 1
    assert "dropped" in lines[0]
    assert "padding_max to at least 640" in lines[0]


def test_the_server_warns_too(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING, logger="dsm.core.config")
    Config(
        mode="server",
        server_ip="10.0.0.1",
        server_port=51820,
        listen_port=51820,
        key_file="/tmp/test.key",
        cert_file="/tmp/test.crt",
        ca_root_file="/tmp/test-ca.pem",
        attest_key_file="/tmp/test-attest.key",
        transport="udp",
        dns_providers=["https://1.1.1.1/dns-query"],
        dns_provider_pins={"https://1.1.1.1/dns-query": ["a" * 64]},
        allowed_cns_file="/tmp/test-allowed-cns.txt",
        padding_max=1024,
    )
    assert len(_one_size_warnings(caplog)) == 1


@pytest.mark.parametrize(
    ("transport", "padding_max", "mtu"),
    [
        ("udp", 1400, 1360),  # the defaults
        ("udp", 1024, 984),  # mtu fits the one size exactly
        ("udp", 1400, 1500),  # DSM splits it into pieces that fill 1400
        ("udp", 1450, 1360),  # 1400 is the largest class at or below 1450
        ("tcp", 1024, 1360),  # every TCP frame is 1400
    ],
)
def test_no_warning_when_a_full_size_packet_fits(
    caplog: pytest.LogCaptureFixture, transport: str, padding_max: int, mtu: int
) -> None:
    caplog.set_level(logging.WARNING, logger="dsm.core.config")
    _config(transport, padding_max=padding_max, mtu=mtu)
    assert _one_size_warnings(caplog) == []


def _hints(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == "dsm.client" and r.levelno == logging.WARNING
    ]


@pytest.mark.parametrize(
    ("path_mtu", "by_hand"),
    [
        (1300, ", or set padding_max = 1152 and mtu = 1112 in both configs"),
        (1400, ", or set padding_max = 1280 and mtu = 1240 in both configs"),
        # 512 - 40 = 472 is below the smallest mtu a config takes.
        (600, ""),
    ],
)
def test_the_start_up_hint_no_longer_says_lower_mtu(
    caplog: pytest.LogCaptureFixture, path_mtu: int, by_hand: str
) -> None:
    # Lowering mtu alone no longer makes a datagram smaller: every packet
    # takes the one size, which only padding_max or auto_mtu can lower.
    caplog.set_level(logging.WARNING, logger="dsm.client")
    _log_path_mtu(_config("udp"), path_mtu)
    (line,) = _hints(caplog)
    assert line.startswith("configured tun mtu=1360 exceeds usable inner")
    assert line.endswith(f"turn on auto_mtu with pmtu_discover{by_hand}")
    assert "lower" not in line


@pytest.mark.parametrize(("path_mtu", "auto_mtu"), [(1500, False), (1300, True)])
def test_no_start_up_hint_when_mtu_fits_or_auto_mtu_is_on(
    caplog: pytest.LogCaptureFixture, path_mtu: int, auto_mtu: bool
) -> None:
    caplog.set_level(logging.WARNING, logger="dsm.client")
    _log_path_mtu(_config("udp", auto_mtu=auto_mtu), path_mtu)
    assert _hints(caplog) == []


def test_the_start_up_hint_warns_when_every_datagram_is_too_big(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # A hand-set mtu that fits the path does not make a datagram smaller:
    # every packet still takes the one size, 1400 + 28 = 1428 > 1300, so
    # with DF on the kernel refuses every one.
    caplog.set_level(logging.WARNING, logger="dsm.client")
    config = _config("udp", mtu=1100, pmtu_discover=True)
    _log_path_mtu(config, 1300)
    (line,) = _hints(caplog)
    assert "every datagram" in line
    assert "bigger than the path MTU 1300" in line
    assert line.endswith(
        "turn on auto_mtu with pmtu_discover, or set padding_max = 1152 and "
        "mtu = 1112 in both configs"
    )


@pytest.mark.parametrize(("mtu", "padding_max"), [(1100, 1152), (984, 1024)])
def test_no_start_up_hint_when_the_one_size_fits_the_path(
    caplog: pytest.LogCaptureFixture, mtu: int, padding_max: int
) -> None:
    caplog.set_level(logging.WARNING, logger="dsm.client")
    config = _config("udp", mtu=mtu, padding_max=padding_max, pmtu_discover=True)
    _log_path_mtu(config, 1300)
    assert _hints(caplog) == []
