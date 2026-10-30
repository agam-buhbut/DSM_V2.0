"""Tests for dsm.session.auto_mtu_loop — adaptive TUN-MTU adjustment.

The loop runs as a background task during a session, polls the kernel-
discovered path MTU on each tick, and adjusts the TUN's MTU to track it:
lower-on-drop is immediate; raise-toward-config.mtu is gated on
``AUTO_MTU_HYSTERESIS_RISES`` consecutive observations to guard against
flap from transient PMTU bumps.

We unit-test the decision logic with a scripted ``get_path_mtu`` and a
mocked ``TunDevice.set_mtu``.
"""

from __future__ import annotations

import asyncio
import unittest
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import MagicMock, patch

from dsm.core.config import Config
from dsm.core.protocol import fragment_ip_packet
from dsm.net.transport.tcp import TCPTransport
from dsm.net.transport.udp import UDPTransport
from dsm.net.tunnel import TunDevice
from dsm.session import auto_mtu_loop
from dsm.traffic.shaper import TrafficShaper


def _make_config(**overrides: Any) -> Config:
    """Valid client-mode Config with the auto-MTU adapter enabled and a
    very short polling interval so tests run fast."""
    defaults: dict[str, Any] = {
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
        "auto_mtu": True,
        "pmtu_check_interval_s": 1.0,  # tests override to ~0.01
    }
    defaults.update(overrides)
    return Config(**defaults)


@dataclass
class _StubCtx:
    """Minimal duck-typed DataPathContext for the auto-MTU loop.

    The loop touches ``tun``, ``shutdown``, and (Phase 1.7) ``shaper``
    (to clamp the size-class ceiling to the discovered PMTU); we don't
    need the full session-state machinery. ``shaper`` is a MagicMock —
    these tests assert on TUN-MTU decisions, not on shaper calls.
    """

    tun: Any
    shutdown: asyncio.Event
    shaper: Any = field(default_factory=MagicMock)


def _make_udp_transport_with_pmtus(pmtus: Iterator[int | None]) -> UDPTransport:
    """A real UDPTransport instance (unbound) whose ``get_path_mtu`` is
    monkey-patched to return successive scripted values."""
    t = UDPTransport()
    next_pmtu = lambda: next(pmtus)
    t.get_path_mtu = next_pmtu  # type: ignore[method-assign]
    return t


def _scripted(*values: int | None) -> Iterator[int | None]:
    """Yield ``values`` in order, then None forever (loop keeps polling
    after the test's interesting events)."""
    for v in values:
        yield v
    while True:
        yield None


async def _run_loop_for(
    config: Config,
    transport: Any,
    *,
    ticks: int,
) -> tuple[MagicMock, list[int]]:
    """Run ``auto_mtu_loop`` for at least ``ticks`` poll cycles, then
    shut it down. Returns (tun mock, list of mtu args passed to set_mtu).
    """
    tun = MagicMock()
    set_mtu_calls: list[int] = []
    tun.set_mtu = MagicMock(side_effect=lambda m: set_mtu_calls.append(m))

    shutdown = asyncio.Event()
    ctx = _StubCtx(tun=tun, shutdown=shutdown)

    task = asyncio.create_task(auto_mtu_loop(ctx, transport, config))
    # Each tick = pmtu_check_interval_s. Add a small slack so we don't
    # race the loop's wait_for.
    await asyncio.sleep(config.pmtu_check_interval_s * ticks + 0.05)
    shutdown.set()
    try:
        await asyncio.wait_for(task, timeout=2.0)
    except TimeoutError:
        task.cancel()
        raise

    return tun, set_mtu_calls


class TestAutoMtuLoop(unittest.IsolatedAsyncioTestCase):
    async def test_lowers_on_pmtu_drop(self) -> None:
        # config.mtu = 1400; first PMTU read = 1300 → classes up to 1272
        # leave 1152 the largest, so the TUN MTU drops to 1152 - 40 = 1112.
        config = _make_config(mtu=1400, pmtu_check_interval_s=0.01)
        transport = _make_udp_transport_with_pmtus(_scripted(1300))
        _, calls = await _run_loop_for(config, transport, ticks=2)
        self.assertEqual(calls, [1112])

    async def test_no_change_when_pmtu_above_config(self) -> None:
        # PMTU is 1600; usable = 1532, clamped to ceiling 1400 = config.mtu.
        # current starts at 1400, usable == 1400 → else branch, no call.
        config = _make_config(mtu=1400, pmtu_check_interval_s=0.01)
        transport = _make_udp_transport_with_pmtus(_scripted(1600, 1600, 1600))
        _, calls = await _run_loop_for(config, transport, ticks=4)
        self.assertEqual(calls, [])

    async def test_hysteresis_rises_below_threshold_do_not_raise(self) -> None:
        # Start: drop to lower TUN MTU. Then 2 consecutive higher PMTUs
        # — below the hysteresis threshold of 3.
        config = _make_config(mtu=1400, pmtu_check_interval_s=0.01)
        transport = _make_udp_transport_with_pmtus(
            _scripted(1100, 1300, 1300)  # 1 lower, then 2 same higher
        )
        _, calls = await _run_loop_for(config, transport, ticks=4)
        # Only the initial lower; the 2 raises haven't reached threshold.
        self.assertEqual(calls, [984])

    async def test_hysteresis_three_stable_rises_raise(self) -> None:
        config = _make_config(mtu=1400, pmtu_check_interval_s=0.01)
        # First: lower to 1024-40=984 (path 1100). Then 3 consecutive 1300
        # readings → after the 3rd, raise to 1152-40=1112.
        transport = _make_udp_transport_with_pmtus(_scripted(1100, 1300, 1300, 1300))
        _, calls = await _run_loop_for(config, transport, ticks=5)
        self.assertEqual(
            calls,
            [984, 1112],
        )

    async def test_floor_clamp_min_tun_mtu(self) -> None:
        # The fitted TUN MTU would be < AUTO_MTU_FLOOR → clamp to it.
        config = _make_config(mtu=1400, pmtu_check_interval_s=0.01)
        # Largest class <= 472 is 384; 384 - 40 = 344 < 472 → clamp to 472.
        transport = _make_udp_transport_with_pmtus(_scripted(500))
        _, calls = await _run_loop_for(config, transport, ticks=2)
        self.assertEqual(calls, [472])

    async def test_ceiling_clamp_config_mtu(self) -> None:
        # After lowering and stabilizing high, never raise above config.mtu.
        config = _make_config(mtu=1400, pmtu_check_interval_s=0.01)
        transport = _make_udp_transport_with_pmtus(
            _scripted(1100, 9000, 9000, 9000, 9000, 9000)  # absurd PMTU
        )
        _, calls = await _run_loop_for(config, transport, ticks=7)
        # First lower to 984. After 3 rises at the ceiling, raise to 1400.
        # No further raises because we're at the ceiling already.
        self.assertEqual(
            calls,
            [984, config.mtu],
        )

    async def test_disabled_returns_immediately(self) -> None:
        config = _make_config(auto_mtu=False, pmtu_check_interval_s=0.01)
        # Even with PMTUs that would trigger lowering, loop must no-op.
        transport = _make_udp_transport_with_pmtus(_scripted(800, 800, 800))
        _, calls = await _run_loop_for(config, transport, ticks=4)
        self.assertEqual(calls, [])

    async def test_non_udp_returns_immediately(self) -> None:
        config = _make_config(transport="tcp", pmtu_check_interval_s=0.01)
        # TCPTransport has no get_path_mtu meaning; loop must no-op.
        transport = TCPTransport()
        tun = MagicMock()
        shutdown = asyncio.Event()
        ctx = _StubCtx(tun=tun, shutdown=shutdown)
        # No need to set shutdown; non-UDP path returns synchronously.
        await asyncio.wait_for(auto_mtu_loop(ctx, transport, config), timeout=1.0)
        tun.set_mtu.assert_not_called()

    async def test_no_thrash_on_oscillation_around_boundary(self) -> None:
        # PMTU oscillates ±20 around 1300. Lowering on each drop would
        # call set_mtu repeatedly; the design's "lower only when usable
        # < current" rule should prevent that — once we drop to 1112,
        # subsequent reads at 1320 are RISES (need hysteresis), not
        # further drops.
        config = _make_config(mtu=1400, pmtu_check_interval_s=0.01)
        transport = _make_udp_transport_with_pmtus(
            _scripted(1300, 1320, 1280, 1320, 1280, 1320)
        )
        _, calls = await _run_loop_for(config, transport, ticks=7)
        # First lower at 1300 → 1112. Then 1320 (class 1280 fits, 1240) is a
        # rise (rises=1). 1280 (class 1152 fits) → 1112, equal: the TUN MTU
        # stays and only the size ceiling drops (1272 → 1252), rises=0.
        # 1320 → rise (rises=1). 1280 → nothing changes, rises=0.
        # 1320 → rise (rises=1).
        # End state: one set_mtu call (no infinite thrash).
        self.assertLessEqual(len(calls), 3)
        # Both calls should be lowers (no rises landed — never reached 3 stable).
        for c in calls:
            self.assertLess(c, 1400)

    async def test_shutdown_event_terminates_loop(self) -> None:
        config = _make_config(pmtu_check_interval_s=0.5)  # long-ish
        transport = _make_udp_transport_with_pmtus(_scripted())  # all None

        tun = MagicMock()
        shutdown = asyncio.Event()
        ctx = _StubCtx(tun=tun, shutdown=shutdown)

        task = asyncio.create_task(auto_mtu_loop(ctx, transport, config))
        # Set shutdown almost immediately; loop should exit within
        # ~one interval (the asyncio.wait_for unblocks).
        await asyncio.sleep(0.05)
        shutdown.set()
        await asyncio.wait_for(task, timeout=1.0)


async def _calls_until_first_set_mtu(
    config: Config, shaper: TrafficShaper, path_mtu: int
) -> list[int]:
    """Run auto_mtu_loop on one path-MTU reading until it calls set_mtu."""
    calls: list[int] = []
    lowered = asyncio.Event()

    def record(mtu: int) -> None:
        calls.append(mtu)
        lowered.set()

    tun = MagicMock()
    tun.set_mtu = MagicMock(side_effect=record)
    ctx = _StubCtx(tun=tun, shutdown=asyncio.Event(), shaper=shaper)
    transport = _make_udp_transport_with_pmtus(_scripted(path_mtu))
    task = asyncio.create_task(auto_mtu_loop(ctx, transport, config))
    await asyncio.wait_for(lowered.wait(), timeout=2.0)
    ctx.shutdown.set()
    await asyncio.wait_for(task, timeout=2.0)
    return calls


class TestAutoMtuFullPacketFitsAClass(unittest.IsolatedAsyncioTestCase):
    """Finding #8: after auto_mtu lowers the TUN MTU, a full-size TUN packet
    must leave in one of the size classes chaff also uses, never at the
    exact-size fallback that marks it as real."""

    async def test_full_size_packet_lands_in_an_active_class(self) -> None:
        # (kernel path MTU, TUN MTU auto_mtu must pick): the largest class
        # that fits the path (path - 28) minus 40. 650 and 552 are paths a
        # forged ICMP "frag needed" can set (the kernel floor is 552).
        cases = ((1300, 1112), (1420, 1240), (1100, 984), (650, 472), (552, 472))
        for path_mtu, want_tun in cases:
            with self.subTest(path_mtu=path_mtu):
                config = _make_config(pmtu_check_interval_s=0.01)  # mtu 1360
                shaper = TrafficShaper.from_config(config)
                calls = await _calls_until_first_set_mtu(config, shaper, path_mtu)
                self.assertEqual(len(calls), 1)
                active = shaper._active_classes
                for inner in fragment_ip_packet(b"\x45" * calls[0], 0, 1):
                    self.assertIn(shaper.pad_packet(inner)[1], active)
                self.assertEqual(calls[0], want_tun)


class TestTunSetMtuFloor(unittest.TestCase):
    def test_set_mtu_keeps_auto_mtu_floor(self) -> None:
        # The real device must take the value auto_mtu picked, not 576.
        with patch("dsm.net.tunnel._run_commands") as run:
            TunDevice("mtun-test").set_mtu(472)
            TunDevice("mtun-test").set_mtu(0)
        mtus = [c.args[0][0][-1] for c in run.call_args_list]
        self.assertEqual(mtus, ["472", "472"])


async def _run_on_readings(
    config: Config, shaper: TrafficShaper, *path_mtus: int
) -> tuple[MagicMock, list[int]]:
    """Run auto_mtu_loop until it has acted on every reading in ``path_mtus``.

    Returns the TUN mock and the size ceilings the loop set on ``shaper``
    (the real shaper still applies each one).
    """
    readings = iter(path_mtus)
    done = asyncio.Event()

    def next_reading() -> int | None:
        value = next(readings, None)
        if value is None:
            # The loop acts on a reading before it asks for the next one.
            done.set()
        return value

    transport = UDPTransport()
    transport.get_path_mtu = next_reading  # type: ignore[method-assign]
    ceilings: list[int] = []
    set_ceiling = shaper.set_size_class_ceiling

    def record(max_outer: int) -> None:
        ceilings.append(max_outer)
        set_ceiling(max_outer)

    tun = MagicMock()
    ctx = _StubCtx(tun=tun, shutdown=asyncio.Event(), shaper=shaper)
    with patch.object(shaper, "set_size_class_ceiling", side_effect=record):
        task = asyncio.create_task(auto_mtu_loop(ctx, transport, config))
        await asyncio.wait_for(done.wait(), timeout=2.0)
        ctx.shutdown.set()
        await asyncio.wait_for(task, timeout=2.0)
    return tun, ceilings


class TestAutoMtuCeilingWithHandSetMtu(unittest.IsolatedAsyncioTestCase):
    """A hand-set mtu below the fit keeps its TUN MTU on a smaller path, but
    the size ceiling must still drop. Otherwise the classes too big for the
    path stay in use, and every packet drawn there is lost (DF is set)."""

    async def test_ceiling_drops_without_a_tun_change(self) -> None:
        for mtu in (1100, 1000):
            with self.subTest(mtu=mtu):
                config = _make_config(mtu=mtu, pmtu_check_interval_s=0.01)
                shaper = TrafficShaper.from_config(config)
                tun, ceilings = await _run_on_readings(config, shaper, 1300)
                tun.set_mtu.assert_not_called()
                self.assertEqual(ceilings, [1272])  # path 1300 - IP/UDP 28
                self.assertEqual(shaper._active_classes[-1], 1152)

    async def test_ceiling_rises_only_after_three_steady_readings(self) -> None:
        config = _make_config(mtu=1100, pmtu_check_interval_s=0.01)
        shaper = TrafficShaper.from_config(config)
        _, ceilings = await _run_on_readings(config, shaper, 1300, 1500, 1500)
        self.assertEqual(ceilings, [1272])
        self.assertEqual(shaper._active_classes[-1], 1152)

        shaper = TrafficShaper.from_config(config)
        tun, ceilings = await _run_on_readings(config, shaper, 1300, 1500, 1500, 1500)
        tun.set_mtu.assert_not_called()
        # Back to padding_max (1400): the shaper never goes above it anyway.
        self.assertEqual(ceilings, [1272, 1400])
        self.assertEqual(shaper._active_classes[-1], 1400)


class TestAutoMtuCeilingWhenSetMtuFails(unittest.IsolatedAsyncioTestCase):
    """A TUN MTU that cannot be lowered must not keep the old size too. With
    DF on, every datagram at the old size is refused. A packet too big for
    the new size is dropped, never sent at its exact size, so the lower
    size leaks nothing, and small packets keep flowing."""

    async def test_the_ceiling_drops_when_set_mtu_fails(self) -> None:
        config = _make_config(pmtu_check_interval_s=0.01)  # mtu 1360
        shaper = TrafficShaper.from_config(config)
        tries: list[int] = []
        tried_twice = asyncio.Event()

        def refuse(mtu: int) -> None:
            tries.append(mtu)
            if len(tries) == 2:
                tried_twice.set()
            raise OSError("RTNETLINK answers: Operation not permitted")

        tun = MagicMock()
        tun.set_mtu = MagicMock(side_effect=refuse)
        ctx = _StubCtx(tun=tun, shutdown=asyncio.Event(), shaper=shaper)
        transport = _make_udp_transport_with_pmtus(_scripted(1300, 1300))
        ceilings: list[int] = []
        set_ceiling = shaper.set_size_class_ceiling

        def record(max_outer: int) -> None:
            ceilings.append(max_outer)
            set_ceiling(max_outer)

        with patch.object(shaper, "set_size_class_ceiling", side_effect=record):
            task = asyncio.create_task(auto_mtu_loop(ctx, transport, config))
            # The loop handles the second reading in full before it waits.
            await asyncio.wait_for(tried_twice.wait(), timeout=2.0)
            ctx.shutdown.set()
            await asyncio.wait_for(task, timeout=2.0)
        # The TUN MTU is tried again at each reading; the size goes down once.
        self.assertEqual(tries, [1112, 1112])
        self.assertEqual(ceilings, [1272])  # path 1300 - IP/UDP 28
        self.assertEqual(shaper._active_classes[-1], 1152)


class TestAutoMtuConfigValidation(unittest.TestCase):
    def test_pmtu_check_interval_lower_bound(self) -> None:
        with self.assertRaises(ValueError):
            _make_config(pmtu_check_interval_s=0.0)
        with self.assertRaises(ValueError):
            _make_config(pmtu_check_interval_s=-1.0)

    def test_pmtu_check_interval_upper_bound(self) -> None:
        with self.assertRaises(ValueError):
            _make_config(pmtu_check_interval_s=4000.0)

    def test_pmtu_check_interval_default(self) -> None:
        # Default is 30.0 per Config (we override in _make_config to 1.0).
        # Build raw Config to verify the actual default.
        from dsm.core.config import Config as RawConfig

        raw = RawConfig(
            mode="client",
            server_ip="10.0.0.1",
            server_port=51820,
            listen_port=51821,
            key_file="/tmp/k",
            cert_file="/tmp/c",
            ca_root_file="/tmp/ca",
            attest_key_file="/tmp/ak",
            expected_server_cn="dsm-x",
            transport="udp",
        )
        self.assertEqual(raw.pmtu_check_interval_s, 30.0)
        self.assertFalse(raw.auto_mtu)


if __name__ == "__main__":
    unittest.main()
