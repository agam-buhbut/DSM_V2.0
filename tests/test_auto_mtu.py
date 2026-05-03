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
from dataclasses import dataclass
from typing import Any
from unittest.mock import MagicMock

from dsm.core.config import Config, MIN_TUN_MTU
from dsm.net.transport.tcp import TCPTransport
from dsm.net.transport.udp import UDPTransport
from dsm.session import (
    AUTO_MTU_HYSTERESIS_RISES,
    WIRE_OVERHEAD,
    auto_mtu_loop,
)


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

    The loop only touches ``tun`` and ``shutdown``; we don't need the
    full session-state machinery.
    """
    tun: Any
    shutdown: asyncio.Event


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
    initial_mtu: int | None = None,
) -> tuple[MagicMock, list[int]]:
    """Run ``auto_mtu_loop`` for at least ``ticks`` poll cycles, then
    shut it down. Returns (tun mock, list of mtu args passed to set_mtu).
    """
    tun = MagicMock()
    set_mtu_calls: list[int] = []
    tun.set_mtu = MagicMock(side_effect=lambda m: set_mtu_calls.append(m))

    shutdown = asyncio.Event()
    ctx = _StubCtx(tun=tun, shutdown=shutdown)

    if initial_mtu is not None:
        # The loop tracks `current` internally starting from config.mtu.
        # Tests parametrize via config.mtu, not initial_mtu directly.
        pass  # noqa: silenced — initial_mtu kept for future flexibility

    task = asyncio.create_task(auto_mtu_loop(ctx, transport, config))
    # Each tick = pmtu_check_interval_s. Add a small slack so we don't
    # race the loop's wait_for.
    await asyncio.sleep(config.pmtu_check_interval_s * ticks + 0.05)
    shutdown.set()
    try:
        await asyncio.wait_for(task, timeout=2.0)
    except asyncio.TimeoutError:
        task.cancel()
        raise

    return tun, set_mtu_calls


class TestAutoMtuLoop(unittest.IsolatedAsyncioTestCase):
    async def test_lowers_on_pmtu_drop(self) -> None:
        # config.mtu = 1400; first PMTU read = 1300 → usable = 1232.
        # Loop should lower TUN MTU to 1232 on first tick.
        config = _make_config(mtu=1400, pmtu_check_interval_s=0.01)
        transport = _make_udp_transport_with_pmtus(_scripted(1300))
        _, calls = await _run_loop_for(config, transport, ticks=2)
        self.assertEqual(calls, [1300 - WIRE_OVERHEAD])

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
        self.assertEqual(calls, [1100 - WIRE_OVERHEAD])

    async def test_hysteresis_three_stable_rises_raise(self) -> None:
        config = _make_config(mtu=1400, pmtu_check_interval_s=0.01)
        # First: lower to 1100-68=1032. Then 3 consecutive 1300 readings
        # → after the 3rd, raise to 1300-68=1232.
        transport = _make_udp_transport_with_pmtus(
            _scripted(1100, 1300, 1300, 1300)
        )
        _, calls = await _run_loop_for(config, transport, ticks=5)
        self.assertEqual(
            calls,
            [1100 - WIRE_OVERHEAD, 1300 - WIRE_OVERHEAD],
        )

    async def test_floor_clamp_min_tun_mtu(self) -> None:
        # PMTU - WIRE_OVERHEAD would be < MIN_TUN_MTU → clamp to MIN_TUN_MTU.
        config = _make_config(mtu=1400, pmtu_check_interval_s=0.01)
        # 600 - 68 = 532 < MIN_TUN_MTU (576) → clamp to 576.
        transport = _make_udp_transport_with_pmtus(_scripted(600))
        _, calls = await _run_loop_for(config, transport, ticks=2)
        self.assertEqual(calls, [MIN_TUN_MTU])

    async def test_ceiling_clamp_config_mtu(self) -> None:
        # After lowering and stabilizing high, never raise above config.mtu.
        config = _make_config(mtu=1400, pmtu_check_interval_s=0.01)
        transport = _make_udp_transport_with_pmtus(
            _scripted(1100, 9000, 9000, 9000, 9000, 9000)  # absurd PMTU
        )
        _, calls = await _run_loop_for(config, transport, ticks=7)
        # First lower to 1032. After 3 rises at the ceiling, raise to 1400.
        # No further raises because we're at the ceiling already.
        self.assertEqual(
            calls,
            [1100 - WIRE_OVERHEAD, config.mtu],
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
        await asyncio.wait_for(
            auto_mtu_loop(ctx, transport, config), timeout=1.0
        )
        tun.set_mtu.assert_not_called()

    async def test_no_thrash_on_oscillation_around_boundary(self) -> None:
        # PMTU oscillates ±20 around 1300. Lowering on each drop would
        # call set_mtu repeatedly; the design's "lower only when usable
        # < current" rule should prevent that — once we drop to 1232,
        # subsequent reads at 1320 are RISES (need hysteresis), not
        # further drops.
        config = _make_config(mtu=1400, pmtu_check_interval_s=0.01)
        transport = _make_udp_transport_with_pmtus(
            _scripted(1300, 1320, 1280, 1320, 1280, 1320)
        )
        _, calls = await _run_loop_for(config, transport, ticks=7)
        # First lower at 1300 → 1232. Then 1320 is a rise (rises=1).
        # 1280 < current (1232)? 1280 - 68 = 1212; 1212 < 1232 → ANOTHER LOWER.
        # 1320 → rise (rises=1, was reset by the new lower).
        # 1280 → 1212 < 1212? equal → else, no change, rises=0.
        # 1320 → rise (rises=1).
        # End state: at most 2 set_mtu calls (no infinite thrash).
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
        c = _make_config()
        del_overrides = {k: v for k, v in {}.items()}  # no-op; default
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
