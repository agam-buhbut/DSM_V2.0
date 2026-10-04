"""Regression lock for symmetric server↔client traffic shaping.

The server must pad and chaff outgoing packets identically to the client.
Any divergence reintroduces a direction-correlation fingerprint: a passive
observer could tell "client→server" packets from "server→client" packets
by size or timing distribution.

These tests do not boot the transport layer. They construct client-side
and server-side TrafficShaper instances with matching parameters and
assert that the *primitives used by both ends* (pad_packet, make_chaff_padded)
emit output drawn from the same size-class support set, and that both ends
build their shaper from the same config keys (TrafficShaper.from_config).
"""

from __future__ import annotations

import asyncio
import unittest

from dsm.core.config import Config
from dsm.core.protocol import SIZE_CLASSES, InnerPacket, PacketType
from dsm.traffic.shaper import TrafficShaper, make_chaff_packet

PADDING_MIN = 128
PADDING_MAX = 1400


class _Clock:
    """Injectable monotonic clock for deterministic pacing-symmetry tests."""

    def __init__(self, start: float = 1000.0) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, dt: float) -> None:
        self.t += dt


def _sizes_from_many_packets(shaper: TrafficShaper, trials: int) -> set[int]:
    """Call pad_packet many times and collect the target outer sizes."""
    sizes: set[int] = set()
    for _ in range(trials):
        inner = InnerPacket(ptype=PacketType.DATA, epoch_id=0, payload=b"x" * 40)
        _, target = shaper.pad_packet(inner)
        sizes.add(target)
    return sizes


def _departures(
    shaper: TrafficShaper, start: float, end: float, *, backlog: bool
) -> int:
    """Poll ``shaper`` from ``start`` to ``end`` at each next_wake and count
    the slots. With ``backlog`` a large real queue has waited since
    ``start``."""
    count = 0
    now = start
    while now < end:
        queue_len, oldest_wait = (100, now - start) if backlog else (0, 0.0)
        slots, now = shaper.poll(now, queue_len, oldest_wait, 0)
        count += slots
    return count


class TestSymmetricShaping(unittest.TestCase):
    def test_identical_config_yields_identical_size_support(self) -> None:
        client = TrafficShaper(PADDING_MIN, PADDING_MAX)
        server = TrafficShaper(PADDING_MIN, PADDING_MAX)

        # With 500 trials each side should hit every active class.
        client_sizes = _sizes_from_many_packets(client, 500)
        server_sizes = _sizes_from_many_packets(server, 500)

        self.assertEqual(client_sizes, server_sizes)

    def test_padded_outputs_stay_within_configured_bounds(self) -> None:
        server = TrafficShaper(PADDING_MIN, PADDING_MAX)
        for _ in range(200):
            inner = InnerPacket(ptype=PacketType.DATA, epoch_id=0, payload=b"y")
            _, target = server.pad_packet(inner)
            self.assertGreaterEqual(target, PADDING_MIN)
            self.assertLessEqual(target, PADDING_MAX)
            self.assertIn(target, SIZE_CLASSES)

    def test_chaff_from_both_ends_has_same_support(self) -> None:
        async def _run() -> None:
            client = TrafficShaper(PADDING_MIN, PADDING_MAX)
            server = TrafficShaper(PADDING_MIN, PADDING_MAX)
            client_targets: set[int] = set()
            server_targets: set[int] = set()
            for _ in range(500):
                _, ct = await make_chaff_packet(client, epoch_id=0)
                _, st = await make_chaff_packet(server, epoch_id=0)
                client_targets.add(ct)
                server_targets.add(st)
            self.assertEqual(client_targets, server_targets)
            for t in client_targets:
                self.assertIn(t, SIZE_CLASSES)

        asyncio.run(_run())

    def test_both_ends_build_the_same_tier_ladder_from_config(self) -> None:
        """Client and server both build their shaper with
        TrafficShaper.from_config, so the same config gives both ends the same
        tiers. Each session's secret timing values differ by design, so exact
        schedules cannot match; instead both ends must idle inside the same
        first-tier band and both must step up under the same backlog.
        """
        shared = {
            "server_ip": "10.0.0.1",
            "server_port": 51820,
            "listen_port": 51821,
            "key_file": "/tmp/test.key",
            "cert_file": "/tmp/test.crt",
            "ca_root_file": "/tmp/test-ca.pem",
            "attest_key_file": "/tmp/test-attest.key",
            "shaper_tiers_pps": [20, 100],
            "shaper_decoy_interval_s": 0,
            "shaper_linger_s": [0, 0],
        }
        client_cfg = Config(
            mode="client", expected_server_cn="dsm-test-server", **shared
        )
        server_cfg = Config(
            mode="server",
            dns_providers=["https://1.1.1.1/dns-query"],
            dns_provider_pins={"https://1.1.1.1/dns-query": ["a" * 64]},
            allowed_cns_file="/tmp/test-allowed-cns.txt",
            **shared,
        )
        for cfg in (client_cfg, server_cfg):
            clock = _Clock()
            shaper = TrafficShaper.from_config(cfg, clock=clock)
            start = clock()
            idle = _departures(shaper, start, start + 30.0, backlog=False)
            # Tier 0 is 20 packets/s times a secret 0.8-1.2 session scale.
            # A 30 s count also varies by chance, so allow 10% either side.
            self.assertGreaterEqual(idle, 16 * 30 * 0.9, cfg.mode)
            self.assertLessEqual(idle, 24 * 30 * 1.1, cfg.mode)
            busy = _departures(shaper, start + 30.0, start + 35.0, backlog=True)
            # A standing backlog steps up to the 100-packet/s tier.
            self.assertGreater(busy, 24 * 5 * 1.5, cfg.mode)


if __name__ == "__main__":
    unittest.main()
