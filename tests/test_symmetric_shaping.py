"""Regression lock for symmetric server↔client traffic shaping.

The server must pad and chaff outgoing packets identically to the client.
Any divergence reintroduces a direction-correlation fingerprint: a passive
observer could tell "client→server" packets from "server→client" packets
by size or timing distribution.

These tests do not boot the transport layer. They construct client-side
and server-side TrafficShaper instances with matching parameters and
assert that the *primitives used by both ends* (pad_packet, make_chaff)
emit output drawn from the same size-class support set.
"""

from __future__ import annotations

import asyncio
import unittest

from dsm.core.protocol import InnerPacket, PacketType, SIZE_CLASSES
from dsm.traffic.shaper import TrafficShaper, make_chaff_packet

PADDING_MIN = 128
PADDING_MAX = 1400


def _sizes_from_many_packets(shaper: TrafficShaper, trials: int) -> set[int]:
    """Call pad_packet many times and collect the target outer sizes."""
    sizes: set[int] = set()
    for _ in range(trials):
        inner = InnerPacket(ptype=PacketType.DATA, epoch_id=0, payload=b"x" * 40)
        _, target = shaper.pad_packet(inner)
        sizes.add(target)
    return sizes


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

    def test_both_ends_report_chaff_during_idle_window(self) -> None:
        """After idle threshold, both client and server schedulers should
        be willing to emit chaff (should_send_chaff → True) at comparable
        rates. Exact equality is impossible with CSPRNG; require each side
        to fire at least once in a short polling window."""
        client = TrafficShaper(PADDING_MIN, PADDING_MAX)
        server = TrafficShaper(PADDING_MIN, PADDING_MAX)

        client_fires = sum(1 for _ in range(1000) if client.should_send_chaff())
        server_fires = sum(1 for _ in range(1000) if server.should_send_chaff())

        self.assertGreater(client_fires, 0)
        self.assertGreater(server_fires, 0)


if __name__ == "__main__":
    unittest.main()
