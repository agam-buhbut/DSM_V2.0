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

    def test_both_ends_pace_identically_under_same_envelope_config(self) -> None:
        """Client and server shapers driven by the same envelope config must
        release the SAME per-tick wire budget given the same queue input.

        The wire rate is paced by the envelope (update_envelope /
        release_budget), so direction symmetry now means: identical config +
        identical queue history => identical release schedule. A divergence
        here would let a passive observer tell client→server from
        server→client by the chaff/real cadence rather than by size.

        Driven by an injected deterministic clock and a fixed idle floor
        (min == max) so the only per-session randomness is removed and the
        pacing math is fully reproducible across both ends.
        """

        def _make(clock: _Clock) -> TrafficShaper:
            return TrafficShaper(
                PADDING_MIN,
                PADDING_MAX,
                clock=clock,
                envelope_idle_floor_min_pps=1.0,
                envelope_idle_floor_max_pps=1.0,
                envelope_ceiling_pps=100.0,
                envelope_rise_per_s=2.0,
                envelope_fall_half_life_s=4.0,
                envelope_latency_budget_ms=1000,
            )

        client_clk, server_clk = _Clock(), _Clock()
        client, server = _make(client_clk), _make(server_clk)

        # Same queue history on both ends over ~3s: idle, then a sustained
        # backlog whose oldest packet breaches the 1s budget (forcing the
        # override on both ends), then idle again. The window is long enough
        # that the 1pps floor alone releases several packets, so the schedule
        # is non-trivial. Record each end's per-tick release budget.
        depths = [0] * 50 + [200] * 150 + [0] * 100
        ages = [0.0] * 50 + [1.5] * 150 + [0.0] * 100
        client_budget: list[int] = []
        server_budget: list[int] = []
        for depth, age in zip(depths, ages):
            client_clk.advance(0.01)
            server_clk.advance(0.01)
            client.update_envelope(client_clk(), depth, age)
            server.update_envelope(server_clk(), depth, age)
            client_budget.append(client.release_budget(client_clk()))
            server_budget.append(server.release_budget(server_clk()))

        self.assertEqual(client_budget, server_budget)
        # Sanity: the run actually drove releases (not a trivially-equal
        # all-zero schedule).
        self.assertGreater(sum(client_budget), 0)


if __name__ == "__main__":
    unittest.main()
