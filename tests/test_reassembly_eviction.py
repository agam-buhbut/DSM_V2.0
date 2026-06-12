"""Tests for lazy eviction of stale fragment sets in ``ReassemblyBuffer``.

``dsm.core.protocol.ReassemblyBuffer._cleanup_expired`` runs on every
``add_fragment`` call. It is the anti-DoS path: incomplete fragment sets
that never get their missing pieces must be reclaimed so a peer cannot
pin memory by sending one fragment of many never-completed sets. These
tests drive that eviction directly with an injected monotonic clock
(no sleeps, no real time dependence) and prove three properties:

  * a stale incomplete set IS evicted once it ages past ``timeout_s``;
  * a still-fresh incomplete set in the SAME buffer is NOT evicted by
    the same sweep (eviction is per-entry, keyed on each set's own
    ``first_seen`` — not a global flush);
  * the eviction sweep does not corrupt a set that completes on the very
    call that triggers the sweep — it still reassembles to exact bytes.

Time injection note: ``_PendingReassembly.first_seen`` is populated by a
dataclass ``default_factory=time.monotonic`` that captures the function
object at import time, so it does not honor a patch of the module's
``time`` reference. ``_cleanup_expired`` reads ``now`` through that
module reference and IS patchable. We therefore inject the fake clock on
the ``now`` side (via ``mock.patch.object``) and set each set's
``first_seen`` explicitly when seeding — both ends are fully controlled,
so the tests are deterministic.
"""

from __future__ import annotations

import unittest
from unittest import mock

from dsm.core.protocol import (
    Fragment,
    ReassemblyBuffer,
    _PendingReassembly,
)


class _FakeClock:
    """Controllable stand-in for the ``time`` module's ``monotonic``.

    Only ``monotonic`` is used by the code under test; supplying just
    that attribute keeps the fake minimal and surfaces any accidental
    reliance on other ``time`` members as an ``AttributeError`` rather
    than silent real-clock leakage.
    """

    def __init__(self, start: float = 1000.0) -> None:
        self._t = start

    def monotonic(self) -> float:
        return self._t

    def advance(self, delta: float) -> None:
        self._t += delta

    def set(self, value: float) -> None:
        self._t = value


def _seed(
    rb: ReassemblyBuffer,
    fid: int,
    *,
    total: int,
    received: dict[int, bytes],
    first_seen: float,
) -> None:
    """Insert an incomplete pending set with an explicit ``first_seen``.

    This injects time at the data boundary (the field the default factory
    would otherwise fill from the real clock), keeping the test free of
    wall-clock coupling.
    """
    rb._pending[fid] = _PendingReassembly(
        total=total, received=dict(received), first_seen=first_seen
    )


class TestReassemblyEviction(unittest.TestCase):
    def test_stale_incomplete_set_is_evicted(self) -> None:
        clock = _FakeClock(start=1000.0)
        with mock.patch("dsm.core.protocol.time", clock):
            rb = ReassemblyBuffer(timeout_s=5.0)
            # An incomplete set (1 of 2 fragments) that arrived at t=1000.
            _seed(rb, 10, total=2, received={0: b"AAAA"}, first_seen=1000.0)
            self.assertIn(10, rb._pending)

            # Time moves strictly past the timeout, then ANY add_fragment
            # call triggers the lazy sweep.
            clock.set(1005.001)
            trigger = Fragment(fragment_id=20, index=0, total=2, data=b"BBBB")
            rb.add_fragment(trigger)

            # KEY assertion: the stale, never-completed set is gone. If
            # _cleanup_expired did not run (or compared the wrong way), the
            # set would still pin its buffer here.
            self.assertNotIn(10, rb._pending)
            # The fragment that triggered the sweep is itself still pending
            # (it is incomplete and fresh), proving add_fragment kept it.
            self.assertIn(20, rb._pending)

    def test_fresh_set_survives_sweep_that_evicts_a_stale_one(self) -> None:
        clock = _FakeClock(start=1000.0)
        with mock.patch("dsm.core.protocol.time", clock):
            rb = ReassemblyBuffer(timeout_s=5.0)
            # Stale: arrived at t=1000, will be older than timeout at t>1005.
            _seed(rb, 10, total=2, received={0: b"old0"}, first_seen=1000.0)
            # Fresh: arrived at t=1004, only 2.001s old at sweep time.
            _seed(rb, 11, total=2, received={0: b"new0"}, first_seen=1004.0)

            clock.set(1006.001)
            trigger = Fragment(fragment_id=30, index=0, total=2, data=b"trig")
            rb.add_fragment(trigger)

            # Discriminating: eviction is per-entry on each set's own age,
            # not a blanket flush. The stale set goes; the fresh one stays.
            self.assertNotIn(10, rb._pending)
            self.assertIn(11, rb._pending)

    def test_set_exactly_at_timeout_boundary_is_retained(self) -> None:
        clock = _FakeClock(start=1000.0)
        with mock.patch("dsm.core.protocol.time", clock):
            rb = ReassemblyBuffer(timeout_s=5.0)
            _seed(rb, 10, total=2, received={0: b"edge"}, first_seen=1000.0)

            # now - first_seen == timeout exactly. The comparison is strict
            # ('> timeout'), so this set must NOT be evicted.
            clock.set(1005.0)
            rb._cleanup_expired()
            self.assertIn(10, rb._pending)

            # One tick past the boundary and it is evicted — proving the
            # retention above was the boundary, not a no-op sweep.
            clock.set(1005.0001)
            rb._cleanup_expired()
            self.assertNotIn(10, rb._pending)

    def test_completed_set_reassembles_on_sweep_call(self) -> None:
        clock = _FakeClock(start=1000.0)
        with mock.patch("dsm.core.protocol.time", clock):
            rb = ReassemblyBuffer(timeout_s=5.0)
            # A stale incomplete set that the completing call must evict.
            _seed(rb, 10, total=2, received={0: b"stale0"}, first_seen=1000.0)
            # A second set that already has fragment 0 and is still fresh.
            _seed(rb, 11, total=2, received={0: b"hello "}, first_seen=1004.0)

            # Advance so the stale set (id=10) is past timeout but the
            # fresh set (id=11) is not.
            clock.set(1006.001)

            # The final fragment of id=11 arrives: this single call runs the
            # sweep (evicting id=10) AND completes id=11.
            last = Fragment(fragment_id=11, index=1, total=2, data=b"world")
            result = rb.add_fragment(last)

            # KEY assertion: completion is byte-exact and ordered by index,
            # and the sweep on the same call did not disturb it.
            self.assertEqual(result, b"hello world")
            # The stale set was evicted by that same sweep...
            self.assertNotIn(10, rb._pending)
            # ...and the completed set was removed on completion.
            self.assertNotIn(11, rb._pending)

    def test_eviction_runs_well_under_pending_cap(self) -> None:
        # The lazy-eviction path is independent of the capacity drop path:
        # stale sets are reclaimed even when nowhere near max_pending.
        clock = _FakeClock(start=1000.0)
        with mock.patch("dsm.core.protocol.time", clock):
            rb = ReassemblyBuffer(max_pending=256, timeout_s=5.0)
            for fid in range(5):
                _seed(
                    rb,
                    fid,
                    total=2,
                    received={0: bytes([fid])},
                    first_seen=1000.0,
                )
            self.assertEqual(len(rb._pending), 5)
            self.assertLess(len(rb._pending), rb._max_pending)

            clock.set(1010.0)
            rb._cleanup_expired()

            # All five stale sets reclaimed despite being far under the cap.
            self.assertEqual(len(rb._pending), 0)


if __name__ == "__main__":
    unittest.main()
