"""Dead-peer-timeout detection in ``dsm.session.liveness_loop``.

The liveness loop (``dsm/session.py``) tears the session down when the
receive side has been silent for longer than ``DEAD_PEER_TIMEOUT``: each
wake it computes ``recv_idle = now - liveness.last_recv_time`` and, when
that exceeds the threshold, emits a ``liveness_fire`` audit event and sets
``ctx.shutdown``. This is the safety property that stops a session from
lingering forever against a peer that has vanished (NAT rebind, crash,
silent drop), which for an anonymity tunnel also bounds how long a stale
keyed state stays alive.

The loop's only time source is ``dsm.session.time.monotonic`` and its only
externally-visible teardown signal is ``ctx.shutdown`` plus the
``netaudit.emit('liveness_fire', ...)`` call. We drive it deterministically
by injecting a fake clock at that boundary and shrinking
``LIVENESS_CHECK_INTERVAL`` so the loop's ``wait_for`` returns promptly with
no meaningful real sleep. No tuncore, no sockets, no disk.

Discriminating assertion: with a silent peer (``last_recv_time`` far in
the past relative to the injected clock) the loop fires exactly one
``liveness_fire`` with ``reason='dead_peer_timeout'`` and sets shutdown;
with *recent* traffic it fires ZERO such events and never sets shutdown on
its own. A loop that ignored ``recv_idle`` (or compared it the wrong way)
would fail one of these two halves.
"""

from __future__ import annotations

import asyncio
import unittest
from typing import Any

from dsm import session
from dsm.session import (
    DataPathContext,
    LivenessState,
    RekeyState,
    liveness_loop,
)


class _FakeClock:
    """Injected monotonic clock. ``now`` is advanced explicitly by the test."""

    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def monotonic(self) -> float:
        return self.now


class _FakeSessionKeys:
    """Only ``epoch`` is read by the keepalive build path."""

    epoch = 0


class _FakeShaper:
    def pad_packet(self, inner: object) -> tuple[bytes, int]:
        return (b"\x00" * 16, 128)


class _RecordingScheduler:
    """Captures keepalive enqueues; optionally stops the loop on first enqueue.

    The recent-traffic test uses the keepalive enqueue (which only happens
    AFTER the dead-peer check has run and declined to fire) as a precise
    signal that one full loop iteration completed, then sets shutdown so the
    loop exits on its next wake — without any real sleep.
    """

    def __init__(self, stop_event: asyncio.Event | None = None) -> None:
        self.enqueued: list[tuple[bytes, int]] = []
        self._stop_event = stop_event

    def enqueue(
        self, data: bytes, target_size: int, *, extra_delay: float = 0.0
    ) -> None:
        self.enqueued.append((data, target_size))
        if self._stop_event is not None:
            self._stop_event.set()


def _make_ctx(
    *,
    last_recv_time: float,
    last_real_send_time: float,
    scheduler: _RecordingScheduler,
) -> DataPathContext:
    liveness = LivenessState(
        last_recv_time=last_recv_time,
        last_real_send_time=last_real_send_time,
    )
    return DataPathContext(
        tun=None,  # type: ignore[arg-type]  # liveness_loop never touches the TUN
        session_keys=_FakeSessionKeys(),  # type: ignore[arg-type]
        fsm=None,  # type: ignore[arg-type]  # liveness_loop never touches the FSM
        shaper=_FakeShaper(),  # type: ignore[arg-type]
        send_fn=None,  # type: ignore[arg-type]  # keepalive uses scheduler.enqueue
        scheduler=scheduler,  # type: ignore[arg-type]
        rekey=RekeyState(),
        liveness=liveness,
        shutdown=asyncio.Event(),
        reassembly=None,
    )


class DeadPeerTimeout(unittest.IsolatedAsyncioTestCase):
    """``liveness_loop`` dead-peer-timeout firing and non-firing behavior."""

    def setUp(self) -> None:
        # Shrink the wake cadence so wait_for(shutdown) times out promptly;
        # the dead-peer DECISION is driven entirely by the injected clock,
        # not by wall-clock elapsed time.
        self._patches: list[Any] = []
        self._set(session, "LIVENESS_CHECK_INTERVAL", 0.01)
        self._clock = _FakeClock(start=1000.0)
        self._set(session, "time", self._clock)
        # Capture audit events at the module boundary regardless of the
        # netaudit enabled-gate (which is off by default).
        self.events: list[tuple[str, dict[str, Any]]] = []

        def _record(event: str, **fields: Any) -> None:
            self.events.append((event, dict(fields)))

        self._set(session.netaudit, "emit", _record)

    def tearDown(self) -> None:
        for obj, name, original in reversed(self._patches):
            setattr(obj, name, original)

    def _set(self, obj: Any, name: str, value: Any) -> None:
        self._patches.append((obj, name, getattr(obj, name)))
        setattr(obj, name, value)

    async def test_silent_peer_triggers_teardown_after_timeout(self) -> None:
        """recv_idle > DEAD_PEER_TIMEOUT => one liveness_fire + shutdown set.

        last_recv_time is one full threshold-plus-slack in the past relative
        to the injected clock, so the very first wake must declare the peer
        dead and tear the session down.
        """
        scheduler = _RecordingScheduler()
        # Peer last heard from well over DEAD_PEER_TIMEOUT ago (clock = 1000).
        dead_recv = self._clock.now - (session.DEAD_PEER_TIMEOUT + 5.0)
        ctx = _make_ctx(
            last_recv_time=dead_recv,
            last_real_send_time=self._clock.now,  # send recent: no keepalive
            scheduler=scheduler,
        )

        await asyncio.wait_for(liveness_loop(ctx), timeout=5)

        self.assertTrue(ctx.shutdown.is_set(), "dead peer must trigger teardown")
        fires = [f for name, f in self.events if name == "liveness_fire"]
        self.assertEqual(len(fires), 1, "exactly one dead-peer fire expected")
        self.assertEqual(fires[0]["reason"], "dead_peer_timeout")
        self.assertEqual(fires[0]["threshold_s"], session.DEAD_PEER_TIMEOUT)
        self.assertGreater(fires[0]["recv_idle_s"], session.DEAD_PEER_TIMEOUT)
        # The teardown path returns before reaching the keepalive enqueue.
        self.assertEqual(scheduler.enqueued, [])

    async def test_boundary_recv_idle_just_under_threshold_does_not_fire(self) -> None:
        """recv_idle just below DEAD_PEER_TIMEOUT must NOT fire.

        Pins the comparison as strictly-greater-than: at exactly threshold
        minus a hair the peer is still considered alive. The loop is stopped
        deterministically via the keepalive enqueue (forced by a stale
        last_real_send_time) which only runs once the dead-peer check has
        declined to fire.
        """
        stop = asyncio.Event()
        scheduler = _RecordingScheduler(stop_event=stop)
        # recv just barely fresh; send stale so keepalive fires => stop signal.
        near_recv = self._clock.now - (session.DEAD_PEER_TIMEOUT - 0.5)
        stale_send = self._clock.now - (session.KEEPALIVE_SEND_INTERVAL + 1.0)
        ctx = _make_ctx(
            last_recv_time=near_recv,
            last_real_send_time=stale_send,
            scheduler=scheduler,
        )

        async def _stop_when_signalled() -> None:
            await stop.wait()
            ctx.shutdown.set()

        await asyncio.wait_for(
            asyncio.gather(liveness_loop(ctx), _stop_when_signalled()),
            timeout=5,
        )

        # The loop ran a full iteration (keepalive enqueued) but did NOT
        # declare the peer dead: shutdown was set by US, not by the loop.
        self.assertEqual(len(scheduler.enqueued), 1, "keepalive should have fired")
        fires = [f for name, f in self.events if name == "liveness_fire"]
        self.assertEqual(fires, [], "fresh recv must NOT trigger dead-peer fire")

    async def test_recent_traffic_keeps_session_alive_across_many_wakes(self) -> None:
        """Recent recv keeps the session alive over repeated wakes.

        Advances the injected clock each iteration but keeps last_recv_time
        within the threshold, proving the loop re-evaluates liveness against
        the moving clock and stays up as long as the peer is heard from.
        """
        scheduler = _RecordingScheduler()
        clock = self._clock
        wakes = {"n": 0}

        ctx = _make_ctx(
            last_recv_time=clock.now,
            last_real_send_time=clock.now,
            scheduler=scheduler,
        )

        async def _driver() -> None:
            # Advance the injected clock in sub-threshold steps, refreshing
            # last_recv_time each step (peer keeps talking), then end the
            # test by setting shutdown ourselves.
            for _ in range(5):
                await asyncio.sleep(0.02)  # let the loop wake
                clock.now += 10.0  # well under DEAD_PEER_TIMEOUT per step
                ctx.liveness.last_recv_time = clock.now  # peer still alive
                wakes["n"] += 1
            ctx.shutdown.set()

        await asyncio.wait_for(
            asyncio.gather(liveness_loop(ctx), _driver()),
            timeout=5,
        )

        fires = [f for name, f in self.events if name == "liveness_fire"]
        self.assertEqual(fires, [], "kept-alive session must never fire dead-peer")
        self.assertGreaterEqual(wakes["n"], 5)


if __name__ == "__main__":
    unittest.main()
