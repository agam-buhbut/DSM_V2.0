"""Packet send scheduler, driven by the tier shaper.

The tier shaper decides when packets leave. Each wake the loop polls the
shaper, sends ``slots_due`` packets (queued real packets first, chaff for the
rest) and sleeps until the shaper's ``next_wake``. Queuing a packet never
wakes the loop early, so send times never move toward real-packet arrivals.
A queued packet may take the very next slot. There is no mode without a
shaper, so nothing can leave unshaped by mistake.

Packets queued at the same moment leave in the order they were queued.
"""

from __future__ import annotations

import asyncio
import heapq
import itertools
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:
    from dsm.traffic.shaper import TrafficShaper

log = logging.getLogger(__name__)

_T = TypeVar("_T")
_SendFn = Callable[[bytes, int], Awaitable[None]]

# Bounded queue. Sized for low-RAM targets: 512 * ~1500B ≈ 768 KiB
# worst-case. Drop policy is drop-oldest regardless of packet type,
# which preserves anonymity (real/chaff indistinguishable on the wire,
# so drop-oldest does not reveal traffic shape).
MAX_QUEUE_SIZE = 512


@dataclass(order=True)
class _ScheduledPacket:
    send_time: float
    # Tie-break: packets with the same send time leave in queue order.
    order: int
    data: bytes = field(compare=False)
    target_size: int = field(compare=False)
    # Per-packet sender (a PATH_CHALLENGE to a candidate address); None
    # means the scheduler's own send_fn.
    send_via: _SendFn | None = field(default=None, compare=False)


class SendScheduler:
    """Async send scheduler: queued packets and chaff leave in the tier
    shaper's slots."""

    def __init__(
        self,
        send_fn: _SendFn,
        chaff_fn: Callable[[], Awaitable[tuple[bytes, int]]] | None = None,
        should_chaff_fn: Callable[[], bool] | None = None,
        *,
        shaper: TrafficShaper,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """
        Args:
            send_fn: async callable(data, target_size) to transmit a packet
            chaff_fn: async callable() -> (chaff_data, target_size)
            should_chaff_fn: callable() -> bool, a GATE on filling free slots
                with chaff (the server keeps it closed until the client addr
                is known); a slot with no real packet and a closed gate stays
                empty.
            shaper: decides when packets leave. Each wake the loop asks it how
                many slots are due, sends that many packets (real first, chaff
                for the rest) and sleeps until the shaper's next wake.
            clock: injectable monotonic clock; it must be the clock the shaper
                was built with.
        """
        self._send_fn = send_fn
        self._chaff_fn = chaff_fn
        self._should_chaff_fn = should_chaff_fn
        self._shaper = shaper
        self._clock = clock
        self._queue: list[_ScheduledPacket] = []
        self._order = itertools.count()
        self._max_queue_size = MAX_QUEUE_SIZE
        self._running = False
        self._task: asyncio.Task[None] | None = None
        # When to poll next, and real packets sent since the last poll (the
        # shaper's step-down check counts them).
        self._next_wake = 0.0
        self._real_sent = 0

    def enqueue(
        self,
        data: bytes,
        target_size: int,
        *,
        send_via: _SendFn | None = None,
    ) -> None:
        """Queue a packet. It may take the very next slot.

        ``send_via`` sends this one packet with a different function (the
        server's PATH_CHALLENGE to a candidate address) when its turn comes.
        """
        if len(self._queue) >= self._max_queue_size:
            heapq.heappop(self._queue)  # drop oldest
            log.warning("scheduler queue full, dropping oldest packet")
        heapq.heappush(
            self._queue,
            _ScheduledPacket(
                self._clock(), next(self._order), data, target_size, send_via
            ),
        )

    async def start(self) -> None:
        self._running = True
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _run(self) -> None:
        # Sleep until the shaper's next wake; nothing shortens that sleep, so
        # queuing a packet cannot pull a send time toward its arrival.
        while self._running:
            await self._tick(self._clock())
            await asyncio.sleep(max(0.0, self._next_wake - self._clock()))

    async def _keep_alive(self, coro: Awaitable[_T], what: str) -> _T | None:
        """Await ``coro``, absorbing failures so the detached loop stays alive.

        Transport-level failures (network down, peer closed, socket closed
        under us) are logged at WARNING and skipped. Any OTHER exception is
        logged at ERROR with a traceback and the loop CONTINUES: this detached
        task must stay alive so chaff and real egress keep flowing — a dead
        scheduler silently breaks the constant-traffic anonymity property with
        no shutdown signal. Returns ``None`` when ``coro`` failed.
        """
        try:
            return await coro
        except (TimeoutError, ConnectionError, OSError) as e:
            log.warning("%s failed: %s", what, type(e).__name__)
        except Exception:
            log.error(
                "scheduler %s raised unexpectedly — keeping loop alive",
                what,
                exc_info=True,
            )
        return None

    async def _send_one(self, pkt: _ScheduledPacket) -> None:
        """Send a single packet, keeping the detached loop alive on error."""
        send = pkt.send_via if pkt.send_via is not None else self._send_fn
        await self._keep_alive(send(pkt.data, pkt.target_size), "send")

    async def _tick(self, now: float) -> None:
        """Fill exactly the slots that are due.

        Queued packets go first, oldest first; chaff fills the remaining
        slots. The count comes from the shaper, never from the queue, so the
        wire rate follows the tier, not the real traffic.
        """
        oldest_wait = 0.0
        if self._queue and self._queue[0].send_time <= now:
            oldest_wait = now - self._queue[0].send_time
        slots, self._next_wake = self._shaper.poll(
            now, len(self._queue), oldest_wait, self._real_sent
        )
        self._real_sent = 0
        chaff_allowed = self._should_chaff_fn is None or self._should_chaff_fn()
        for _ in range(slots):
            if self._queue and self._queue[0].send_time <= now:
                await self._send_one(heapq.heappop(self._queue))
                self._real_sent += 1
            elif self._chaff_fn is not None and chaff_allowed:
                # Chaff fills the slot. Sent DIRECTLY (not via enqueue) so it
                # never counts as real demand.
                await self._send_chaff()
            else:
                # No real packet due and chaff not allowed (e.g. the server
                # before the client addr is known): the slot stays empty.
                break

    async def _send_chaff(self) -> None:
        """Generate one chaff packet and send it at once.

        Bypasses the queue so chaff (the fill) is never counted as real
        demand. Keeps the loop alive on a chaff_fn error.
        """
        if self._chaff_fn is None:
            return
        result = await self._keep_alive(self._chaff_fn(), "chaff generation")
        if result is None:
            return
        chaff_data, chaff_size = result
        await self._keep_alive(self._send_fn(chaff_data, chaff_size), "send")
