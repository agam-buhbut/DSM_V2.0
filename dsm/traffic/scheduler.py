"""Jittered packet send scheduler.

Maintains a priority queue of pending packets, each with a scheduled
send time = enqueue_time + jitter. Pops the next packet when its time
arrives. Generates chaff when the queue is empty and the shaper says so.
"""

from __future__ import annotations

import asyncio
import heapq
import logging
import time
from dataclasses import dataclass, field
from typing import Callable, Awaitable

log = logging.getLogger(__name__)


@dataclass(order=True)
class _ScheduledPacket:
    send_time: float
    data: bytes = field(compare=False)
    target_size: int = field(compare=False)


class SendScheduler:
    """Async send scheduler with jitter and chaff injection."""

    def __init__(
        self,
        send_fn: Callable[[bytes, int], Awaitable[None]],
        chaff_fn: Callable[[], Awaitable[tuple[bytes, int]]] | None = None,
        should_chaff_fn: Callable[[], bool] | None = None,
        jitter_ms_min: int = 1,
        jitter_ms_max: int = 50,
    ) -> None:
        """
        Args:
            send_fn: async callable(data, target_size) to transmit a packet
            chaff_fn: async callable() -> (chaff_data, target_size)
            should_chaff_fn: callable() -> bool, whether to inject chaff now
            jitter_ms_min/max: jitter range in milliseconds
        """
        self._send_fn = send_fn
        self._chaff_fn = chaff_fn
        self._should_chaff_fn = should_chaff_fn
        self._jitter_min = jitter_ms_min / 1000.0
        self._jitter_max = jitter_ms_max / 1000.0
        self._queue: list[_ScheduledPacket] = []
        self._max_queue_size = 2048
        self._running = False
        self._task: asyncio.Task[None] | None = None
        self._event = asyncio.Event()

    def enqueue(self, data: bytes, target_size: int) -> None:
        """Enqueue a packet with random jitter delay."""
        if len(self._queue) >= self._max_queue_size:
            heapq.heappop(self._queue)  # drop oldest
            log.warning("scheduler queue full, dropping oldest packet")
        from dsm.core.rand import csprng_float
        jitter = self._jitter_min + csprng_float() * (self._jitter_max - self._jitter_min)
        send_time = time.monotonic() + jitter
        heapq.heappush(self._queue, _ScheduledPacket(send_time, data, target_size))
        self._event.set()

    async def start(self) -> None:
        """Start the scheduler loop."""
        self._running = True
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        """Stop the scheduler loop."""
        self._running = False
        self._event.set()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _run(self) -> None:
        while self._running:
            now = time.monotonic()

            # Send any packets whose time has arrived
            while self._queue and self._queue[0].send_time <= now:
                pkt = heapq.heappop(self._queue)
                try:
                    await self._send_fn(pkt.data, pkt.target_size)
                except Exception:
                    log.exception("send failed")

            # Inject chaff independently of queue state to avoid leaking
            # traffic activity via chaff-only / no-chaff timing patterns.
            if (
                self._chaff_fn
                and self._should_chaff_fn
                and self._should_chaff_fn()
            ):
                try:
                    chaff_data, chaff_size = await self._chaff_fn()
                    self.enqueue(chaff_data, chaff_size)
                except Exception:
                    log.exception("chaff generation failed")

            # Sleep until next packet or a jittered poll interval.
            # Jitter prevents a fixed 50ms cadence from fingerprinting the scheduler.
            from dsm.core.rand import csprng_float
            poll_jitter = 0.03 + csprng_float() * 0.04  # 30-70ms
            if self._queue:
                wait_time = max(0, self._queue[0].send_time - time.monotonic())
                wait_time = min(wait_time, poll_jitter)
            else:
                wait_time = poll_jitter

            self._event.clear()
            try:
                await asyncio.wait_for(self._event.wait(), timeout=wait_time)
            except asyncio.TimeoutError:
                pass
