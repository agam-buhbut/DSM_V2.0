"""Packet send scheduler.

Two modes:

* Shaper mode (a ``shaper`` is given; client and server use this): the tier
  shaper decides when packets leave. Each wake the loop polls the shaper,
  sends ``slots_due`` packets (queued real packets first, chaff for the rest)
  and sleeps until the shaper's ``next_wake``. Queuing a packet never wakes
  the loop early, so send times never move toward real-packet arrivals. A
  queued packet may take the very next slot: no jitter, no extra delay.
* Legacy mode (no shaper; kept for the integration and resilience tests):
  each packet gets a random jitter delay (plus any ``extra_delay``); the loop
  drains every packet whose send time has come, polls the chaff callback,
  and wakes early when a packet is queued.

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

from dsm.core.rand import csprng_float

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

# Legacy-mode poll jitter. A fixed 50 ms cadence would fingerprint the
# scheduler on the wire; randomising the wake-up to
# ``_POLL_JITTER_MIN .. _POLL_JITTER_MIN + _POLL_JITTER_RANGE`` (i.e.
# 30-70 ms) breaks that signal without materially affecting throughput.
_POLL_JITTER_MIN = 0.03
_POLL_JITTER_RANGE = 0.04


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
    """Async send scheduler with jitter and chaff injection."""

    def __init__(
        self,
        send_fn: _SendFn,
        chaff_fn: Callable[[], Awaitable[tuple[bytes, int]]] | None = None,
        should_chaff_fn: Callable[[], bool] | None = None,
        jitter_ms_min: int = 1,
        jitter_ms_max: int = 50,
        *,
        shaper: TrafficShaper | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """
        Args:
            send_fn: async callable(data, target_size) to transmit a packet
            chaff_fn: async callable() -> (chaff_data, target_size)
            should_chaff_fn: callable() -> bool. In legacy mode it is the
                chaff decision. In shaper mode it is a GATE on filling free
                slots with chaff (the server keeps it closed until the client
                addr is known); a slot with no real packet and a closed gate
                stays empty.
            jitter_ms_min/max: jitter range in milliseconds (legacy mode
                only; in shaper mode a queued packet takes the next slot)
            shaper: when provided, the loop is SHAPER-DRIVEN: each wake it
                asks the shaper how many slots are due, sends that many
                packets (real first, chaff for the rest) and sleeps until the
                shaper's next wake. When ``None`` the loop keeps the legacy
                "drain all due + poll chaff" behavior.
            clock: injectable monotonic clock; in shaper mode it must be the
                clock the shaper was built with.
        """
        self._send_fn = send_fn
        self._chaff_fn = chaff_fn
        self._should_chaff_fn = should_chaff_fn
        self._jitter_min = jitter_ms_min / 1000.0
        self._jitter_max = jitter_ms_max / 1000.0
        self._shaper = shaper
        self._clock = clock
        self._queue: list[_ScheduledPacket] = []
        self._order = itertools.count()
        self._max_queue_size = MAX_QUEUE_SIZE
        self._running = False
        self._task: asyncio.Task[None] | None = None
        self._event = asyncio.Event()
        # Shaper mode: when to poll next, and real packets sent since the
        # last poll (the shaper's step-down check counts them).
        self._next_wake = 0.0
        self._real_sent = 0

    def enqueue(
        self,
        data: bytes,
        target_size: int,
        *,
        extra_delay: float = 0.0,
        send_via: _SendFn | None = None,
    ) -> None:
        """Queue a packet.

        Shaper mode: the packet may take the very next slot; ``extra_delay``
        and the jitter range are ignored, because the slot schedule already
        decides timing.

        Legacy mode: the packet waits a random jitter delay plus
        ``extra_delay`` (the fragment send path uses it to spread the N
        fragments of an oversized TUN packet, so they don't leave as a
        recognizable "1 → N tightly-spaced packets" burst).

        ``send_via`` sends this one packet with a different function (the
        server's PATH_CHALLENGE to a candidate address) when its turn comes.
        """
        if len(self._queue) >= self._max_queue_size:
            heapq.heappop(self._queue)  # drop oldest
            log.warning("scheduler queue full, dropping oldest packet")
        send_time = self._clock()
        if self._shaper is None:
            jitter = self._jitter_min + csprng_float() * (
                self._jitter_max - self._jitter_min
            )
            send_time += jitter + max(0.0, extra_delay)
        heapq.heappush(
            self._queue,
            _ScheduledPacket(send_time, next(self._order), data, target_size, send_via),
        )
        # Only the legacy loop wakes early for a new packet. In shaper mode
        # waking here would pull send times toward real arrivals.
        if self._shaper is None:
            self._event.set()

    async def start(self) -> None:
        self._running = True
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
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
            # Clear the event BEFORE the queue check: an enqueue() during the
            # iteration then sets it after our clear and survives to the next
            # wait_for. Clearing after would swallow it and stall ~30-70 ms.
            self._event.clear()
            now = self._clock()
            if self._shaper is not None:
                await self._shaper_tick(now, self._shaper)
            else:
                await self._legacy_tick(now)
            await self._sleep_until_next()

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

    async def _legacy_tick(self, now: float) -> None:
        """Additive-Poisson path: drain all due packets, then poll chaff."""
        while self._queue and self._queue[0].send_time <= now:
            await self._send_one(heapq.heappop(self._queue))

        # Inject chaff independently of queue state to avoid leaking
        # traffic activity via chaff-only / no-chaff timing patterns.
        if self._chaff_fn and self._should_chaff_fn and self._should_chaff_fn():
            await self._emit_chaff()

    async def _shaper_tick(self, now: float, shaper: TrafficShaper) -> None:
        """Shaper-driven path: fill exactly the slots that are due.

        Queued packets go first, oldest first; chaff fills the remaining
        slots. The count comes from the shaper, never from the queue, so the
        wire rate follows the tier, not the real traffic.
        """
        oldest_wait = 0.0
        if self._queue and self._queue[0].send_time <= now:
            oldest_wait = now - self._queue[0].send_time
        slots, self._next_wake = shaper.poll(
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
                await self._send_chaff_direct()
            else:
                # No real packet due and chaff not allowed (e.g. the server
                # before the client addr is known): the slot stays empty.
                break

    async def _emit_chaff(self) -> None:
        """Legacy path: generate one chaff packet and enqueue it.

        Keeps the detached loop alive on a chaff_fn error.
        """
        if self._chaff_fn is None:
            return
        result = await self._keep_alive(self._chaff_fn(), "chaff generation")
        if result is not None:
            chaff_data, chaff_size = result
            self.enqueue(chaff_data, chaff_size)

    async def _send_chaff_direct(self) -> None:
        """Shaper path: generate one chaff packet and send it immediately.

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

    async def _sleep_until_next(self) -> None:
        """Sleep until the next wake.

        Shaper mode sleeps until the shaper's ``next_wake`` and nothing else
        shortens that sleep. Legacy mode waits for the next queued packet, a
        jittered poll interval, or an enqueue, whichever comes first.
        """
        if self._shaper is not None:
            await asyncio.sleep(max(0.0, self._next_wake - self._clock()))
            return
        poll_jitter = _POLL_JITTER_MIN + csprng_float() * _POLL_JITTER_RANGE
        if self._queue:
            wait_time = max(0.0, self._queue[0].send_time - self._clock())
            wait_time = min(wait_time, poll_jitter)
        else:
            wait_time = poll_jitter

        try:
            await asyncio.wait_for(self._event.wait(), timeout=wait_time)
        except TimeoutError:
            pass
