"""Packet send scheduler, driven by the tier shaper.

The tier shaper decides when packets leave. Each wake the loop polls the
shaper, sends ``slots_due`` packets (queued real packets first, chaff for the
rest) and sleeps until the shaper's ``next_wake``. Queuing a packet never
wakes the loop early, so send times never move toward real-packet arrivals.
A queued packet may take the very next slot. The send loop has no mode
without a shaper, so it cannot send unshaped traffic by mistake (the
SESSION_CLOSE at teardown goes out directly, by design).

Control messages (rekey packets, PATH_CHALLENGE, PATH_RESPONSE) wait in
their own small queue, which is always sent first and which the data
queue's drop-oldest never touches. They still take normal slots, so the wire
looks the same. Within each queue, packets leave in the order they were
queued.
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

from dsm.core.log import RepeatLog

if TYPE_CHECKING:
    from dsm.traffic.shaper import TrafficShaper

log = logging.getLogger(__name__)

_T = TypeVar("_T")
_SendFn = Callable[[bytes, int], Awaitable[None]]

# Bounded data queue. Sized for low-RAM targets: 512 * ~1500B ≈ 768 KiB
# worst-case. Drop policy is drop-oldest, which preserves anonymity
# (real/chaff indistinguishable on the wire, so drop-oldest does not reveal
# traffic shape).
MAX_QUEUE_SIZE = 512

# Control messages have deadlines of a few seconds (a rekey, an address
# check), so they must not wait behind, or be dropped with, a full data
# queue. Only a few are ever queued at once; if more pile up, the oldest
# control packet is dropped, as in the data queue.
MAX_CONTROL_QUEUE_SIZE = 32


@dataclass(order=True)
class _ScheduledPacket:
    # When the packet was queued; each queue sends its oldest first.
    queued_at: float
    # Tie-break: packets queued at the same moment leave in queue order.
    order: int
    data: bytes = field(compare=False)
    target_size: int = field(compare=False)
    # Per-packet sender (a PATH_CHALLENGE to a candidate address, or a
    # REKEY_INIT that notes its send time); None means the scheduler's own
    # send_fn.
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
        # Control messages: always sent before the data queue.
        self._control: list[_ScheduledPacket] = []
        self._order = itertools.count()
        self._max_queue_size = MAX_QUEUE_SIZE
        self._running = False
        self._task: asyncio.Task[None] | None = None
        # When to poll next, and real packets sent since the last poll (the
        # shaper's step-down check counts them).
        self._next_wake = 0.0
        self._real_sent = 0
        # A full queue and a failing send can repeat once per packet: log
        # the first, then at most one line per 10 s with a count.
        self._drop_log = RepeatLog(log, logging.WARNING, clock=clock)
        self._control_drop_log = RepeatLog(log, logging.WARNING, clock=clock)
        self._failure_logs: dict[tuple[str, type[BaseException]], RepeatLog] = {}

    def enqueue(
        self,
        data: bytes,
        target_size: int,
        *,
        send_via: _SendFn | None = None,
        control: bool = False,
    ) -> None:
        """Queue a packet. It may take the very next slot.

        ``send_via`` sends this one packet with a different function (the
        server's PATH_CHALLENGE to a candidate address) when its turn comes.

        ``control`` marks a control message: it goes to the control queue,
        which is sent before any data and which the data queue's drop-oldest
        never touches.
        """
        packet = _ScheduledPacket(
            self._clock(), next(self._order), data, target_size, send_via
        )
        if control:
            if len(self._control) >= MAX_CONTROL_QUEUE_SIZE:
                heapq.heappop(self._control)  # drop oldest
                self._control_drop_log.log(
                    "control queue full, dropping oldest control packet"
                )
            heapq.heappush(self._control, packet)
            return
        if len(self._queue) >= self._max_queue_size:
            heapq.heappop(self._queue)  # drop oldest
            self._drop_log.log("scheduler queue full, dropping oldest packet")
        heapq.heappush(self._queue, packet)

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
        under us) are skipped and logged at WARNING. Any OTHER exception is
        logged at ERROR with a traceback and the loop CONTINUES: this detached
        task must stay alive so chaff and real egress keep flowing — a dead
        scheduler silently breaks the constant-traffic anonymity property with
        no shutdown signal. Both can repeat once per packet, so each kind of
        failure logs its first one, then at most one line per 10 s with a
        count (an unexpected error's traceback only on lines about a single
        failure). Returns ``None`` when ``coro`` failed.
        """
        try:
            return await coro
        except (TimeoutError, ConnectionError, OSError) as e:
            self._failure_log(what, e, logging.WARNING).log(
                "%s failed: %s", what, type(e).__name__
            )
        # The loop must survive any bug in a send (see above); the error is
        # logged with its traceback, and repeats are counted.
        except Exception as e:  # noqa: BLE001
            self._failure_log(what, e, logging.ERROR).log(
                "scheduler %s raised unexpectedly — keeping loop alive",
                what,
                exc_info=True,
            )
        return None

    def _failure_log(self, what: str, error: BaseException, level: int) -> RepeatLog:
        """The repeat log for one kind of failure: what failed, and the
        error's class. A class always lands in the same except branch above,
        so a kind always logs at the same level."""
        kind = (what, type(error))
        if kind not in self._failure_logs:
            self._failure_logs[kind] = RepeatLog(log, level, clock=self._clock)
        return self._failure_logs[kind]

    async def _send_one(self, pkt: _ScheduledPacket) -> None:
        """Send a single packet, keeping the detached loop alive on error."""
        send = pkt.send_via if pkt.send_via is not None else self._send_fn
        await self._keep_alive(send(pkt.data, pkt.target_size), "send")

    async def _tick(self, now: float) -> None:
        """Fill exactly the slots that are due.

        Queued control messages go first, then queued data, each oldest
        first; chaff fills the remaining slots. The count comes from the
        shaper, never from the queues, so the wire rate follows the tier,
        not the real traffic.
        """
        heads = [q[0].queued_at for q in (self._control, self._queue) if q]
        oldest_wait = max(0.0, now - min(heads)) if heads else 0.0
        slots, self._next_wake = self._shaper.poll(
            now, len(self._control) + len(self._queue), oldest_wait, self._real_sent
        )
        self._real_sent = 0
        chaff_allowed = self._should_chaff_fn is None or self._should_chaff_fn()
        for _ in range(slots):
            queue = self._control or self._queue
            if queue:
                await self._send_one(heapq.heappop(queue))
                self._real_sent += 1
            elif self._chaff_fn is not None and chaff_allowed:
                # Chaff fills the slot. Sent DIRECTLY (not via enqueue) so it
                # never counts as real demand.
                await self._send_chaff()
            else:
                # Nothing queued and chaff not allowed (e.g. the server
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
