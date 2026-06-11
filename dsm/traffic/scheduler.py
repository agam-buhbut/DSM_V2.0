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
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from dsm.core.rand import csprng_float

if TYPE_CHECKING:
    from dsm.traffic.shaper import TrafficShaper

log = logging.getLogger(__name__)

# Bounded queue. Sized for low-RAM targets: 512 * ~1500B ≈ 768 KiB
# worst-case. Drop policy is drop-oldest regardless of packet type,
# which preserves anonymity (real/chaff indistinguishable on the wire,
# so drop-oldest does not reveal traffic shape).
MAX_QUEUE_SIZE = 512

# Inter-tick poll jitter for the send loop. A fixed 50 ms cadence would
# fingerprint the scheduler on the wire; randomising the wake-up to
# ``_POLL_JITTER_MIN .. _POLL_JITTER_MIN + _POLL_JITTER_RANGE`` (i.e.
# 30-70 ms) breaks that signal without materially affecting throughput.
_POLL_JITTER_MIN = 0.03
_POLL_JITTER_RANGE = 0.04


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
        *,
        shaper: TrafficShaper | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """
        Args:
            send_fn: async callable(data, target_size) to transmit a packet
            chaff_fn: async callable() -> (chaff_data, target_size)
            should_chaff_fn: callable() -> bool. In legacy mode it is the
                additive-Poisson chaff decision. In envelope mode it acts as a
                GATE on the chaff-fill (e.g. the server suppresses chaff until
                the client addr is known); the envelope budget still governs
                the count when the gate is open.
            jitter_ms_min/max: jitter range in milliseconds
            shaper: when provided, the loop is ENVELOPE-DRIVEN — each poll it
                asks the shaper for the per-tick wire budget and emits exactly
                that many packets (real queue first, chaff fills the rest),
                making the wire rate independent of real-traffic volume. When
                ``None`` the loop keeps the legacy "drain all due + poll chaff"
                behavior (kept for the integration/resilience tests).
            clock: injectable monotonic clock for deterministic pacing tests.
        """
        self._send_fn = send_fn
        self._chaff_fn = chaff_fn
        self._should_chaff_fn = should_chaff_fn
        self._jitter_min = jitter_ms_min / 1000.0
        self._jitter_max = jitter_ms_max / 1000.0
        self._shaper = shaper
        self._clock = clock
        self._queue: list[_ScheduledPacket] = []
        self._max_queue_size = MAX_QUEUE_SIZE
        self._running = False
        self._task: asyncio.Task[None] | None = None
        self._event = asyncio.Event()

    def enqueue(
        self,
        data: bytes,
        target_size: int,
        *,
        extra_delay: float = 0.0,
    ) -> None:
        """Enqueue a packet with random jitter delay.

        ``extra_delay`` (default 0) is added to the per-packet jitter
        before scheduling. Used by the fragment send path to spread out
        the N fragments of an oversized TUN packet across multiple
        jitter windows — otherwise all N fragments arrive within
        jitter_max (~50 ms) of each other, producing a recognizable
        "1 → N tightly-spaced packets" traffic-analysis signature.
        """
        if len(self._queue) >= self._max_queue_size:
            heapq.heappop(self._queue)  # drop oldest
            log.warning("scheduler queue full, dropping oldest packet")
        jitter = self._jitter_min + csprng_float() * (
            self._jitter_max - self._jitter_min
        )
        send_time = self._clock() + jitter + max(0.0, extra_delay)
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
            # M-BUG-11: clear the event BEFORE checking the queue, not
            # after sleeping. Previous order: send-loop → chaff-inject
            # → _event.clear() → wait_for(_event.wait()). If
            # `enqueue()` fired during the send-loop iteration (between
            # the queue check and the clear), it called `_event.set()`;
            # then the subsequent `clear()` discarded that signal and
            # the loop waited the full poll_jitter (~30-70 ms) before
            # noticing the new packet. Clearing first means any
            # `_event.set()` during the iteration arrives AFTER our
            # clear and survives to the next wait_for.
            self._event.clear()
            now = self._clock()
            if self._shaper is not None:
                await self._envelope_tick(now, self._shaper)
            else:
                await self._legacy_tick(now)
            await self._sleep_until_next()

    async def _send_one(self, pkt: _ScheduledPacket) -> None:
        """Send a single packet, keeping the detached loop alive on error.

        Transport-level failures (network down, peer closed, socket closed
        under us) are logged at WARNING and skipped. Any OTHER exception is
        logged at ERROR with a traceback and the loop CONTINUES (DSM-002):
        this detached task must stay alive so chaff and real egress keep
        flowing — a dead scheduler silently breaks the constant-traffic
        anonymity property with no shutdown signal.
        """
        try:
            await self._send_fn(pkt.data, pkt.target_size)
        except (TimeoutError, ConnectionError, OSError) as e:
            log.warning("send failed: %s", type(e).__name__)
        except Exception:
            log.error(
                "scheduler send_fn raised unexpectedly — keeping loop alive",
                exc_info=True,
            )

    async def _legacy_tick(self, now: float) -> None:
        """Additive-Poisson path: drain all due packets, then poll chaff."""
        while self._queue and self._queue[0].send_time <= now:
            await self._send_one(heapq.heappop(self._queue))

        # Inject chaff independently of queue state to avoid leaking
        # traffic activity via chaff-only / no-chaff timing patterns.
        if self._chaff_fn and self._should_chaff_fn and self._should_chaff_fn():
            await self._emit_chaff()

    async def _envelope_tick(self, now: float, shaper: TrafficShaper) -> None:
        """Envelope-driven path: emit exactly the shaper's per-tick budget.

        Real queued packets (whose jitter ``send_time`` has arrived) drain
        first; chaff fills the remaining budget. The envelope governs the
        COUNT (decoupling the wire rate from real volume); the per-packet
        jitter still governs intra-tick ordering — a packet never leaves
        before its jitter ``send_time``.
        """
        oldest_age = 0.0
        if self._queue and self._queue[0].send_time <= now:
            oldest_age = max(0.0, now - self._queue[0].send_time)
        shaper.update_envelope(now, len(self._queue), oldest_age)
        budget = shaper.release_budget(now)
        chaff_allowed = self._should_chaff_fn is None or self._should_chaff_fn()
        for _ in range(budget):
            if self._queue and self._queue[0].send_time <= now:
                await self._send_one(heapq.heappop(self._queue))
            elif self._chaff_fn is not None and chaff_allowed:
                # Chaff fills the remaining budget. Send it DIRECTLY (not via
                # enqueue) so it does not inflate the queue depth that drives
                # the envelope — chaff is the fill, never the demand signal.
                await self._send_chaff_direct()
            else:
                # No real packet due and chaff not available/allowed this
                # tick: leave the budget slot unfilled (e.g. server before the
                # client addr is known — see server.py's chaff gate).
                break

    async def _emit_chaff(self) -> None:
        """Legacy path: generate one chaff packet and enqueue it.

        Keeps the detached loop alive on a chaff_fn error (DSM-002).
        """
        if self._chaff_fn is None:
            return
        try:
            chaff_data, chaff_size = await self._chaff_fn()
            self.enqueue(chaff_data, chaff_size)
        except (TimeoutError, ConnectionError, OSError) as e:
            log.warning("chaff generation failed: %s", type(e).__name__)
        except Exception:
            log.error(
                "scheduler chaff_fn raised unexpectedly — keeping loop alive",
                exc_info=True,
            )

    async def _send_chaff_direct(self) -> None:
        """Envelope path: generate one chaff packet and send it immediately.

        Bypasses the jittered queue so chaff (the fill) is never counted as
        real demand by the envelope. Keeps the loop alive on a chaff_fn error.
        """
        if self._chaff_fn is None:
            return
        try:
            chaff_data, chaff_size = await self._chaff_fn()
        except (TimeoutError, ConnectionError, OSError) as e:
            log.warning("chaff generation failed: %s", type(e).__name__)
            return
        except Exception:
            log.error(
                "scheduler chaff_fn raised unexpectedly — keeping loop alive",
                exc_info=True,
            )
            return
        await self._send_one(_ScheduledPacket(0.0, chaff_data, chaff_size))

    async def _sleep_until_next(self) -> None:
        """Sleep until the next queued packet or a jittered poll interval.

        Jitter prevents a fixed 50 ms cadence from fingerprinting the
        scheduler; the per-poll cadence also paces the envelope's release.
        """
        poll_jitter = _POLL_JITTER_MIN + csprng_float() * _POLL_JITTER_RANGE
        if self._queue and self._shaper is None:
            wait_time = max(0.0, self._queue[0].send_time - self._clock())
            wait_time = min(wait_time, poll_jitter)
        else:
            # Envelope mode polls on the jittered cadence regardless of queue
            # depth: the release budget — not a packet's send_time — decides
            # how many leave, so we must wake every poll to advance pacing.
            wait_time = poll_jitter

        try:
            await asyncio.wait_for(self._event.wait(), timeout=wait_time)
        except TimeoutError:
            pass
