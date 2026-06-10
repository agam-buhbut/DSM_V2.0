"""DSM-002 part B: the detached SendScheduler task must survive an unexpected
exception from send_fn or chaff_fn and keep flowing — a dead scheduler silently
breaks the constant-traffic anonymity property with no shutdown signal.

Event-driven and deterministic: no fixed sleeps for synchronization.
"""

from __future__ import annotations

import asyncio
import unittest

from dsm.traffic.scheduler import SendScheduler


class SchedulerResilience(unittest.IsolatedAsyncioTestCase):
    async def test_send_fn_exception_keeps_loop_alive(self) -> None:
        calls: list[bytes] = []
        first_attempted = asyncio.Event()
        delivered = asyncio.Event()
        n = {"i": 0}

        async def send_fn(data: bytes, size: int) -> None:
            n["i"] += 1
            if n["i"] == 1:
                first_attempted.set()
                raise RuntimeError("boom")  # unexpected, non-transport error
            calls.append(data)
            delivered.set()

        sched = SendScheduler(send_fn, jitter_ms_min=1, jitter_ms_max=1)
        await sched.start()
        try:
            sched.enqueue(b"a", 128)
            await asyncio.wait_for(first_attempted.wait(), timeout=2)
            # The raise was caught; the detached task must still be running.
            self.assertIsNotNone(sched._task)
            self.assertFalse(sched._task.done())  # type: ignore[union-attr]
            # A subsequent packet is still delivered (loop survived).
            sched.enqueue(b"b", 128)
            await asyncio.wait_for(delivered.wait(), timeout=2)
            self.assertEqual(calls, [b"b"])
        finally:
            await sched.stop()

    async def test_chaff_fn_exception_keeps_loop_alive(self) -> None:
        sent: list[bytes] = []
        delivered = asyncio.Event()
        chaff_attempted = asyncio.Event()
        chaff_on = {"v": True}

        async def send_fn(data: bytes, size: int) -> None:
            sent.append(data)
            if data == b"real":
                delivered.set()

        async def chaff_fn() -> tuple[bytes, int]:
            chaff_attempted.set()
            raise RuntimeError("chaff boom")

        sched = SendScheduler(
            send_fn,
            chaff_fn=chaff_fn,
            should_chaff_fn=lambda: chaff_on["v"],
            jitter_ms_min=1,
            jitter_ms_max=1,
        )
        await sched.start()
        try:
            await asyncio.wait_for(chaff_attempted.wait(), timeout=2)
            chaff_on["v"] = False  # stop further chaff attempts
            self.assertIsNotNone(sched._task)
            self.assertFalse(sched._task.done())  # type: ignore[union-attr]
            # Real egress still works after a chaff exception.
            sched.enqueue(b"real", 128)
            await asyncio.wait_for(delivered.wait(), timeout=2)
        finally:
            await sched.stop()


if __name__ == "__main__":
    unittest.main()
