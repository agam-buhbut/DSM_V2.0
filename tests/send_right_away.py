"""For tests only: a stand-in for the tier shaper that sends right away.

Production code never uses this. ``SendScheduler`` always needs a shaper, so
tests that drive the send loop, but not the shaper's timing, use this
stand-in to stay fast and deterministic. Every queued packet leaves at the
next poll, and one slot is free when nothing is queued, so the chaff path
still runs. The loop polls again 5 ms later.
"""

from __future__ import annotations

_WAKE_S = 0.005


class SendRightAway:
    """Answers ``poll`` like the tier shaper does, without any pacing."""

    def poll(
        self, now: float, queue_len: int, oldest_wait: float, real_sent: int
    ) -> tuple[int, float]:
        return max(queue_len, 1), now + _WAKE_S
