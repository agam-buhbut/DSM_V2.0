"""A frame dropped by ``skip`` does not restart a handshake wait.

A peer that keeps sending copies of an earlier message must not stretch a
wait past its deadline. The inner receive and the clock are both fakes: each
fake frame "arrives" after ``step`` seconds of fake time, so nothing waits on
the wall clock.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from dsm.crypto import handshake
from dsm.crypto.handshake import HANDSHAKE_TIMEOUT, MAX_RETRIES, HandshakeError

Addr = tuple[str, int]

# More inner receives than any correct run makes: reaching it means the
# deadline was not kept.
_RECV_LIMIT = 50


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class _SkippableFrames:
    """Stands in for ``handshake._recv_one``. A frame arrives every ``step``
    seconds of fake time; a wait shorter than that times out at its end, as
    ``asyncio.wait_for`` would."""

    def __init__(self, clock: _Clock, step: float) -> None:
        self.clock = clock
        self.step = step
        self.timeouts: list[float] = []

    async def __call__(self, _transport: Any, timeout: float) -> tuple[bytes, None]:
        self.timeouts.append(timeout)
        if len(self.timeouts) > _RECV_LIMIT:
            raise AssertionError("a skipped frame restarted the wait")
        if timeout < self.step:
            self.clock.now += timeout
            raise TimeoutError
        self.clock.now += self.step
        return b"a copy of an earlier message", None


def _always_skip(_frame: bytes) -> bool:
    return True


@pytest.mark.parametrize("step", [1.0, 1.5])
async def test_a_skipped_frame_does_not_restart_the_wait(
    monkeypatch: pytest.MonkeyPatch, step: float
) -> None:
    clock = _Clock()
    start = clock.now
    frames = _SkippableFrames(clock, step)
    monkeypatch.setattr(asyncio.get_running_loop(), "time", clock)
    monkeypatch.setattr(handshake, "_recv_one", frames)
    transport: Any = object()

    with pytest.raises(TimeoutError):
        await handshake._recv_one_skipping(transport, 5.0, _always_skip)

    # The TimeoutError comes at the original deadline, not later.
    assert clock.now - start == 5.0
    # Each inner receive gets only what is left of the wait.
    assert frames.timeouts == [5.0 - i * step for i in range(len(frames.timeouts))]
    assert len(frames.timeouts) > 2


async def test_retries_keep_their_own_deadlines_while_frames_are_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every try waits ``HANDSHAKE_TIMEOUT`` at most, so the whole recv ends
    after ``MAX_RETRIES`` waits and the backoff between them."""
    clock = _Clock()
    start = clock.now
    frames = _SkippableFrames(clock, step=1.0)
    retransmits: list[float] = []
    transport: Any = object()

    async def _sleep(delay: float) -> None:
        clock.now += delay

    async def _retransmit() -> None:
        retransmits.append(clock.now)

    with monkeypatch.context() as patch:
        patch.setattr(asyncio.get_running_loop(), "time", clock)
        patch.setattr(handshake, "_recv_one", frames)
        patch.setattr(handshake.asyncio, "sleep", _sleep)
        with pytest.raises(HandshakeError):
            await handshake._recv_with_retry(
                transport, retransmit=_retransmit, skip=_always_skip
            )

    backoff = sum(handshake.BACKOFF_BASE * 2**i for i in range(MAX_RETRIES - 1))
    assert clock.now - start == MAX_RETRIES * HANDSHAKE_TIMEOUT + backoff
    assert len(retransmits) == MAX_RETRIES - 1
    # Each try starts with a fresh full wait.
    assert frames.timeouts.count(HANDSHAKE_TIMEOUT) == MAX_RETRIES
