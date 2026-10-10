"""server_handshake makes its attest signature in a worker thread.

A TPM signature took about 0.2 s on the server box, and the server can be
serving a live session meanwhile. These tests patch
build_attest_payload with stand-ins, so they need no tuncore and no
sockets; a threading.Event stands in for the TPM.
"""

from __future__ import annotations

import asyncio
import gc
import logging
import threading
from typing import Any
from unittest.mock import patch

import pytest

from dsm.crypto import handshake
from dsm.crypto.attest import PeerRole

_ARGS: dict[str, Any] = {
    "attest_key": object(),
    "cert_der": b"cert",
    "handshake_hash": b"\x00" * 32,
    "our_static_pub": b"\x01" * 32,
    "our_role": PeerRole.RESPONDER,
}


class _SlowSign:
    """Stand-in for build_attest_payload that blocks until released."""

    def __init__(self) -> None:
        self.started = threading.Event()
        self.release = threading.Event()
        self.finished = threading.Event()
        self.thread: threading.Thread | None = None

    def __call__(self, **_kwargs: Any) -> bytes:
        self.thread = threading.current_thread()
        self.started.set()
        self.release.wait(10.0)
        self.finished.set()
        return b"payload"


async def _until_started(sign: _SlowSign) -> None:
    assert await asyncio.to_thread(sign.started.wait, 10.0)


async def _yield(rounds: int = 20) -> None:
    for _ in range(rounds):
        await asyncio.sleep(0)


async def test_the_payload_is_built_in_a_worker_thread() -> None:
    sign = _SlowSign()
    sign.release.set()
    with patch.object(handshake, "build_attest_payload", new=sign):
        payload = await handshake._attest_payload_in_thread(**_ARGS)
    assert payload == b"payload"
    assert sign.thread is not None
    assert sign.thread is not threading.main_thread()


async def test_the_event_loop_keeps_running_while_the_signature_is_made() -> None:
    sign = _SlowSign()
    with patch.object(handshake, "build_attest_payload", new=sign):
        work = asyncio.ensure_future(handshake._attest_payload_in_thread(**_ARGS))
        await _until_started(sign)
        await _yield()
        assert not work.done()
        sign.release.set()
        assert await asyncio.wait_for(work, 10.0) == b"payload"


async def test_a_cancelled_handshake_waits_for_its_signature_to_finish() -> None:
    """Review Focus 4: the server zeroizes the attest key when it stops; a
    signature still running in a thread must end first."""
    sign = _SlowSign()
    with patch.object(handshake, "build_attest_payload", new=sign):
        work = asyncio.ensure_future(handshake._attest_payload_in_thread(**_ARGS))
        await _until_started(sign)
        work.cancel()
        await _yield()
        assert not work.done(), "the cancel must wait for the signing thread"
        sign.release.set()
        await asyncio.wait({work}, timeout=10.0)
    assert work.cancelled()
    assert sign.finished.is_set()


async def test_a_second_cancel_still_waits_for_the_thread() -> None:
    sign = _SlowSign()
    with patch.object(handshake, "build_attest_payload", new=sign):
        work = asyncio.ensure_future(handshake._attest_payload_in_thread(**_ARGS))
        await _until_started(sign)
        work.cancel()
        await _yield(2)
        work.cancel()
        await _yield()
        assert not work.done()
        sign.release.set()
        await asyncio.wait({work}, timeout=10.0)
    assert work.cancelled()
    assert sign.finished.is_set()


async def test_an_error_in_the_thread_reaches_the_handshake() -> None:
    def _fails(**_kwargs: Any) -> bytes:
        raise RuntimeError("TPM error: test")

    with patch.object(handshake, "build_attest_payload", new=_fails):
        with pytest.raises(RuntimeError, match="TPM error: test"):
            await handshake._attest_payload_in_thread(**_ARGS)


async def test_an_error_after_a_cancel_is_dropped_with_one_debug_line(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The handshake is over either way, so the error is dropped: asyncio
    must not log it later as "never retrieved", with its text."""
    caplog.set_level(logging.DEBUG)
    started = threading.Event()
    release = threading.Event()

    def _fails(**_kwargs: Any) -> bytes:
        started.set()
        release.wait(10.0)
        raise RuntimeError("TPM error: some detail")

    with patch.object(handshake, "build_attest_payload", new=_fails):
        work = asyncio.ensure_future(handshake._attest_payload_in_thread(**_ARGS))
        assert await asyncio.to_thread(started.wait, 10.0)
        work.cancel()
        await _yield()
        release.set()
        await asyncio.wait({work}, timeout=10.0)
    assert work.cancelled()
    del work
    gc.collect()
    await _yield()
    lines = [(r.name, r.levelno, r.getMessage()) for r in caplog.records]
    assert [line for line in lines if line[1] >= logging.ERROR] == []
    assert (
        "dsm.crypto.handshake",
        logging.DEBUG,
        "signature after a cancel failed: RuntimeError",
    ) in lines
    assert all("some detail" not in message for _, _, message in lines)
