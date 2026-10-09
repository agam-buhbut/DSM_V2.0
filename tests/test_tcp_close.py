"""``TCPTransport.aclose`` never holds up a retry or a stop.

With a dead peer, ``wait_closed`` waits for unsent data until the kernel's
TCP timeout (minutes); after the peer reset the connection, it raises. In
both cases ``aclose`` drops the connection and returns. The StreamWriter is
faked, so nothing touches the network.
"""

from __future__ import annotations

import asyncio
import errno
import os
from unittest.mock import patch

from dsm.net.transport.tcp import TCPTransport


class _FakeTransport:
    def __init__(self) -> None:
        self.aborts = 0

    def abort(self) -> None:
        self.aborts += 1


class _FakeWriter:
    """Stands in for ``asyncio.StreamWriter``."""

    def __init__(
        self, error: BaseException | None = None, *, hang: bool = False
    ) -> None:
        self.transport = _FakeTransport()
        self.closes = 0
        self.waits = 0
        self.wait_cancelled = False
        self._error = error
        self._hang = hang

    def close(self) -> None:
        self.closes += 1

    async def wait_closed(self) -> None:
        self.waits += 1
        if self._hang:
            try:
                await asyncio.Event().wait()  # the peer never answers
            except asyncio.CancelledError:
                self.wait_cancelled = True
                raise
        if self._error is not None:
            raise self._error


def _transport(writer: _FakeWriter) -> TCPTransport:
    transport = TCPTransport()
    transport._writer = writer  # type: ignore[assignment]
    return transport


def _reset() -> ConnectionResetError:
    return ConnectionResetError(errno.ECONNRESET, os.strerror(errno.ECONNRESET))


async def test_a_reset_peer_is_not_an_error_at_close() -> None:
    writer = _FakeWriter(_reset())
    transport = _transport(writer)

    await transport.aclose()  # does not raise

    assert writer.closes == 1
    assert writer.transport.aborts == 1
    assert transport._closed


async def test_a_close_the_peer_never_answers_ends_after_the_bound() -> None:
    writer = _FakeWriter(hang=True)
    transport = _transport(writer)

    with patch("dsm.net.transport.tcp.CLOSE_TIMEOUT_S", 0.01):
        # The outer bound only turns a hang into a failure.
        await asyncio.wait_for(transport.aclose(), timeout=5)

    assert writer.wait_cancelled
    assert writer.transport.aborts == 1
    assert transport._closed


async def test_a_normal_close_does_not_abort() -> None:
    writer = _FakeWriter()
    transport = _transport(writer)

    await transport.aclose()

    assert writer.closes == 1
    assert writer.waits == 1
    assert writer.transport.aborts == 0
    assert transport._closed


async def test_a_second_aclose_does_nothing() -> None:
    writer = _FakeWriter(_reset())
    transport = _transport(writer)

    await transport.aclose()
    await transport.aclose()

    assert writer.closes == 1
    assert writer.waits == 1
    assert writer.transport.aborts == 1
