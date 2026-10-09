"""The DNS code never waits long for a TLS connection to close.

With a dead DoH/DoT peer and unsent data, ``wait_closed`` waits until the
kernel's TCP timeout (minutes); after the peer reset the connection, it
raises. In both cases ``_close_writer`` drops the connection and returns. The
StreamWriter is faked, so nothing touches the network.
"""

from __future__ import annotations

import asyncio
import errno
import os
import socket
from typing import cast
from unittest.mock import patch

import pytest

from dsm.net.dns import DNSResolver, _close_writer, _open_pinned_tls_connection


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

    def get_extra_info(self, _name: str) -> object:
        return object()  # the SSL object, checked by the faked pin check

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


def _stream(writer: _FakeWriter) -> asyncio.StreamWriter:
    return cast(asyncio.StreamWriter, writer)


def _reset() -> ConnectionResetError:
    return ConnectionResetError(errno.ECONNRESET, os.strerror(errno.ECONNRESET))


async def test_a_reset_peer_is_not_an_error_at_close() -> None:
    writer = _FakeWriter(_reset())

    await _close_writer(_stream(writer))  # does not raise

    assert writer.closes == 1
    assert writer.transport.aborts == 1


async def test_a_close_the_peer_never_answers_ends_after_the_bound() -> None:
    writer = _FakeWriter(hang=True)

    with patch("dsm.net.dns.CLOSE_TIMEOUT", 0.01):
        # The outer bound only turns a hang into a failure.
        await asyncio.wait_for(_close_writer(_stream(writer)), timeout=5)

    assert writer.wait_cancelled
    assert writer.transport.aborts == 1


async def test_a_normal_close_does_not_abort() -> None:
    writer = _FakeWriter()

    await _close_writer(_stream(writer))

    assert writer.closes == 1
    assert writer.waits == 1
    assert writer.transport.aborts == 0


async def test_query_cleanup_is_bounded_and_keeps_the_error() -> None:
    # The resolver's cleanup after a query: a dead peer must not hold it up,
    # and the error from the query must still come out.
    writer = _FakeWriter(hang=True)

    async def fake_open(*_a: object, **_k: object) -> tuple[object, _FakeWriter]:
        return object(), writer

    async def failing_query(*_a: object, **_k: object) -> bytes:
        raise RuntimeError("query failed")

    resolver = DNSResolver(["p"], {"p": ["aa" * 32]})

    with (
        patch("dsm.net.dns._open_pinned_tls_connection", fake_open),
        patch("dsm.net.dns.CLOSE_TIMEOUT", 0.01),
        pytest.raises(RuntimeError, match="query failed"),
    ):
        await asyncio.wait_for(
            resolver._resolve_via_pinned_tls("p", "host", 443, 1.0, failing_query),
            timeout=5,
        )

    assert writer.closes == 1
    assert writer.wait_cancelled
    assert writer.transport.aborts == 1


class _PinMismatch(Exception):
    pass


async def test_the_second_site_closes_with_the_bound_and_raises_the_pin_error() -> None:
    # A pin mismatch closes the connection before any qname is sent, then
    # raises. A dead peer must not hold that close up.
    writer = _FakeWriter(hang=True)
    sockets: list[socket.socket] = []
    loop = asyncio.get_running_loop()

    async def fake_getaddrinfo(*_a: object, **_k: object) -> list[tuple[object, ...]]:
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 443))]

    async def fake_sock_connect(*_a: object) -> None:
        return None

    async def fake_open_connection(
        *_a: object, sock: socket.socket, **_k: object
    ) -> tuple[object, _FakeWriter]:
        sockets.append(sock)
        return object(), writer

    def mismatch(*_a: object) -> None:
        raise _PinMismatch("pin does not match")

    try:
        with (
            patch.object(loop, "getaddrinfo", fake_getaddrinfo),
            patch.object(loop, "sock_connect", fake_sock_connect),
            patch("dsm.net.dns.apply_so_mark"),
            patch("dsm.net.dns.asyncio.open_connection", fake_open_connection),
            patch("dsm.net.dns_pinning.build_pinned_ssl_context"),
            patch("dsm.net.dns_pinning.verify_pin_on_ssl_object", mismatch),
            patch("dsm.net.dns.CLOSE_TIMEOUT", 0.01),
            pytest.raises(_PinMismatch),
        ):
            await asyncio.wait_for(
                _open_pinned_tls_connection(
                    "host", 443, [b"\x00" * 32], "p", timeout=1.0
                ),
                timeout=5,
            )
    finally:
        for sock in sockets:
            sock.close()

    assert writer.closes == 1
    assert writer.wait_cancelled
    assert writer.transport.aborts == 1
