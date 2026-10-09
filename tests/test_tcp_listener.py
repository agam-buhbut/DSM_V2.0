"""TCPListener: one listening socket that queues each accepted connection as
its own TCPTransport. Loopback sockets only (127.0.0.1, port 0)."""

from __future__ import annotations

import asyncio
import logging
import socket
from typing import Any

import pytest

from dsm.net.transport import tcp as tcp_mod
from dsm.net.transport.tcp import TCPListener, TCPTransport


@pytest.fixture(autouse=True)
def _no_so_mark(monkeypatch: pytest.MonkeyPatch) -> None:
    # SO_MARK needs CAP_NET_ADMIN, which the test user does not have.
    monkeypatch.setattr(tcp_mod, "apply_so_mark", lambda sock: None)


class _FakeWriter:
    def __init__(self, peer: Any) -> None:
        self._peer = peer
        self.closed = False

    def get_extra_info(self, name: str) -> Any:
        return self._peer if name == "peername" else None

    def close(self) -> None:
        self.closed = True


async def _queued(listener: TCPListener) -> tuple[TCPTransport, tuple[str, int]]:
    return await asyncio.wait_for(listener.connections.get(), 5.0)


async def test_every_connection_is_queued_and_the_listener_stays_open() -> None:
    listener = TCPListener()
    port = await listener.start("127.0.0.1", 0)
    clients: list[tuple[asyncio.StreamReader, asyncio.StreamWriter]] = []
    queued: list[tuple[TCPTransport, tuple[str, int]]] = []
    try:
        for _ in range(3):
            clients.append(await asyncio.open_connection("127.0.0.1", port))
        for _ in range(3):
            queued.append(await _queued(listener))
        client_ports = sorted(w.get_extra_info("sockname")[1] for _, w in clients)
        assert sorted(peer[1] for _, peer in queued) == client_ports
        assert all(peer[0] == "127.0.0.1" for _, peer in queued)
        assert all(isinstance(conn, TCPTransport) for conn, _ in queued)
    finally:
        listener.close()
        for conn, _ in queued:
            conn.close()
        for _, writer in clients:
            writer.close()


async def test_a_queued_connection_carries_frames_both_ways() -> None:
    listener = TCPListener()
    port = await listener.start("127.0.0.1", 0)
    client = TCPTransport()
    await client.connect("127.0.0.1", port)
    conn, _ = await _queued(listener)
    try:
        await client.send(b"ping")
        assert await asyncio.wait_for(conn.recv(), 5.0) == b"ping"
        await conn.send(b"pong")
        assert await asyncio.wait_for(client.recv(), 5.0) == b"pong"
    finally:
        listener.close()
        conn.close()
        client.close()


async def test_aclose_ends_a_queued_connection() -> None:
    """from_streams fills what the bounded aclose uses, so the session stack
    can close the winning connection with it."""
    listener = TCPListener()
    port = await listener.start("127.0.0.1", 0)
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        conn, _ = await _queued(listener)
        await asyncio.wait_for(conn.aclose(), 5.0)
        assert await asyncio.wait_for(reader.read(), 5.0) == b""
        await conn.aclose()  # a second close does nothing
    finally:
        listener.close()
        writer.close()


async def test_close_stops_listening_and_closes_queued_connections() -> None:
    listener = TCPListener()
    port = await listener.start("127.0.0.1", 0)
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        listener.connections.put_nowait(await _queued(listener))  # still queued
        listener.close()
        assert listener.connections.empty()
        assert await asyncio.wait_for(reader.read(), 5.0) == b""
        with pytest.raises(OSError):
            await asyncio.open_connection("127.0.0.1", port)
    finally:
        writer.close()


async def test_a_connection_after_close_is_closed_at_once() -> None:
    listener = TCPListener()
    listener.close()
    writer = _FakeWriter(("127.0.0.1", 40000))
    listener._on_connect(None, writer)  # type: ignore[arg-type]
    assert writer.closed
    assert listener.connections.empty()


async def test_a_connection_with_no_peer_address_is_closed_at_once() -> None:
    listener = TCPListener()
    writer = _FakeWriter(None)
    listener._on_connect(None, writer)  # type: ignore[arg-type]
    assert writer.closed
    assert listener.connections.empty()


async def test_a_connection_that_cannot_be_marked_is_closed(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def _no_permission(sock: Any) -> None:
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(tcp_mod, "apply_so_mark", _no_permission)
    caplog.set_level(logging.ERROR, logger="dsm.net.transport.tcp")
    listener = TCPListener()
    port = await listener.start("127.0.0.1", 0)
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        assert await asyncio.wait_for(reader.read(), 5.0) == b""
        assert listener.connections.empty()
        records = [r for r in caplog.records if r.name == "dsm.net.transport.tcp"]
        assert [r.levelno for r in records] == [logging.ERROR]
        assert "SO_MARK" in records[0].getMessage()
    finally:
        listener.close()
        writer.close()


async def test_start_on_a_taken_port_raises_oserror() -> None:
    taken = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        taken.bind(("127.0.0.1", 0))
        taken.listen(1)
        listener = TCPListener()
        with pytest.raises(OSError):
            await listener.start("127.0.0.1", taken.getsockname()[1])
        listener.close()
    finally:
        taken.close()
