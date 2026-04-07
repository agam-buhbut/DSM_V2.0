"""Async TCP fallback transport with length-prefix framing.

Frame format: [length: 4 bytes big-endian][payload: length bytes]
"""

from __future__ import annotations

import asyncio
import logging
import struct

log = logging.getLogger(__name__)

MAX_FRAME_SIZE = 65536
LEN_PREFIX_SIZE = 4


class TCPTransport:
    """Non-blocking TCP transport with length-prefix framing."""

    def __init__(self) -> None:
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._server: asyncio.Server | None = None
        self._closed = False

    async def connect(self, host: str, port: int, timeout: float = 10.0) -> None:
        """Connect to a remote TCP endpoint."""
        self._reader, self._writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        log.debug("TCP connected to %s:%d", host, port)

    async def listen(
        self,
        host: str = "0.0.0.0",
        port: int = 0,
    ) -> int:
        """Listen for a single incoming connection. Returns actual port."""
        accepted: asyncio.Future[tuple[asyncio.StreamReader, asyncio.StreamWriter]] = (
            asyncio.get_running_loop().create_future()
        )

        async def on_connect(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            if not accepted.done():
                accepted.set_result((reader, writer))

        self._server = await asyncio.start_server(on_connect, host, port)
        actual_port = self._server.sockets[0].getsockname()[1]
        log.debug("TCP listening on %s:%d", host, actual_port)

        self._reader, self._writer = await accepted
        self._server.close()
        return actual_port

    async def send(self, data: bytes) -> None:
        """Send a length-prefixed frame."""
        if self._writer is None:
            raise RuntimeError("not connected")
        if len(data) > MAX_FRAME_SIZE:
            raise ValueError(f"frame too large: {len(data)}")
        frame = struct.pack("!I", len(data)) + data
        self._writer.write(frame)
        await self._writer.drain()

    async def recv(self, timeout: float | None = None) -> bytes:
        """Receive a length-prefixed frame."""
        if self._reader is None:
            raise RuntimeError("not connected")

        async def _read() -> bytes:
            reader = self._reader
            assert reader is not None
            len_buf = await reader.readexactly(LEN_PREFIX_SIZE)
            (length,) = struct.unpack("!I", len_buf)
            if length > MAX_FRAME_SIZE:
                raise ValueError(f"frame length {length} exceeds max {MAX_FRAME_SIZE}")
            if length == 0:
                return b""
            return await reader.readexactly(length)

        if timeout is not None:
            return await asyncio.wait_for(_read(), timeout)
        return await _read()

    def close(self) -> None:
        if self._writer and not self._closed:
            self._writer.close()
            self._closed = True
        if self._server:
            self._server.close()

    async def aclose(self) -> None:
        """Async close with proper TCP teardown."""
        if self._writer and not self._closed:
            self._writer.close()
            await self._writer.wait_closed()
            self._closed = True
        if self._server:
            self._server.close()

    @property
    def is_open(self) -> bool:
        return self._writer is not None and not self._closed
