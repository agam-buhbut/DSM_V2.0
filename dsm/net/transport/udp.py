"""Async UDP transport using asyncio DatagramProtocol."""

from __future__ import annotations

import asyncio
import logging

from dsm.net.transport._fwmark import apply_so_mark

log = logging.getLogger(__name__)

# Maximum UDP payload (Ethernet MTU - IP header - UDP header)
MAX_DATAGRAM = 1472


class UDPTransport:
    """Non-blocking UDP send/receive."""

    def __init__(self) -> None:
        self._transport: asyncio.DatagramTransport | None = None
        self._protocol: _UDPProtocol | None = None
        self._recv_queue: asyncio.Queue[tuple[bytes, tuple[str, int]]] = asyncio.Queue(maxsize=1024)
        self._closed = False

    async def bind(self, local_addr: str = "0.0.0.0", local_port: int = 0) -> int:
        """Bind to a local address. Returns the actual bound port."""
        loop = asyncio.get_running_loop()
        protocol = _UDPProtocol(self._recv_queue)
        self._protocol = protocol
        transport, _ = await loop.create_datagram_endpoint(
            lambda: protocol,
            local_addr=(local_addr, local_port),
        )
        apply_so_mark(transport.get_extra_info("socket"))
        self._transport = transport
        actual_port = transport.get_extra_info("sockname")[1]
        log.debug("UDP bound to %s:%d", local_addr, actual_port)
        return actual_port

    async def send(self, data: bytes, addr: tuple[str, int]) -> None:
        """Send a datagram to the specified address."""
        if self._transport is None:
            raise RuntimeError("transport not bound")
        if len(data) > MAX_DATAGRAM:
            raise ValueError(f"datagram too large: {len(data)} > {MAX_DATAGRAM}")
        self._transport.sendto(data, addr)

    async def recv(self, timeout: float | None = None) -> tuple[bytes, tuple[str, int]]:
        """Receive a datagram. Returns (data, (host, port))."""
        if timeout is not None:
            return await asyncio.wait_for(self._recv_queue.get(), timeout)
        return await self._recv_queue.get()

    def close(self) -> None:
        if self._transport and not self._closed:
            self._transport.close()
            self._closed = True

    async def aclose(self) -> None:
        """Async close (UDP has no pending writes, delegates to sync close)."""
        self.close()

    @property
    def is_open(self) -> bool:
        return self._transport is not None and not self._closed


class _UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, queue: asyncio.Queue[tuple[bytes, tuple[str, int]]]) -> None:
        self._queue = queue

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            self._queue.put_nowait((data, addr))
        except asyncio.QueueFull:
            log.warning("recv queue full, dropping packet from %s", addr)

    def error_received(self, exc: Exception) -> None:
        log.error("UDP error: %s", exc)

    def connection_lost(self, exc: Exception | None) -> None:
        if exc:
            log.error("UDP connection lost: %s", exc)
