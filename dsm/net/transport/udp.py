"""Async UDP transport using asyncio DatagramProtocol."""

from __future__ import annotations

import asyncio
import logging
import socket

from dsm.net.transport._fwmark import apply_so_mark

log = logging.getLogger(__name__)

# Maximum UDP payload (Ethernet MTU - IP header - UDP header)
MAX_DATAGRAM = 1472
# Bounded recv queue. Sized for low-RAM targets: 256 * ~1500B ≈ 384 KiB
# worst-case. Overflow drops at the kernel→protocol boundary, never at
# the user-packet boundary, so anonymity is unchanged (attacker cannot
# distinguish a drop from loss on the link).
RECV_QUEUE_SIZE = 256

# Linux IP_MTU_DISCOVER values (from <linux/in.h>). Kept here to avoid a
# runtime `socket` import-failure on non-Linux platforms where the
# constants don't exist; actual use is still gated by a hasattr check.
_IP_MTU_DISCOVER = getattr(socket, "IP_MTU_DISCOVER", 10)
_IP_PMTUDISC_DO = getattr(socket, "IP_PMTUDISC_DO", 2)  # DF bit set, hard error on oversize
_IP_MTU = getattr(socket, "IP_MTU", 14)


class UDPTransport:
    """Non-blocking UDP send/receive."""

    def __init__(self) -> None:
        self._transport: asyncio.DatagramTransport | None = None
        self._protocol: _UDPProtocol | None = None
        self._recv_queue: asyncio.Queue[tuple[bytes, tuple[str, int]]] = asyncio.Queue(
            maxsize=RECV_QUEUE_SIZE,
        )
        self._closed = False
        # True if bind() enabled kernel PMTUD (IP_PMTUDISC_DO). Consulted
        # by `get_path_mtu()`.
        self._pmtu_enabled = False

    async def bind(
        self,
        local_addr: str = "0.0.0.0",
        local_port: int = 0,
        pmtu_discover: bool = False,
    ) -> int:
        """Bind to a local address. Returns the actual bound port.

        ``pmtu_discover``: if True, enable kernel-level Path MTU Discovery
        on the socket. The kernel will set the DF bit on outbound
        datagrams and track the discovered path MTU (queryable via
        ``get_path_mtu()``). Only effective on Linux.
        """
        loop = asyncio.get_running_loop()
        protocol = _UDPProtocol(self._recv_queue)
        self._protocol = protocol
        # Pre-create the socket so we can set SO_REUSEADDR before bind.
        # Without this a fast restart on a fixed listen_port races the
        # kernel's TIME_WAIT cleanup and bind fails with EADDRINUSE —
        # painful enough during dev iteration that it's the default.
        # SO_REUSEPORT is intentionally NOT set: it would let two
        # instances bind the same port silently.
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setblocking(False)
        try:
            sock.bind((local_addr, local_port))
        except OSError:
            sock.close()
            raise
        transport, _ = await loop.create_datagram_endpoint(
            lambda: protocol,
            sock=sock,
        )
        sock = transport.get_extra_info("socket")
        apply_so_mark(sock)
        if pmtu_discover and sock is not None:
            try:
                sock.setsockopt(socket.IPPROTO_IP, _IP_MTU_DISCOVER, _IP_PMTUDISC_DO)
                self._pmtu_enabled = True
                log.debug("UDP PMTUD enabled (IP_PMTUDISC_DO)")
            except OSError as e:
                log.warning("failed to enable PMTUD on UDP socket: %s", e)
        self._transport = transport
        actual_port = transport.get_extra_info("sockname")[1]
        log.debug("UDP bound to %s:%d", local_addr, actual_port)
        return actual_port

    def get_path_mtu(self) -> int | None:
        """Query the kernel's current Path MTU for this socket.

        Returns ``None`` if PMTUD was not enabled, the socket isn't open,
        or the kernel doesn't have a PMTU estimate yet (no packets sent
        or no ICMP replies received). The returned value is the raw
        IP_MTU — VPN wire-level overhead (IP+UDP+outer header+GCM tag)
        must still be subtracted to get the usable inner payload budget.
        """
        if self._transport is None or not self._pmtu_enabled:
            return None
        sock = self._transport.get_extra_info("socket")
        if sock is None:
            return None
        try:
            return sock.getsockopt(socket.IPPROTO_IP, _IP_MTU)
        except OSError:
            return None

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
