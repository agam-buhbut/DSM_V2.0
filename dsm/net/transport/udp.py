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

# Linux IP_MTU_DISCOVER values (from <linux/in.h>). CPython's `socket` module
# does not export these on any platform, so they are spelled out here.
_IP_MTU_DISCOVER = getattr(socket, "IP_MTU_DISCOVER", 10)
_IP_PMTUDISC_DO = getattr(socket, "IP_PMTUDISC_DO", 2)  # DF set, hard error
_IP_MTU = getattr(socket, "IP_MTU", 14)


class UDPTransport:
    """Non-blocking UDP send/receive."""

    def __init__(self) -> None:
        self._transport: asyncio.DatagramTransport | None = None
        self._recv_queue: asyncio.Queue[tuple[bytes, tuple[str, int]]] = asyncio.Queue(
            maxsize=RECV_QUEUE_SIZE,
        )
        self._closed = False
        # True if bind() enabled kernel PMTUD (IP_PMTUDISC_DO). Consulted
        # by `get_path_mtu()`.
        self._pmtu_enabled = False
        # Serialize send() vs rebind_to_fresh_port() so a
        # concurrent rebind cannot race the chaff/scheduler sendto.
        # Uncontended on the steady-state path.
        self._send_lock: asyncio.Lock = asyncio.Lock()
        # Track deferred-close TimerHandles so close()/aclose()
        # can cancel them and close any pending old transports
        # synchronously. Without this, a shutdown during the 250ms
        # post-rebind window leaves the old transport alive until the
        # timer fires — kernel cleans it up eventually but the queued
        # close() callback also dereferences a closed transport.
        self._deferred_closes: list[
            tuple[asyncio.TimerHandle, asyncio.DatagramTransport]
        ] = []

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
        """Send a datagram to the specified address.

        Takes the swap-lock so a concurrent
        `rebind_to_fresh_port()` (called from `_handle_rekey_ack` in
        the recv-loop) cannot replace `self._transport` between the
        ``is None`` check and the ``sendto`` — which would race the
        chaff scheduler / send_packet and land sendto on a closed
        transport. asyncio.Lock is uncontended on the steady-state
        path (rebind fires once per rekey, ~600s).
        """
        async with self._send_lock:
            if self._transport is None:
                raise RuntimeError("transport not bound")
            if len(data) > MAX_DATAGRAM:
                raise ValueError(f"datagram too large: {len(data)} > {MAX_DATAGRAM}")
            self._transport.sendto(data, addr)

    async def rebind_to_fresh_port(self) -> int:
        """Rebind to a fresh ephemeral source port.

        Closes the current socket and binds a new one with kernel-picked
        ephemeral port + the same options (SO_MARK, PMTUD). The
        ``_recv_queue`` is preserved across the swap, so the recv loop continues —
        packets that arrive on the OLD socket
        between the close and the next sock arrival are dropped (a
        protocol-level ACK or retransmit deals with any loss).

        Returns the new bound port. Caller (e.g., rekey completion
        hook) typically discards the return value but it is useful for
        logging / observability.

        SAFETY: only call from a context where no concurrent send is
        in flight (the data-path scheduler tick is single-threaded so
        this holds for the typical caller).
        """
        if self._transport is None:
            raise RuntimeError("transport not bound; cannot rebind")
        loop = asyncio.get_running_loop()
        old_transport = self._transport
        # Capture old bind addr so we keep listening on the same local
        # interface (just on a different ephemeral port).
        old_sock = old_transport.get_extra_info("socket")
        old_addr = old_sock.getsockname() if old_sock else ("0.0.0.0", 0)
        local_addr = old_addr[0]

        new_protocol = _UDPProtocol(self._recv_queue)
        new_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        new_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        new_sock.setblocking(False)
        try:
            new_sock.bind((local_addr, 0))  # 0 = kernel picks
        except OSError:
            new_sock.close()
            raise
        new_transport, _ = await loop.create_datagram_endpoint(
            lambda: new_protocol,
            sock=new_sock,
        )
        new_sock = new_transport.get_extra_info("socket")
        apply_so_mark(new_sock)
        if self._pmtu_enabled and new_sock is not None:
            try:
                new_sock.setsockopt(
                    socket.IPPROTO_IP, _IP_MTU_DISCOVER, _IP_PMTUDISC_DO
                )
            except OSError as e:
                log.warning("failed to re-enable PMTUD on rebind: %s", e)

        # Atomic swap. Take the send lock so a concurrent send sees
        # either the OLD transport (pre-swap) or the NEW (post-swap)
        # but never an in-flight half-state.
        async with self._send_lock:
            self._transport = new_transport
        new_port = new_transport.get_extra_info("sockname")[1]

        # Don't immediately close the old transport
        # — server replies to the OLD src addr that are already in flight
        # (sent before the server's `post_authenticate` saw the NEW addr)
        # would otherwise be dropped at kernel ICMP-port-unreachable.
        # Defer the close ~250ms so the old socket keeps accepting
        # inbound until the server learns the new addr from our first
        # post-rebind packet. Both old and new protocols feed the SAME
        # `self._recv_queue`, so deferred-old packets still arrive.
        # Track the handle + transport so shutdown can
        # cancel/close cleanly without leaving an orphan callback.
        # Register the deferred close WITHIN the
        # send_lock context above (we re-take it briefly here) so
        # `close()` running concurrently sees the new entry before tearing down.
        async with self._send_lock:
            if self._closed:
                old_transport.close()
                log.info("UDP rebind raced with close(); old transport closed sync")
                return new_port
            handle = loop.call_later(0.25, old_transport.close)
            self._deferred_closes.append((handle, old_transport))
        log.info("UDP rebound to fresh ephemeral port %d", new_port)
        return new_port

    async def recv(self, timeout: float | None = None) -> tuple[bytes, tuple[str, int]]:
        if timeout is not None:
            return await asyncio.wait_for(self._recv_queue.get(), timeout)
        return await self._recv_queue.get()

    def close(self) -> None:
        # Drain pending deferred-close handles before tearing
        # down the current transport. Cancel each timer (if it hasn't
        # fired yet) and close the old transport synchronously so the
        # process doesn't leave behind orphan sockets on shutdown.
        # Mark _closed FIRST so any concurrent
        # rebind_to_fresh_port() coroutine resuming after this point
        # observes the closed state and skips registering new deferred
        # handles (it closes its old transport synchronously instead).
        self._closed = True
        for handle, old_transport in self._deferred_closes:
            handle.cancel()
            old_transport.close()
        self._deferred_closes.clear()
        if self._transport:
            self._transport.close()

    async def aclose(self) -> None:
        """Async close (UDP has no pending writes, delegates to sync close)."""
        self.close()


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
