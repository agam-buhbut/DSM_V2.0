"""Async TCP fallback transport with length-prefix framing.

Frame format: [length: 4 bytes big-endian][payload: length bytes]
"""

from __future__ import annotations

import asyncio
import logging
import struct

from dsm.core.log import RepeatLog
from dsm.net.transport._fwmark import apply_so_mark

log = logging.getLogger(__name__)

MAX_FRAME_SIZE = 65536
LEN_PREFIX_SIZE = 4
# The longest aclose waits for the peer to take the close.
CLOSE_TIMEOUT_S = 2.0


class FramingError(ValueError):
    """A TCP frame violates the wire format.

    Subclasses ValueError so existing ``except ValueError`` handlers still
    match.
    """


class TCPTransport:
    """Non-blocking TCP transport with length-prefix framing."""

    def __init__(self) -> None:
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._server: asyncio.Server | None = None
        self._closed = False

    @classmethod
    def from_streams(
        cls, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> TCPTransport:
        """Wrap one accepted connection. Marking its socket is the caller's job."""
        transport = cls()
        transport._reader = reader
        transport._writer = writer
        return transport

    async def connect(self, host: str, port: int, timeout: float = 10.0) -> None:
        """Connect to a remote TCP endpoint.

        The SO_MARK fwmark MUST be set BEFORE the initial SYN — otherwise
        an unmarked SYN can be routed through a stale TUN/ip-rule from a
        prior dsm run, leaking the connection attempt onto the wrong
        interface. asyncio.open_connection does the full 3-way handshake
        before returning, so we cannot mark the socket post-hoc; instead
        we create the socket, mark it, connect manually, then hand it to
        open_connection via the ``sock`` parameter. Mirrors the pattern
        used by ``dsm/net/dns.py:_open_pinned_tls_connection``.
        """
        import socket as socket_mod

        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(host, port, type=socket_mod.SOCK_STREAM)
        if not infos:
            raise OSError(f"no addrinfo for {host}:{port}")
        family, sock_type, proto, _canon, sockaddr = infos[0]

        sock = socket_mod.socket(family, sock_type, proto)
        try:
            sock.setblocking(False)
            apply_so_mark(sock)  # BEFORE connect — see docstring above.
            await asyncio.wait_for(
                loop.sock_connect(sock, sockaddr),
                timeout=timeout,
            )
        except BaseException:
            sock.close()
            raise

        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(sock=sock),
                timeout=timeout,
            )
        except BaseException:
            try:
                sock.close()
            except OSError:
                pass
            raise
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
        apply_so_mark(self._writer.get_extra_info("socket"))
        self._server.close()
        return actual_port

    async def send(self, data: bytes) -> None:
        if self._writer is None:
            raise RuntimeError("not connected")
        if len(data) > MAX_FRAME_SIZE:
            raise FramingError(f"frame too large: {len(data)}")
        frame = struct.pack("!I", len(data)) + data
        self._writer.write(frame)
        await self._writer.drain()

    async def recv(self, timeout: float | None = None) -> bytes:
        """Receive a length-prefixed frame.

        Raises ``ConnectionError`` on clean peer disconnect (EOF mid-frame).
        Callers' recv loops should treat this the same as shutdown — propagating
        IncompleteReadError directly would tear down the asyncio.gather without
        a clean log line.
        """
        if self._reader is None:
            raise RuntimeError("not connected")

        async def _read() -> bytes:
            reader = self._reader
            assert reader is not None
            try:
                len_buf = await reader.readexactly(LEN_PREFIX_SIZE)
                (length,) = struct.unpack("!I", len_buf)
                if length > MAX_FRAME_SIZE:
                    raise FramingError(
                        f"frame length {length} exceeds max {MAX_FRAME_SIZE}"
                    )
                # Reject zero-length frames. They have no meaning
                # in the DSM wire protocol (smallest legitimate frame is
                # OUTER_HEADER_SIZE + GCM_TAG_SIZE = 36 bytes for an
                # empty inner payload) and a peer spamming `\x00\x00\x00\x00`
                # would otherwise burn an event-loop iteration + a doomed
                # decrypt attempt per "frame", a small DoS amplifier.
                if length == 0:
                    raise ConnectionError(
                        "TCP peer sent zero-length frame — invalid DSM wire"
                    )
                return await reader.readexactly(length)
            except asyncio.IncompleteReadError as e:
                raise ConnectionError(
                    f"TCP peer closed mid-frame ({len(e.partial)} of "
                    f"{e.expected} bytes received)"
                ) from None

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
        """Close and await the writer's FIN handshake, at most CLOSE_TIMEOUT_S."""
        if self._writer and not self._closed:
            writer = self._writer
            self._closed = True
            writer.close()
            # A close must never hold up a retry or a stop: with a dead peer,
            # wait_closed waits for unsent data until the kernel's TCP
            # timeout (minutes). A peer that reset the connection is not an
            # error at close time. Either way, drop the connection and its
            # unsent data. (TimeoutError is an OSError.)
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=CLOSE_TIMEOUT_S)
            except OSError:
                writer.transport.abort()
        if self._server:
            self._server.close()


class TCPListener:
    """One listening socket that queues each accepted connection.

    Each connection becomes its own :class:`TCPTransport`, marked with
    SO_MARK as ``TCPTransport.listen`` does, and is put on ``connections``
    with its peer address for the caller to admit or close. The socket stays
    open until :meth:`close`, which also closes every connection still
    queued and any that arrives after it.
    """

    def __init__(self) -> None:
        self.connections: asyncio.Queue[tuple[TCPTransport, tuple[str, int]]] = (
            asyncio.Queue()
        )
        self._server: asyncio.Server | None = None
        self._closed = False
        self._mark_errors = RepeatLog(log, logging.ERROR)

    async def start(self, host: str = "0.0.0.0", port: int = 0) -> int:
        """Open the listening socket and return the bound port.

        Raises:
            OSError: the socket could not be opened (for example, the port
                is in use).
        """
        self._server = await asyncio.start_server(self._on_connect, host, port)
        bound: int = self._server.sockets[0].getsockname()[1]
        log.debug("TCP listening on %s:%d", host, bound)
        return bound

    def _on_connect(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        # A plain callback, not a coroutine: admitting the connection is the
        # caller's job, so asyncio makes no task for it here.
        peer = writer.get_extra_info("peername")
        if self._closed or not peer:
            # Arrived after close(), or the peer is already gone.
            writer.close()
            return
        try:
            apply_so_mark(writer.get_extra_info("socket"))
        except OSError:
            # Unmarked, the session's packets could loop into the tunnel.
            self._mark_errors.log(
                "cannot mark an accepted TCP connection (SO_MARK); closed it",
                exc_info=True,
            )
            writer.close()
            return
        self.connections.put_nowait(
            (TCPTransport.from_streams(reader, writer), (str(peer[0]), int(peer[1])))
        )

    def close(self) -> None:
        """Stop listening and close every connection still queued."""
        self._closed = True
        if self._server is not None:
            # No wait_closed(): from Python 3.12 it also waits for every
            # accepted connection, the winning session's included.
            self._server.close()
        while not self.connections.empty():
            conn, _ = self.connections.get_nowait()
            conn.close()
