"""Where each packet goes when one server serves several clients
(multi-client spec §2.5, §2.9, §3.1, §3.2).

Nothing here opens a packet: only its session does, once.
"""

from __future__ import annotations

import asyncio
import enum
import ipaddress
import logging
from collections.abc import Callable
from typing import assert_never

from dsm.core.log import RepeatLog
from dsm.net.session_slot import SESSION_QUEUE_PACKETS, ServerSession, SessionTable
from dsm.net.transport.udp import UDPTransport
from dsm.net.tunnel import TunDevice

log = logging.getLogger(__name__)

# The shortest IPv4 header.
_IPV4_HEADER_LEN = 20


class Verdict(enum.Enum):
    """What :func:`check_from_client` says about a client's packet."""

    OK = enum.auto()
    NOT_IPV4 = enum.auto()
    WRONG_SOURCE = enum.auto()
    TO_ANOTHER_CLIENT = enum.auto()


def check_from_client(
    packet: bytes, own: bytes, server: bytes, network: ipaddress.IPv4Network
) -> Verdict:
    """Whether a packet a client sent may go to the TUN (spec §3.1).

    ``own`` and ``server`` are 4 raw address bytes: the client's tunnel
    address and the server's. The key that opened the packet decides which
    inner source it may carry, so no client can send as another (cryptokey
    routing). A destination inside ``network`` other than the server is
    another client, the network address or the broadcast address:
    client-to-client traffic is blocked (spec §3.2). Inner IPv6 is dropped;
    clients send none. Never raises.
    """
    if len(packet) < _IPV4_HEADER_LEN or packet[0] >> 4 != 4:
        return Verdict.NOT_IPV4
    if packet[12:16] != own:
        return Verdict.WRONG_SOURCE
    destination = packet[16:20]
    if destination != server and ipaddress.IPv4Address(destination) in network:
        return Verdict.TO_ANOTHER_CLIENT
    return Verdict.OK


class _SessionUDPView(UDPTransport):
    """One session's packets from the run's UDP socket (spec §2.5).

    The dispatcher puts each packet whose header fits this session on its
    queue with :meth:`deliver`; the session's receive loop reads them with
    :meth:`recv`, with the real sender address, as it reads the socket
    today. :meth:`send` goes out on the run's socket to the address the
    session gives: its egress address, or a PATH_CHALLENGE's.

    Subclasses ``UDPTransport`` because the data path branches on
    ``isinstance(transport, UDPTransport)``. ``__init__`` skips the base
    initializer, as the acceptor's views do: only the methods below are
    called on a server session's transport.
    """

    def __init__(  # pylint: disable=super-init-not-called
        self, real: UDPTransport, others_drops: Callable[[], int]
    ) -> None:
        self._real = real
        # The dispatcher's count of packets no session fits. Junk shares the
        # socket, so it can cost any session packets, and the auto cap's
        # flood rule must see it.
        self._others_drops = others_drops
        self._queue: asyncio.Queue[tuple[bytes, tuple[str, int]]] = asyncio.Queue(
            maxsize=SESSION_QUEUE_PACKETS
        )
        self._drops = 0

    def deliver(self, data: bytes, addr: tuple[str, int]) -> bool:
        """Queue one packet for the session. False, and counted, when full."""
        try:
            self._queue.put_nowait((data, addr))
        except asyncio.QueueFull:
            self._drops += 1
            return False
        return True

    async def recv(self, timeout: float | None = None) -> tuple[bytes, tuple[str, int]]:
        if timeout is not None:
            return await asyncio.wait_for(self._queue.get(), timeout)
        return await self._queue.get()

    async def send(self, data: bytes, addr: tuple[str, int]) -> None:
        await self._real.send(data, addr)

    def recv_drops(self) -> int:
        """The socket's drops, the packets no session fits, and this queue's."""
        return self._real.recv_drops() + self._others_drops() + self._drops

    def too_big_drops(self) -> int:
        """The socket's; 0, as the server never sets DF."""
        return self._real.too_big_drops()

    def close(self) -> None:
        """Nothing: the run owns the socket."""

    async def aclose(self) -> None:
        """Nothing: the run owns the socket."""


class ClientTun(TunDevice):
    """One session's side of the shared TUN (spec §2.9).

    :meth:`read` takes the packets the router queued for this session.
    :meth:`awrite` checks every packet the session opened with
    :func:`check_from_client` and writes only allowed ones to the shared TUN;
    every DATA payload and every reassembled FRAGMENT passes here.

    Subclasses ``TunDevice`` so ``DataPathContext.tun`` keeps its type and
    ``dsm/session.py`` does not change; ``__init__`` skips the base
    initializer. Write errors are the shared TUN's: ``EAGAIN`` drops the
    packet there, and any other ``OSError`` goes up and ends this session.
    """

    def __init__(  # pylint: disable=super-init-not-called
        self, tun: TunDevice, session: ServerSession, network: ipaddress.IPv4Network
    ) -> None:
        self._tun = tun
        self._session = session
        self._network = network
        self._own = session.tunnel.client.packed
        self._server = session.tunnel.server.packed
        # Per session, at most one line per 10 s each: the CN, never an
        # address.
        self._wrong_source_log = RepeatLog(log, logging.WARNING)
        self._other_client_log = RepeatLog(log, logging.INFO)
        self._not_ipv4_log = RepeatLog(log, logging.DEBUG)

    async def read(self) -> bytes:
        return await self._session.tun_queue.get()

    async def awrite(self, data: bytes) -> int:
        """Write ``data`` to the shared TUN if this client may send it; 0 when
        it is dropped."""
        verdict = check_from_client(data, self._own, self._server, self._network)
        if verdict is Verdict.OK:
            return await self._tun.awrite(data)
        cn = self._session.client.cn
        if verdict is Verdict.WRONG_SOURCE:
            self._wrong_source_log.log(
                "dropped a packet from client_cn=%s whose source is not its "
                "tunnel address",
                cn,
            )
        elif verdict is Verdict.TO_ANOTHER_CLIENT:
            self._other_client_log.log(
                "dropped a packet from client_cn=%s to another client "
                "(client-to-client traffic is blocked)",
                cn,
            )
        elif verdict is Verdict.NOT_IPV4:
            self._not_ipv4_log.log(
                "dropped a packet from client_cn=%s that is not IPv4", cn
            )
        else:
            assert_never(verdict)
        return 0

    def set_mtu(self, mtu: int) -> None:
        """The server's TUN MTU is set once, at start; only the client runs
        the auto-MTU loop."""
        raise NotImplementedError("the server's TUN MTU is set once, at start")


class TunRouter:
    """The one reader of the shared TUN (spec §2.9): each packet goes to the
    session that owns its inner destination.

    It never waits for a session: a full queue drops the packet, like loss on
    the link, so one slow client cannot hold up another.
    """

    def __init__(
        self,
        tun: TunDevice,
        table: SessionTable,
        network: ipaddress.IPv4Network,
        server: ipaddress.IPv4Address,
    ) -> None:
        self._tun = tun
        self._table = table
        self._network = network
        self._server = server.packed
        self._not_ipv4_log = RepeatLog(log, logging.DEBUG)
        self._from_client_log = RepeatLog(log, logging.DEBUG)
        self._no_client_log = RepeatLog(log, logging.DEBUG)
        self._full_log = RepeatLog(log, logging.DEBUG)

    async def run(self) -> None:
        """Route packets until cancelled. An ``OSError`` from the TUN goes up:
        the server stops."""
        while True:
            self._route(await self._tun.read())

    def _route(self, packet: bytes) -> None:
        if len(packet) < _IPV4_HEADER_LEN or packet[0] >> 4 != 4:
            self._not_ipv4_log.log("dropped a TUN packet that is not IPv4")
            return
        source = packet[12:16]
        if source != self._server and ipaddress.IPv4Address(source) in self._network:
            # Only another client could be that source; each session's check
            # and the nft rule already stop it (spec §3.2). A third layer.
            self._from_client_log.log(
                "dropped a TUN packet from a client's tunnel address"
            )
            return
        session = self._table.by_tunnel(packet[16:20])
        if session is None:
            self._no_client_log.log("dropped a TUN packet for no client")
            return
        try:
            session.tun_queue.put_nowait(packet)
        except asyncio.QueueFull:
            session.tun_drops += 1
            self._full_log.log("dropped a TUN packet: its session's queue is full")


class UDPDispatcher:
    """The one reader of the server's UDP socket (spec §2.5).

    Each packet goes, unopened, to the first session whose header check
    passes: the holder of the sender's hint first, then every other live
    session. A packet no session fits is counted in :attr:`unmatched` and
    offered to the handshake acceptor. Only the session opens its packets,
    once, with today's ``decrypt_packet``; the header check changes nothing,
    and a packet never moves a hint.
    """

    def __init__(
        self,
        transport: UDPTransport,
        table: SessionTable,
        offer: Callable[[bytes, tuple[str, int]], None],
    ) -> None:
        self._transport = transport
        self._table = table
        self._offer = offer
        self._unmatched = 0
        self._full_log = RepeatLog(log, logging.DEBUG)
        self._no_view_log = RepeatLog(log, logging.ERROR)

    @property
    def unmatched(self) -> int:
        """Packets no session fitted, each offered to the acceptor."""
        return self._unmatched

    async def run(self) -> None:
        """Route packets until cancelled."""
        while True:
            data, addr = await self._transport.recv()
            self.route(data, addr)

    def route(self, data: bytes, addr: tuple[str, int]) -> None:
        """Give one packet to its session, or to the acceptor. Never raises."""
        hinted = self._table.by_peer(addr)
        if hinted is not None and hinted.session_keys.header_matches(data):
            self._deliver(hinted, data, addr)
            return
        for session in self._table.sessions():
            if session is not hinted and session.session_keys.header_matches(data):
                self._deliver(session, data, addr)
                return
        self._unmatched += 1
        self._offer(data, addr)

    def _deliver(
        self, session: ServerSession, data: bytes, addr: tuple[str, int]
    ) -> None:
        view = session.transport
        # Every session of a UDP run reads through its view, so anything else
        # is dropped (fail closed). A full view counts the drop itself.
        if not isinstance(view, _SessionUDPView):
            self._no_view_log.log(
                "dropped a UDP packet: session %d has no UDP view", session.number
            )
        elif not view.deliver(data, addr):
            self._full_log.log("dropped a UDP packet: its session's queue is full")
