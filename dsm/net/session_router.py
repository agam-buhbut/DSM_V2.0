"""Where each packet goes when one server serves several clients
(multi-client spec §2.5, §2.9, §3.1, §3.2).

Nothing here opens a packet: only its session does, once.
"""

from __future__ import annotations

import asyncio
import enum
import ipaddress
from collections.abc import Callable

from dsm.net.session_slot import SESSION_QUEUE_PACKETS
from dsm.net.transport.udp import UDPTransport

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


class _SessionUDPView(UDPTransport):  # pyright: ignore[reportUnusedClass]
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

    def close(self) -> None:
        """Nothing: the run owns the socket."""

    async def aclose(self) -> None:
        """Nothing: the run owns the socket."""
