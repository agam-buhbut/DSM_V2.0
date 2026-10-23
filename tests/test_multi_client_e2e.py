"""End to end on loopback with several clients (multi-client spec §8.2):
real handshakes, the real acceptor, dispatcher, session table, router and
data loops; the TUN, the host managers and the DNS proxy are fakes (the
harness of test_reconnect_replace_e2e.py). Each client gets the address of
its allowlist line; no client can send as another or to another; a TUN
packet reaches only its client; a third client gets in while the others run;
a stop sends every client a SESSION_CLOSE.
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import tuncore
from dsm.core.protocol import INNER_STRUCT, PacketType
from dsm.net.transport.udp import UDPTransport
from tests.test_reconnect_replace_e2e import (
    A_CN,
    B_CN,
    C_CN,
    WAN,
    _connect,
    _ipv4,
    _send,
    _server,
    _socket,
    _Tun,
    _tun_gets,
    _World,
)


def _inner(wire: bytes, keys: tuncore.SessionKeyManager) -> tuple[int, bytes] | None:
    """The type and payload of a packet that opens under ``keys``, else None."""
    opened = keys.open_packet(wire)
    if opened is None:
        return None
    plaintext = opened[1]
    ptype, _flags, length = INNER_STRUCT.unpack_from(plaintext)
    return ptype, plaintext[INNER_STRUCT.size : INNER_STRUCT.size + length]


def _data_in(sock: UDPTransport, keys: tuncore.SessionKeyManager) -> list[bytes]:
    """The DATA payloads already queued on ``sock`` that open under ``keys``
    (chaff and other types are skipped). Does not wait."""
    found: list[bytes] = []
    while not sock._recv_queue.empty():
        wire, _addr = sock._recv_queue.get_nowait()
        inner = _inner(wire, keys)
        if inner is not None and inner[0] == PacketType.DATA:
            found.append(inner[1])
    return found


async def _receives(
    sock: UDPTransport,
    keys: tuncore.SessionKeyManager,
    ptype: int,
    timeout: float,
    payload: bytes | None = None,
) -> None:
    """Read ``sock`` until a packet of ``ptype`` (with ``payload``, when
    given) opens under ``keys``; a TimeoutError after ``timeout`` s."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        wire, _addr = await asyncio.wait_for(sock.recv(), deadline - loop.time())
        inner = _inner(wire, keys)
        if inner is not None and inner[0] == ptype:
            if payload is None or inner[1] == payload:
                return


async def _first_data(
    sock: UDPTransport, keys: tuncore.SessionKeyManager, timeout: float
) -> bytes:
    """The first DATA payload that reaches ``sock`` and opens under ``keys``;
    a TimeoutError after ``timeout`` s."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        wire, _addr = await asyncio.wait_for(sock.recv(), deadline - loop.time())
        inner = _inner(wire, keys)
        if inner is not None and inner[0] == PacketType.DATA:
            return inner[1]


async def test_each_client_gets_the_address_of_its_allowlist_line() -> None:
    world = _World([B_CN, A_CN, C_CN])  # the file lists B first
    async with _server(world) as server:
        socks: list[UDPTransport] = []
        try:
            for device, expected in (
                (world.a, "10.8.0.3"),
                (world.b, "10.8.0.2"),
                (world.c, "10.8.0.4"),
            ):
                sock = await _socket()
                socks.append(sock)
                keys, tunnel = await _connect(world, device, sock, server)
                assert str(tunnel.client) == expected
                packet = _ipv4(expected, WAN, expected.encode())
                await _send(sock, keys, server, 1, PacketType.DATA, packet)
                await _tun_gets(packet, 10.0)
        finally:
            for sock in socks:
                await sock.aclose()


async def test_a_client_cannot_send_as_another_or_to_another() -> None:
    world = _World([A_CN, B_CN])
    async with _server(world) as server:
        a_sock, b_sock = await _socket(), await _socket()
        try:
            a_keys, a_tunnel = await _connect(world, world.a, a_sock, server)
            _b_keys, b_tunnel = await _connect(world, world.b, b_sock, server)
            a_ip, b_ip = str(a_tunnel.client), str(b_tunnel.client)
            as_b = _ipv4(b_ip, WAN, b"as B")
            to_b = _ipv4(a_ip, b_ip, b"to B")
            fine = _ipv4(a_ip, WAN, b"fine")
            for seq, packet in enumerate((as_b, to_b, fine), start=1):
                await _send(a_sock, a_keys, server, seq, PacketType.DATA, packet)
            # The first packet the TUN gets is the good one: the other two
            # were dropped before it.
            await _tun_gets(fine, 10.0)
            assert _Tun.written.empty()
        finally:
            await a_sock.aclose()
            await b_sock.aclose()


async def test_a_tun_packet_for_b_reaches_only_b() -> None:
    world = _World([A_CN, B_CN])
    async with _server(world) as server:
        a_sock, b_sock = await _socket(), await _socket()
        try:
            a_keys, a_tunnel = await _connect(world, world.a, a_sock, server)
            b_keys, b_tunnel = await _connect(world, world.b, b_sock, server)
            packet = _ipv4(WAN, str(b_tunnel.client), b"for B")
            _Tun.incoming.put_nowait(packet)
            # B never sent a data packet: its session sends to its handshake
            # address from the start.
            await _receives(b_sock, b_keys, PacketType.DATA, 10.0, payload=packet)
            assert packet not in _data_in(a_sock, a_keys)
            # A session sends in order: a copy of B's packet queued for A
            # would reach A before this one.
            for_a = _ipv4(WAN, str(a_tunnel.client), b"for A")
            _Tun.incoming.put_nowait(for_a)
            assert await _first_data(a_sock, a_keys, 10.0) == for_a
        finally:
            await a_sock.aclose()
            await b_sock.aclose()


async def test_a_third_client_gets_in_while_a_takeover_and_b_run() -> None:
    world = _World([A_CN, B_CN, C_CN])
    async with _server(world) as server:
        first, b_sock = await _socket(), await _socket()
        again: UDPTransport | None = None
        c_sock: UDPTransport | None = None
        try:
            await _connect(world, world.a, first, server)
            b_keys, b_tunnel = await _connect(world, world.b, b_sock, server)
            await first.aclose()  # A dies
            again = await _socket()
            _a2_keys, a2_tunnel = await _connect(world, world.a, again, server)
            assert str(a2_tunnel.client) == "10.8.0.2"
            c_sock = await _socket()
            c_keys, c_tunnel = await _connect(world, world.c, c_sock, server)
            assert str(c_tunnel.client) == "10.8.0.4"
            for sock, keys, tunnel, text in (
                (c_sock, c_keys, c_tunnel, b"from C"),
                (b_sock, b_keys, b_tunnel, b"B still up"),
            ):
                packet = _ipv4(str(tunnel.client), WAN, text)
                await _send(sock, keys, server, 1, PacketType.DATA, packet)
                await _tun_gets(packet, 10.0)
        finally:
            await first.aclose()
            for sock in (again, c_sock):
                if sock is not None:
                    await sock.aclose()
            await b_sock.aclose()


async def test_a_stop_sends_every_client_a_session_close() -> None:
    world = _World([A_CN, B_CN])
    # The sockets outlive the server, so they can hear its goodbye.
    # _server patches SO_MARK (needs a capability) only while it runs.
    with patch("dsm.net.transport.udp.apply_so_mark", lambda sock: None):
        a_sock, b_sock = await _socket(), await _socket()
    try:
        async with _server(world) as server:
            a_keys, _a_tunnel = await _connect(world, world.a, a_sock, server)
            b_keys, _b_tunnel = await _connect(world, world.b, b_sock, server)
        # run_server has returned (exit 0): each session said goodbye on the
        # way out, before the host state went (spec §2.2).
        await _receives(a_sock, a_keys, PacketType.SESSION_CLOSE, 5.0)
        await _receives(b_sock, b_keys, PacketType.SESSION_CLOSE, 5.0)
    finally:
        await a_sock.aclose()
        await b_sock.aclose()
