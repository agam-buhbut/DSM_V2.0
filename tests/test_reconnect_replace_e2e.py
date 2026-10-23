"""End to end on loopback: another client gets its own session at once, and
a client that comes back replaces only its own old session.

Real handshakes, the real acceptor, dispatcher, session table, router,
session receive loops, shaper and scheduler; the TUN, the host managers and
the DNS proxy are fakes. test_multi_client_e2e.py reuses this harness.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
from collections.abc import AsyncGenerator
from dataclasses import replace
from typing import Any
from unittest.mock import patch

import tuncore
from dsm.core.protocol import INNER_STRUCT, PacketType
from dsm.crypto.cert_allowlist import CNAllowlist
from dsm.crypto.handshake import client_handshake
from dsm.net._addresses import TunnelAssignment
from dsm.net.handshake_gate import SourceLimiter
from dsm.net.transport.udp import UDPTransport
from dsm.server import run_server
from tests.cert_helpers import (
    SERVER_AUTH_OID,
    EnrolledDevice,
    make_enrolled_device,
    make_test_ca,
)
from tests.test_handshake_acceptor_limits import _minutes
from tests.test_server_dns_fatal import _server_config

Addr = tuple[str, int]
A_CN = "dsm-e2e-a-client"
B_CN = "dsm-e2e-b-client"
C_CN = "dsm-e2e-c-client"
SERVER_CN = "dsm-e2e-server"
WAN = "93.184.216.34"  # an internet address


class _Quiet:
    applied = True  # the NAT table loads (MasqueradeManager.applied)

    def __init__(self, *_a: Any, **_k: Any) -> None:
        pass

    def apply(self) -> None:
        pass

    def remove(self) -> None:
        pass


class _Tun:
    """Fake shared TUN: what sessions write goes to ``written``; a packet put
    on ``incoming`` is read by the router, as if from the internet."""

    written: asyncio.Queue[bytes]
    incoming: asyncio.Queue[bytes]

    def __init__(self, *_a: Any, **_k: Any) -> None:
        pass

    def open(self) -> None:
        pass

    def configure(self, *_a: Any, **_k: Any) -> None:
        pass

    def close(self) -> None:
        pass

    async def read(self) -> bytes:
        return await _Tun.incoming.get()

    async def awrite(self, data: bytes) -> int:
        _Tun.written.put_nowait(bytes(data))
        return len(data)


class _Resolver:
    def __init__(self, *_a: Any, **_k: Any) -> None:
        pass

    async def close(self) -> None:
        pass


class _Dns:
    def __init__(self, *_a: Any, **_k: Any) -> None:
        pass

    async def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    def forget(self, client_ip: str) -> None:
        del client_ip


class _LoopbackUDP(UDPTransport):
    """The server's socket, on 127.0.0.1 and a free port."""

    bound: asyncio.Future[int]

    async def bind(
        self,
        local_addr: str = "0.0.0.0",
        local_port: int = 0,
        pmtu_discover: bool = False,
    ) -> int:
        del local_addr, local_port, pmtu_discover
        port = await super().bind("127.0.0.1", 0)
        _LoopbackUDP.bound.set_result(port)
        return port


class _Stores:
    """KeyStore / AttestStore stand-in holding the test server's keys."""

    identity: Any = None
    attest_key: Any = None

    def __init__(self, *_a: Any, **_k: Any) -> None:
        pass

    def unload(self) -> None:
        pass


class _Materials:
    def __init__(self, cert_der: bytes, ca_root: Any) -> None:
        self.cert_der = cert_der
        self.ca_root = ca_root
        self.crl = None


class _World:
    def __init__(self, allowed: list[str]) -> None:
        self.ca = make_test_ca()
        self.server = make_enrolled_device(
            self.ca, subject_cn=SERVER_CN, eku=SERVER_AUTH_OID
        )
        self.a = make_enrolled_device(self.ca, subject_cn=A_CN)
        self.b = make_enrolled_device(self.ca, subject_cn=B_CN)
        self.c = make_enrolled_device(self.ca, subject_cn=C_CN)
        # The allowlist file's order: the n-th name gets the n-th address.
        self.allowlist = CNAllowlist(cns=frozenset(allowed), order=tuple(allowed))
        self.captured: dict[str, asyncio.Event] = {}


@contextlib.asynccontextmanager
async def _server(world: _World) -> AsyncGenerator[Addr, None]:
    """run_server on 127.0.0.1 with fake host state; yields its address."""
    _Tun.written = asyncio.Queue()
    _Tun.incoming = asyncio.Queue()
    _LoopbackUDP.bound = asyncio.get_running_loop().create_future()
    _Stores.identity = world.server.identity
    _Stores.attest_key = world.server.attest_key

    def _capture(shutdown: asyncio.Event) -> None:
        world.captured["shutdown"] = shutdown

    patches = [
        patch("tuncore.harden_process"),
        patch("dsm.core.hardening.set_process_nondumpable"),
        patch("dsm.crypto.attest_gate.enforce_attest_backend_policy"),
        patch(
            "dsm.server.load_cert_materials",
            return_value=_Materials(world.server.cert_der, world.ca.certificate),
        ),
        patch("dsm.server.verify_cert_matches_identity"),
        patch(
            "dsm.server.CNAllowlist.from_file",
            return_value=world.allowlist,
        ),
        patch("dsm.crypto._stores.load_daemon_stores", return_value=True),
        patch("dsm.server.KeyStore", _Stores),
        patch("dsm.server.AttestStore", _Stores),
        patch("dsm.server.ServerRateLimitManager", _Quiet),
        patch("dsm.server.TcpTimestampsDisabler", _Quiet),
        patch("dsm.server.check_clock_sync", return_value=None),
        patch("dsm.server.IPForwardingManager", _Quiet),
        patch("dsm.server.MasqueradeManager", _Quiet),
        patch("dsm.server.TunDevice", _Tun),
        patch("dsm.server.DNSResolver", _Resolver),
        patch("dsm.server.LocalDNSProxy", _Dns),
        patch("dsm.server.UDPTransport", _LoopbackUDP),
        # Loopback clients all share 127.0.0.1: a clock that moves a minute
        # per reading keeps the per-address budgets out of this test's way.
        patch("dsm.server.SourceLimiter", lambda: SourceLimiter(clock=_minutes())),
        patch("dsm.server.setup_signal_handlers", _capture),
        patch("dsm.net.transport.udp.apply_so_mark", lambda sock: None),
    ]
    with contextlib.ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)
        run = asyncio.ensure_future(
            run_server(replace(_server_config(), dns_blocklist=False))
        )
        try:
            port = await asyncio.wait_for(_LoopbackUDP.bound, 10.0)
            yield ("127.0.0.1", port)
        finally:
            shutdown = world.captured.get("shutdown")
            if shutdown is not None:
                shutdown.set()
            rc = await asyncio.wait_for(run, 20.0)
            assert rc == 0, f"run_server returned {rc}"


async def _socket() -> UDPTransport:
    sock = UDPTransport()
    await sock.bind("127.0.0.1", 0)
    return sock


async def _connect(
    world: _World, device: EnrolledDevice, sock: UDPTransport, server: Addr
) -> tuple[tuncore.SessionKeyManager, TunnelAssignment]:
    keys, _hash, _server_pub, tunnel = await asyncio.wait_for(
        client_handshake(
            sock,
            device.identity,
            server,
            attest_key=device.attest_key,
            cert_der=device.cert_der,
            ca_root=world.ca.certificate,
            expected_server_cn=SERVER_CN,
        ),
        timeout=20.0,
    )
    return keys, tunnel


def _ipv4(src: str, dst: str, payload: bytes = b"") -> bytes:
    """An IPv4 packet: a 20-byte header (version, length, protocol and the
    two addresses, which is all the server reads) and ``payload``."""
    header = bytearray(20)
    header[0] = 0x45
    header[2:4] = (20 + len(payload)).to_bytes(2, "big")
    header[9] = 17  # UDP
    header[12:16] = ipaddress.IPv4Address(src).packed
    header[16:20] = ipaddress.IPv4Address(dst).packed
    return bytes(header) + payload


async def _send(
    sock: UDPTransport,
    keys: tuncore.SessionKeyManager,
    server: Addr,
    seq: int,
    ptype: int,
    payload: bytes = b"",
) -> None:
    plaintext = (
        INNER_STRUCT.pack(ptype, (keys.epoch & 0x0F) << 4, len(payload)) + payload
    )
    await sock.send(bytes(keys.seal_packet(seq, plaintext)), server)


async def _tun_gets(expected: bytes, timeout: float) -> None:
    assert await asyncio.wait_for(_Tun.written.get(), timeout) == expected


async def test_a_client_that_comes_back_replaces_only_its_own_session() -> None:
    world = _World([A_CN, B_CN])
    async with _server(world) as server:
        b_sock = await _socket()
        first = await _socket()
        again: UDPTransport | None = None
        try:
            b_keys, b_tunnel = await _connect(world, world.b, b_sock, server)
            a_keys, a_tunnel = await _connect(world, world.a, first, server)
            a_ip, b_ip = str(a_tunnel.client), str(b_tunnel.client)
            packet = _ipv4(a_ip, WAN, b"from A")
            await _send(first, a_keys, server, 1, PacketType.DATA, packet)
            await _tun_gets(packet, 10.0)
            # A dies as by kill -9: its socket closes, no SESSION_CLOSE.
            await first.aclose()
            # A again (same identity, a new socket) replaces its own old
            # session at once, not after the 60 s dead-peer timer, and keeps
            # its address.
            again = await _socket()
            a2_keys, a2_tunnel = await _connect(world, world.a, again, server)
            assert a2_tunnel == a_tunnel
            packet = _ipv4(a_ip, WAN, b"from A again")
            await _send(again, a2_keys, server, 1, PacketType.DATA, packet)
            await _tun_gets(packet, 2.0)
            # B's session was not touched.
            packet = _ipv4(b_ip, WAN, b"B still up")
            await _send(b_sock, b_keys, server, 1, PacketType.DATA, packet)
            await _tun_gets(packet, 5.0)
        finally:
            await first.aclose()
            if again is not None:
                await again.aclose()
            await b_sock.aclose()


async def test_another_client_gets_its_own_session_at_once() -> None:
    world = _World([A_CN, B_CN])
    async with _server(world) as server:
        a_sock, b_sock = await _socket(), await _socket()
        try:
            a_keys, a_tunnel = await _connect(world, world.a, a_sock, server)
            # The first try works: no refusal, no wait for A's session to end.
            b_keys, b_tunnel = await _connect(world, world.b, b_sock, server)
            assert (str(a_tunnel.client), str(b_tunnel.client)) == (
                "10.8.0.2",
                "10.8.0.3",
            )
            for sock, keys, tunnel, text in (
                (a_sock, a_keys, a_tunnel, b"from A"),
                (b_sock, b_keys, b_tunnel, b"from B"),
            ):
                packet = _ipv4(str(tunnel.client), WAN, text)
                await _send(sock, keys, server, 1, PacketType.DATA, packet)
                await _tun_gets(packet, 10.0)
        finally:
            await a_sock.aclose()
            await b_sock.aclose()
