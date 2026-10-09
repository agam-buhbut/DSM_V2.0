"""End to end on loopback: a client that comes back replaces its old session
(step R), and another client waits until the session ends.

Real handshakes, the real acceptor, slot, in-session accept, session
receive loop, shaper and scheduler; the TUN, the host managers and the DNS
proxy are fakes. Box only: needs the built tuncore (its Shaper) and the
soft attest backend.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator
from dataclasses import replace
from typing import Any
from unittest.mock import patch

import pytest

import tuncore
from dsm.core.protocol import (
    INNER_STRUCT,
    OUTER_HEADER_SIZE,
    SEQ_STRUCT,
    OuterPacket,
    PacketType,
)
from dsm.crypto import handshake
from dsm.crypto.cert_allowlist import CNAllowlist
from dsm.crypto.handshake import HandshakeError, client_handshake
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
SERVER_CN = "dsm-e2e-server"


class _Quiet:
    def __init__(self, *_a: Any, **_k: Any) -> None:
        pass

    def apply(self) -> None:
        pass

    def remove(self) -> None:
        pass


class _Tun:
    """Fake TUN: what the server writes goes to ``written``; it never yields
    a packet to send."""

    written: asyncio.Queue[bytes]

    def __init__(self, *_a: Any, **_k: Any) -> None:
        pass

    def open(self) -> None:
        pass

    def configure(self, *_a: Any, **_k: Any) -> None:
        pass

    def close(self) -> None:
        pass

    async def read(self) -> bytes:
        await asyncio.Event().wait()
        return b""

    async def awrite(self, data: bytes) -> None:
        _Tun.written.put_nowait(bytes(data))


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
    def __init__(self, allowed: set[str]) -> None:
        self.ca = make_test_ca()
        self.server = make_enrolled_device(
            self.ca, subject_cn=SERVER_CN, eku=SERVER_AUTH_OID
        )
        self.a = make_enrolled_device(self.ca, subject_cn=A_CN)
        self.b = make_enrolled_device(self.ca, subject_cn=B_CN)
        self.allowed = allowed
        self.captured: dict[str, asyncio.Event] = {}


@contextlib.asynccontextmanager
async def _server(world: _World) -> AsyncIterator[Addr]:
    """run_server on 127.0.0.1 with fake host state; yields its address."""
    _Tun.written = asyncio.Queue()
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
            return_value=CNAllowlist(cns=frozenset(world.allowed)),
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
) -> tuncore.SessionKeyManager:
    keys, _hash, _server_pub = await asyncio.wait_for(
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
    return keys


async def _connect_eventually(
    world: _World, device: EnrolledDevice, server: Addr
) -> tuple[tuncore.SessionKeyManager, UDPTransport]:
    """Connect as a client does after a refusal: try again, a new socket each
    time (a few useless attempts may still hold the shared loopback address)."""
    for _ in range(20):
        sock = await _socket()
        try:
            return await _connect(world, device, sock, server), sock
        except HandshakeError:
            await sock.aclose()
    raise AssertionError("the client never connected")


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
    nonce, ct, _epoch = keys.encrypt(plaintext, SEQ_STRUCT.pack(seq))
    outer = OuterPacket(seq=seq, nonce=bytes(nonce), ciphertext=bytes(ct))
    await sock.send(outer.serialize(OUTER_HEADER_SIZE + len(ct)), server)


async def _tun_gets(expected: bytes, timeout: float) -> None:
    assert await asyncio.wait_for(_Tun.written.get(), timeout) == expected


async def test_a_client_that_comes_back_replaces_its_old_session() -> None:
    world = _World({A_CN})
    async with _server(world) as server:
        first = await _socket()
        a_keys = await _connect(world, world.a, first, server)
        await _send(first, a_keys, server, 1, PacketType.DATA, b"from A")
        await _tun_gets(b"from A", 10.0)
        # A dies as by kill -9: its socket closes, no SESSION_CLOSE.
        await first.aclose()
        # A again (same identity, a new socket): the server ends the old
        # session at once, not after the 60 s dead-peer timer.
        again = await _socket()
        try:
            a2_keys = await _connect(world, world.a, again, server)
            await _send(again, a2_keys, server, 1, PacketType.DATA, b"from A again")
            await _tun_gets(b"from A again", 2.0)
        finally:
            await again.aclose()


async def test_another_client_waits_until_the_session_ends() -> None:
    world = _World({A_CN, B_CN})
    async with _server(world) as server:
        a_sock = await _socket()
        try:
            a_keys = await _connect(world, world.a, a_sock, server)
            await _send(a_sock, a_keys, server, 1, PacketType.DATA, b"from A")
            await _tun_gets(b"from A", 10.0)
            with (
                patch.object(handshake, "HANDSHAKE_TIMEOUT", 0.3),
                patch.object(handshake, "BACKOFF_BASE", 0.01),
            ):
                b_sock = await _socket()
                try:
                    # B gets msg2, then nothing: refused before the last frame.
                    with pytest.raises(HandshakeError):
                        await _connect(world, world.b, b_sock, server)
                finally:
                    await b_sock.aclose()
                # A's session is untouched.
                await _send(a_sock, a_keys, server, 2, PacketType.DATA, b"A still up")
                await _tun_gets(b"A still up", 5.0)
                # A says goodbye; then B gets in.
                await _send(a_sock, a_keys, server, 3, PacketType.SESSION_CLOSE)
                b_keys, b_sock = await _connect_eventually(world, world.b, server)
            try:
                await _send(b_sock, b_keys, server, 1, PacketType.DATA, b"from B")
                await _tun_gets(b"from B", 5.0)
            finally:
                await b_sock.aclose()
        finally:
            await a_sock.aclose()
