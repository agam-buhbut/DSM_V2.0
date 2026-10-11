"""The real client over TCP through the gated TCP accept (wire v2).

Loopback sockets, the ``TCPListener``, ``_accept_until_winner_tcp`` with a
``HandshakeGate`` made from the test CA and the server's name,
``server_handshake`` and ``client_handshake`` are all real; only the config,
key store and certificate holders are small stand-ins. The other TCP gate
tests script the handshake (test_handshake_gate_acceptor.py) or pass no gate
(test_handshake_admit_hook.py).

TCP asks for no cookies, so these tests need no XChaCha: they run on the old
wheel with the shim as well as in CI. Nothing waits on the wall clock; the
timeouts only turn a hang into a failure.
"""

from __future__ import annotations

import asyncio
import contextlib
import random
import time
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

from dsm.crypto import handshake
from dsm.crypto.cert_allowlist import CNAllowlist
from dsm.crypto.handshake import HANDSHAKE_FRAME_SIZE, client_handshake
from dsm.net import handshake_acceptor as hsa
from dsm.net._addresses import SINGLE_CLIENT_TUNNEL
from dsm.net.handshake_gate import (
    GateKeys,
    HandshakeGate,
    SourceLimiter,
    compute_mac1,
    stamp_msg1,
)
from dsm.net.transport.tcp import TCPListener, TCPTransport
from tests.test_handshake_admit_hook import CLIENT_CN, SERVER_CN, _Parties
from tests.test_tcp_accept_concurrency import _Config


@pytest.fixture(autouse=True)
def _no_so_mark() -> Iterator[None]:
    with (
        patch("dsm.net.transport.udp.apply_so_mark", lambda sock: None),
        patch("dsm.net.transport.tcp.apply_so_mark", lambda sock: None),
    ):
        yield


@dataclass
class _Server:
    port: int
    accept: asyncio.Future[Any]


@contextlib.asynccontextmanager
async def _gated_tcp_server(p: _Parties, gate: HandshakeGate) -> AsyncIterator[_Server]:
    """A loopback listener feeding the real gated TCP accept; the accept is
    stopped and the listener closed on the way out."""
    keystore: Any = SimpleNamespace(identity=p.server.identity)
    attest_store: Any = SimpleNamespace(attest_key=p.server.attest_key)
    materials: Any = SimpleNamespace(
        cert_der=p.server.cert_der, ca_root=p.ca.certificate, crl=None
    )
    listener = TCPListener()
    port = await listener.start("127.0.0.1", 0)
    shutdown = asyncio.Event()
    accept = asyncio.ensure_future(
        hsa._accept_until_winner_tcp(
            _Config(8),
            keystore,
            attest_store,
            materials,
            CNAllowlist(cns=frozenset({CLIENT_CN})),
            listener.connections,
            shutdown,
            SourceLimiter(),
            gate=gate,
        )
    )
    try:
        yield _Server(port, accept)
    finally:
        shutdown.set()
        try:
            _keys, _pub, transport = await asyncio.wait_for(accept, 5.0)
            if transport is not None:
                transport.close()
        finally:
            listener.close()


def _gate(p: _Parties) -> HandshakeGate:
    return HandshakeGate(GateKeys.derive(p.ca.certificate, SERVER_CN))


async def test_the_client_connects_over_tcp_through_the_gated_accept() -> None:
    p = _Parties()
    gate = _gate(p)
    # Under load a UDP server asks for a cookie first. TCP never does, so the
    # real client, which only reads cookie replies over UDP, must still get in.
    gate.load.note_trouble()
    assert gate.load.under_load(0)
    client_t: Any = TCPTransport()
    received: list[bytes] = []
    real_recv = client_t.recv

    async def _recv(*args: Any, **kwargs: Any) -> bytes:
        data = await real_recv(*args, **kwargs)
        received.append(data)
        return data

    client_t.recv = _recv
    async with _gated_tcp_server(p, gate) as server:
        try:
            await client_t.connect("127.0.0.1", server.port)
            client_res, accepted = await asyncio.wait_for(
                asyncio.gather(
                    client_handshake(
                        client_t,
                        p.client.identity,
                        ("127.0.0.1", server.port),
                        attest_key=p.client.attest_key,
                        cert_der=p.client.cert_der,
                        ca_root=p.ca.certificate,
                        expected_server_cn=SERVER_CN,
                    ),
                    server.accept,
                ),
                timeout=30.0,
            )
        finally:
            await client_t.aclose()
    _client_keys, _hash, _server_pub, tunnel = client_res
    server_keys, client_pub, server_side = accepted
    assert tunnel == SINGLE_CLIENT_TUNNEL
    assert server_keys is not None
    assert client_pub == bytes(p.client.identity.public_key)
    assert server_side is not None
    # msg2 and the bootstrap reply, nothing else: no cookie reply.
    assert [len(frame) for frame in received] == [HANDSHAKE_FRAME_SIZE] * 2


def _bad_frame(kind: str, p: _Parties) -> bytes:
    """A 1400-byte first frame whose mac1 does not fit the gate of ``p``'s
    server."""
    frame = bytearray(random.Random(kind).randbytes(HANDSHAKE_FRAME_SIZE))
    if kind != "random":
        keys, now = GateKeys.derive(p.ca.certificate, SERVER_CN), time.time()
        if kind == "other CA":
            keys = GateKeys.from_ca_der(b"another CA", SERVER_CN)
        elif kind == "other CN":
            keys = GateKeys.derive(p.ca.certificate, "another-server")
        else:  # "old clock": two whole windows (10 minutes) back
            now -= 600
        stamp_msg1(frame, compute_mac1(bytes(frame[:32]), keys, now))
    return bytes(frame)


@pytest.mark.parametrize("kind", ["random", "other CA", "other CN", "old clock"])
async def test_a_tcp_first_frame_with_a_bad_mac1_is_closed_before_any_work(
    kind: str,
) -> None:
    p = _Parties()
    gate = _gate(p)
    calls: list[tuple[Any, ...]] = []
    real: Any = handshake.server_handshake

    async def _spy(*args: Any, **kwargs: Any) -> Any:
        calls.append(args)
        return await real(*args, **kwargs)  # pylint: disable=missing-kwoa

    client_t = TCPTransport()
    with (
        patch("dsm.crypto.handshake.server_handshake", new=_spy),
        patch("dsm.crypto.handshake.build_attest_payload") as sign,
    ):
        async with _gated_tcp_server(p, gate) as server:
            try:
                await client_t.connect("127.0.0.1", server.port)
                await client_t.send(_bad_frame(kind, p))
                # A reply would come back as a frame; a close raises.
                with pytest.raises(ConnectionError):
                    await client_t.recv(timeout=5.0)
            finally:
                await client_t.aclose()
            assert not server.accept.done()
    assert not calls
    sign.assert_not_called()
    # A bad mac1 is scanner noise, not trouble: it must not turn cookies on.
    assert not gate.load.under_load(0)
