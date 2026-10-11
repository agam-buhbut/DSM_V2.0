"""The client's side of the handshake gate (wire v2, spec §7.5; T10 §3.16
tests 17-18): it stamps msg1, answers a cookie reply at once with the same e
and a valid mac2, keeps the latest mac2 for its timer resends, gives up after
two cookie replies, and reads a frame that is not a cookie reply as msg2.
Real client_handshake over loopback UDP, against the real acceptor or a
scripted server. Laptop: no (old wheel and shim). Every test here sends or
opens a cookie reply, and the client tries each frame as one, so all of them
need tuncore's xchacha_seal and xchacha_open from the Task 5 wheel and run in
CI.
"""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine, Iterator
from typing import Any
from unittest.mock import patch

import pytest

from dsm.crypto import handshake
from dsm.crypto.cert_allowlist import CNAllowlist
from dsm.crypto.handshake import HANDSHAKE_FRAME_SIZE, HandshakeError, client_handshake
from dsm.net import handshake_acceptor as hsa
from dsm.net.handshake_gate import (
    GateKeys,
    HandshakeGate,
    SourceLimiter,
    compute_mac2,
    open_cookie_reply,
)
from dsm.net.transport.udp import UDPTransport
from tests.cert_helpers import (
    SERVER_AUTH_OID,
    EnrolledDevice,
    IssuingCA,
    make_enrolled_device,
    make_test_ca,
)
from tests.test_handshake_acceptor_limits import _Config, _minutes

SERVER_CN = "dsm-cookie-server"
CLIENT_CN = "dsm-cookie-client"
Addr = tuple[str, int]


@pytest.fixture(autouse=True)
def _no_so_mark() -> Iterator[None]:
    with patch("dsm.net.transport.udp.apply_so_mark", lambda sock: None):
        yield


@pytest.fixture
def fast_retries() -> Iterator[None]:
    """A timer resend after about 0.2 s instead of 5 s."""
    with (
        patch.object(handshake, "HANDSHAKE_TIMEOUT", 0.2),
        patch.object(handshake, "BACKOFF_BASE", 0.01),
    ):
        yield


@pytest.fixture
def slow_retries() -> Iterator[None]:
    """No timer resend for 60 s, so a resend sooner is the one sent at once."""
    with patch.object(handshake, "HANDSHAKE_TIMEOUT", 60.0):
        yield


class _Recording(UDPTransport):
    """The server's socket: keeps every frame it receives and sends."""

    def __init__(self) -> None:
        super().__init__()
        self.received: list[bytes] = []
        self.sent: list[bytes] = []

    async def recv(self, timeout: float | None = None) -> tuple[bytes, Addr]:
        data, addr = await super().recv(timeout)
        self.received.append(bytes(data))
        return data, addr

    async def send(self, data: bytes, addr: Addr) -> None:
        self.sent.append(bytes(data))
        await super().send(data, addr)


class _Server:
    """The run's keystore, attest store and certificates, in one object."""

    def __init__(self, ca: IssuingCA, device: EnrolledDevice) -> None:
        self.identity = device.identity
        self.attest_key = device.attest_key
        self.cert_der = device.cert_der
        self.ca_root = ca.certificate
        self.crl = None


async def _pair(server_t: UDPTransport) -> tuple[UDPTransport, Addr]:
    port = await server_t.bind("127.0.0.1", 0)
    client_t = UDPTransport()
    await client_t.bind("127.0.0.1", 0)
    return client_t, ("127.0.0.1", port)


def _client(
    ca: IssuingCA, device: EnrolledDevice, sock: UDPTransport, server: Addr
) -> Coroutine[Any, Any, Any]:
    return client_handshake(
        sock,
        device.identity,
        server,
        attest_key=device.attest_key,
        cert_der=device.cert_der,
        ca_root=ca.certificate,
        expected_server_cn=SERVER_CN,
    )


async def test_the_client_answers_a_cookie_reply_and_connects() -> None:
    # T10 test 17, against the real acceptor while it is under load.
    ca = make_test_ca()
    server = _Server(
        ca, make_enrolled_device(ca, subject_cn=SERVER_CN, eku=SERVER_AUTH_OID)
    )
    device = make_enrolled_device(ca, subject_cn=CLIENT_CN)
    keys = GateKeys.derive(ca.certificate, SERVER_CN)
    gate = HandshakeGate(keys)
    gate.load.note_trouble()  # under load: a new msg1 needs a cookie
    server_t = _Recording()
    client_t, addr = await _pair(server_t)
    shutdown = asyncio.Event()
    accept = asyncio.ensure_future(
        hsa._accept_until_winner(
            _Config(8),
            server,
            server,
            server,
            CNAllowlist(cns=frozenset({CLIENT_CN})),
            server_t,
            shutdown,
            SourceLimiter(clock=_minutes()),
            None,
            gate,
        )
    )
    try:
        result = await asyncio.wait_for(_client(ca, device, client_t, addr), 30.0)
        session_keys, _pub, _transport = await asyncio.wait_for(accept, 30.0)
    finally:
        shutdown.set()
        await asyncio.gather(accept, return_exceptions=True)
        await client_t.aclose()
        await server_t.aclose()
    assert result[0] is not None
    assert session_keys is not None
    first, second = server_t.received[0], server_t.received[1]
    assert second[:48] == first[:48]  # the same e and mac1
    cookie = open_cookie_reply(server_t.sent[0], keys, first[32:48])
    assert cookie is not None
    assert second[48:64] == compute_mac2(first[:48], cookie)
    frames = server_t.received + server_t.sent
    assert all(len(f) == HANDSHAKE_FRAME_SIZE for f in frames)


async def test_a_timer_resend_after_a_cookie_carries_the_latest_mac2(
    fast_retries: None,
) -> None:
    # Review Focus 3: the immediate resend after a cookie reply is lost.
    ca = make_test_ca()
    device = make_enrolled_device(ca, subject_cn=CLIENT_CN)
    keys = GateKeys.derive(ca.certificate, SERVER_CN)
    gate = HandshakeGate(keys)
    server_t = UDPTransport()
    client_t, addr = await _pair(server_t)
    attempt = asyncio.ensure_future(_client(ca, device, client_t, addr))
    try:
        first, peer = await asyncio.wait_for(server_t.recv(), 5.0)
        reply = gate.cookie_reply(first, peer)
        assert reply is not None
        await server_t.send(reply, peer)
        resend, _ = await asyncio.wait_for(server_t.recv(), 5.0)  # "lost"
        timer_resend, _ = await asyncio.wait_for(server_t.recv(), 5.0)
    finally:
        attempt.cancel()
        await asyncio.gather(attempt, return_exceptions=True)
        await client_t.aclose()
        await server_t.aclose()
    cookie = open_cookie_reply(reply, keys, first[32:48])
    assert cookie is not None
    assert resend[:48] == first[:48]
    assert resend[48:64] == compute_mac2(first[:48], cookie)
    assert timer_resend[:64] == resend[:64]


async def test_the_client_resends_at_once_after_a_cookie_reply(
    slow_retries: None,
) -> None:
    # Spec §7.5: "resend at once", not at the next timer resend. The timer
    # is 60 s away here, so the 5 s wait fails if the client waits for it.
    ca = make_test_ca()
    device = make_enrolled_device(ca, subject_cn=CLIENT_CN)
    keys = GateKeys.derive(ca.certificate, SERVER_CN)
    gate = HandshakeGate(keys)
    server_t = UDPTransport()
    client_t, addr = await _pair(server_t)
    attempt = asyncio.ensure_future(_client(ca, device, client_t, addr))
    try:
        first, peer = await asyncio.wait_for(server_t.recv(), 5.0)
        reply = gate.cookie_reply(first, peer)
        assert reply is not None
        await server_t.send(reply, peer)
        resend, _ = await asyncio.wait_for(server_t.recv(), 5.0)
    finally:
        attempt.cancel()
        await asyncio.gather(attempt, return_exceptions=True)
        await client_t.aclose()
        await server_t.aclose()
    cookie = open_cookie_reply(reply, keys, first[32:48])
    assert cookie is not None
    assert resend[:48] == first[:48]
    assert resend[48:64] == compute_mac2(first[:48], cookie)


async def test_a_third_cookie_reply_ends_the_attempt() -> None:
    # T10 test 18, first half.
    ca = make_test_ca()
    device = make_enrolled_device(ca, subject_cn=CLIENT_CN)
    gate = HandshakeGate(GateKeys.derive(ca.certificate, SERVER_CN))
    server_t = UDPTransport()
    client_t, addr = await _pair(server_t)
    received: list[bytes] = []

    async def _serve() -> None:
        while True:
            frame, peer = await server_t.recv()
            received.append(frame)
            reply = gate.cookie_reply(frame, peer)
            assert reply is not None
            await server_t.send(reply, peer)

    serve = asyncio.ensure_future(_serve())
    try:
        with pytest.raises(HandshakeError, match="more than 2 cookie replies"):
            await asyncio.wait_for(_client(ca, device, client_t, addr), 10.0)
    finally:
        serve.cancel()
        await asyncio.gather(serve, return_exceptions=True)
        await client_t.aclose()
        await server_t.aclose()
    assert len(received) == 3  # msg1 and two resends with mac2


async def test_a_reply_sealed_for_another_mac1_is_read_as_msg2() -> None:
    # T10 test 18, second half: a wrong AAD means "not a cookie reply".
    ca = make_test_ca()
    device = make_enrolled_device(ca, subject_cn=CLIENT_CN)
    gate = HandshakeGate(GateKeys.derive(ca.certificate, SERVER_CN))
    server_t = UDPTransport()
    client_t, addr = await _pair(server_t)
    attempt = asyncio.ensure_future(_client(ca, device, client_t, addr))
    try:
        first, peer = await asyncio.wait_for(server_t.recv(), 5.0)
        other = bytearray(first)
        other[32] ^= 0x01  # another msg1's mac1
        reply = gate.cookie_reply(bytes(other), peer)
        assert reply is not None
        await server_t.send(reply, peer)
        with pytest.raises(HandshakeError):
            await asyncio.wait_for(attempt, 10.0)
    finally:
        attempt.cancel()
        await asyncio.gather(attempt, return_exceptions=True)
        await client_t.aclose()
        await server_t.aclose()
