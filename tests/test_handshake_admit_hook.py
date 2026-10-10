"""server_handshake's admit_client hook: it sees each client that passed
every check, once, before the last handshake frame, and may refuse it. Real
handshakes over loopback UDP and TCP, like test_handshake_integration.py."""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Iterator
from typing import Any
from unittest.mock import patch

import pytest

from dsm.crypto import handshake
from dsm.crypto.cert_allowlist import CNAllowlist
from dsm.crypto.crl import CRL
from dsm.crypto.handshake import (
    CertRevokedError,
    ClientRefusedError,
    CNNotAllowedError,
    HandshakeError,
    VerifiedClient,
    client_handshake,
    server_handshake,
)
from dsm.net._addresses import SINGLE_CLIENT_TUNNEL, TunnelAssignment
from dsm.net.transport.tcp import TCPListener, TCPTransport
from dsm.net.transport.udp import UDPTransport
from tests.cert_helpers import SERVER_AUTH_OID, make_enrolled_device, make_test_ca
from tests.test_handshake_integration import _build_crl_with_revoked

CLIENT_CN = "dsm-hook-client"
SERVER_CN = "dsm-hook-server"
Addr = tuple[str, int]


@pytest.fixture(autouse=True)
def _no_so_mark() -> Iterator[None]:
    with (
        patch("dsm.net.transport.udp.apply_so_mark", lambda sock: None),
        patch("dsm.net.transport.tcp.apply_so_mark", lambda sock: None),
    ):
        yield


@pytest.fixture
def fast_retries() -> Iterator[None]:
    """A client whose last frame never comes fails in about 1 s, not 18 s."""
    with (
        patch.object(handshake, "HANDSHAKE_TIMEOUT", 0.2),
        patch.object(handshake, "BACKOFF_BASE", 0.01),
    ):
        yield


class _Parties:
    def __init__(self) -> None:
        self.ca = make_test_ca()
        self.client = make_enrolled_device(self.ca, subject_cn=CLIENT_CN)
        self.server = make_enrolled_device(
            self.ca, subject_cn=SERVER_CN, eku=SERVER_AUTH_OID
        )


class _Hook:
    """admit_client stand-in: records each client and how many frames the
    server had sent by then; refuses when told to; returns the one address
    today's server gives."""

    def __init__(self, sent: list[bytes], *, refuse: bool = False) -> None:
        self.sent = sent
        self.refuse = refuse
        self.calls: list[tuple[VerifiedClient, int]] = []

    def __call__(self, client: VerifiedClient) -> TunnelAssignment:
        self.calls.append((client, len(self.sent)))
        if self.refuse:
            raise ClientRefusedError("test refusal")
        return SINGLE_CLIENT_TUNNEL


def _count_sends(transport: Any, sent: list[bytes]) -> None:
    """Record every frame the server sends through ``transport``."""
    real = transport.send

    async def _send(data: bytes, *args: Any) -> None:
        sent.append(bytes(data))
        await real(data, *args)

    transport.send = _send


async def _run(
    p: _Parties,
    server_t: Any,
    client_t: Any,
    server_addr: Addr,
    *,
    hook: Any = None,
    allowlist: CNAllowlist | None = None,
    crl: CRL | None = None,
) -> tuple[Any, Any]:
    if allowlist is None:  # not ``or``: an empty CNAllowlist is falsy
        allowlist = CNAllowlist(cns=frozenset({CLIENT_CN}))
    return await asyncio.wait_for(
        asyncio.gather(
            client_handshake(
                client_t,
                p.client.identity,
                server_addr,
                attest_key=p.client.attest_key,
                cert_der=p.client.cert_der,
                ca_root=p.ca.certificate,
                expected_server_cn=SERVER_CN,
            ),
            server_handshake(
                server_t,
                p.server.identity,
                attest_key=p.server.attest_key,
                cert_der=p.server.cert_der,
                ca_root=p.ca.certificate,
                cn_allowlist=allowlist,
                crl=crl,
                admit_client=hook,
            ),
            return_exceptions=True,
        ),
        timeout=30.0,
    )


async def _udp_pair() -> tuple[UDPTransport, UDPTransport, Addr]:
    server_t = UDPTransport()
    port = await server_t.bind("127.0.0.1", 0)
    client_t = UDPTransport()
    await client_t.bind("127.0.0.1", 0)
    return server_t, client_t, ("127.0.0.1", port)


async def _run_udp(p: _Parties, sent: list[bytes], **kwargs: Any) -> tuple[Any, Any]:
    server_t, client_t, addr = await _udp_pair()
    try:
        _count_sends(server_t, sent)
        return await _run(p, server_t, client_t, addr, **kwargs)
    finally:
        await client_t.aclose()
        await server_t.aclose()


def _ok(results: tuple[Any, Any]) -> None:
    for result in results:
        assert not isinstance(result, BaseException), result


async def test_the_hook_sees_the_client_once_before_the_last_frame_udp() -> None:
    p = _Parties()
    sent: list[bytes] = []
    hook = _Hook(sent)
    results = await _run_udp(p, sent, hook=hook)
    _ok(results)
    assert len(hook.calls) == 1
    client, frames_before = hook.calls[0]
    assert client == VerifiedClient(
        cn=CLIENT_CN, noise_static=bytes(p.client.identity.public_key)
    )
    assert frames_before == 1  # msg2 only: the bootstrap reply comes after
    assert len(sent) == 2


async def test_the_hook_sees_the_client_once_before_the_last_frame_tcp() -> None:
    p = _Parties()
    listener = TCPListener()
    port = await listener.start("127.0.0.1", 0)
    client_t = TCPTransport()
    sent: list[bytes] = []
    hook = _Hook(sent)
    try:
        await client_t.connect("127.0.0.1", port)
        server_t, _peer = await asyncio.wait_for(listener.connections.get(), 5.0)
        _count_sends(server_t, sent)
        try:
            results = await _run(p, server_t, client_t, ("127.0.0.1", port), hook=hook)
        finally:
            await server_t.aclose()
    finally:
        await client_t.aclose()
        listener.close()
    _ok(results)
    assert [c.cn for c, _n in hook.calls] == [CLIENT_CN]
    assert hook.calls[0][1] == 1
    assert len(sent) == 2


async def test_a_refusal_sends_no_last_frame_and_the_client_fails(
    fast_retries: None,
) -> None:
    p = _Parties()
    sent: list[bytes] = []
    hook = _Hook(sent, refuse=True)
    client_res, server_res = await _run_udp(p, sent, hook=hook)
    assert isinstance(server_res, ClientRefusedError)
    assert isinstance(server_res, HandshakeError)
    assert isinstance(client_res, HandshakeError)
    assert len(hook.calls) == 1
    assert len(sent) == 1  # msg2 only: no bootstrap reply, no session keys


async def test_the_hook_is_not_called_for_a_name_off_the_allowlist(
    fast_retries: None,
) -> None:
    p = _Parties()
    sent: list[bytes] = []
    hook = _Hook(sent)
    results = await _run_udp(p, sent, hook=hook, allowlist=CNAllowlist(cns=frozenset()))
    assert any(isinstance(r, CNNotAllowedError) for r in results)
    assert hook.calls == []


async def test_the_hook_is_not_called_for_a_revoked_client(
    fast_retries: None,
) -> None:
    p = _Parties()
    crl = _build_crl_with_revoked(p.ca, [p.client.cert.serial_number])
    sent: list[bytes] = []
    hook = _Hook(sent)
    results = await _run_udp(p, sent, hook=hook, crl=crl)
    assert any(isinstance(r, CertRevokedError) for r in results)
    assert hook.calls == []


async def test_without_the_hook_nothing_changes() -> None:
    p = _Parties()
    sent: list[bytes] = []
    (client_keys, _hash, _server_pub, tunnel), (server_keys, client_static) = (
        await _run_udp(p, sent)
    )
    assert bytes(client_static) == bytes(p.client.identity.public_key)
    assert tunnel == SINGLE_CLIENT_TUNNEL
    opened = server_keys.open_packet(client_keys.seal_packet(1, b"ping"))
    assert opened is not None
    assert opened[1] == b"ping"


async def test_the_server_signs_in_a_worker_thread_and_the_client_on_the_loop() -> None:
    p = _Parties()
    real = handshake.build_attest_payload
    threads: dict[str, threading.Thread] = {}

    def _recording(**kwargs: Any) -> bytes:
        threads[kwargs["our_role"].name] = threading.current_thread()
        return real(**kwargs)

    sent: list[bytes] = []
    with patch.object(handshake, "build_attest_payload", new=_recording):
        _ok(await _run_udp(p, sent))
    assert threads["RESPONDER"] is not threading.main_thread()
    assert threads["INITIATOR"] is threading.main_thread()
