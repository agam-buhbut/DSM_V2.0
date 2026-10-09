"""A copy of msg1 that reaches the server during an attempt is skipped, not
read as msg3 or as the bootstrap frame (F2). Real tuncore Noise over an
in-memory UDP link; nothing waits on the wall clock."""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from typing import Any

import pytest
from cryptography.x509.oid import ExtendedKeyUsageOID

from dsm.crypto.cert_allowlist import CNAllowlist
from dsm.crypto.handshake import (
    HANDSHAKE_FRAME_SIZE,
    HandshakeError,
    client_handshake,
    server_handshake,
)
from dsm.net.transport.udp import UDPTransport
from tests.cert_helpers import (
    CLIENT_AUTH_OID,
    SERVER_AUTH_OID,
    make_enrolled_device,
    make_test_ca,
)

Addr = tuple[str, int]
_CLIENT: Addr = ("198.51.100.7", 40000)
_SERVER: Addr = ("192.0.2.1", 51820)


class _End(UDPTransport):
    """One end of an in-memory UDP link (no socket)."""

    def __init__(self, me: Addr) -> None:  # pylint: disable=super-init-not-called
        self.me = me
        self.inbox: asyncio.Queue[tuple[bytes, Addr]] = asyncio.Queue()
        self.peer: _End | None = None
        self.sent: list[bytes] = []
        # After send number n (from 0), also deliver a copy of send number k.
        self.copy_after: dict[int, int] = {}
        # After send number n, also deliver these bytes.
        self.inject_after: dict[int, bytes] = {}

    async def recv(  # type: ignore[override]
        self, timeout: float | None = None
    ) -> tuple[bytes, Addr]:
        if timeout is None:
            return await self.inbox.get()
        return await asyncio.wait_for(self.inbox.get(), timeout)

    async def send(self, data: bytes, addr: Addr) -> None:  # type: ignore[override]
        assert self.peer is not None and addr == self.peer.me
        self.sent.append(bytes(data))
        self.peer.inbox.put_nowait((bytes(data), self.me))
        n = len(self.sent) - 1
        if n in self.copy_after:
            self.peer.inbox.put_nowait((self.sent[self.copy_after[n]], self.me))
        if n in self.inject_after:
            self.peer.inbox.put_nowait((self.inject_after[n], self.me))


def _link() -> tuple[_End, _End]:
    client, server = _End(_CLIENT), _End(_SERVER)
    client.peer, server.peer = server, client
    return client, server


@dataclass
class _Pki:
    ca: Any
    client: Any
    server: Any


@pytest.fixture(name="pki")
def _pki() -> _Pki:
    ca = make_test_ca()
    return _Pki(
        ca=ca,
        client=make_enrolled_device(
            ca, subject_cn="dsm-f2-client", eku=CLIENT_AUTH_OID
        ),
        server=make_enrolled_device(
            ca, subject_cn="dsm-f2-server", eku=SERVER_AUTH_OID
        ),
    )


async def _run_pair(
    pki: _Pki, client_end: _End, server_end: _End
) -> tuple[asyncio.Task[Any], asyncio.Task[Any], set[asyncio.Task[Any]]]:
    client_task: asyncio.Task[Any] = asyncio.ensure_future(
        client_handshake(
            client_end,
            pki.client.identity,
            _SERVER,
            attest_key=pki.client.attest_key,
            cert_der=pki.client.cert_der,
            ca_root=pki.ca.certificate,
            expected_server_cn="dsm-f2-server",
            required_server_eku=ExtendedKeyUsageOID.SERVER_AUTH,
        )
    )
    server_task: asyncio.Task[Any] = asyncio.ensure_future(
        server_handshake(
            server_end,
            pki.server.identity,
            attest_key=pki.server.attest_key,
            cert_der=pki.server.cert_der,
            ca_root=pki.ca.certificate,
            cn_allowlist=CNAllowlist(cns=frozenset({"dsm-f2-client"})),
            required_client_eku=ExtendedKeyUsageOID.CLIENT_AUTH,
        )
    )
    # The timeout is only a safety net; a passing run ends in milliseconds,
    # and a failing server ends the wait at once (FIRST_EXCEPTION).
    _done, pending = await asyncio.wait(
        {client_task, server_task}, timeout=30.0, return_when=asyncio.FIRST_EXCEPTION
    )
    for task in pending:
        task.cancel()
    await asyncio.gather(*pending, return_exceptions=True)
    return client_task, server_task, pending


async def test_a_resent_msg1_before_msg3_is_ignored(pki: _Pki) -> None:
    """(red today) The copy is skipped, not read as msg3."""
    client_end, server_end = _link()
    client_end.copy_after = {0: 0}  # the server gets msg1 twice
    client_task, server_task, pending = await _run_pair(pki, client_end, server_end)
    assert pending == set()
    _keys, client_static = server_task.result()
    client_task.result()
    assert client_static == bytes(pki.client.identity.public_key)
    # msg2 went out once. A second copy would reach the client while it waits
    # for the bootstrap reply, and the client would fail on it.
    assert len(server_end.sent) == 2  # msg2 and the bootstrap reply


async def test_a_resent_msg1_during_the_bootstrap_wait_is_ignored(pki: _Pki) -> None:
    """(red today) A copy that arrives after msg3 is skipped too."""
    client_end, server_end = _link()
    client_end.copy_after = {1: 0}  # after msg3, a copy of msg1
    client_task, server_task, pending = await _run_pair(pki, client_end, server_end)
    assert pending == set()
    server_task.result()
    client_task.result()
    assert len(server_end.sent) == 2


async def test_any_other_frame_in_place_of_msg3_still_fails(pki: _Pki) -> None:
    """Review Focus 5: only a true copy of msg1 is skipped."""
    client_end, server_end = _link()
    client_end.inject_after = {0: os.urandom(HANDSHAKE_FRAME_SIZE)}
    _client_task, server_task, _pending = await _run_pair(pki, client_end, server_end)
    assert isinstance(server_task.exception(), HandshakeError)


def test_only_a_full_size_copy_of_msg1_counts_as_a_resend() -> None:
    """Review Focus 5. Imported here so the tests above show the real
    failure before the fix, not an ImportError."""
    from dsm.crypto.handshake import _is_resent_msg1

    msg1 = bytes(range(32)) + b"\x01" * (HANDSHAKE_FRAME_SIZE - 32)
    assert _is_resent_msg1(msg1, msg1)
    assert _is_resent_msg1(msg1[:32] + b"\x02" * (HANDSHAKE_FRAME_SIZE - 32), msg1)
    assert not _is_resent_msg1(b"\xff" + msg1[1:], msg1)
    assert not _is_resent_msg1(msg1[:-1], msg1)
    assert not _is_resent_msg1(msg1 + b"\x00", msg1)
