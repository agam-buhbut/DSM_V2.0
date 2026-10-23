"""What a wire version mismatch looks like (spec §8.2) and the startup lines
(§8.1). The client's two texts, through a fake socket, and "wire v2" at
start on both ends. Laptop: yes (old wheel + shim).
"""

from __future__ import annotations

import asyncio
import logging
import random
from dataclasses import replace
from typing import Any
from unittest.mock import patch

import pytest

from dsm.crypto import handshake
from dsm.crypto.handshake import HandshakeError, client_handshake
from dsm.net.transport.udp import UDPTransport
from tests.cert_helpers import make_enrolled_device, make_test_ca
from tests.test_client_fail_closed import _Run
from tests.test_server_dns_fatal import _base_patches, _run_until, _server_config

Addr = tuple[str, int]
SERVER: Addr = ("192.0.2.1", 51820)

UNREADABLE = (
    "could not read the server's reply. The server may run a different DSM "
    "wire version (this build: wire v2), or this is not your DSM server."
)
NO_ANSWER = (
    "no answer after 3 tries. Check the server address and port, "
    "expected_server_cn and the CA file, the clock (within 5 minutes), and "
    "that the server runs DSM wire v2."
)


class _Answering(UDPTransport):
    """A client socket whose server answers each msg1 with ``reply``, or
    never. Nothing touches the network."""

    def __init__(self, reply: bytes | None) -> None:
        super().__init__()
        self._reply = reply

    async def send(self, data: bytes, addr: Addr) -> None:
        del data
        if self._reply is not None:
            self._recv_queue.put_nowait((self._reply, addr))


class _Listener:
    """A TCP listener: an empty connection queue, and a close."""

    def __init__(self) -> None:
        self.connections: asyncio.Queue[Any] = asyncio.Queue()

    def close(self) -> None:
        pass


async def _attempt(sock: UDPTransport) -> None:
    ca = make_test_ca()
    device = make_enrolled_device(ca, subject_cn="dsm-msg-client")
    await client_handshake(
        sock,
        device.identity,
        SERVER,
        attest_key=device.attest_key,
        cert_der=device.cert_der,
        ca_root=ca.certificate,
        expected_server_cn="dsm-msg-server",
    )


async def test_a_reply_the_client_cannot_read_names_the_wire_version() -> None:
    # An old server (prologue 1) or something that is not DSM: msg2 does not
    # read. 1400 random bytes stand for it.
    sock = _Answering(random.Random(1).randbytes(1400))
    with pytest.raises(HandshakeError) as err:
        await _attempt(sock)
    assert str(err.value) == UNREADABLE
    assert isinstance(err.value.__cause__, RuntimeError)


async def test_no_answer_says_what_to_check() -> None:
    with (
        patch.object(handshake, "HANDSHAKE_TIMEOUT", 0.01),
        patch.object(handshake, "BACKOFF_BASE", 0.001),
        pytest.raises(HandshakeError) as err,
    ):
        await _attempt(_Answering(None))
    assert str(err.value) == NO_ANSWER


async def test_the_server_says_wire_v2_when_it_starts(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="dsm")
    captured: dict[str, Any] = {}
    with _base_patches(captured):
        rc = await _run_until(replace(_server_config(), dns_blocklist=False), captured)
    assert rc == 0
    lines = [r.getMessage() for r in caplog.records]
    assert "server listening on UDP port 51820 (wire v2)" in lines


async def test_the_server_says_wire_v2_when_it_starts_on_tcp(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="dsm")
    captured: dict[str, Any] = {}

    async def _listener(_config: Any) -> _Listener:
        return _Listener()

    with _base_patches(captured), patch("dsm.server._open_tcp_listener", _listener):
        rc = await _run_until(
            replace(_server_config(), dns_blocklist=False, transport="tcp"), captured
        )
    assert rc == 0
    lines = [r.getMessage() for r in caplog.records]
    assert "server listening on TCP port 51820 (wire v2)" in lines


async def test_the_client_says_wire_v2_when_it_starts(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="dsm")
    run = _Run()
    run.handshakes = [HandshakeError("no server here")]
    run.stop_at_wait = 1
    assert await run.run() == 0
    assert "client starting (wire v2)" in [r.getMessage() for r in caplog.records]
