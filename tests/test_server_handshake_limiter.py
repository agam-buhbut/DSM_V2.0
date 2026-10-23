"""run_server keeps one SourceLimiter, one SessionTable and one gate for the
whole run and hands them to its one acceptor; the TCP acceptor reads the
run's one listener, which is opened once, at start, and closed at the end."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from typing import Any
from unittest.mock import patch

from dsm.core.config import Config
from dsm.net.handshake_gate import HandshakeGate, SourceLimiter
from dsm.net.session_slot import SessionTable
from tests.test_server_dns_fatal import _base_patches, _run_until, _server_config
from tests.test_server_multi import _Acceptor


def _tcp_config() -> Config:
    return replace(_server_config(), transport="tcp", dns_blocklist=False)


class _FakeListener:
    """Stands in for TCPListener: records the port and whether it closed."""

    made: list[_FakeListener] = []

    def __init__(self) -> None:
        self.connections: asyncio.Queue[Any] = asyncio.Queue()
        self.ports: list[int] = []
        self.closed = False
        _FakeListener.made.append(self)

    async def start(self, host: str = "0.0.0.0", port: int = 0) -> int:
        del host
        self.ports.append(port)
        return port

    def close(self) -> None:
        self.closed = True


async def test_the_udp_acceptor_gets_the_runs_limiter_table_and_gate() -> None:
    captured: dict[str, Any] = {}
    _Acceptor.made = []
    with _base_patches(captured), patch("dsm.server.ClientAcceptor", _Acceptor):
        rc = await _run_until(replace(_server_config(), dns_blocklist=False), captured)
    assert rc == 0
    (acceptor,) = _Acceptor.made
    assert isinstance(acceptor.limiter, SourceLimiter)
    assert isinstance(acceptor.table, SessionTable)
    assert acceptor.table is captured["table"]  # the one the host setup got
    assert isinstance(acceptor.gate, HandshakeGate)


async def test_the_tcp_acceptor_reads_the_runs_one_listener() -> None:
    captured: dict[str, Any] = {}
    _Acceptor.made = []
    _FakeListener.made = []
    with (
        _base_patches(captured),
        patch("dsm.server.TCPListener", _FakeListener),
        patch("dsm.server.ClientAcceptor", _Acceptor),
    ):
        rc = await _run_until(_tcp_config(), captured)
    assert rc == 0
    (listener,) = _FakeListener.made
    (acceptor,) = _Acceptor.made
    assert listener.ports == [51820]  # opened once, at start, on the config port
    assert acceptor.tcp is listener.connections
    assert acceptor.udp is None
    assert isinstance(acceptor.limiter, SourceLimiter)
    assert listener.closed  # the run's stack closes it at the end
