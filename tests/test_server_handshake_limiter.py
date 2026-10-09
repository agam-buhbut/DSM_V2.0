"""run_server keeps one SourceLimiter for the whole run and hands it to every
accept; the TCP accept opens one listener per accept cycle and closes it."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import dsm.server as server_mod
from dsm.core.config import Config
from dsm.core.fsm import SessionFSM, State
from dsm.net.handshake_gate import SourceLimiter
from dsm.server import _drive_fsm_to_idle, run_server
from tests.test_server_dns_fatal import _base_patches, _server_config


async def _session(*args: Any) -> None:
    _drive_fsm_to_idle(args[1])  # what a finished session leaves


async def _no_udp_accept(*_args: Any, **_k: Any) -> Any:
    raise AssertionError("the UDP acceptor must not run in TCP mode")


def _tcp_config() -> Config:
    return replace(_server_config(), transport="tcp", dns_blocklist=False)


async def test_every_udp_accept_gets_the_same_limiter() -> None:
    seen: list[Any] = []
    captured: dict[str, Any] = {}

    async def _accept(*args: Any, **_k: Any) -> tuple[Any, Any, Any]:
        seen.append(args[7] if len(args) > 7 else None)
        if len(seen) == 1:
            return object(), b"\x01" * 32, args[5]
        args[6].set()  # process_shutdown
        return None, None, args[5]

    with (
        _base_patches(_accept, captured),
        patch("dsm.server._run_one_session", new=_session),
    ):
        rc = await run_server(replace(_server_config(), dns_blocklist=False))

    assert rc == 0
    assert len(seen) == 2
    assert isinstance(seen[0], SourceLimiter)
    assert seen[0] is seen[1]


async def test_every_tcp_accept_gets_the_same_limiter() -> None:
    seen: list[Any] = []
    captured: dict[str, Any] = {}

    async def _accept(*args: Any) -> tuple[Any, Any, Any]:
        seen.append(args[8] if len(args) > 8 else None)
        if len(seen) == 1:
            return object(), b"\x01" * 32, AsyncMock()
        args[7].set()  # process_shutdown
        return None, None, None

    with (
        _base_patches(_no_udp_accept, captured),
        patch("dsm.server._accept_one_session", new=_accept),
        patch("dsm.server._run_one_session", new=_session),
    ):
        rc = await run_server(_tcp_config())

    assert rc == 0
    assert len(seen) == 2
    assert isinstance(seen[0], SourceLimiter)
    assert seen[0] is seen[1]


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


async def _accept_one(
    acceptor: Any, previous: Any = None
) -> tuple[tuple[Any, Any, Any], SessionFSM, SourceLimiter, asyncio.Event]:
    fsm = SessionFSM()
    fsm.transition(State.CONNECTING)
    limiter = SourceLimiter()
    shutdown = asyncio.Event()
    _FakeListener.made = []
    with (
        patch("dsm.server.TCPListener", _FakeListener),
        patch("dsm.server._accept_until_winner_tcp", new=acceptor),
    ):
        result = await server_mod._accept_one_session(
            _tcp_config(),
            fsm,
            MagicMock(),
            MagicMock(),
            MagicMock(),
            MagicMock(),
            previous,
            shutdown,
            limiter,
        )
    return result, fsm, limiter, shutdown


async def test_tcp_accept_hands_queue_and_limiter_to_the_acceptor() -> None:
    got: dict[str, Any] = {}
    winner_conn = object()
    previous = MagicMock()
    previous.aclose = AsyncMock()

    async def _acceptor(*args: Any) -> tuple[Any, Any, Any]:
        got["args"] = args
        got["open_during"] = not _FakeListener.made[0].closed
        return "keys", b"\x01" * 32, winner_conn

    (keys, pub, transport), fsm, limiter, shutdown = await _accept_one(
        _acceptor, previous
    )
    listener = _FakeListener.made[0]
    previous.aclose.assert_awaited_once_with()
    assert listener.ports == [51820]
    assert got["args"][5] is listener.connections
    assert got["args"][6] is shutdown
    assert got["args"][7] is limiter
    assert got["open_during"] is True
    assert listener.closed
    assert (keys, pub, transport) == ("keys", b"\x01" * 32, winner_conn)
    assert fsm.state is State.HANDSHAKING


async def test_tcp_accept_on_shutdown_closes_the_listener_and_idles_the_fsm() -> None:
    async def _acceptor(*_args: Any) -> tuple[None, None, None]:
        return None, None, None

    result, fsm, _limiter, _shutdown = await _accept_one(_acceptor)
    assert result == (None, None, None)
    assert _FakeListener.made[0].closed
    assert fsm.state is State.IDLE


async def test_tcp_accept_closes_the_listener_when_the_acceptor_fails() -> None:
    async def _acceptor(*_args: Any) -> Any:
        raise RuntimeError("acceptor bug")

    with pytest.raises(RuntimeError, match="acceptor bug"):
        await _accept_one(_acceptor)
    assert _FakeListener.made[0].closed
