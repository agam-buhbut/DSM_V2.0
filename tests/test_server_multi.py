"""run_server with several clients (multi-client spec §2.2, §2.7, §2.8, §5):
the host state every client shares, the acceptor's restarts, and the
sessions. Host I/O is faked at the boundary; no sockets, no root.
"""

from __future__ import annotations

import asyncio
import contextlib
import errno
import logging
import os
from collections.abc import Callable, Generator
from contextlib import AsyncExitStack, ExitStack, contextmanager
from dataclasses import replace
from typing import Any
from unittest.mock import patch

import pytest

from dsm import server
from dsm.core.config import Config
from dsm.core.fsm import SessionFSM, State
from dsm.core.protocol import InnerPacket, PacketType
from dsm.crypto.cert_allowlist import CNAllowlist
from dsm.crypto.handshake import VerifiedClient
from dsm.net.dns import DNSResolver
from dsm.net.dns_proxy import DNSProxyPortInUseError
from dsm.net.handshake_acceptor import AcceptedClient
from dsm.net.session_router import ClientTun, _SessionUDPView
from dsm.net.session_slot import ServerSession, SessionTable
from dsm.server import (
    SERVER_RECV_QUEUE_PACKETS,
    _drive_fsm_to_idle,
    _run_acceptor,
    _set_up_host,
    run_server,
)
from tests.test_handshake_acceptor_limits import _spin
from tests.test_server_dns_fatal import (
    _base_patches,
    _FakeScheduler,
    _FakeStore,
    _FakeTun,
    _FakeUDPTransport,
    _noop_send,
    _server_config,
)

A = "dsm-a-client"
B = "dsm-b-client"


class _HostParts:
    """The host managers ``_set_up_host`` uses, faked; each records what it
    did. With ``nat_loads`` False the NAT load fails as MasqueradeManager's
    does: no exception, ``applied`` False. Use as a context manager."""

    def __init__(self) -> None:
        self.events: list[str] = []
        self.nat_clients: dict[str, str] | None = None
        self.proxy_args: dict[str, Any] = {}
        self.configure_error: Exception | None = None
        self.dns_error: Exception | None = None
        self.nat_loads = True
        self._stack = ExitStack()

    def __enter__(self) -> _HostParts:
        parts = self

        class _Tun:
            def __init__(self, name: str) -> None:
                parts.events.append(f"tun {name}")

            def open(self) -> None:
                parts.events.append("tun open")

            def configure(self, *, local_ip: str, mtu: int, server_mode: bool) -> None:
                del mtu
                if parts.configure_error is not None:
                    raise parts.configure_error
                parts.events.append(f"tun up {local_ip} server_mode={server_mode}")

            def close(self) -> None:
                parts.events.append("tun close")

        class _Forwarding:
            def __init__(self, tun_name: str) -> None:
                del tun_name

            def apply(self) -> None:
                parts.events.append("forwarding on")

            def remove(self) -> None:
                parts.events.append("forwarding off")

        class _Nat:
            def __init__(self, tun_name: str, *, clients: dict[str, str]) -> None:
                del tun_name
                parts.nat_clients = clients
                self.applied = False

            def apply(self) -> None:
                # As MasqueradeManager.apply: a failed load never raises.
                self.applied = parts.nat_loads
                if self.applied:
                    parts.events.append("nat on")

            def remove(self) -> None:
                parts.events.append("nat off")

        class _Proxy:
            def __init__(self, resolver: Any, **kwargs: Any) -> None:
                parts.proxy_args = {"resolver": resolver, **kwargs}

            async def start(self) -> None:
                if parts.dns_error is not None:
                    raise parts.dns_error
                parts.events.append("dns on")

            def stop(self) -> None:
                parts.events.append("dns off")

        for target, fake in (
            ("dsm.server.TunDevice", _Tun),
            ("dsm.server.IPForwardingManager", _Forwarding),
            ("dsm.server.MasqueradeManager", _Nat),
            ("dsm.server.LocalDNSProxy", _Proxy),
        ):
            self._stack.enter_context(patch(target, fake))
        return self

    def __exit__(self, *exc: object) -> None:
        self._stack.close()


async def test_host_state_comes_up_in_order_and_goes_down_in_reverse(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="dsm.server")
    with _HostParts() as parts:
        async with AsyncExitStack() as stack:
            await _set_up_host(_server_config(), stack, None, SessionTable([A, B]))
            assert parts.events == [
                "tun mtun0",
                "tun open",
                "tun up 10.8.0.1 server_mode=True",
                "forwarding on",
                "nat on",
                "dns on",
            ]
            parts.events.clear()
    assert parts.events == ["dns off", "nat off", "forwarding off", "tun close"]
    assert "tunnel 10.8.0.1/24 up; addresses for 2 clients" in [
        r.getMessage() for r in caplog.records
    ]


async def test_the_nat_table_gets_every_clients_address() -> None:
    with _HostParts() as parts:
        async with AsyncExitStack() as stack:
            await _set_up_host(_server_config(), stack, None, SessionTable([A, B]))
    assert parts.nat_clients == {"10.8.0.2": A, "10.8.0.3": B}


async def test_the_dns_proxy_gets_a_resolver_per_client() -> None:
    # The run's blocklist reaching this proxy is §7 item 18's test, in
    # tests/test_dns_blocklist_server.py (Task 8 Step 6).
    with _HostParts() as parts:
        async with AsyncExitStack() as stack:
            await _set_up_host(_server_config(), stack, None, SessionTable([A]))
    args = parts.proxy_args
    assert (args["bind_ip"], args["bind_port"]) == ("10.8.0.1", 53)
    first, second = args["per_client"](), args["per_client"]()
    assert isinstance(args["resolver"], DNSResolver)
    assert isinstance(first, DNSResolver) and isinstance(second, DNSResolver)
    assert len({id(args["resolver"]), id(first), id(second)}) == 3


async def test_a_busy_dns_port_unwinds_what_was_built() -> None:
    with _HostParts() as parts:
        parts.dns_error = DNSProxyPortInUseError("10.8.0.1:53 is taken")
        with pytest.raises(DNSProxyPortInUseError):
            async with AsyncExitStack() as stack:
                await _set_up_host(_server_config(), stack, None, SessionTable([A]))
    assert parts.events[-3:] == ["nat off", "forwarding off", "tun close"]
    assert "dns off" not in parts.events


async def test_a_tun_that_fails_to_configure_is_closed_again() -> None:
    with _HostParts() as parts:
        parts.configure_error = RuntimeError(
            "TUN configure failed: ip link set mtun0 up"
        )
        with pytest.raises(RuntimeError, match="TUN configure failed"):
            async with AsyncExitStack() as stack:
                await _set_up_host(_server_config(), stack, None, SessionTable([A]))
    assert parts.events == ["tun mtun0", "tun open", "tun close"]


async def test_a_nat_table_that_does_not_load_stops_the_setup() -> None:
    # Fail closed (roadmap item 1.8): no DNS proxy is built; forwarding and
    # the TUN unwind.
    with _HostParts() as parts:
        parts.nat_loads = False
        with pytest.raises(RuntimeError, match="NAT table .* did not load"):
            async with AsyncExitStack() as stack:
                await _set_up_host(_server_config(), stack, None, SessionTable([A]))
    assert parts.proxy_args == {}
    assert parts.events == [
        "tun mtun0",
        "tun open",
        "tun up 10.8.0.1 server_mode=True",
        "forwarding on",
        "forwarding off",
        "tun close",
    ]


class _CrashingAcceptor:
    """run() raises ``crashes`` times, then runs until cancelled. stop()
    raises ``stop_errors`` times, as part B's does with a worker's bug."""

    def __init__(self, crashes: int, stop_errors: int = 0) -> None:
        self.crashes = crashes
        self.stop_errors = stop_errors
        self.runs = 0
        self.stops = 0

    async def run(self) -> None:
        self.runs += 1
        if self.runs <= self.crashes:
            raise RuntimeError("acceptor bug")
        await asyncio.Event().wait()

    async def stop(self) -> None:
        self.stops += 1
        if self.stops <= self.stop_errors:
            raise RuntimeError("worker bug")


def _backoffs(
    calls: list[int], *, shutdown_at: int | None = None
) -> Callable[[int, asyncio.Event], Any]:
    async def _backoff(failures: int, shutdown: asyncio.Event) -> bool:
        calls.append(failures)
        if failures == shutdown_at:
            shutdown.set()
            return True
        return False

    return _backoff


async def test_an_acceptor_crash_is_logged_stopped_and_run_again(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.ERROR, logger="dsm.server")
    acceptor = _CrashingAcceptor(crashes=2)
    calls: list[int] = []
    with patch("dsm.server._backoff_or_shutdown", _backoffs(calls)):
        task = asyncio.ensure_future(_run_acceptor(acceptor, asyncio.Event()))  # type: ignore[arg-type]
        assert await _spin(lambda: acceptor.runs == 3)
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
    assert calls == [1, 2]
    assert acceptor.stops == 2
    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert [r.getMessage() for r in errors] == [
        "handshake accept failed; retrying after a backoff"
    ] * 2
    assert all(r.exc_info is not None for r in errors)


async def test_a_stop_that_raises_after_a_crash_is_logged_and_run_again(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.ERROR, logger="dsm.server")
    acceptor = _CrashingAcceptor(crashes=1, stop_errors=1)
    calls: list[int] = []
    with patch("dsm.server._backoff_or_shutdown", _backoffs(calls)):
        task = asyncio.ensure_future(_run_acceptor(acceptor, asyncio.Event()))  # type: ignore[arg-type]
        assert await _spin(lambda: acceptor.runs == 2)
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
    assert (acceptor.stops, calls) == (1, [1])
    # The crash, then the worker's bug that stop() raised.
    assert [r.getMessage() for r in caplog.records] == [
        "handshake accept failed; retrying after a backoff"
    ] * 2


async def test_shutdown_during_the_backoff_ends_the_acceptor_loop() -> None:
    acceptor = _CrashingAcceptor(crashes=5)
    calls: list[int] = []
    with patch("dsm.server._backoff_or_shutdown", _backoffs(calls, shutdown_at=1)):
        await asyncio.wait_for(_run_acceptor(acceptor, asyncio.Event()), 5.0)  # type: ignore[arg-type]
    assert (acceptor.runs, acceptor.stops, calls) == (1, 1, [1])


async def test_a_cancel_ends_the_acceptor_loop_without_an_error_line(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.ERROR, logger="dsm.server")
    acceptor = _CrashingAcceptor(crashes=0)
    task = asyncio.ensure_future(_run_acceptor(acceptor, asyncio.Event()))  # type: ignore[arg-type]
    assert await _spin(lambda: acceptor.runs == 1)
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task
    assert task.cancelled()
    assert caplog.records == []


PEER_A = ("198.51.100.7", 40000)
PEER_A2 = ("198.51.100.7", 40001)  # A again, from a new port
PEER_B = ("203.0.113.9", 51000)


class _Keys:
    """Session keys as the dispatcher sees them: every header fits."""

    epoch = 0

    def header_matches(self, _wire: bytes) -> bool:
        return True


class _Listener:
    def __init__(self) -> None:
        self.connections: asyncio.Queue[Any] = asyncio.Queue()

    def close(self) -> None:
        pass


class _Acceptor:
    """Stands in for ClientAcceptor and keeps what run_server gave it.
    ``admit`` does what a worker does after a full handshake (spec §2.7):
    the table's admit and confirm, then on_client."""

    made: list[_Acceptor] = []

    def __init__(
        self,
        config: Any,
        keystore: Any,
        attest_store: Any,
        materials: Any,
        cn_allowlist: Any,
        limiter: Any,
        table: Any,
        gate: Any,
        on_client: Any,
        *,
        udp: Any = None,
        tcp: Any = None,
        clock: Any = None,
    ) -> None:
        del config, keystore, attest_store, materials, cn_allowlist, clock
        self.limiter = limiter
        self.table = table
        self.gate = gate
        self.on_client = on_client
        self.udp = udp
        self.tcp = tcp
        self.offered: list[tuple[bytes, tuple[str, int]]] = []
        self.runs = 0
        self.stops = 0
        self.live_at_stop: list[bool] = []
        # Raised by stop(), as part B's stop() raises a worker's bug.
        self.stop_error: Exception | None = None
        # When set, stop() waits on it (a test cancels the run meanwhile).
        self.stop_wait: asyncio.Event | None = None
        _Acceptor.made.append(self)

    def offer(self, data: bytes, addr: tuple[str, int]) -> None:
        self.offered.append((data, addr))

    async def run(self) -> None:
        self.runs += 1
        await asyncio.Event().wait()

    async def stop(self) -> None:
        self.stops += 1
        # Whether any session had been told to stop before the acceptor.
        self.live_at_stop = [s.shutdown.is_set() for s in self.table.sessions()]
        if self.stop_wait is not None:
            await self.stop_wait.wait()
        if self.stop_error is not None:
            raise self.stop_error

    def admit(
        self,
        cn: str,
        peer: tuple[str, int],
        *,
        transport: Any = None,
        held: tuple[bytes, ...] = (),
    ) -> None:
        attempt = object()
        client = VerifiedClient(cn=cn, noise_static=cn.encode().ljust(32, b"\x00")[:32])
        self.table.admit(attempt, client)
        _, tunnel = self.table.confirm(attempt)
        try:
            self.on_client(
                AcceptedClient(
                    session_keys=_Keys(),  # type: ignore[arg-type]
                    client=client,
                    tunnel=tunnel,
                    transport=transport if transport is not None else self.udp,
                    peer=peer,
                    held=held,
                )
            )
        finally:
            self.table.release(attempt)


class _Sessions:
    """Stands in for _run_one_session: each session runs until its shutdown
    is set, or ends at once for a CN in ``end_at_once`` (as a dead peer
    would)."""

    def __init__(self, events: list[str] | None = None) -> None:
        self.events: list[str] = events if events is not None else []
        self.started: list[ServerSession] = []
        # The tun each session got, in the order of ``started``.
        self.tuns: list[Any] = []
        self.end_at_once: set[str] = set()
        self.fail: set[str] = set()
        self.fsms: list[SessionFSM] = []

    async def __call__(
        self,
        _config: Any,
        fsm: SessionFSM,
        _keystore: Any,
        session: ServerSession,
        tun: Any,
        _on_peer: Any,
    ) -> None:
        fsm.transition(State.ESTABLISHED)
        self.started.append(session)
        self.fsms.append(fsm)
        self.tuns.append(tun)
        cn = session.client.cn
        self.events.append(f"{cn} started")
        try:
            if cn in self.fail:
                raise RuntimeError("session bug")
            if cn not in self.end_at_once:
                await session.shutdown.wait()
        finally:
            self.events.append(f"{cn} ended")
        _drive_fsm_to_idle(fsm)


@contextmanager
def _multi(
    captured: dict[str, Any], sessions: _Sessions, cns: tuple[str, ...] = (A, B)
) -> Generator[None, None, None]:
    """run_server with host I/O faked, the allowlist ``cns`` in that order,
    the stand-in acceptor and sessions."""
    _Acceptor.made = []
    allowlist = CNAllowlist(cns=frozenset(cns), order=cns)
    with (
        _base_patches(captured),
        patch("dsm.server.CNAllowlist.from_file", return_value=allowlist),
        patch("dsm.server.ClientAcceptor", _Acceptor),
        patch("dsm.server._run_one_session", sessions),
    ):
        yield


async def _start(config: Config | None = None) -> asyncio.Future[int]:
    """Start run_server; return once its acceptor runs."""
    run = asyncio.ensure_future(
        run_server(config or replace(_server_config(), dns_blocklist=False))
    )
    assert await _spin(
        lambda: run.done() or (bool(_Acceptor.made) and _Acceptor.made[0].runs == 1)
    )
    assert not run.done(), "run_server ended at start"
    return run


async def _stop(run: asyncio.Future[int], captured: dict[str, Any]) -> int:
    captured["event"].set()  # as SIGTERM would
    return await asyncio.wait_for(run, 5.0)


def _errors(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.levelno >= logging.ERROR]


async def test_two_clients_are_served_at_once(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="dsm.server")
    captured: dict[str, Any] = {}
    sessions = _Sessions()
    with _multi(captured, sessions):
        run = await _start()
        acceptor = _Acceptor.made[0]
        acceptor.admit(A, PEER_A)
        acceptor.admit(B, PEER_B)
        assert await _spin(lambda: len(sessions.started) == 2)
        a, b = sessions.started
        assert (str(a.tunnel.client), str(b.tunnel.client)) == ("10.8.0.2", "10.8.0.3")
        assert isinstance(a.transport, _SessionUDPView)
        assert isinstance(b.transport, _SessionUDPView)
        assert a.transport is not b.transport
        sent: list[bytes] = []
        for session, tun in zip(sessions.started, sessions.tuns, strict=True):
            # Its own side of the host TUN: it reads its own session's queue,
            # and what it may send goes to the host TUN.
            assert isinstance(tun, ClientTun)
            session.tun_queue.put_nowait(b"to " + session.client.cn.encode())
            got = await asyncio.wait_for(tun.read(), 1.0)
            assert got == b"to " + session.client.cn.encode()
            # An IPv4 header from its tunnel address to the server.
            out = (
                bytes([0x45])
                + bytes(11)
                + session.tunnel.client.packed
                + session.tunnel.server.packed
            )
            assert await tun.awrite(out) == len(out)
            sent.append(out)
        assert captured["host"].tun.written == sent
        assert captured["table"].sessions() == [a, b]
        assert not a.shutdown.is_set() and not b.shutdown.is_set()
        rc = await _stop(run, captured)
    assert rc == 0
    lines = [r.getMessage() for r in caplog.records]
    assert f"session 1: client_cn={A}, tunnel address 10.8.0.2" in lines
    assert f"session 2: client_cn={B}, tunnel address 10.8.0.3" in lines
    assert f"session 1 ended (client_cn={A})" in lines


async def test_the_port_and_the_host_come_up_once_before_any_client() -> None:
    captured: dict[str, Any] = {}
    events: list[str] = captured.setdefault("events", [])

    class _Socket(_FakeUDPTransport):
        async def bind(self, *_a: object, **_k: object) -> int:
            events.append("bind")
            return 51820

    sessions = _Sessions(events)
    with _multi(captured, sessions), patch("dsm.server.UDPTransport", _Socket):
        run = await _start()
        _Acceptor.made[0].admit(A, PEER_A)
        assert await _spin(lambda: len(sessions.started) == 1)
        rc = await _stop(run, captured)
    assert rc == 0
    assert events == [
        "bind",
        "host up",
        f"{A} started",
        f"{A} ended",
        "routing stopped",
        "host down",
    ]
    assert _FakeUDPTransport.made[-1].recv_queue_size == SERVER_RECV_QUEUE_PACKETS
    assert SERVER_RECV_QUEUE_PACKETS == 4096


async def test_a_takeover_ends_only_that_cns_old_session(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="dsm")
    captured: dict[str, Any] = {}
    sessions = _Sessions()
    with _multi(captured, sessions):
        run = await _start()
        acceptor = _Acceptor.made[0]
        acceptor.admit(A, PEER_A)
        acceptor.admit(B, PEER_B)
        acceptor.admit(A, PEER_A2)  # A comes back from a new port
        assert await _spin(
            lambda: len(sessions.started) == 3 and f"{A} ended" in sessions.events
        )
        old_a, b, new_a = sessions.started
        assert old_a.shutdown.is_set()
        assert not b.shutdown.is_set() and not new_a.shutdown.is_set()
        assert new_a.tunnel == old_a.tunnel
        table = captured["table"]
        assert table.by_tunnel(new_a.tunnel.client.packed) is new_a
        assert table.by_peer(PEER_A2) is new_a and table.by_peer(PEER_A) is None
        rc = await _stop(run, captured)
    assert rc == 0
    assert f"client reconnected (client_cn={A}); ending its old session" in [
        r.getMessage() for r in caplog.records
    ]


async def test_a_session_that_ends_by_itself_leaves_the_table(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="dsm.server")
    captured: dict[str, Any] = {}
    sessions = _Sessions()
    sessions.end_at_once.add(A)  # as a dead peer would end it
    with _multi(captured, sessions):
        run = await _start()
        _Acceptor.made[0].admit(A, PEER_A)
        assert await _spin(
            lambda: len(sessions.started) == 1 and not captured["table"].sessions()
        )
        assert not run.done()  # the server serves on
        rc = await _stop(run, captured)
    assert rc == 0
    assert f"session 1 ended (client_cn={A})" in [
        r.getMessage() for r in caplog.records
    ]


async def test_dns_state_is_forgotten_only_when_a_cn_has_no_newer_session() -> None:
    captured: dict[str, Any] = {}
    sessions = _Sessions()
    sessions.end_at_once.add(B)  # B's session ends by itself
    with _multi(captured, sessions):
        run = await _start()
        acceptor = _Acceptor.made[0]
        proxy = captured["host"].dns_proxy
        acceptor.admit(A, PEER_A)
        acceptor.admit(A, PEER_A2)  # a takeover: A's old session ends
        assert await _spin(lambda: f"{A} ended" in sessions.events)
        assert proxy.forgotten == []  # A's newer session keeps the cache
        acceptor.admit(B, PEER_B)
        assert await _spin(lambda: proxy.forgotten == ["10.8.0.3"])
        rc = await _stop(run, captured)  # A's last session ends at the stop
    assert rc == 0
    assert proxy.forgotten == ["10.8.0.3", "10.8.0.2"]


async def test_a_signal_stops_the_acceptor_then_every_session_then_the_host() -> None:
    captured: dict[str, Any] = {}
    events: list[str] = captured.setdefault("events", [])
    sessions = _Sessions(events)
    with _multi(captured, sessions):
        run = await _start()
        acceptor = _Acceptor.made[0]
        acceptor.admit(A, PEER_A)
        acceptor.admit(B, PEER_B)
        assert await _spin(lambda: len(sessions.started) == 2)
        rc = await _stop(run, captured)
    assert rc == 0
    assert acceptor.stops == 1
    assert acceptor.live_at_stop == [False, False]
    # Every session, then the routing, then the host state (spec §2.2).
    assert sorted(events[-4:-2]) == sorted([f"{A} ended", f"{B} ended"])
    assert events[-2:] == ["routing stopped", "host down"]


async def test_a_stop_that_raises_still_ends_every_session_before_the_host(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.ERROR, logger="dsm")
    captured: dict[str, Any] = {}
    events: list[str] = captured.setdefault("events", [])
    sessions = _Sessions(events)
    with _multi(captured, sessions):
        run = await _start()
        acceptor = _Acceptor.made[0]
        acceptor.stop_error = RuntimeError("a worker bug")
        acceptor.admit(A, PEER_A)
        acceptor.admit(B, PEER_B)
        assert await _spin(lambda: len(sessions.started) == 2)
        rc = await _stop(run, captured)
    assert rc == 0
    assert sorted(events[-4:-2]) == sorted([f"{A} ended", f"{B} ended"])
    assert events[-2:] == ["routing stopped", "host down"]
    (error,) = _errors(caplog)
    assert error.getMessage() == "handshake accept failed while stopping"
    assert error.exc_info is not None


async def test_a_cancel_still_ends_every_session_before_the_host() -> None:
    captured: dict[str, Any] = {}
    events: list[str] = captured.setdefault("events", [])
    sessions = _Sessions(events)
    with _multi(captured, sessions):
        run = await _start()
        acceptor = _Acceptor.made[0]
        acceptor.admit(A, PEER_A)
        acceptor.admit(B, PEER_B)
        assert await _spin(lambda: len(sessions.started) == 2)
        run.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await asyncio.wait_for(run, 5.0)
    assert run.cancelled()
    assert acceptor.stops == 1
    assert acceptor.live_at_stop == [False, False]
    assert sorted(events[-4:-2]) == sorted([f"{A} ended", f"{B} ended"])
    assert events[-2:] == ["routing stopped", "host down"]


async def test_a_second_cancel_during_the_stop_still_ends_the_sessions() -> None:
    captured: dict[str, Any] = {}
    events: list[str] = captured.setdefault("events", [])
    sessions = _Sessions(events)
    with _multi(captured, sessions):
        run = await _start()
        acceptor = _Acceptor.made[0]
        acceptor.stop_wait = asyncio.Event()  # never set: stop() waits
        acceptor.admit(A, PEER_A)
        assert await _spin(lambda: len(sessions.started) == 1)
        run.cancel()
        assert await _spin(lambda: acceptor.stops == 1)
        run.cancel()  # lands inside acceptor.stop()
        with contextlib.suppress(asyncio.CancelledError):
            await asyncio.wait_for(run, 5.0)
    assert run.cancelled()
    assert events[-3:] == [f"{A} ended", "routing stopped", "host down"]


async def test_frames_held_at_the_handshake_reach_the_new_session() -> None:
    captured: dict[str, Any] = {}
    sessions = _Sessions()
    with _multi(captured, sessions):
        run = await _start()
        _Acceptor.made[0].admit(A, PEER_A, held=(b"late frame 1", b"late frame 2"))
        assert await _spin(lambda: len(sessions.started) == 1)
        view = sessions.started[0].transport
        got = [await asyncio.wait_for(view.recv(), 1.0) for _ in range(2)]
        rc = await _stop(run, captured)
    assert rc == 0
    assert got == [(b"late frame 1", PEER_A), (b"late frame 2", PEER_A)]


async def test_tcp_connections_each_become_a_session() -> None:
    captured: dict[str, Any] = {}
    sessions = _Sessions()
    listener = _Listener()
    conn_a, conn_b = object(), object()

    async def _open(_config: Any) -> _Listener:
        return listener

    with _multi(captured, sessions), patch("dsm.server._open_tcp_listener", _open):
        run = await _start(
            replace(_server_config(), dns_blocklist=False, transport="tcp")
        )
        acceptor = _Acceptor.made[0]
        acceptor.admit(A, PEER_A, transport=conn_a)
        acceptor.admit(B, PEER_B, transport=conn_b)
        assert await _spin(lambda: len(sessions.started) == 2)
        rc = await _stop(run, captured)
    assert rc == 0
    assert acceptor.tcp is listener.connections and acceptor.udp is None
    assert [s.transport for s in sessions.started] == [conn_a, conn_b]


async def test_a_tun_read_error_stops_the_run_with_exit_1(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.ERROR, logger="dsm")
    captured: dict[str, Any] = {}
    events: list[str] = captured.setdefault("events", [])
    sessions = _Sessions(events)
    with _multi(captured, sessions):
        run = await _start()
        _Acceptor.made[0].admit(A, PEER_A)
        assert await _spin(lambda: len(sessions.started) == 1)
        captured["host"].tun.fail.set()
        rc = await asyncio.wait_for(run, 5.0)
    assert rc == 1
    (error,) = _errors(caplog)
    assert error.getMessage() == (
        "the tunnel device failed ([Errno 5] Input/output error); stopping"
    )
    assert error.exc_info is None
    assert events[-2:] == [f"{A} ended", "host down"]


async def test_a_routing_failure_during_the_stop_is_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.ERROR, logger="dsm")
    captured: dict[str, Any] = {}
    events: list[str] = captured.setdefault("events", [])
    sessions = _Sessions(events)
    fail = asyncio.Event()
    raised: list[OSError] = []

    class _Router:
        """Routes nothing until ``fail``; then fails as a TUN read would."""

        def __init__(self, *_a: Any) -> None:
            pass

        async def run(self) -> None:
            await fail.wait()
            raised.append(OSError(errno.EIO, os.strerror(errno.EIO)))
            raise raised[0]

    with _multi(captured, sessions), patch("dsm.server.TunRouter", _Router):
        run = await _start()
        acceptor = _Acceptor.made[0]
        acceptor.stop_wait = asyncio.Event()
        acceptor.admit(A, PEER_A)
        assert await _spin(lambda: len(sessions.started) == 1)
        captured["event"].set()  # as SIGTERM would
        assert await _spin(lambda: acceptor.stops == 1)
        fail.set()  # the TUN goes away while the run stops
        assert await _spin(lambda: bool(raised))
        acceptor.stop_wait.set()
        rc = await asyncio.wait_for(run, 5.0)
    assert rc == 0  # the signal came first
    (error,) = _errors(caplog)
    assert error.getMessage() == "packet routing failed while stopping"
    assert error.exc_info is not None and error.exc_info[1] is raised[0]
    assert events[-2:] == [f"{A} ended", "host down"]


async def test_a_dispatcher_bug_stops_the_run_with_exit_1(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.ERROR, logger="dsm")
    captured: dict[str, Any] = {}

    class _Broken:
        unmatched = 0

        def __init__(self, *_a: Any) -> None:
            pass

        async def run(self) -> None:
            raise RuntimeError("dispatcher bug")

    with _multi(captured, _Sessions()), patch("dsm.server.UDPDispatcher", _Broken):
        rc = await asyncio.wait_for(
            run_server(replace(_server_config(), dns_blocklist=False)), 5.0
        )
    assert rc == 1
    (error,) = _errors(caplog)
    assert error.getMessage() == "packet routing failed; stopping"
    assert error.exc_info is not None


async def test_a_host_setup_failure_at_start_exits_1_before_any_client(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.ERROR, logger="dsm")
    captured: dict[str, Any] = {}

    async def _broken(*_a: Any) -> Any:
        raise RuntimeError("TUN configure failed: ip link set mtun0 up")

    with _multi(captured, _Sessions()), patch("dsm.server._set_up_host", _broken):
        rc = await asyncio.wait_for(
            run_server(replace(_server_config(), dns_blocklist=False)), 5.0
        )
    assert rc == 1
    (error,) = _errors(caplog)
    assert error.getMessage() == (
        "could not set up the tunnel at start: "
        "TUN configure failed: ip link set mtun0 up; exiting"
    )
    assert error.exc_info is None
    assert _Acceptor.made == []


async def test_tunnel_addresses_that_cannot_be_built_exit_1_before_the_host(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.ERROR, logger="dsm")
    captured: dict[str, Any] = {}

    def _bad(_cns: Any) -> SessionTable:
        raise ValueError("10.8.0.2 is not in 10.8.0.0/24")

    with _multi(captured, _Sessions()), patch("dsm.server.SessionTable", _bad):
        rc = await asyncio.wait_for(
            run_server(replace(_server_config(), dns_blocklist=False)), 5.0
        )
    assert rc == 1
    (error,) = _errors(caplog)
    assert error.getMessage() == (
        "tunnel addresses could not be built: 10.8.0.2 is not in 10.8.0.0/24; "
        "exiting"
    )
    assert error.exc_info is None
    assert captured["events"] == []  # no host state was built
    assert _Acceptor.made == []


async def test_a_nat_table_that_does_not_load_exits_1_before_any_client(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Fail closed (roadmap item 1.8): the real host setup, with a NAT load
    # that fails.
    caplog.set_level(logging.ERROR, logger="dsm")
    captured: dict[str, Any] = {}
    with (
        _multi(captured, _Sessions()),
        _HostParts() as parts,
        patch("dsm.server._set_up_host", _set_up_host),  # the real one
    ):
        parts.nat_loads = False
        rc = await asyncio.wait_for(
            run_server(replace(_server_config(), dns_blocklist=False)), 5.0
        )
    assert rc == 1
    (error,) = _errors(caplog)
    assert error.getMessage() == (
        "could not set up the tunnel at start: the NAT table (MASQUERADE, "
        "client isolation, flow tags) did not load; exiting"
    )
    assert error.exc_info is None
    assert _Acceptor.made == []
    assert parts.proxy_args == {}
    assert parts.events[-2:] == ["forwarding off", "tun close"]


async def test_a_session_crash_ends_only_that_session(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.ERROR, logger="dsm")
    captured: dict[str, Any] = {}
    sessions = _Sessions()
    sessions.fail.add(A)
    with _multi(captured, sessions):
        run = await _start()
        acceptor = _Acceptor.made[0]
        acceptor.admit(A, PEER_A)
        acceptor.admit(B, PEER_B)
        assert await _spin(
            lambda: len(sessions.started) == 2 and f"{A} ended" in sessions.events
        )
        a, b = sessions.started
        assert captured["table"].sessions() == [b]
        assert sessions.fsms[0].state is State.IDLE  # its closing FSM lines ran
        assert not b.shutdown.is_set()
        sessions.fail.clear()
        acceptor.admit(A, PEER_A2)  # the client comes back: served again
        assert await _spin(lambda: len(sessions.started) == 3)
        rc = await _stop(run, captured)
    assert rc == 0
    (error,) = _errors(caplog)
    assert error.getMessage() == (
        f"session 1 failed (client_cn={A}); other clients are not affected"
    )
    assert error.exc_info is not None


NEW_PEER = ("203.0.113.77", 41000)


class _Sock(_FakeUDPTransport):
    """The run's socket under one session's view."""


class _AlwaysValid:
    """PathValidationState stand-in: every PATH_RESPONSE validates; no
    challenge is ever queued."""

    valid = True

    def validate(self, _addr: Any, _payload: bytes) -> bool:
        return self.valid

    def clear(self) -> None:
        pass

    def should_challenge(self, _addr: Any) -> None:
        return None


class _NeverValid(_AlwaysValid):
    """Every PATH_RESPONSE fails validation."""

    valid = False


@pytest.mark.parametrize(
    ("validator", "moves"), [(_AlwaysValid, True), (_NeverValid, False)]
)
async def test_egress_starts_at_the_peer_and_only_a_validated_roam_moves_it(
    validator: type[_AlwaysValid], moves: bool
) -> None:
    table = SessionTable([A])
    attempt = object()
    client = VerifiedClient(cn=A, noise_static=b"\x01" * 32)
    table.admit(attempt, client)
    _, tunnel = table.confirm(attempt)
    table.release(attempt)
    session = ServerSession(
        number=1,
        client=client,
        tunnel=tunnel,
        session_keys=_Keys(),  # type: ignore[arg-type]
        transport=_SessionUDPView(_Sock(), lambda: 0),
        shutdown=asyncio.Event(),
        tun_queue=asyncio.Queue(),
        peer=PEER_A,
    )
    table.add(session)
    seen: dict[str, Any] = {}

    def _send_fn(
        _keys: Any, _transport: Any, dest_addr: Any, *_a: Any, **_k: Any
    ) -> Any:
        seen["dest"] = dest_addr
        return _noop_send

    async def _loops(*_a: Any, post_authenticate: Any, **_k: Any) -> None:
        seen["first"] = seen["dest"]()  # before any packet arrived
        # A packet that merely opens, from another address, moves nothing.
        await post_authenticate(NEW_PEER, InnerPacket(PacketType.DATA, 0, b""))
        seen["after_data"] = (seen["dest"](), table.by_peer(PEER_A))
        await post_authenticate(
            NEW_PEER, InnerPacket(PacketType.PATH_RESPONSE, 0, bytes(16))
        )

    fsm = SessionFSM()
    fsm.transition(State.CONNECTING)
    fsm.transition(State.HANDSHAKING)
    with (
        patch("dsm.server.make_send_fn", _send_fn),
        patch("dsm.server.SendScheduler", _FakeScheduler),
        patch("dsm.server.PathValidationState", validator),
        patch("dsm.session.run_data_loops", _loops),
    ):
        await server._run_one_session(
            _server_config(),
            fsm,
            _FakeStore(),  # type: ignore[arg-type]
            session,
            ClientTun(_FakeTun(), session, server._TUNNEL.network),  # type: ignore[arg-type]
            lambda addr: table.note_peer(session, addr),
        )
    assert seen["first"] == PEER_A
    assert seen["after_data"] == (PEER_A, session)
    if moves:
        assert seen["dest"]() == NEW_PEER
        assert table.by_peer(NEW_PEER) is session and table.by_peer(PEER_A) is None
    else:
        assert seen["dest"]() == PEER_A
        assert table.by_peer(PEER_A) is session and table.by_peer(NEW_PEER) is None
