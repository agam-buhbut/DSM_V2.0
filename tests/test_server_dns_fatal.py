"""run_server and the DNS proxy (multi-client spec §2.2, §5): the proxy is
built once, at start. A busy :53 there stops the server with one ERROR line
and exit code 1, before any client is served.

Also the run_server fakes other test files share: ``_server_config``,
``_base_patches`` (host I/O, keys, stores and the host setup faked at the
boundary; no root, no network, no real TUN, nftables or DNS) and
``_run_until``.
"""

from __future__ import annotations

import asyncio
import errno
import logging
import os
from collections.abc import Callable, Generator
from contextlib import AsyncExitStack, contextmanager
from typing import Any
from unittest.mock import patch

import pytest

from dsm.core.config import Config
from dsm.net.dns_proxy import DNSProxyPortInUseError
from dsm.net.handshake_gate import GateKeys
from dsm.net.transport.udp import RECV_QUEUE_SIZE
from dsm.server import _Host, run_server
from tests.test_handshake_acceptor_limits import _spin


def _server_config() -> Config:
    return Config(
        mode="server",
        server_ip="0.0.0.0",
        server_port=51820,
        listen_port=51820,
        key_file="/tmp/dsm-test.key",
        cert_file="/tmp/dsm-test.crt",
        ca_root_file="/tmp/dsm-test-ca.pem",
        attest_key_file="/tmp/dsm-test-attest.key",
        allowed_cns_file="/tmp/dsm-test-allowed-cns.txt",
        transport="udp",
        dns_providers=["https://10.0.0.53/dns-query"],
        dns_provider_pins={"https://10.0.0.53/dns-query": ["a" * 64]},
    )


class _NonEmptyAllowlist:
    """Duck-typed CNAllowlist: one name, so run_server does not abort."""

    order = ("dsm-a-client",)

    def __len__(self) -> int:
        return 1


class _FakeMaterials:
    cert_der = b""
    ca_root = object()
    crl = None


class _FakeStore:
    def __init__(self, *_a: object, **_k: object) -> None:
        self.identity = type("_Id", (), {"public_key": b"\x00" * 32})()
        self.attest_key = object()

    def unload(self) -> None:
        pass


class _SyncManager:
    def __init__(self, *_a: object, **_k: object) -> None:
        pass

    def apply(self) -> None:
        pass

    def remove(self) -> None:
        pass


class _FakeScheduler:  # pyright: ignore[reportUnusedClass]  # other test files use it
    def __init__(self, *_a: object, **_k: object) -> None:
        pass

    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        pass


class _FakeUDPTransport:
    """The run's UDP socket: it binds, never receives, and records sends."""

    made: list[_FakeUDPTransport] = []

    def __init__(self, *, recv_queue_size: int = RECV_QUEUE_SIZE) -> None:
        self.recv_queue_size = recv_queue_size
        self.sent: list[tuple[bytes, tuple[str, int]]] = []
        _FakeUDPTransport.made.append(self)

    async def bind(self, *_a: object, **_k: object) -> int:
        return 51820

    async def recv(self, timeout: float | None = None) -> tuple[bytes, tuple[str, int]]:
        del timeout
        await asyncio.Event().wait()  # nothing arrives; ends when cancelled
        raise AssertionError("unreachable")

    def recv_drops(self) -> int:
        return 0

    async def send(self, data: bytes, addr: tuple[str, int]) -> None:
        self.sent.append((bytes(data), addr))

    async def aclose(self) -> None:
        pass


class _FakeTun:
    """The shared TUN as the router reads it: nothing, until ``fail`` is set;
    then it fails like a TUN device that went away. With ``events``, a read
    the stop cancels writes ``routing stopped`` there."""

    def __init__(self, events: list[str] | None = None) -> None:
        self.fail = asyncio.Event()
        self.written: list[bytes] = []
        self._events = events

    async def read(self) -> bytes:
        try:
            await self.fail.wait()
        except asyncio.CancelledError:
            if self._events is not None:
                self._events.append("routing stopped")
            raise
        raise OSError(errno.EIO, os.strerror(errno.EIO))

    async def awrite(self, data: bytes) -> int:
        self.written.append(bytes(data))
        return len(data)


class _FakeDNSProxy:
    def __init__(self) -> None:
        self.forgotten: list[str] = []

    def forget(self, client_ip: str) -> None:
        self.forgotten.append(client_ip)


async def _noop_send(  # pyright: ignore[reportUnusedFunction]  # other test files use it
    *_a: object,
    **_k: object,
) -> None:
    pass


async def _fake_host(  # pyright: ignore[reportUnusedFunction]  # other test files use it
    *_a: object,
) -> _Host:
    """Stands in for _set_up_host: sets up nothing."""
    return _Host(tun=_FakeTun(), dns_proxy=_FakeDNSProxy())  # type: ignore[arg-type]


@contextmanager
def _base_patches(captured: dict[str, Any]) -> Generator[None, None, None]:
    """Fake everything run_server touches on the host.

    ``captured`` gets ``event`` (the ``process_shutdown`` event the signal
    handlers would set), and from the faked host setup ``host`` (a ``_Host``
    with a ``_FakeTun`` and a ``_FakeDNSProxy``), ``blocklist`` and
    ``table``; ``captured["events"]`` gets ``host up``, ``routing stopped``
    and ``host down``. The acceptor, the dispatcher and the router are real:
    with no packets they only wait.
    """
    events: list[str] = captured.setdefault("events", [])

    def _capture_signal_handlers(shutdown: asyncio.Event) -> None:
        captured["event"] = shutdown

    async def _set_up_host(
        config: Config, stack: AsyncExitStack, blocklist: Any, table: Any
    ) -> _Host:
        del config
        host = _Host(tun=_FakeTun(events), dns_proxy=_FakeDNSProxy())  # type: ignore[arg-type]
        captured.update(host=host, blocklist=blocklist, table=table)
        events.append("host up")
        stack.callback(events.append, "host down")
        return host

    _FakeUDPTransport.made = []
    patches = [
        patch("tuncore.harden_process"),
        patch("dsm.core.hardening.set_process_nondumpable"),
        patch("dsm.crypto.attest_gate.enforce_attest_backend_policy"),
        patch("dsm.server.load_cert_materials", return_value=_FakeMaterials()),
        patch(
            "dsm.server.server_gate_keys",
            return_value=GateKeys(mac1_key=bytes(32), cookie_key=bytes(32)),
        ),
        patch("dsm.server.verify_cert_matches_identity"),
        patch("dsm.server.CNAllowlist.from_file", return_value=_NonEmptyAllowlist()),
        patch("dsm.crypto._stores.load_daemon_stores", return_value=True),
        patch("dsm.server.KeyStore", _FakeStore),
        patch("dsm.server.AttestStore", _FakeStore),
        patch("dsm.server.ServerRateLimitManager", _SyncManager),
        patch("dsm.server.TcpTimestampsDisabler", _SyncManager),
        patch("dsm.server.UDPTransport", _FakeUDPTransport),
        patch("dsm.server.setup_signal_handlers", _capture_signal_handlers),
        patch("dsm.server._set_up_host", _set_up_host),
    ]
    for p in patches:
        p.start()
    try:
        yield
    finally:
        for p in reversed(patches):
            p.stop()


async def _run_until(  # pyright: ignore[reportUnusedFunction]  # other test files use it
    config: Config, captured: dict[str, Any], until: Callable[[], bool] = lambda: True
) -> int:
    """Under ``_base_patches(captured)``: run run_server until its host is
    up and ``until()`` holds, then stop it as a signal would; its exit code."""
    run = asyncio.ensure_future(run_server(config))
    assert await _spin(lambda: run.done() or ("host" in captured and until()))
    if not run.done():
        captured["event"].set()
    return await asyncio.wait_for(run, 5.0)


async def test_a_busy_dns_port_at_start_exits_1_before_any_client(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.ERROR, logger="dsm")
    captured: dict[str, Any] = {}
    acceptors: list[Any] = []

    async def _busy(*_a: object) -> _Host:
        raise DNSProxyPortInUseError(
            "DNS proxy cannot bind 10.8.0.1:53 — another resolver is already "
            "bound there. Stop the host resolver, or change the TUN address."
        )

    with (
        _base_patches(captured),
        patch("dsm.server._set_up_host", _busy),
        patch("dsm.server.ClientAcceptor", lambda *a, **_k: acceptors.append(a)),
    ):
        rc = await asyncio.wait_for(run_server(_server_config()), 5.0)
    assert rc == 1
    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert len(errors) == 1
    assert errors[0].getMessage().startswith("FATAL: DNS proxy port conflict — ")
    assert errors[0].exc_info is None
    assert acceptors == []  # no client could be served
