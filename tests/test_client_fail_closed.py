"""The client never fails open: only a stop the user asks for takes the kill
switch down.

``run_client`` runs with every host and network part faked, as in
tests/test_rp_filter_strict.py. Each host step is written to ``events``, and
``_tables_after`` replays them the way nft would, so a test can check that a
kill-switch table is up at every step. The waits between tries go through a
fake ``_wait_or_stop`` that records each wait and can stop DSM during it, so
nothing sleeps.
"""

from __future__ import annotations

import asyncio
import errno
import logging
import os
from contextlib import ExitStack
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

import dsm.client as client_mod
from dsm.core.config import Config
from dsm.crypto.handshake import (
    CertAuthError,
    CertRevokedError,
    CNMismatchError,
    HandshakeError,
)
from dsm.net._addresses import SINGLE_CLIENT_TUNNEL
from dsm.net.resolv_conf import ResolvConfError
from dsm.net.transport.tcp import FramingError


def _config(**changes: Any) -> Config:
    values: dict[str, Any] = {
        "mode": "client",
        "server_ip": "10.0.0.1",
        "server_port": 51820,
        "listen_port": 0,
        "key_file": "/tmp/dsm-test.key",
        "cert_file": "/tmp/dsm-test.crt",
        "ca_root_file": "/tmp/dsm-test-ca.pem",
        "attest_key_file": "/tmp/dsm-test-attest.key",
        "expected_server_cn": "dsm-test-server",
        "transport": "udp",
    }
    values.update(changes)
    return Config(**values)


def _tables_after(events: list[str]) -> set[str]:
    """The kill-switch tables nft would hold after these steps."""
    tables: set[str] = set()
    for event in events:
        if event == "pre.apply":  # replaces every client table (Task 1)
            tables = {"pre"}
        elif event == "nft.apply":  # one commit: the pre table out, full in
            tables = {"full"}
        elif event == "pre.remove":
            tables.discard("pre")
        elif event == "nft.remove":
            tables.discard("full")
    return tables


class _Materials:
    cert_der = b""
    ca_root = object()
    crl = None


class _Identity:
    public_key = b"\x01" * 32


class _FakeStore:
    def __init__(self, *_a: object, **_k: object) -> None:
        self.identity = _Identity()
        self.attest_key = object()

    def unload(self) -> None:
        pass


class _FakeKeys:
    epoch = 0


class _FakeScheduler:
    def __init__(self, *_a: object, **_k: object) -> None:
        pass

    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        pass


async def _no_send(_data: bytes, _target_size: int) -> None:
    pass


class _Run:
    """One faked ``run_client`` run. Set the fields, then ``await run()``."""

    def __init__(self) -> None:
        self.events: list[str] = []
        self.waits: list[float] = []
        self.blocked_during_waits: list[bool] = []
        self.stops: list[asyncio.Event] = []
        # Per try, in order: None for a good handshake, or the error it raises.
        self.handshakes: list[BaseException | None] = []
        # Per UDP bind / TCP connect, in order: None, or the error it raises.
        self.bind_errors: list[BaseException | None] = []
        self.connect_errors: list[BaseException | None] = []
        # Per session, in order: True if the user stops DSM during it.
        self.stop_in_session: list[bool] = []
        # An error the session raises (a bug in a live session).
        self.session_error: BaseException | None = None
        # The user stops DSM during this wait (1 = the first); None: never.
        self.stop_at_wait: int | None = None
        # Errors a host step raises, e.g. {"tun": {"configure": RuntimeError()}}.
        self.raise_on: dict[str, dict[str, BaseException]] = {}

    def _recorder(self, name: str) -> type:
        events = self.events
        failures = self.raise_on.get(name, {})

        class _Rec:
            def __init__(self, *_a: object, **_k: object) -> None:
                pass

            def _step(self, step: str) -> None:
                events.append(f"{name}.{step}")
                if step in failures:
                    raise failures[step]

            def apply(self) -> None:
                self._step("apply")

            def remove(self) -> None:
                self._step("remove")

            def open(self) -> None:
                self._step("open")

            def configure(self, *_a: object, **_k: object) -> None:
                self._step("configure")

            def close(self) -> None:
                self._step("close")

        return _Rec

    def _udp(self) -> type:
        events = self.events
        errors = self.bind_errors

        class _FakeUdp:
            async def bind(self, *_a: object, **_k: object) -> int:
                events.append("transport.bind")
                error = errors.pop(0) if errors else None
                if error is not None:
                    raise error
                return 0

            def get_path_mtu(self) -> int | None:
                return None

            async def aclose(self) -> None:
                events.append("transport.aclose")

        return _FakeUdp

    def _tcp(self) -> type:
        events = self.events
        errors = self.connect_errors

        class _FakeTcp:
            async def connect(self, *_a: object, **_k: object) -> None:
                events.append("transport.connect")
                error = errors.pop(0) if errors else None
                if error is not None:
                    raise error

            async def aclose(self) -> None:
                events.append("transport.aclose")

        return _FakeTcp

    async def handshake(
        self, *_a: object, **_k: object
    ) -> tuple[Any, bytes, bytes, Any]:
        self.events.append("handshake")
        error = self.handshakes.pop(0) if self.handshakes else None
        if error is not None:
            raise error
        return _FakeKeys(), b"", b"\x02" * 32, SINGLE_CLIENT_TUNNEL

    async def data_loops(
        self, *_a: object, extra_loops: tuple[Any, ...] = (), **_k: object
    ) -> None:
        for loop in extra_loops:
            loop.close()  # never started here
        self.events.append("session")
        if self.session_error is not None:
            raise self.session_error
        stop = self.stop_in_session.pop(0) if self.stop_in_session else False
        if stop:
            self.stops[0].set()

    async def wait(self, shutdown: asyncio.Event, delay: float) -> bool:
        self.waits.append(delay)
        self.events.append("wait")
        self.blocked_during_waits.append(bool(_tables_after(self.events)))
        if self.stop_at_wait == len(self.waits):
            shutdown.set()
            return True
        return False

    async def run(self, config: Config | None = None, handshake: Any = None) -> int:
        patches = [
            patch("tuncore.harden_process"),
            patch("dsm.core.hardening.set_process_nondumpable"),
            patch("dsm.crypto.attest_gate.enforce_attest_backend_policy"),
            patch("dsm.client.setup_signal_handlers", self.stops.append),
            patch("dsm.client.load_cert_materials", return_value=_Materials()),
            patch("dsm.client.verify_cert_matches_identity"),
            patch("dsm.crypto._stores.load_daemon_stores", return_value=True),
            patch("dsm.client.KeyStore", _FakeStore),
            patch("dsm.client.AttestStore", _FakeStore),
            patch("dsm.client.PreHandshakeKillSwitch", self._recorder("pre")),
            patch("dsm.client.check_clock_sync", return_value=None),
            patch("dsm.client.UDPTransport", self._udp()),
            patch("dsm.client.TCPTransport", self._tcp()),
            patch("dsm.crypto.handshake.client_handshake", handshake or self.handshake),
            patch("dsm.client.TcpTimestampsDisabler", self._recorder("tcp_ts")),
            patch("dsm.client.SrcValidMarkEnabler", self._recorder("svm")),
            patch("dsm.client.TunDevice", self._recorder("tun")),
            patch("dsm.client.NFTablesManager", self._recorder("nft")),
            patch("dsm.client.ResolvConfManager", self._recorder("resolv")),
            patch("dsm.client.make_send_fn", return_value=_no_send),
            patch("dsm.client.TrafficShaper"),
            patch("dsm.client.SendScheduler", _FakeScheduler),
            patch("dsm.session.run_data_loops", self.data_loops),
            patch("dsm.client._wait_or_stop", self.wait),
        ]
        with ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            return await asyncio.wait_for(
                client_mod.run_client(config or _config()), timeout=10
            )


async def test_a_failed_handshake_keeps_the_block_and_tries_again() -> None:
    run = _Run()
    run.handshakes = [HandshakeError("timed out"), HandshakeError("timed out")]
    run.stop_at_wait = 2  # Ctrl-C during the second wait

    rc = await run.run()

    assert rc == 0
    assert run.events.count("handshake") == 2
    assert run.waits == [1.0, 2.0]
    assert run.blocked_during_waits == [True, True]
    # A fresh socket for each try.
    assert run.events.count("transport.bind") == 2
    assert run.events.count("transport.aclose") == 2
    # Only the stop takes the kill switch down, as the very last step.
    assert run.events.count("pre.remove") == 1
    assert run.events[-1] == "pre.remove"


async def test_a_dropped_session_swaps_back_to_the_pre_table_and_reconnects() -> None:
    run = _Run()
    run.stop_in_session = [False, True]  # the first drops; Ctrl-C in the second

    rc = await run.run()

    assert rc == 0
    assert run.events.count("session") == 2
    assert run.waits == [1.0]
    assert run.blocked_during_waits == [True]
    assert "nft.remove" not in run.events
    first = run.events.index("session")
    swap = run.events.index("pre.apply", first)
    # resolv.conf back, the TUN closed under the full kill switch, then the
    # swap back to the pre table: all before the wait.
    assert run.events.index("resolv.remove", first) < run.events.index(
        "tun.close", first
    )
    assert run.events.index("tun.close", first) < swap < run.events.index("wait")
    assert run.events[-1] == "pre.remove"


async def test_there_is_never_a_moment_without_a_kill_switch_table() -> None:
    run = _Run()
    run.handshakes = [HandshakeError("lost"), None, None]
    run.stop_in_session = [False, True]

    rc = await run.run()

    assert rc == 0
    assert run.waits == [1.0, 1.0]
    start = run.events.index("pre.apply")
    last = len(run.events) - 1
    assert run.events[last] == "pre.remove"
    for i in range(start + 1, last + 1):
        assert _tables_after(run.events[:i]), run.events[:i]


@pytest.mark.parametrize(
    "error",
    [
        CertAuthError("server attestation verify failed"),
        CNMismatchError("server CN 'x' does not match expected 'y'"),
        CertRevokedError("server cert serial 7 is revoked"),
    ],
)
async def test_a_cert_error_from_the_network_keeps_the_block(error: Exception) -> None:
    # Someone on the path can send a bad or revoked cert in msg2; that must
    # not be a way to turn the kill switch off.
    run = _Run()
    run.handshakes = [error]
    run.stop_at_wait = 1

    rc = await run.run()

    assert rc == 0
    assert run.blocked_during_waits == [True]
    assert run.events[-1] == "pre.remove"


async def test_a_stop_during_the_handshake_ends_it_at_once() -> None:
    run = _Run()
    cancelled: list[bool] = []

    async def stuck(*_a: object, **_k: object) -> tuple[Any, bytes, bytes]:
        run.stops[0].set()  # Ctrl-C while the handshake waits for the server
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancelled.append(True)
            raise
        raise AssertionError("not reached")

    rc = await run.run(handshake=stuck)

    assert rc == 0
    assert cancelled == [True]
    assert run.waits == []
    assert run.events[-1] == "pre.remove"


async def test_a_bad_tcp_frame_in_the_handshake_keeps_the_block_and_tries_again(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Someone on the path can reset the connection and then send a length
    # over the limit. That must not end the retry loop.
    run = _Run()
    bad_frame = FramingError("frame length 4294967295 exceeds max 65536")
    run.handshakes = [bad_frame, bad_frame]
    run.stop_at_wait = 2
    caplog.set_level(logging.ERROR, logger="dsm")

    rc = await run.run(_config(transport="tcp"))

    assert rc == 0
    assert run.events.count("handshake") == 2
    assert run.waits == [1.0, 2.0]
    assert run.blocked_during_waits == [True, True]
    assert run.events[-1] == "pre.remove"
    messages = [r.getMessage() for r in caplog.records]
    assert "handshake failed: FramingError" in messages
    assert not any("4294967295" in m for m in messages)


async def test_a_tcp_connect_error_is_retried_and_names_no_address(
    caplog: pytest.LogCaptureFixture,
) -> None:
    run = _Run()
    run.connect_errors = [
        ConnectionRefusedError(
            errno.ECONNREFUSED, "Connect call failed ('10.0.0.1', 51820)"
        )
    ]
    run.stop_at_wait = 1
    caplog.set_level(logging.WARNING, logger="dsm")

    rc = await run.run(_config(transport="tcp"))

    assert rc == 0
    assert run.blocked_during_waits == [True]
    messages = [r.getMessage() for r in caplog.records]
    assert "cannot connect to the server: Connection refused" in messages
    assert not any("10.0.0.1" in m for m in messages)


async def test_a_port_in_use_after_the_first_try_keeps_the_block() -> None:
    run = _Run()
    run.handshakes = [HandshakeError("lost")]
    run.bind_errors = [
        None,
        OSError(errno.EADDRINUSE, os.strerror(errno.EADDRINUSE)),
    ]
    run.stop_at_wait = 2

    rc = await run.run()

    assert rc == 0
    assert run.events.count("transport.bind") == 2
    assert run.blocked_during_waits == [True, True]


async def test_a_resolv_conf_error_after_the_first_try_keeps_the_block() -> None:
    run = _Run()
    run.handshakes = [HandshakeError("lost")]
    run.raise_on = {
        "resolv": {
            "apply": ResolvConfError(Path("/etc/resolv.conf"), "Read-only file system")
        }
    }
    run.stop_at_wait = 2

    rc = await run.run()

    assert rc == 0
    assert "nft.remove" not in run.events
    assert run.blocked_during_waits == [True, True]


async def test_an_error_while_setting_up_the_tunnel_leaves_the_block_up(
    caplog: pytest.LogCaptureFixture,
) -> None:
    run = _Run()
    run.raise_on = {"tun": {"configure": RuntimeError("boom")}}
    caplog.set_level(logging.ERROR, logger="dsm")

    with pytest.raises(RuntimeError, match="boom"):
        await run.run()

    assert "pre.remove" not in run.events
    assert "tun.close" in run.events
    assert _tables_after(run.events) == {"pre"}
    assert any("left the kill switch up" in r.getMessage() for r in caplog.records)


async def test_an_error_in_a_live_session_swaps_back_and_keeps_the_block() -> None:
    run = _Run()
    run.session_error = RuntimeError("bug")

    with pytest.raises(RuntimeError, match="bug"):
        await run.run()

    assert "pre.remove" not in run.events
    assert "nft.remove" not in run.events
    session = run.events.index("session")
    assert run.events.index("tun.close", session) < run.events.index(
        "pre.apply", session
    )
    assert _tables_after(run.events) == {"pre"}


async def test_the_outage_notice_comes_once_per_outage(
    caplog: pytest.LogCaptureFixture,
) -> None:
    run = _Run()
    run.handshakes = [
        HandshakeError("a"),
        HandshakeError("b"),
        None,
        HandshakeError("c"),
    ]
    run.stop_in_session = [False]
    run.stop_at_wait = 4
    caplog.set_level(logging.WARNING, logger="dsm")

    with patch("dsm.client.OUTAGE_NOTICE_EVERY_S", 0.0):
        rc = await run.run()

    assert rc == 0
    assert run.waits == [1.0, 2.0, 1.0, 2.0]
    notices = [
        r.getMessage()
        for r in caplog.records
        if "all traffic is blocked" in r.getMessage()
    ]
    # One for the outage at start, one after the session dropped.
    assert len(notices) == 2


async def test_a_name_is_looked_up_once_and_the_hint_names_no_address(
    caplog: pytest.LogCaptureFixture, tmp_path: Path
) -> None:
    run = _Run()
    run.handshakes = [HandshakeError("lost") for _ in range(5)]
    run.stop_at_wait = 5
    lookup = AsyncMock(return_value="10.0.0.1")
    caplog.set_level(logging.WARNING, logger="dsm")

    with (
        patch("dsm.client._resolve_server_endpoint", lookup),
        # Keep the saved-address file (F3) in tmp_path.
        patch("dsm.client._SERVER_ENDPOINT_FILE", tmp_path / "server-endpoint.json"),
    ):
        rc = await run.run(_config(server_ip="vpn.example.org"))

    assert rc == 0
    lookup.assert_awaited_once()
    hints = [
        r.getMessage()
        for r in caplog.records
        if r.getMessage().startswith("server IP may have changed")
    ]
    assert len(hints) == 1
    assert "vpn.example.org" not in hints[0]
    assert "10.0.0.1" not in hints[0]


async def test_a_failed_lookup_with_no_saved_address_exits(
    caplog: pytest.LogCaptureFixture, tmp_path: Path
) -> None:
    run = _Run()
    caplog.set_level(logging.ERROR, logger="dsm")
    lookup = AsyncMock(side_effect=OSError("timed out resolving server hostname"))

    with (
        patch("dsm.client._resolve_server_endpoint", lookup),
        # No saved address (F3): this file does not exist.
        patch("dsm.client._SERVER_ENDPOINT_FILE", tmp_path / "server-endpoint.json"),
    ):
        rc = await run.run(_config(server_ip="vpn.example.org"))

    assert rc == 1
    assert run.events == []  # a kill switch a crash left stays as it is
    assert any("sudo dsm cleanup" in r.getMessage() for r in caplog.records)
