"""Phase 1.8: daemon lifecycle correctness.

Covers all four sub-parts:

  * Part A — ``run_client`` / ``run_server`` return ``int`` exit codes
    (nonzero on error paths, 0 on clean shutdown) and ``main()``
    ``sys.exit``s the value.
  * Part B — the client installs signal handlers BEFORE the
    pre-handshake kill switch, so a SIGTERM during connect unwinds the
    AsyncExitStack instead of leaving the kill switch applied.
  * Part C — the server runs until a signal: a session that ends on its own
    (dead-peer timeout / peer SESSION_CLOSE / rekey give-up) ends only
    itself and the acceptor keeps serving, while a process shutdown
    (SIGTERM) ends every session. See ``ServerKeepsServing``.
  * Part D — ``main()`` config-load failures print ``config: <msg>`` to
    stderr and ``sys.exit(2)`` rather than surfacing a raw traceback.

Mocking is confined to I/O / hardening boundaries (``tuncore`` syscalls,
``set_process_nondumpable``, the host-state managers) plus the one
collaborator each test forces to fail; no network, no root, no real
filesystem mutation.
"""

from __future__ import annotations

import asyncio
import io
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from dsm.core.config import Config


def _client_config() -> Config:
    return Config(
        mode="client",
        server_ip="10.0.0.1",
        server_port=51820,
        listen_port=0,
        key_file="/tmp/dsm-test.key",
        cert_file="/tmp/dsm-test.crt",
        ca_root_file="/tmp/dsm-test-ca.pem",
        attest_key_file="/tmp/dsm-test-attest.key",
        expected_server_cn="dsm-test-server",
        transport="udp",
    )


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
        # Phase 1.10: DNS providers must be IP literals (a hostname provider
        # dead-loops through the TUN), so this fixture uses an IP-literal host.
        dns_providers=["https://10.0.0.53/dns-query"],
        dns_provider_pins={"https://10.0.0.53/dns-query": ["a" * 64]},
    )


class ClientExitCode(unittest.IsolatedAsyncioTestCase):
    async def test_run_client_returns_nonzero_on_attest_policy_failure(self) -> None:
        from dsm.client import run_client
        from dsm.crypto.attest_gate import SoftAttestNotAllowedError

        cfg = _client_config()
        with (
            patch("tuncore.harden_process"),
            patch("dsm.core.hardening.set_process_nondumpable"),
            patch(
                "dsm.crypto.attest_gate.enforce_attest_backend_policy",
                side_effect=SoftAttestNotAllowedError("nope"),
            ),
        ):
            rc = await run_client(cfg)
        self.assertIsInstance(rc, int)
        self.assertNotEqual(rc, 0)


class ServerExitCode(unittest.IsolatedAsyncioTestCase):
    async def test_run_server_returns_nonzero_on_attest_policy_failure(self) -> None:
        from dsm.crypto.attest_gate import SoftAttestNotAllowedError
        from dsm.server import run_server

        cfg = _server_config()
        with (
            patch("tuncore.harden_process"),
            patch("dsm.core.hardening.set_process_nondumpable"),
            patch(
                "dsm.crypto.attest_gate.enforce_attest_backend_policy",
                side_effect=SoftAttestNotAllowedError("nope"),
            ),
        ):
            rc = await run_server(cfg)
        self.assertIsInstance(rc, int)
        self.assertNotEqual(rc, 0)


class MainPropagatesExitCode(unittest.TestCase):
    """``main()`` must ``sys.exit`` the daemon's return value so a nonzero
    exit reaches systemd (``Restart=on-failure``) and a clean shutdown is 0.
    """

    def test_main_exits_with_run_client_return_value(self) -> None:
        import dsm.__main__ as entry

        argv = ["dsm", "--mode", "client"]
        with (
            patch.object(entry.os, "geteuid", return_value=0),  # main() wants root
            patch.object(entry.sys, "argv", argv),
            patch.object(entry, "_load_config_or_exit", return_value=_client_config()),
            patch("dsm.core.log.configure"),
            patch("dsm.core.netaudit.configure"),
            patch("dsm.client.run_client", new_callable=MagicMock) as run_client_mock,
            patch.object(entry.asyncio, "run", return_value=7) as run_mock,
        ):
            # asyncio.run is mocked to return the sentinel directly, so
            # nothing awaits what run_client returns. patch() would make an
            # AsyncMock for this async function, and calling it creates a
            # coroutine that is never awaited ("coroutine was never awaited"
            # warning). A plain MagicMock creates none.
            run_client_mock.return_value = None
            with self.assertRaises(SystemExit) as cm:
                entry.main()
        self.assertEqual(cm.exception.code, 7)
        run_mock.assert_called_once()


class ClientSignalOrdering(unittest.TestCase):
    def test_signal_handlers_set_up_before_pre_killswitch(self) -> None:
        import inspect

        from dsm import client

        src = inspect.getsource(client.run_client)
        idx_handlers = src.find("setup_signal_handlers(shutdown)")
        idx_killswitch = src.find("pre_killswitch.apply()")
        self.assertNotEqual(idx_handlers, -1)
        self.assertNotEqual(idx_killswitch, -1)
        self.assertLess(
            idx_handlers,
            idx_killswitch,
            "signal handlers must be installed before the pre-handshake "
            "kill switch (Phase 1.8 H10)",
        )

    def test_shutdown_event_created_once(self) -> None:
        """The early shutdown event must be the SAME one reused by the data
        path — a second ``asyncio.Event()`` would mean signals set an event
        nobody waits on. Guard against a regression that re-introduces the
        duplicate.
        """
        import inspect

        from dsm import client

        src = inspect.getsource(client.run_client)
        self.assertEqual(
            src.count("shutdown = asyncio.Event()"),
            1,
            "run_client must create the shutdown event exactly once",
        )


class ClientSigtermDuringHandshakeUnwinds(unittest.IsolatedAsyncioTestCase):
    """A SIGTERM-equivalent (shutdown set) during the connect/handshake
    window must unwind the AsyncExitStack — i.e. the pre-handshake kill
    switch's ``remove`` must run — rather than leaking the rules.

    This is the behavioural counterpart to the source-order assertion: it
    drives ``run_client`` up to the handshake, sets the shutdown event the
    signal handler would set, and asserts ``PreHandshakeKillSwitch.remove``
    was invoked during teardown.
    """

    async def test_sigterm_window_removes_pre_killswitch(self) -> None:
        from dsm.crypto.handshake import HandshakeError

        cfg = _client_config()

        applied = {"value": False}
        removed = {"value": False}

        class _FakeKillSwitch:
            def __init__(self, *_a: object, **_k: object) -> None:
                pass

            def apply(self) -> None:
                applied["value"] = True

            def remove(self) -> None:
                removed["value"] = True

        # Materials / store doubles: make load succeed so we reach the
        # AsyncExitStack and the kill switch, then fail the handshake so the
        # stack unwinds (the path a SIGTERM-during-connect would also take:
        # the handshake never completes and teardown runs).
        class _Materials:
            cert_der = b""
            ca_root = object()
            crl = None

        from dsm import session as session_mod

        stops: list[asyncio.Event] = []

        def _real_signal_handlers(shutdown: asyncio.Event) -> None:
            # The real install, plus a handle on the event it sets.
            stops.append(shutdown)
            session_mod.setup_signal_handlers(shutdown)

        async def _failing_handshake(*_a: object, **_k: object) -> None:
            # SIGTERM arrives during the handshake: the handler sets the
            # shutdown event, then the handshake fails. A failed handshake
            # alone keeps the kill switch up and tries again.
            stops[0].set()
            raise HandshakeError("connect interrupted")

        class _FakeTransport:
            async def bind(self, *_a: object, **_k: object) -> None:
                pass

            async def aclose(self) -> None:
                pass

        class _FakeStore:
            def __init__(self, *_a: object, **_k: object) -> None:
                # Attributes the handshake-arg construction reads off the
                # store before client_handshake (the failing double) runs.
                self.identity = object()
                self.attest_key = object()

            def unload(self) -> None:
                pass

        with (
            patch("tuncore.harden_process"),
            patch("dsm.core.hardening.set_process_nondumpable"),
            patch("dsm.crypto.attest_gate.enforce_attest_backend_policy"),
            patch("dsm.client.load_cert_materials", return_value=_Materials()),
            patch("dsm.client.verify_cert_matches_identity"),
            patch("dsm.crypto._stores.load_daemon_stores", return_value=True),
            patch("dsm.client.KeyStore", _FakeStore),
            patch("dsm.client.AttestStore", _FakeStore),
            patch("dsm.client.PreHandshakeKillSwitch", _FakeKillSwitch),
            patch("dsm.client.UDPTransport", _FakeTransport),
            # Real setup_signal_handlers runs against this test's isolated
            # event loop (torn down per test), exercising the actual early
            # install rather than a mock.
            patch("dsm.client.setup_signal_handlers", _real_signal_handlers),
            patch("dsm.crypto.handshake.client_handshake", _failing_handshake),
        ):
            rc = await asyncio.wait_for(run_client_local(cfg), timeout=10)

        self.assertTrue(applied["value"], "pre-handshake kill switch was applied")
        self.assertTrue(
            removed["value"],
            "AsyncExitStack must remove the pre-handshake kill switch on "
            "teardown (no leaked rules after an interrupted handshake)",
        )
        self.assertEqual(rc, 0)


async def run_client_local(cfg: Config) -> int:
    from dsm.client import run_client

    return await run_client(cfg)


class ConfigLoadErrors(unittest.TestCase):
    def test_missing_config_exits_2_with_clean_message(self) -> None:
        from dsm.__main__ import _load_config_or_exit

        buf = io.StringIO()
        with redirect_stderr(buf):
            with self.assertRaises(SystemExit) as cm:
                _load_config_or_exit(Path("/nonexistent/dsm-config.toml"))
        self.assertEqual(cm.exception.code, 2)
        self.assertIn("config:", buf.getvalue())
        self.assertNotIn("Traceback", buf.getvalue())


class ServerKeepsServing(unittest.IsolatedAsyncioTestCase):
    """Part C: the server runs until a signal. A session that ends on its own
    ends only itself: the acceptor keeps serving, and the next client gets a
    session. A signal ends every session and run_server returns 0.

    run_server runs with the host I/O faked (test_server_dns_fatal) and a
    scripted acceptor and sessions (test_server_multi)."""

    async def test_a_session_that_ends_does_not_stop_the_server(self) -> None:
        from tests.test_handshake_acceptor_limits import _spin
        from tests.test_server_multi import (
            PEER_A,
            PEER_B,
            A,
            B,
            _Acceptor,
            _multi,
            _Sessions,
            _start,
            _stop,
        )

        captured: dict[str, Any] = {}
        sessions = _Sessions()
        sessions.end_at_once.add(A)  # as a dead peer would end it
        with _multi(captured, sessions):
            run = await _start(_server_config())
            acceptor = _Acceptor.made[0]
            acceptor.admit(A, PEER_A)
            self.assertTrue(await _spin(lambda: f"{A} ended" in sessions.events))
            acceptor.admit(B, PEER_B)
            self.assertTrue(await _spin(lambda: f"{B} started" in sessions.events))
            self.assertFalse(run.done())
            self.assertEqual((acceptor.runs, acceptor.stops), (1, 0))
            rc = await _stop(run, captured)
        self.assertEqual(rc, 0)

    async def test_a_signal_ends_every_session_and_exits_0(self) -> None:
        from tests.test_handshake_acceptor_limits import _spin
        from tests.test_server_multi import (
            PEER_A,
            PEER_B,
            A,
            B,
            _Acceptor,
            _multi,
            _Sessions,
            _start,
            _stop,
        )

        captured: dict[str, Any] = {}
        sessions = _Sessions()
        with _multi(captured, sessions):
            run = await _start(_server_config())
            acceptor = _Acceptor.made[0]
            acceptor.admit(A, PEER_A)
            acceptor.admit(B, PEER_B)
            self.assertTrue(await _spin(lambda: len(sessions.started) == 2))
            rc = await _stop(run, captured)
        self.assertEqual(rc, 0)
        self.assertTrue(all(s.shutdown.is_set() for s in sessions.started))
        self.assertEqual(
            sorted(sessions.events[-2:]), sorted([f"{A} ended", f"{B} ended"])
        )


if __name__ == "__main__":
    unittest.main()
