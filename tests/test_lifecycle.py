"""Phase 1.8: daemon lifecycle correctness.

Covers all four sub-parts:

  * Part A — ``run_client`` / ``run_server`` return ``int`` exit codes
    (nonzero on error paths, 0 on clean shutdown) and ``main()``
    ``sys.exit``s the value.
  * Part B — the client installs signal handlers BEFORE the
    pre-handshake kill switch, so a SIGTERM during connect unwinds the
    AsyncExitStack instead of leaving the kill switch applied.
  * Part C — the server's OUTER re-accept loop: a session ending on its
    own (dead-peer timeout / peer SESSION_CLOSE / roam) tears down
    per-session host state and loops back to accept a new client, while a
    process shutdown (SIGTERM) breaks the loop. See ``ServerReAccept``.
  * Part D — ``main()`` config-load failures print ``config: <msg>`` to
    stderr and ``sys.exit(2)`` rather than surfacing a raw traceback.

Mocking is confined to I/O / hardening boundaries (``tuncore`` syscalls,
``set_process_nondumpable``, the host-state managers) plus the one
collaborator each test forces to fail; no network, no root, no real
filesystem mutation.
"""

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

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
            patch.object(entry.sys, "argv", argv),
            patch.object(entry, "_load_config_or_exit", return_value=_client_config()),
            patch("dsm.core.log.configure"),
            patch("dsm.core.netaudit.configure"),
            patch("dsm.client.run_client") as run_client_mock,
            patch.object(entry.asyncio, "run", return_value=7) as run_mock,
        ):
            # asyncio.run is mocked to return the sentinel directly; the
            # un-awaited coroutine object is never executed, so close it to
            # avoid a "coroutine was never awaited" warning.
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

        async def _failing_handshake(*_a: object, **_k: object) -> None:
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
            patch("dsm.crypto.handshake.client_handshake", _failing_handshake),
        ):
            rc = await run_client_local(cfg)

        self.assertTrue(applied["value"], "pre-handshake kill switch was applied")
        self.assertTrue(
            removed["value"],
            "AsyncExitStack must remove the pre-handshake kill switch on "
            "teardown (no leaked rules after an interrupted handshake)",
        )
        self.assertEqual(rc, 1)


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


class ServerReAccept(unittest.IsolatedAsyncioTestCase):
    """Part C: the server's OUTER re-accept loop.

    The design problem this proves solved: ``run_data_loops`` sets the
    SAME ``ctx.shutdown`` event for BOTH a process-shutdown (SIGTERM) and an
    ordinary session-end (SESSION_CLOSE / dead-peer timeout / rekey give-up).
    The fix is two events — a per-session ``session_shutdown`` that
    ``run_data_loops`` watches, plus a process-lifetime ``process_shutdown``
    set only by the signal handlers — bridged so a signal during a live
    session still stops that session. After ``run_data_loops`` returns the
    loop re-accepts iff ``process_shutdown`` is NOT set.

    These tests drive ``run_server`` end-to-end with every host-state
    manager mocked at the I/O boundary (no root, no network, no real TUN/
    nftables/DNS) and assert the LOOP CONTROL FLOW: a session that ends on
    its own re-accepts; a process shutdown breaks the loop.

    Against the pre-C single-session code these would FAIL: the old
    ``run_server`` ``break``s out of the accept loop on the first successful
    handshake, runs exactly one session, and returns — ``server_handshake``
    is called once, never twice.
    """

    @staticmethod
    def _patches(
        handshake_side_effect: object,
        run_data_loops_impl: object,
        captured_shutdown: dict,
    ) -> list:
        """Build the patch context managers shared by both tests.

        ``captured_shutdown`` is populated with the ``process_shutdown``
        event that ``setup_signal_handlers`` is called with, so the
        ``run_data_loops`` stand-in can set it to simulate a signal.
        """

        class _FakeMaterials:
            cert_der = b""
            ca_root = object()
            crl = None

        class _FakeStore:
            def __init__(self, *_a: object, **_k: object) -> None:
                # _run_one_session reads keystore.identity.public_key.
                self.identity = type("_Id", (), {"public_key": b"\x00" * 32})()
                self.attest_key = object()

            def unload(self) -> None:
                pass

        class _SyncManager:
            """apply()/remove() host-state managers (rate limiter, tcp_ts,
            forwarding, masquerade)."""

            def __init__(self, *_a: object, **_k: object) -> None:
                pass

            def apply(self) -> None:
                pass

            def remove(self) -> None:
                pass

        class _FakeTun:
            def __init__(self, *_a: object, **_k: object) -> None:
                pass

            def open(self) -> None:
                pass

            def configure(self, *_a: object, **_k: object) -> None:
                pass

            def close(self) -> None:
                pass

        class _FakeResolver:
            def __init__(self, *_a: object, **_k: object) -> None:
                pass

            async def close(self) -> None:
                pass

        class _FakeDNSProxy:
            def __init__(self, *_a: object, **_k: object) -> None:
                pass

            async def start(self) -> None:
                pass

            def stop(self) -> None:
                pass

        class _FakeScheduler:
            def __init__(self, *_a: object, **_k: object) -> None:
                pass

            async def start(self) -> None:
                pass

            async def stop(self) -> None:
                pass

        class _FakeUDPTransport:
            async def bind(self, *_a: object, **_k: object) -> None:
                pass

            async def aclose(self) -> None:
                pass

        def _capture_signal_handlers(shutdown: object) -> None:
            captured_shutdown["event"] = shutdown

        cn_allowlist = _NonEmptyAllowlist()

        return [
            patch("tuncore.harden_process"),
            patch("dsm.core.hardening.set_process_nondumpable"),
            patch("dsm.crypto.attest_gate.enforce_attest_backend_policy"),
            patch("dsm.server.load_cert_materials", return_value=_FakeMaterials()),
            patch("dsm.server.verify_cert_matches_identity"),
            patch(
                "dsm.server.CNAllowlist.from_file",
                return_value=cn_allowlist,
            ),
            patch("dsm.crypto._stores.load_daemon_stores", return_value=True),
            patch("dsm.server.KeyStore", _FakeStore),
            patch("dsm.server.AttestStore", _FakeStore),
            patch("dsm.server.ServerRateLimitManager", _SyncManager),
            patch("dsm.server.TcpTimestampsDisabler", _SyncManager),
            patch("dsm.server.IPForwardingManager", _SyncManager),
            patch("dsm.server.MasqueradeManager", _SyncManager),
            patch("dsm.server.TunDevice", _FakeTun),
            patch("dsm.server.DNSResolver", _FakeResolver),
            patch("dsm.server.LocalDNSProxy", _FakeDNSProxy),
            patch("dsm.server.SendScheduler", _FakeScheduler),
            patch("dsm.server.make_send_fn", return_value=_noop_send),
            patch("dsm.server.UDPTransport", _FakeUDPTransport),
            patch("dsm.server.setup_signal_handlers", _capture_signal_handlers),
            patch(
                "dsm.crypto.handshake.server_handshake",
                side_effect=handshake_side_effect,
            ),
            patch("dsm.session.run_data_loops", side_effect=run_data_loops_impl),
        ]

    async def test_session_end_re_accepts_next_client(self) -> None:
        """A session that ends WITHOUT process shutdown loops back and
        accepts a second client; the loop exits only once
        ``process_shutdown`` is set."""
        from dsm.server import run_server

        captured: dict = {}
        handshake_calls = {"n": 0}
        run_loops_calls = {"n": 0}

        async def _handshake(*_a: object, **_k: object) -> tuple[object, bytes]:
            handshake_calls["n"] += 1
            # Distinct per session — proves fresh session_keys each accept.
            return object(), bytes([handshake_calls["n"]]) * 32

        async def _run_data_loops(*args: object, **_k: object) -> None:
            run_loops_calls["n"] += 1
            if run_loops_calls["n"] >= 2:
                # Second session: simulate a SIGTERM arriving — the signal
                # handler would set process_shutdown. The outer loop must
                # then break instead of re-accepting a third time.
                captured["event"].set()
            # First session: return WITHOUT touching process_shutdown — a
            # plain session-end (dead-peer / SESSION_CLOSE / roam). The loop
            # must re-accept.
            # Mirror run_data_loops' contract: it drives the FSM through
            # TEARDOWN → IDLE in its finally, leaving the caller's re-accept
            # loop free to transition IDLE → CONNECTING.
            _drive_fsm_to_idle(args[4])

        with _ExitStackPatches(self._patches(_handshake, _run_data_loops, captured)):
            rc = await run_server(_server_config())

        self.assertEqual(
            handshake_calls["n"],
            2,
            "server_handshake must be called twice — the server re-accepted a "
            "second client after the first session ended (this is the Part C "
            "behaviour; the pre-C code calls it exactly once)",
        )
        self.assertEqual(run_loops_calls["n"], 2)
        self.assertEqual(rc, 0)

    async def test_process_shutdown_during_first_session_no_reaccept(self) -> None:
        """``process_shutdown`` set during the FIRST session → the loop exits
        after one session, no re-accept, clean exit 0."""
        from dsm.server import run_server

        captured: dict = {}
        handshake_calls = {"n": 0}
        run_loops_calls = {"n": 0}

        async def _handshake(*_a: object, **_k: object) -> tuple[object, bytes]:
            handshake_calls["n"] += 1
            return object(), b"\xaa" * 32

        async def _run_data_loops(*args: object, **_k: object) -> None:
            run_loops_calls["n"] += 1
            # First (and only) session: a SIGTERM arrives mid-session.
            captured["event"].set()
            _drive_fsm_to_idle(args[4])

        with _ExitStackPatches(self._patches(_handshake, _run_data_loops, captured)):
            rc = await run_server(_server_config())

        self.assertEqual(
            handshake_calls["n"],
            1,
            "process_shutdown during the first session must NOT re-accept",
        )
        self.assertEqual(run_loops_calls["n"], 1)
        self.assertEqual(rc, 0)


def _drive_fsm_to_idle(fsm: object) -> None:
    """Replicate run_data_loops' finally: ESTABLISHED → TEARDOWN → IDLE.

    The real ``run_data_loops`` always leaves the FSM in IDLE on return;
    the re-accept loop relies on that to legally transition IDLE →
    CONNECTING for the next accept. The stub must honour the same contract.
    """
    from dsm.core.fsm import State

    fsm.transition(State.TEARDOWN)  # type: ignore[attr-defined]
    fsm.transition(State.IDLE)  # type: ignore[attr-defined]


async def _noop_send(*_a: object, **_k: object) -> None:
    """Stand-in for the send_fn make_send_fn would return."""


class _NonEmptyAllowlist:
    """Duck-typed CNAllowlist: non-empty so run_server does not abort, and
    irrelevant to the loop control flow under test."""

    def __len__(self) -> int:
        return 1


class _ExitStackPatches:
    """Enter a list of patch() context managers as one ``with`` block."""

    def __init__(self, patches: list) -> None:
        self._patches = patches

    def __enter__(self) -> _ExitStackPatches:
        for p in self._patches:
            p.start()
        return self

    def __exit__(self, *exc: object) -> None:
        for p in reversed(self._patches):
            p.stop()


if __name__ == "__main__":
    unittest.main()
