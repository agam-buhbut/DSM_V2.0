"""Regression: a TCP framing error (oversized length prefix) must NOT exit
run_server's outer accept loop and crash the daemon.

Root cause: `dsm/server.py` wraps `_run_one_session(...)` in
`except Exception` but NOT `_accept_one_session(...)`, so a ValueError
raised by the TCP framing layer during the handshake phase escapes the loop
and terminates the process.

Fix contract:
  1. `dsm.net.transport.tcp` defines ``FramingError(ValueError)`` and raises
     it (not a bare ValueError) at the two validation sites.
  2. `dsm.server.run_server`'s outer while-loop wraps the
     ``_accept_one_session(...)`` call in ``try/except Exception``, logging and
     recovering exactly as the existing ``_run_one_session`` guard does.

This test verifies the fix at the loop level: it stubs ``_accept_one_session``
so the first call raises ``FramingError``, confirms the run_server loop catches
it and continues (does NOT re-raise), and then on the second call signals a
clean process_shutdown so the loop exits normally.

A full in-process server harness for run_server exists in
``tests/test_lifecycle.py``; the loop-level unit test here is a targeted
complement that isolates the FramingError recovery path without needing a real
TUN device, nftables, or cert infrastructure.
"""

from __future__ import annotations

import asyncio
import unittest
from unittest.mock import MagicMock, patch

from dsm.net.transport.tcp import FramingError


class TestFramingErrorDefinition(unittest.TestCase):
    """FramingError must be a subclass of ValueError."""

    def test_framing_error_is_value_error_subclass(self) -> None:
        err = FramingError("frame length 65537 exceeds max 65536")
        self.assertIsInstance(err, ValueError)

    def test_framing_error_can_be_raised_and_caught_as_value_error(self) -> None:
        with self.assertRaises(ValueError):
            raise FramingError("oversized")

    def test_framing_error_can_be_raised_and_caught_as_framing_error(self) -> None:
        with self.assertRaises(FramingError):
            raise FramingError("oversized")


class TestRunServerLoopSurvivesFramingError(unittest.IsolatedAsyncioTestCase):
    """run_server's outer accept loop MUST catch a FramingError and continue.

    The fix is verified by patching _accept_one_session at the server module
    level so the first call raises FramingError (simulating a raw socket
    sending an oversized length prefix during the handshake recv) and the
    second call returns (None, None, None) which triggers the clean
    process_shutdown branch — stopping the loop without re-raising.

    BEFORE the fix: FramingError (a ValueError) propagates out of the while
    loop, out of run_server's AsyncExitStack, and the coroutine raises — the
    daemon dies. The mock sequence would never reach the second call.

    AFTER the fix: the except-Exception guard catches and logs FramingError,
    the loop continues, calls _accept_one_session a second time, receives
    (None, None, None) and breaks cleanly. run_server returns 0.
    """

    async def test_framing_error_does_not_exit_run_server(self) -> None:
        """A FramingError from _accept_one_session must NOT escape run_server."""
        import dsm.server as _server_mod

        call_count = 0

        async def _fake_accept(
            config,
            fsm,
            keystore,
            attest_store,
            materials,
            cn_allowlist,
            transport_obj,
            ps,
        ):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # Simulate the attacker sending an oversized TCP frame prefix.
                raise FramingError("frame length 268435457 exceeds max 65536")
            # Second call: signal shutdown so the loop exits cleanly.
            ps.set()
            return None, None, None

        mock_config = MagicMock()
        mock_config.transport = "tcp"
        mock_config.listen_port = 0
        mock_config.allowed_cns_file = "/fake/cns"
        mock_config.key_file = "/fake/key"
        mock_config.attest_key_file = "/fake/attest"

        mock_materials = MagicMock()
        mock_cn_allowlist = MagicMock()
        mock_cn_allowlist.__len__ = MagicMock(return_value=1)
        mock_keystore = MagicMock()
        mock_keystore.unload = MagicMock()
        mock_attest_store = MagicMock()
        mock_attest_store.unload = MagicMock()

        mock_rate_limiter = MagicMock()
        mock_rate_limiter.apply = MagicMock()
        mock_rate_limiter.remove = MagicMock()

        mock_tcp_ts = MagicMock()
        mock_tcp_ts.apply = MagicMock()
        mock_tcp_ts.remove = MagicMock()

        # run_server uses several local imports; patch at the source modules.
        patches = [
            # tuncore.harden_process — local import inside run_server
            patch("tuncore.harden_process", return_value=None),
            # dsm.core.hardening.set_process_nondumpable — local import
            patch(
                "dsm.core.hardening.set_process_nondumpable",
                return_value=None,
            ),
            # attest gate — local import
            patch(
                "dsm.crypto.attest_gate.enforce_attest_backend_policy",
                return_value=None,
            ),
            # cert / key loading (module-level imports in server.py)
            patch(
                "dsm.server.load_cert_materials",
                return_value=mock_materials,
            ),
            patch(
                "dsm.server.CNAllowlist.from_file",
                return_value=mock_cn_allowlist,
            ),
            patch("dsm.server.KeyStore", return_value=mock_keystore),
            patch("dsm.server.AttestStore", return_value=mock_attest_store),
            # load_daemon_stores — local import inside run_server; returns
            # True (success) so we pass the "stores unlocked" gate.
            patch(
                "dsm.crypto._stores.load_daemon_stores",
                return_value=True,
            ),
            # cert/identity consistency check — module-level import in server
            patch(
                "dsm.server.verify_cert_matches_identity",
                return_value=None,
            ),
            # nftables / network
            patch(
                "dsm.server.ServerRateLimitManager",
                return_value=mock_rate_limiter,
            ),
            patch(
                "dsm.server.TcpTimestampsDisabler",
                return_value=mock_tcp_ts,
            ),
            # signal handlers: no-op in test
            patch("dsm.server.setup_signal_handlers", return_value=None),
            # The function under test
            patch.object(_server_mod, "_accept_one_session", new=_fake_accept),
        ]

        for p in patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in patches])

        # run_server must return 0 (clean shutdown), NOT raise.
        result = await asyncio.wait_for(
            _server_mod.run_server(mock_config),
            timeout=5.0,
        )

        self.assertEqual(
            result,
            0,
            "run_server must return 0 on clean shutdown after a FramingError recovery",
        )
        self.assertEqual(
            call_count,
            2,
            "loop must have continued after FramingError and called "
            "_accept_one_session a second time",
        )


class TestTcpRecvRaisesFramingError(unittest.IsolatedAsyncioTestCase):
    """TCPTransport.recv() raises FramingError (not bare ValueError) on an
    oversized length prefix, and the error is an instance of ValueError so
    existing except-ValueError callers still catch it."""

    async def asyncSetUp(self) -> None:
        self._p = patch("dsm.net.transport.tcp.apply_so_mark", lambda sock: None)
        self._p.start()
        self.addCleanup(self._p.stop)

    async def test_oversized_prefix_raises_framing_error(self) -> None:
        import struct

        from dsm.net.transport.tcp import FramingError, TCPTransport

        server = TCPTransport()

        async def _serve() -> None:
            await server.listen("127.0.0.1", 0)

        listen_task = asyncio.ensure_future(_serve())
        # Wait for asyncio.start_server to complete inside listen() so
        # _server and its sockets are populated. Yielding with sleep(0)
        # in a loop is deterministic and avoids any fixed wall-clock delay.
        while server._server is None:
            await asyncio.sleep(0)
        port = server._server.sockets[0].getsockname()[1]  # type: ignore[union-attr]

        client = TCPTransport()
        await client.connect("127.0.0.1", port)
        await listen_task

        self.addCleanup(client.close)
        self.addCleanup(server.close)

        # Send an oversized length prefix (0x10000001 > MAX_FRAME_SIZE=65536).
        writer = client._writer
        assert writer is not None
        writer.write(struct.pack("!I", 0x10000001))
        await writer.drain()

        with self.assertRaises(FramingError):
            await asyncio.wait_for(server.recv(), timeout=2.0)

    async def test_framing_error_is_also_value_error(self) -> None:
        """FramingError inherits from ValueError for backward compat."""
        import struct

        from dsm.net.transport.tcp import TCPTransport

        server = TCPTransport()

        async def _serve() -> None:
            await server.listen("127.0.0.1", 0)

        listen_task = asyncio.ensure_future(_serve())
        # Wait for asyncio.start_server to complete inside listen() so
        # _server and its sockets are populated. Yielding with sleep(0)
        # in a loop is deterministic and avoids any fixed wall-clock delay.
        while server._server is None:
            await asyncio.sleep(0)
        port = server._server.sockets[0].getsockname()[1]  # type: ignore[union-attr]

        client = TCPTransport()
        await client.connect("127.0.0.1", port)
        await listen_task

        self.addCleanup(client.close)
        self.addCleanup(server.close)

        writer = client._writer
        assert writer is not None
        writer.write(struct.pack("!I", 0x10000001))
        await writer.drain()

        with self.assertRaises(ValueError):
            await asyncio.wait_for(server.recv(), timeout=2.0)


class TestAcceptOneSessionClosesTransportOnUnexpectedException(
    unittest.IsolatedAsyncioTestCase
):
    """_accept_one_session MUST close the TCP listening transport on any
    unexpected exception so file descriptors are not leaked under a sustained
    oversized-frame attack.

    Before the fix: an exception that is not in the
    (CNNotAllowedError, CertRevokedError, CertAuthError, HandshakeError)
    tuple (e.g. FramingError) escapes the except clause and propagates to
    run_server's outer guard, which holds the *previous* transport reference —
    not the new TCPTransport created inside _accept_one_session.  The newly
    allocated transport is never closed until GC collects it.

    After the fix: a bare ``except BaseException`` clause runs
    ``await transport_obj.aclose()`` for TCP before re-raising, so the fd is
    released on every attack-induced exception.
    """

    async def test_framing_error_triggers_transport_aclose(self) -> None:
        """aclose() on the per-attempt TCP transport is called when an
        unexpected exception (FramingError) propagates out of server_handshake
        inside _accept_one_session."""
        import dsm.server as _server_mod
        from dsm.net.transport.tcp import FramingError

        # Track aclose calls on the mock transport.
        aclose_calls: list[str] = []

        mock_transport = MagicMock()

        async def _track_aclose() -> None:
            aclose_calls.append("aclose")

        mock_transport.aclose = _track_aclose

        async def _fake_listen(**kwargs: object) -> int:  # type: ignore[misc]
            return 0

        mock_transport.listen = _fake_listen

        # server_handshake raises FramingError — NOT in the expected-exception
        # tuple, so it must fall through to the BaseException cleanup branch.
        framing_calls = 0

        async def _fake_handshake(*args: object, **kwargs: object) -> None:
            nonlocal framing_calls
            framing_calls += 1
            raise FramingError("frame length 268435457 exceeds max 65536")

        process_shutdown = asyncio.Event()  # NOT set — loop will enter once

        mock_config = MagicMock()
        mock_config.transport = "tcp"
        mock_config.listen_port = 0

        # Patch TCPTransport constructor in dsm.server to return our mock.
        # Patch server_handshake at its definition module so the local import
        # inside _accept_one_session picks up the stub.
        import dsm.crypto.handshake as _hs_mod

        patches = [
            patch("dsm.server.TCPTransport", return_value=mock_transport),
            patch.object(_hs_mod, "server_handshake", new=_fake_handshake),
        ]
        for p in patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in patches])

        with self.assertRaises(FramingError):
            await _server_mod._accept_one_session(
                mock_config,
                MagicMock(),  # fsm
                MagicMock(),  # keystore
                MagicMock(),  # attest_store
                MagicMock(),  # materials
                MagicMock(),  # cn_allowlist
                None,  # transport_obj starts as None (TCP path creates its own)
                process_shutdown,
            )

        self.assertEqual(
            aclose_calls,
            ["aclose"],
            "transport.aclose() must be called exactly once when FramingError "
            "propagates out of server_handshake inside _accept_one_session",
        )
        self.assertEqual(framing_calls, 1, "server_handshake should be called once")


if __name__ == "__main__":
    unittest.main()
