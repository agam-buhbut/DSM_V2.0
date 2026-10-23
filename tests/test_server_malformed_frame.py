"""Regression: a TCP framing error (oversized length prefix) must NOT exit
run_server's outer accept loop and crash the daemon.

Root cause: `dsm/server.py` wraps `_run_one_session(...)` in
`except Exception` but NOT `_accept_one_session(...)`, so a ValueError
raised by the TCP framing layer during the handshake phase escapes the loop
and terminates the process.

Fix contract:
  1. `dsm.net.transport.tcp` defines ``FramingError(ValueError)`` and raises
     it (not a bare ValueError) at the two validation sites.
  2. A FramingError raised while one TCP handshake is read ends only that
     attempt (the acceptor's worker catches it); run_server keeps serving.

``TestRunServerLoopSurvivesFramingError`` drives run_server with the real
acceptor, gate and limiter on a faked listener, and a scripted handshake
after the first frame; the host state is faked.
"""

from __future__ import annotations

import asyncio
import os
import time
import unittest
from typing import Any
from unittest.mock import MagicMock, patch

from dsm.core.fsm import State
from dsm.crypto.handshake import HANDSHAKE_FRAME_SIZE, VerifiedClient
from dsm.net.handshake_gate import GateKeys, compute_mac1, stamp_msg1
from dsm.net.transport.tcp import FramingError
from dsm.server import _drive_fsm_to_idle
from tests.test_handshake_acceptor_limits import _spin
from tests.test_server_dns_fatal import _fake_host
from tests.test_tcp_accept_concurrency import _Conn


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


KEYS = GateKeys(mac1_key=bytes(32), cookie_key=bytes(32))


class _Listener:
    def __init__(self) -> None:
        self.connections: asyncio.Queue[Any] = asyncio.Queue()

    def close(self) -> None:
        pass


def _first_frame() -> bytes:
    """A msg1 with a valid mac1 for the faked gate keys, as a client
    stamps it (the scripted handshake never reads the Noise part)."""
    frame = bytearray(os.urandom(HANDSHAKE_FRAME_SIZE))
    stamp_msg1(frame, compute_mac1(bytes(frame[:32]), KEYS, time.time()))
    return bytes(frame)


class TestRunServerLoopSurvivesFramingError(unittest.IsolatedAsyncioTestCase):
    """A FramingError in one TCP handshake (an oversized length prefix) ends
    only that attempt: run_server keeps serving, and the next connection
    becomes a session."""

    async def test_framing_error_ends_only_that_attempt(self) -> None:
        import dsm.server as _server_mod

        listener = _Listener()
        captured: dict[str, asyncio.Event] = {}
        served: list[Any] = []
        bad = _Conn(("203.0.113.1", 40001), [_first_frame()])
        good = _Conn(("203.0.113.2", 40002), [_first_frame()])

        async def _handshake(
            conn: Any, *_a: Any, admit_client: Any = None, **_k: Any
        ) -> tuple[object, bytes]:
            await conn.recv()  # the first frame, handed back by the gate's view
            if getattr(conn, "_real", conn) is bad:
                raise FramingError("frame length 268435457 exceeds max 65536")
            admit_client(VerifiedClient(cn="dsm-tcp-client", noise_static=b"\x01" * 32))
            return object(), b"\x01" * 32

        async def _session(
            _config: Any, fsm: Any, _keystore: Any, session: Any, *_rest: Any
        ) -> None:
            fsm.transition(State.ESTABLISHED)
            served.append(session)
            await session.shutdown.wait()
            _drive_fsm_to_idle(fsm)

        async def _open(_config: Any) -> _Listener:
            return listener

        def _capture(shutdown: asyncio.Event) -> None:
            captured["event"] = shutdown

        mock_config = MagicMock()
        mock_config.transport = "tcp"
        mock_config.listen_port = 0
        mock_config.allowed_cns_file = "/fake/cns"
        mock_config.key_file = "/fake/key"
        mock_config.attest_key_file = "/fake/attest"
        mock_config.max_inflight_handshakes = 8

        mock_cn_allowlist = MagicMock()
        mock_cn_allowlist.__len__ = MagicMock(return_value=1)
        mock_cn_allowlist.order = ("dsm-tcp-client",)

        patches = [
            patch("tuncore.harden_process", return_value=None),
            patch("dsm.core.hardening.set_process_nondumpable", return_value=None),
            patch(
                "dsm.crypto.attest_gate.enforce_attest_backend_policy",
                return_value=None,
            ),
            patch("dsm.server.load_cert_materials", return_value=MagicMock()),
            patch("dsm.server.server_gate_keys", return_value=KEYS),
            patch("dsm.server.CNAllowlist.from_file", return_value=mock_cn_allowlist),
            patch("dsm.server.KeyStore", return_value=MagicMock()),
            patch("dsm.server.AttestStore", return_value=MagicMock()),
            patch("dsm.crypto._stores.load_daemon_stores", return_value=True),
            patch("dsm.server.verify_cert_matches_identity", return_value=None),
            patch("dsm.server.ServerRateLimitManager", return_value=MagicMock()),
            patch("dsm.server.TcpTimestampsDisabler", return_value=MagicMock()),
            patch("dsm.server.setup_signal_handlers", _capture),
            patch("dsm.server._open_tcp_listener", _open),
            patch("dsm.server._set_up_host", _fake_host),
            patch("dsm.server._run_one_session", _session),
            patch("dsm.crypto.handshake.server_handshake", _handshake),
        ]
        for p in patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in reversed(patches)])

        run = asyncio.ensure_future(_server_mod.run_server(mock_config))
        listener.connections.put_nowait((bad, bad.peer))
        listener.connections.put_nowait((good, good.peer))
        self.assertTrue(
            await _spin(lambda: run.done() or (len(served) == 1 and bad.closed))
        )
        self.assertFalse(run.done(), "a FramingError must not end run_server")
        self.assertIs(served[0].transport, good)
        captured["event"].set()
        self.assertEqual(await asyncio.wait_for(run, 5.0), 0)


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


if __name__ == "__main__":
    unittest.main()
