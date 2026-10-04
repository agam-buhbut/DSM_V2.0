"""How run_server's accept loop handles errors.

* A TCP listener that cannot be opened before any client has been served
  (e.g. the port is taken) is fatal: one ERROR line and exit code 1, so
  systemd restarts the daemon after its delay instead of it spinning.
* Any other accept error, and a listener error after a client has been
  served, waits for ``_backoff_or_shutdown`` before the next attempt. The
  failure count starts over after each served client.

Host-level side effects (hardening, keys, nftables, signals) are patched out;
the first test opens a real loopback listener to occupy the port.
"""

from __future__ import annotations

import asyncio
import errno
import logging
import os
import socket
import unittest
from collections.abc import Callable
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import dsm.server as server_mod
from dsm.server import ListenError, _drive_fsm_to_idle


def _tcp_config(port: int) -> MagicMock:
    config = MagicMock()
    config.transport = "tcp"
    config.listen_port = port
    config.allowed_cns_file = "/fake/cns"
    config.key_file = "/fake/key"
    config.attest_key_file = "/fake/attest"
    return config


def _host_patches() -> list[Any]:
    allowlist = MagicMock()
    allowlist.__len__ = MagicMock(return_value=1)
    return [
        patch("tuncore.harden_process", return_value=None),
        patch("dsm.core.hardening.set_process_nondumpable", return_value=None),
        patch("dsm.crypto.attest_gate.enforce_attest_backend_policy"),
        patch("dsm.server.load_cert_materials", return_value=MagicMock()),
        patch("dsm.server.CNAllowlist.from_file", return_value=allowlist),
        patch("dsm.server.KeyStore", return_value=MagicMock()),
        patch("dsm.server.AttestStore", return_value=MagicMock()),
        patch("dsm.crypto._stores.load_daemon_stores", return_value=True),
        patch("dsm.server.verify_cert_matches_identity", return_value=None),
        patch("dsm.server.ServerRateLimitManager", return_value=MagicMock()),
        patch("dsm.server.TcpTimestampsDisabler", return_value=MagicMock()),
        patch("dsm.server.check_clock_sync", return_value=None),
        patch("dsm.server.setup_signal_handlers", return_value=None),
    ]


class _ErrorRecords(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.ERROR)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


class _AcceptLoopCase(unittest.IsolatedAsyncioTestCase):
    def _start(self, extra: list[Any]) -> None:
        patches = _host_patches() + extra
        for p in patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in reversed(patches)])

    @staticmethod
    def _recording_backoff(
        calls: list[int],
        on_call: Callable[[asyncio.Event], bool] | None = None,
    ) -> Callable[[int, asyncio.Event], Any]:
        async def _backoff(failures: int, shutdown: asyncio.Event) -> bool:
            calls.append(failures)
            return on_call(shutdown) if on_call is not None else False

        return _backoff


class TestListenFailureAtStartup(_AcceptLoopCase):
    async def test_port_in_use_exits_with_one_error_line(self) -> None:
        taken = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        taken.bind(("0.0.0.0", 0))
        taken.listen(1)
        self.addCleanup(taken.close)
        port = taken.getsockname()[1]

        listen_calls = {"n": 0}
        real_listen = server_mod.TCPTransport.listen

        async def _counting_listen(self: Any, *args: Any, **kwargs: Any) -> int:
            listen_calls["n"] += 1
            return await real_listen(self, *args, **kwargs)

        backoff_calls: list[int] = []
        self._start(
            [
                patch.object(server_mod.TCPTransport, "listen", _counting_listen),
                patch(
                    "dsm.server._backoff_or_shutdown",
                    new=self._recording_backoff(backoff_calls),
                ),
            ]
        )
        errors = _ErrorRecords()
        server_log = logging.getLogger("dsm.server")
        server_log.addHandler(errors)
        self.addCleanup(server_log.removeHandler, errors)

        rc = await asyncio.wait_for(server_mod.run_server(_tcp_config(port)), 5.0)

        self.assertEqual(rc, 1)
        self.assertEqual(listen_calls["n"], 1, "must not retry the listen")
        self.assertEqual(backoff_calls, [])
        self.assertEqual(len(errors.records), 1)
        record = errors.records[0]
        message = record.getMessage()
        self.assertIn(f"cannot listen on TCP port {port}", message)
        self.assertIn(os.strerror(errno.EADDRINUSE), message)
        self.assertNotIn("\n", message)
        self.assertIsNone(record.exc_info, "a one-line error, not a traceback")


class TestAcceptErrorsBackOff(_AcceptLoopCase):
    async def test_each_failure_waits_with_a_growing_count(self) -> None:
        accept_calls = {"n": 0}

        async def _accept(*args: Any) -> tuple[Any, Any, Any]:
            accept_calls["n"] += 1
            if accept_calls["n"] <= 2:
                raise RuntimeError("bad pre-auth frame")
            args[7].set()  # process_shutdown
            return None, None, None

        backoff_calls: list[int] = []
        self._start(
            [
                patch("dsm.server._accept_one_session", new=_accept),
                patch(
                    "dsm.server._backoff_or_shutdown",
                    new=self._recording_backoff(backoff_calls),
                ),
            ]
        )

        rc = await asyncio.wait_for(server_mod.run_server(_tcp_config(0)), 5.0)

        self.assertEqual(rc, 0)
        self.assertEqual(accept_calls["n"], 3)
        self.assertEqual(backoff_calls, [1, 2])

    async def test_listen_error_after_a_served_client_backs_off(self) -> None:
        accept_calls = {"n": 0}

        async def _accept(*args: Any) -> tuple[Any, Any, Any]:
            accept_calls["n"] += 1
            if accept_calls["n"] == 1:
                raise RuntimeError("bad pre-auth frame")
            if accept_calls["n"] == 2:
                return object(), b"\x01" * 32, AsyncMock()
            if accept_calls["n"] == 3:
                raise ListenError("cannot listen on TCP port 0: test")
            args[7].set()  # process_shutdown
            return None, None, None

        async def _session(*args: Any) -> None:
            _drive_fsm_to_idle(args[1])  # what a finished session leaves

        backoff_calls: list[int] = []
        self._start(
            [
                patch("dsm.server._accept_one_session", new=_accept),
                patch("dsm.server._run_one_session", new=_session),
                patch(
                    "dsm.server._backoff_or_shutdown",
                    new=self._recording_backoff(backoff_calls),
                ),
            ]
        )

        rc = await asyncio.wait_for(server_mod.run_server(_tcp_config(0)), 5.0)

        self.assertEqual(rc, 0)
        self.assertEqual(accept_calls["n"], 4)
        # The count starts over after the served client.
        self.assertEqual(backoff_calls, [1, 1])

    async def test_shutdown_during_the_backoff_stops_the_loop(self) -> None:
        accept_calls = {"n": 0}

        async def _accept(*_args: Any) -> tuple[Any, Any, Any]:
            accept_calls["n"] += 1
            raise RuntimeError("bad pre-auth frame")

        def _shutdown_now(shutdown: asyncio.Event) -> bool:
            shutdown.set()
            return True

        backoff_calls: list[int] = []
        self._start(
            [
                patch("dsm.server._accept_one_session", new=_accept),
                patch(
                    "dsm.server._backoff_or_shutdown",
                    new=self._recording_backoff(backoff_calls, _shutdown_now),
                ),
            ]
        )

        rc = await asyncio.wait_for(server_mod.run_server(_tcp_config(0)), 5.0)

        self.assertEqual(rc, 0)
        self.assertEqual(accept_calls["n"], 1)
        self.assertEqual(backoff_calls, [1])


if __name__ == "__main__":
    unittest.main()
