"""How run_server handles a port it cannot open and an acceptor that crashes.

* In TCP mode the listener is opened once, at start, and stays open for the
  whole run. If it cannot be opened (e.g. the port is taken) that is fatal:
  one ERROR line and exit code 1, so systemd restarts the daemon after its
  delay instead of it spinning.
* The run's one acceptor runs for the whole run. If it crashes (a bug), it
  is stopped, waits for ``_backoff_or_shutdown`` with a growing count, and
  runs again on the same listener; live sessions are not touched
  (multi-client spec §2.7).

Host-level side effects (hardening, keys, nftables, signals, the host setup)
are patched out; the first test opens a real loopback listener to occupy the
port.
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
from unittest.mock import MagicMock, patch

import dsm.server as server_mod
from dsm.core.fsm import State
from dsm.crypto.handshake import VerifiedClient
from dsm.net.handshake_acceptor import AcceptedClient
from dsm.net.handshake_gate import GateKeys
from dsm.server import _drive_fsm_to_idle
from tests.test_handshake_acceptor_limits import _spin
from tests.test_server_dns_fatal import _fake_host


def _tcp_config(port: int) -> MagicMock:
    config = MagicMock()
    config.transport = "tcp"
    config.listen_port = port
    config.allowed_cns_file = "/fake/cns"
    config.key_file = "/fake/key"
    config.attest_key_file = "/fake/attest"
    config.max_inflight_handshakes = 8
    return config


def _host_patches() -> list[Any]:
    allowlist = MagicMock()
    allowlist.__len__ = MagicMock(return_value=1)
    allowlist.order = ("dsm-a-client",)
    return [
        patch("tuncore.harden_process", return_value=None),
        patch("dsm.core.hardening.set_process_nondumpable", return_value=None),
        patch("dsm.crypto.attest_gate.enforce_attest_backend_policy"),
        patch("dsm.server.load_cert_materials", return_value=MagicMock()),
        patch(
            "dsm.server.server_gate_keys",
            return_value=GateKeys(mac1_key=bytes(32), cookie_key=bytes(32)),
        ),
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
        real_listen = server_mod.TCPListener.start

        async def _counting_listen(self: Any, *args: Any, **kwargs: Any) -> int:
            listen_calls["n"] += 1
            return await real_listen(self, *args, **kwargs)

        backoff_calls: list[int] = []
        self._start(
            [
                patch.object(server_mod.TCPListener, "start", _counting_listen),
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


class _CrashingAcceptor:
    """Stands in for ClientAcceptor. Its first run starts one session, as a
    finished handshake does; run() raises ``crashes`` times in all, then
    waits."""

    crashes = 0
    made: list[_CrashingAcceptor] = []

    def __init__(self, *args: Any, **_k: Any) -> None:
        self.table = args[6]
        self.on_client = args[8]
        self.runs = 0
        self.stops = 0
        _CrashingAcceptor.made.append(self)

    async def run(self) -> None:
        self.runs += 1
        if self.runs == 1:
            attempt = object()
            client = VerifiedClient(cn="dsm-a-client", noise_static=b"\x01" * 32)
            self.table.admit(attempt, client)
            _, tunnel = self.table.confirm(attempt)
            self.table.release(attempt)
            self.on_client(
                AcceptedClient(
                    session_keys=object(),  # type: ignore[arg-type]
                    client=client,
                    tunnel=tunnel,
                    transport=MagicMock(),
                    peer=("198.51.100.7", 40000),
                )
            )
        if self.runs <= _CrashingAcceptor.crashes:
            raise RuntimeError("acceptor bug")
        await asyncio.Event().wait()

    async def stop(self) -> None:
        self.stops += 1


_served: list[Any] = []


async def _session(
    _config: Any, fsm: Any, _keystore: Any, session: Any, *_rest: Any
) -> None:
    fsm.transition(State.ESTABLISHED)
    _served.append(session)
    await session.shutdown.wait()
    _drive_fsm_to_idle(fsm)


class TestAcceptorCrashesBackOff(_AcceptLoopCase):
    def _run_with(
        self, crashes: int, backoff: Callable[..., Any], captured: dict[str, Any]
    ) -> None:
        _CrashingAcceptor.crashes = crashes
        _CrashingAcceptor.made = []
        _served.clear()

        def _capture(shutdown: asyncio.Event) -> None:
            captured["event"] = shutdown

        self._start(
            [
                patch("dsm.server._set_up_host", _fake_host),
                patch("dsm.server.ClientAcceptor", _CrashingAcceptor),
                patch("dsm.server._run_one_session", _session),
                patch("dsm.server._backoff_or_shutdown", new=backoff),
                patch("dsm.server.setup_signal_handlers", _capture),
            ]
        )

    async def test_each_crash_waits_with_a_growing_count(self) -> None:
        backoff_calls: list[int] = []
        captured: dict[str, Any] = {}
        self._run_with(2, self._recording_backoff(backoff_calls), captured)
        run = asyncio.ensure_future(server_mod.run_server(_tcp_config(0)))
        self.assertTrue(
            await _spin(
                lambda: run.done()
                or (
                    bool(_CrashingAcceptor.made) and _CrashingAcceptor.made[0].runs == 3
                )
            )
        )
        captured["event"].set()
        rc = await asyncio.wait_for(run, 5.0)
        self.assertEqual(rc, 0)
        self.assertEqual(backoff_calls, [1, 2])
        # Stopped after each crash, and once more at the run's end.
        self.assertEqual(_CrashingAcceptor.made[0].stops, 3)

    async def test_a_crash_leaves_live_sessions_alone(self) -> None:
        captured: dict[str, Any] = {}
        self._run_with(1, self._recording_backoff([]), captured)
        run = asyncio.ensure_future(server_mod.run_server(_tcp_config(0)))
        # The second run starts in the same loop step as the crash; the
        # session's task takes its first step after that, so wait for both.
        self.assertTrue(
            await _spin(
                lambda: run.done()
                or (
                    bool(_CrashingAcceptor.made)
                    and _CrashingAcceptor.made[0].runs == 2
                    and len(_served) == 1
                )
            )
        )
        (session,) = _served
        self.assertFalse(session.shutdown.is_set())
        self.assertEqual(_CrashingAcceptor.made[0].table.sessions(), [session])
        captured["event"].set()
        rc = await asyncio.wait_for(run, 5.0)
        self.assertEqual(rc, 0)
        self.assertTrue(session.shutdown.is_set())  # ended by the stop, not the crash

    async def test_shutdown_during_the_backoff_stops_the_run(self) -> None:
        def _shutdown_now(shutdown: asyncio.Event) -> bool:
            shutdown.set()
            return True

        backoff_calls: list[int] = []
        self._run_with(5, self._recording_backoff(backoff_calls, _shutdown_now), {})
        rc = await asyncio.wait_for(server_mod.run_server(_tcp_config(0)), 5.0)
        self.assertEqual(rc, 0)
        self.assertEqual(backoff_calls, [1])
        self.assertEqual(_CrashingAcceptor.made[0].runs, 1)


if __name__ == "__main__":
    unittest.main()
