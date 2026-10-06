"""A UDP port the client cannot bind at startup is fatal.

With a fixed ``listen_port`` that is already in use, ``run_client`` logs one
ERROR line (no traceback) and returns 1, like the server does. Before this,
the bind error escaped ``run_client`` as a Python traceback.

Host-level side effects (hardening, keys, kill switch, signals) are faked;
the first tests occupy a real loopback UDP port to get the real OS error.
"""

from __future__ import annotations

import asyncio
import errno
import logging
import os
import socket
import unittest
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import dsm.client as client_mod
from dsm.core.config import Config
from dsm.crypto.handshake import HandshakeError


def _client_config(port: int) -> Config:
    return Config(
        mode="client",
        server_ip="10.0.0.1",
        server_port=51820,
        listen_port=port,
        key_file="/tmp/dsm-test.key",
        cert_file="/tmp/dsm-test.crt",
        ca_root_file="/tmp/dsm-test-ca.pem",
        attest_key_file="/tmp/dsm-test-attest.key",
        expected_server_cn="dsm-test-server",
        transport="udp",
    )


class _ErrorRecords(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.ERROR)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


class _UdpBindCase(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.kill_switch = MagicMock()
        self.keystore = MagicMock()
        self.attest_store = MagicMock()
        # Stands in for the handshake, which needs a real server.
        self.handshake = AsyncMock(side_effect=AssertionError("not reached"))

        patches: list[Any] = [
            patch("tuncore.harden_process", return_value=None),
            patch("dsm.core.hardening.set_process_nondumpable", return_value=None),
            patch("dsm.crypto.attest_gate.enforce_attest_backend_policy"),
            patch("dsm.client.setup_signal_handlers", return_value=None),
            patch("dsm.client.load_cert_materials", return_value=MagicMock()),
            patch("dsm.client.verify_cert_matches_identity", return_value=None),
            patch("dsm.crypto._stores.load_daemon_stores", return_value=True),
            patch("dsm.client.KeyStore", return_value=self.keystore),
            patch("dsm.client.AttestStore", return_value=self.attest_store),
            patch("dsm.client.PreHandshakeKillSwitch", return_value=self.kill_switch),
            patch("dsm.client.check_clock_sync", return_value=None),
            patch("dsm.crypto.handshake.client_handshake", new=self.handshake),
        ]
        for p in patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in reversed(patches)])

        # Watch the whole "dsm" tree, so an error line from any module counts.
        self.errors = _ErrorRecords()
        dsm_log = logging.getLogger("dsm")
        dsm_log.addHandler(self.errors)
        self.addCleanup(dsm_log.removeHandler, self.errors)

    async def _run(self, port: int) -> int:
        return await asyncio.wait_for(client_mod.run_client(_client_config(port)), 5.0)

    def _assert_one_line_exit(self, rc: int, port: int, reason: str) -> None:
        self.assertEqual(rc, 1)
        self.assertEqual(len(self.errors.records), 1)
        record = self.errors.records[0]
        self.assertEqual(
            record.getMessage(),
            f"cannot listen on UDP port {port}: {reason}; exiting",
        )
        self.assertIsNone(record.exc_info, "a one-line error, not a traceback")
        self.handshake.assert_not_called()
        # The exit unwinds the host state that was set up before the bind.
        self.kill_switch.apply.assert_called_once_with()
        self.kill_switch.remove.assert_called_once_with()
        self.keystore.unload.assert_called_once_with()
        self.attest_store.unload.assert_called_once_with()


class TestBindFailureAtStartup(_UdpBindCase):
    async def test_port_in_use_exits_with_one_error_line(self) -> None:
        # A plain socket on a free port; the client must not share it.
        taken = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(taken.close)
        taken.bind(("0.0.0.0", 0))
        port = taken.getsockname()[1]

        rc = await self._run(port)

        self._assert_one_line_exit(rc, port, os.strerror(errno.EADDRINUSE))

    async def test_port_held_by_a_sharing_socket_still_fails(self) -> None:
        # A holder that allows sharing must still make this client fail.
        taken = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(taken.close)
        taken.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        taken.bind(("0.0.0.0", 0))
        port = taken.getsockname()[1]

        rc = await self._run(port)

        self._assert_one_line_exit(rc, port, os.strerror(errno.EADDRINUSE))

    async def test_other_os_error_with_an_errno_names_the_reason(self) -> None:
        bind = AsyncMock(
            side_effect=PermissionError(errno.EACCES, os.strerror(errno.EACCES))
        )
        with patch.object(client_mod.UDPTransport, "bind", bind):
            rc = await self._run(51821)

        self._assert_one_line_exit(rc, 51821, os.strerror(errno.EACCES))
        bind.assert_awaited_once()

    async def test_os_error_without_an_errno_uses_its_text(self) -> None:
        bind = AsyncMock(side_effect=OSError("socket is in an odd state"))
        with patch.object(client_mod.UDPTransport, "bind", bind):
            rc = await self._run(51821)

        self._assert_one_line_exit(rc, 51821, "socket is in an odd state")


class TestBindSuccess(_UdpBindCase):
    async def test_a_bound_port_goes_on_to_the_handshake(self) -> None:
        bind = AsyncMock(return_value=51821)
        # Stop right after the bind: a failed handshake is a normal exit 1.

        self.handshake.side_effect = HandshakeError("stop here")
        with (
            patch.object(client_mod.UDPTransport, "bind", bind),
            patch("dsm.client._emit_handshake_failure"),
        ):
            rc = await self._run(51821)

        self.assertEqual(rc, 1)
        bind.assert_awaited_once_with(local_port=51821, pmtu_discover=False)
        self.handshake.assert_awaited_once()
        messages = [r.getMessage() for r in self.errors.records]
        self.assertEqual(messages, ["handshake failed: stop here"])
        self.kill_switch.remove.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
