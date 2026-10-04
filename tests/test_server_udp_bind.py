"""A UDP port the server cannot bind at startup is fatal.

``run_server`` logs one ERROR line (no traceback) and returns 1, like a TCP
listener that cannot open, so systemd restarts the daemon after its delay.
Before this, the bind error escaped ``run_server`` as a Python traceback.

Host-level side effects (hardening, keys, nftables, signals) are patched out;
the first test occupies a real loopback UDP port to get the real OS error.
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

import dsm.server as server_mod


def _udp_config(port: int) -> MagicMock:
    config = MagicMock()
    config.transport = "udp"
    config.listen_port = port
    config.pmtu_discover = False
    config.allowed_cns_file = "/fake/cns"
    config.key_file = "/fake/key"
    config.attest_key_file = "/fake/attest"
    return config


def _host_patches(rate_limiter: MagicMock) -> list[Any]:
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
        patch("dsm.server.ServerRateLimitManager", return_value=rate_limiter),
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


class _UdpBindCase(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.rate_limiter = MagicMock()
        # Stands in for the UDP accept loop, which needs real datagrams.
        self.accept = AsyncMock()

        patches = _host_patches(self.rate_limiter) + [
            patch("dsm.server._accept_until_winner", new=self.accept)
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
        return await asyncio.wait_for(server_mod.run_server(_udp_config(port)), 5.0)

    def _assert_one_line_exit(self, rc: int, port: int, reason: str) -> None:
        self.assertEqual(rc, 1)
        self.assertEqual(len(self.errors.records), 1)
        record = self.errors.records[0]
        self.assertEqual(
            record.getMessage(),
            f"cannot listen on UDP port {port}: {reason}; exiting",
        )
        self.assertIsNone(record.exc_info, "a one-line error, not a traceback")
        self.accept.assert_not_called()
        # The exit unwinds the host state that was set up before the bind.
        self.rate_limiter.remove.assert_called_once_with()


class TestBindFailureAtStartup(_UdpBindCase):
    async def test_port_in_use_exits_with_one_error_line(self) -> None:
        # A plain socket, without SO_REUSEADDR: the server sets that option,
        # but Linux lets two UDP sockets share a port only if both set it.
        taken = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(taken.close)
        taken.bind(("0.0.0.0", 0))
        port = taken.getsockname()[1]

        rc = await self._run(port)

        self._assert_one_line_exit(rc, port, os.strerror(errno.EADDRINUSE))

    async def test_other_os_error_with_an_errno_names_the_reason(self) -> None:
        bind = AsyncMock(
            side_effect=PermissionError(errno.EACCES, os.strerror(errno.EACCES))
        )
        with patch.object(server_mod.UDPTransport, "bind", bind):
            rc = await self._run(51820)

        self._assert_one_line_exit(rc, 51820, os.strerror(errno.EACCES))
        bind.assert_awaited_once()

    async def test_os_error_without_an_errno_uses_its_text(self) -> None:
        bind = AsyncMock(side_effect=OSError("socket is in an odd state"))
        with patch.object(server_mod.UDPTransport, "bind", bind):
            rc = await self._run(51820)

        self._assert_one_line_exit(rc, 51820, "socket is in an odd state")


class TestBindSuccess(_UdpBindCase):
    async def test_a_bound_port_goes_on_to_accept_clients(self) -> None:
        bind = AsyncMock(return_value=51820)

        async def _accept(*args: Any) -> tuple[None, None, Any]:
            args[6].set()  # process_shutdown
            return None, None, args[5]  # transport_obj

        self.accept.side_effect = _accept
        with patch.object(server_mod.UDPTransport, "bind", bind):
            rc = await self._run(51820)

        self.assertEqual(rc, 0)
        bind.assert_awaited_once_with(local_port=51820, pmtu_discover=False)
        self.accept.assert_awaited_once()
        self.assertEqual(self.errors.records, [])
        self.rate_limiter.remove.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
