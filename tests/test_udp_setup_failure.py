"""A UDP socket is closed when setup fails after bind.

If ``create_datagram_endpoint`` fails (or is cancelled) after the socket
is bound, ``bind`` and ``rebind_to_fresh_port`` must close it instead of
leaking it.
"""

from __future__ import annotations

import asyncio
import socket
import unittest
from typing import Any
from unittest.mock import patch

from dsm.net.transport.udp import UDPTransport


class TestSocketClosedOnSetupFailure(unittest.IsolatedAsyncioTestCase):
    async def _fail_endpoint(self, exc: BaseException) -> list[socket.socket]:
        seen: list[socket.socket] = []

        async def fake(*_args: Any, sock: socket.socket, **_kw: Any) -> Any:
            seen.append(sock)
            raise exc

        loop = asyncio.get_running_loop()
        self.patcher = patch.object(loop, "create_datagram_endpoint", fake)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)
        return seen

    async def test_bind_closes_socket_on_os_error(self) -> None:
        seen = await self._fail_endpoint(OSError("no endpoint"))
        with self.assertRaises(OSError):
            await UDPTransport().bind("127.0.0.1", 0)
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0].fileno(), -1, "socket was left open")

    async def test_bind_closes_socket_on_cancel(self) -> None:
        seen = await self._fail_endpoint(asyncio.CancelledError())
        with self.assertRaises(asyncio.CancelledError):
            await UDPTransport().bind("127.0.0.1", 0)
        self.assertEqual(seen[0].fileno(), -1, "socket was left open")

    async def test_rebind_closes_new_socket_on_error(self) -> None:
        transport = UDPTransport()
        # SO_MARK needs CAP_NET_ADMIN, which the test run does not have.
        with patch("dsm.net.transport.udp.apply_so_mark"):
            await transport.bind("127.0.0.1", 0)
        self.addCleanup(transport.close)
        seen = await self._fail_endpoint(OSError("no endpoint"))
        with self.assertRaises(OSError):
            await transport.rebind_to_fresh_port()
        self.assertEqual(seen[0].fileno(), -1, "new socket was left open")


if __name__ == "__main__":
    unittest.main()
