"""The socket a rebind opens has no SO_REUSEADDR, like the first one.

With SO_REUSEADDR on the client's port, a local user without privileges can
bind the same port on the same address and get the server's packets instead
of DSM. Binding port 0 never needs it.
"""

from __future__ import annotations

import socket
import unittest
from unittest.mock import patch

from dsm.net.transport.udp import UDPTransport


def _reuseaddr(t: UDPTransport) -> int:
    assert t._transport is not None
    sock = t._transport.get_extra_info("socket")
    return int(sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR))


class TestRebindReuseAddr(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._so_mark_patch = patch(
            "dsm.net.transport.udp.apply_so_mark",
            lambda sock: None,
        )
        self._so_mark_patch.start()

    async def asyncTearDown(self) -> None:
        self._so_mark_patch.stop()

    async def test_the_rebind_socket_has_no_reuseaddr(self) -> None:
        t = UDPTransport()
        await t.bind("127.0.0.1", 0)
        try:
            self.assertEqual(_reuseaddr(t), 0)
            await t.rebind_to_fresh_port()
            self.assertEqual(_reuseaddr(t), 0)
        finally:
            await t.aclose()


if __name__ == "__main__":
    unittest.main()
