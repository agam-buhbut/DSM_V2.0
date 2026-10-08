"""After a rebind the old port stays open long enough for the server to move.

The server keeps sending to the client's old port until the new port passes
its address check. If the old socket closes first, those packets are lost at
every key change.
"""

from __future__ import annotations

import asyncio
import socket
import unittest
from unittest.mock import patch

from dsm.net.transport.udp import OLD_PORT_GRACE_S, UDPTransport
from dsm.session import PATH_CHALLENGE_MIN_INTERVAL


class TestOldPortGrace(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._so_mark_patch = patch(
            "dsm.net.transport.udp.apply_so_mark",
            lambda sock: None,
        )
        self._so_mark_patch.start()

    async def asyncTearDown(self) -> None:
        self._so_mark_patch.stop()

    def test_grace_covers_a_few_address_check_tries(self) -> None:
        self.assertGreaterEqual(OLD_PORT_GRACE_S, 3 * PATH_CHALLENGE_MIN_INTERVAL)

    async def test_old_port_receives_after_rebind_and_closes_after_grace(
        self,
    ) -> None:
        t = UDPTransport()
        await t.bind("127.0.0.1", 0)
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            old_port = t._transport.get_extra_info("sockname")[1]  # type: ignore[union-attr]
            await t.rebind_to_fresh_port()

            # The server has not moved yet: it still sends to the old port.
            sender.sendto(b"late", ("127.0.0.1", old_port))
            data, _ = await t.recv(timeout=2.0)
            self.assertEqual(data, b"late")

            (handle, _old), *_ = t._deferred_closes
            delay = handle.when() - asyncio.get_running_loop().time()
            self.assertGreater(delay, OLD_PORT_GRACE_S - 1.0)
            self.assertLessEqual(delay, OLD_PORT_GRACE_S)
        finally:
            sender.close()
            await t.aclose()


if __name__ == "__main__":
    unittest.main()
