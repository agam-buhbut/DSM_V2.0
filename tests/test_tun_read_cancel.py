"""TunDevice.read() must not lose a packet it already took from the fd when
the read is cancelled in the same loop turn (tun_send_loop's 0.1 s wait_for).

asyncio runs fd callbacks before due timers in one turn, so the packet is
read and stored, then the cancel lands before the reading task resumes.
"""

from __future__ import annotations

import asyncio
import socket
import unittest

from dsm.net.tunnel import TunDevice


class ReadCancelledAfterPacket(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.ours, self.peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.ours.setblocking(False)
        self.tun = TunDevice(name="mtun0")
        self.tun._fd = self.ours.fileno()  # noqa: SLF001

    async def asyncTearDown(self) -> None:
        self.ours.close()
        self.peer.close()

    async def test_packet_read_in_the_cancel_turn_comes_out_next(self) -> None:
        loop = asyncio.get_running_loop()
        task = asyncio.ensure_future(self.tun.read())
        await asyncio.sleep(0)  # the read registers its fd callback
        self.peer.send(b"pkt-1")
        # Already due: runs in the next turn, after that turn's fd callback.
        loop.call_at(loop.time(), task.cancel)
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(await asyncio.wait_for(self.tun.read(), 1.0), b"pkt-1")

    async def test_cancel_with_nothing_read_keeps_nothing(self) -> None:
        with self.assertRaises(TimeoutError):
            await asyncio.wait_for(self.tun.read(), 0.01)
        self.peer.send(b"pkt-2")
        self.assertEqual(await asyncio.wait_for(self.tun.read(), 1.0), b"pkt-2")


if __name__ == "__main__":
    unittest.main()
