"""A2: awrite() must DROP a packet (not tear down the session) when the
O_NONBLOCK TUN write buffer is full (EAGAIN)."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from dsm.net.tunnel import TunDevice


class AwriteDropOnFullBuffer(unittest.IsolatedAsyncioTestCase):
    async def test_blocking_io_error_drops_and_returns_zero(self) -> None:
        tun = TunDevice(name="mtun0")
        tun._fd = 42  # dummy fd; os.write is patched  # noqa: SLF001

        with patch(
            "dsm.net.tunnel.os.write", side_effect=BlockingIOError
        ) as mock_write:
            result = await tun.awrite(b"payload")

        # Dropped, not fatal: returns normally with 0 bytes written.
        self.assertEqual(result, 0)
        self.assertEqual(tun._tx_drops, 1)  # noqa: SLF001
        # Exactly one attempt — no executor fallback that would re-raise.
        self.assertEqual(mock_write.call_count, 1)

    async def test_successful_write_does_not_count_drop(self) -> None:
        tun = TunDevice(name="mtun0")
        tun._fd = 42  # noqa: SLF001

        with patch("dsm.net.tunnel.os.write", return_value=7):
            result = await tun.awrite(b"payload")

        self.assertEqual(result, 7)
        self.assertEqual(tun._tx_drops, 0)  # noqa: SLF001


if __name__ == "__main__":
    unittest.main()
