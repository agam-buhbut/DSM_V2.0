"""Tests for ``UDPTransport``'s PMTU discovery plumbing.

The Linux kernel does the actual MTU estimation; these tests only verify
the Python side wires the socket option on correctly, exposes
``get_path_mtu()`` when enabled, and returns ``None`` when not.
"""

from __future__ import annotations

import socket
import sys
import unittest
from unittest.mock import patch

from dsm.net.transport.udp import UDPTransport


class TestUDPPMTU(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        # apply_so_mark needs CAP_NET_ADMIN; disable for the test.
        self._so_mark_patch = patch(
            "dsm.net.transport.udp.apply_so_mark", lambda sock: None,
        )
        self._so_mark_patch.start()

    async def asyncTearDown(self) -> None:
        self._so_mark_patch.stop()

    async def test_get_path_mtu_returns_none_when_disabled(self) -> None:
        """Without ``pmtu_discover=True`` the helper must return None."""
        t = UDPTransport()
        await t.bind("127.0.0.1", 0)
        try:
            self.assertIsNone(t.get_path_mtu())
        finally:
            await t.aclose()

    async def test_get_path_mtu_returns_none_before_bind(self) -> None:
        t = UDPTransport()
        self.assertIsNone(t.get_path_mtu())

    @unittest.skipUnless(
        sys.platform.startswith("linux"),
        "IP_MTU_DISCOVER is Linux-specific",
    )
    async def test_pmtu_discover_enabled_sets_sockopt(self) -> None:
        """With ``pmtu_discover=True`` the kernel sockopt is set, and a
        subsequent getsockopt returns the configured PMTUD mode."""
        from dsm.net.transport.udp import _IP_MTU_DISCOVER

        t = UDPTransport()
        await t.bind("127.0.0.1", 0, pmtu_discover=True)
        try:
            sock = t._transport.get_extra_info("socket")  # type: ignore[union-attr]
            mode = sock.getsockopt(socket.IPPROTO_IP, _IP_MTU_DISCOVER)
            # IP_PMTUDISC_DO == 2 on Linux
            self.assertEqual(mode, 2)
            # PMTU estimate may be None right after bind — kernel hasn't
            # sent anything yet — but the helper must at least not raise.
            _ = t.get_path_mtu()
        finally:
            await t.aclose()

    async def test_pmtu_failure_does_not_break_bind(self) -> None:
        """Simulate a kernel that rejects IP_MTU_DISCOVER (e.g. very
        stripped BSD container). bind() must still succeed with the flag
        set to False in that case."""
        t = UDPTransport()

        # Patch the sockopt to raise so we exercise the fallback path.
        orig_setsockopt = socket.socket.setsockopt

        def failing_setsockopt(self_, level, optname, value):  # type: ignore[no-untyped-def]
            from dsm.net.transport.udp import _IP_MTU_DISCOVER
            if level == socket.IPPROTO_IP and optname == _IP_MTU_DISCOVER:
                raise OSError("simulated rejection")
            return orig_setsockopt(self_, level, optname, value)

        with patch.object(socket.socket, "setsockopt", failing_setsockopt):
            await t.bind("127.0.0.1", 0, pmtu_discover=True)
            try:
                # PMTUD ended up disabled because the sockopt failed;
                # bind itself didn't raise.
                self.assertIsNone(t.get_path_mtu())
            finally:
                await t.aclose()


if __name__ == "__main__":
    unittest.main()
