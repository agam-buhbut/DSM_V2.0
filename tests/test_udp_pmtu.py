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

from dsm.net.transport.udp import _IP_MTU, UDPTransport


class TestUDPPMTU(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        # apply_so_mark needs CAP_NET_ADMIN; disable for the test.
        self._so_mark_patch = patch(
            "dsm.net.transport.udp.apply_so_mark",
            lambda sock: None,
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


class TestUDPRebind(unittest.IsolatedAsyncioTestCase):
    """H-ANON-4: ``rebind_to_fresh_port`` swaps the underlying socket to
    a new ephemeral port while preserving the recv queue."""

    async def asyncSetUp(self) -> None:
        self._so_mark_patch = patch(
            "dsm.net.transport.udp.apply_so_mark",
            lambda sock: None,
        )
        self._so_mark_patch.start()

    async def asyncTearDown(self) -> None:
        self._so_mark_patch.stop()

    async def test_rebind_changes_port_preserves_queue(self) -> None:
        t = UDPTransport()
        await t.bind("127.0.0.1", 0)
        try:
            old_port = t._transport.get_extra_info("sockname")[1]  # type: ignore[union-attr]
            old_queue = t._recv_queue
            new_port = await t.rebind_to_fresh_port()
            self.assertNotEqual(old_port, new_port, "port must change")
            self.assertIs(
                t._recv_queue,
                old_queue,
                "recv queue must be preserved across rebind",
            )
            # The new socket is the live one: sockname reports the fresh port.
            current_port = t._transport.get_extra_info("sockname")[1]  # type: ignore[union-attr]
            self.assertEqual(current_port, new_port)
        finally:
            await t.aclose()

    async def test_rebind_bind_failure_preserves_old_transport(self) -> None:
        """If new bind raises, the old transport stays alive — caller
        catches the OSError without losing the session."""
        t = UDPTransport()
        await t.bind("127.0.0.1", 0)
        try:
            old_transport = t._transport
            old_port = old_transport.get_extra_info("sockname")[1]  # type: ignore[union-attr]

            orig_bind = socket.socket.bind
            failed = {"count": 0}

            def failing_bind(self_, addr):  # type: ignore[no-untyped-def]
                # Fail only the rebind's bind, not the test setup.
                if failed["count"] == 0:
                    failed["count"] += 1
                    raise OSError("simulated bind failure")
                return orig_bind(self_, addr)

            with patch.object(socket.socket, "bind", failing_bind):
                with self.assertRaises(OSError):
                    await t.rebind_to_fresh_port()
            # Old transport still bound to old port.
            self.assertIs(t._transport, old_transport)
            current_port = t._transport.get_extra_info("sockname")[1]  # type: ignore[union-attr]
            self.assertEqual(current_port, old_port)
        finally:
            await t.aclose()


def _route_mtu_control(peer: tuple[str, int]) -> int:
    # What the kernel says for the route to ``peer``: 65535 on a default
    # loopback (lo is 65536, IP_MTU caps at 65535).
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as control:
        control.connect(peer)
        return control.getsockopt(socket.IPPROTO_IP, _IP_MTU)


class TestUDPPMTUReading(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._so_mark_patch = patch(
            "dsm.net.transport.udp.apply_so_mark", lambda sock: None
        )
        self._so_mark_patch.start()
        self._rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._rx.bind(("127.0.0.1", 0))
        self._peer: tuple[str, int] = self._rx.getsockname()

    async def asyncTearDown(self) -> None:
        self._rx.close()
        self._so_mark_patch.stop()

    @unittest.skipUnless(sys.platform.startswith("linux"), "IP_MTU is Linux-only")
    async def test_get_path_mtu_reads_route_after_send(self) -> None:
        """With PMTUD on, a reading comes back after a send, before and after
        a rebind, and the socket itself stays unconnected (connect() would
        pin the client's source address across a network change)."""
        expected = _route_mtu_control(self._peer)
        t = UDPTransport()
        await t.bind("127.0.0.1", 0, pmtu_discover=True)
        try:
            self.assertIsNone(t.get_path_mtu())  # nothing sent yet
            await t.send(b"x" * 100, self._peer)
            self.assertEqual(t.get_path_mtu(), expected)
            await t.rebind_to_fresh_port()
            self.assertEqual(t.get_path_mtu(), expected)
            sock = t._transport.get_extra_info("socket")  # type: ignore[union-attr]
            with self.assertRaises(OSError):
                sock.getpeername()
        finally:
            await t.aclose()

    async def test_get_path_mtu_none_when_probe_cannot_be_marked(self) -> None:
        """An unmarked socket looks up the route through the TUN on a client,
        so a failed mark gives no reading, never the TUN's MTU."""
        t = UDPTransport()
        await t.bind("127.0.0.1", 0, pmtu_discover=True)
        try:
            await t.send(b"x" * 100, self._peer)
            with patch(
                "dsm.net.transport.udp.apply_so_mark",
                side_effect=PermissionError(1, "Operation not permitted"),
            ):
                self.assertIsNone(t.get_path_mtu())
        finally:
            await t.aclose()

    @unittest.skipUnless(sys.platform.startswith("linux"), "IP_MTU is Linux-only")
    async def test_probe_is_marked_before_it_connects(self) -> None:
        """connect() picks the route, so the mark must be on before it."""
        connected_when_marked: list[bool] = []

        def _record(sock: socket.socket | None) -> None:
            assert sock is not None
            try:
                sock.getpeername()
            except OSError:
                connected_when_marked.append(False)
            else:
                connected_when_marked.append(True)

        t = UDPTransport()
        await t.bind("127.0.0.1", 0, pmtu_discover=True)
        try:
            await t.send(b"x" * 100, self._peer)
            with patch("dsm.net.transport.udp.apply_so_mark", _record):
                self.assertIsNotNone(t.get_path_mtu())
            self.assertEqual(connected_when_marked, [False])
        finally:
            await t.aclose()

    async def test_get_path_mtu_none_when_no_probe_socket(self) -> None:
        """Out of file descriptors: no reading, and nothing raised into the
        auto_mtu loop (an error there would end the session)."""
        t = UDPTransport()
        await t.bind("127.0.0.1", 0, pmtu_discover=True)
        try:
            await t.send(b"x" * 100, self._peer)
            with patch.object(
                socket, "socket", side_effect=OSError(24, "Too many open files")
            ):
                self.assertIsNone(t.get_path_mtu())
        finally:
            await t.aclose()


if __name__ == "__main__":
    unittest.main()
