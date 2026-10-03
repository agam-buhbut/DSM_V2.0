"""Tests for LocalDNSProxy port-conflict error handling.

Verifies that binding a blocked port raises a typed, actionable
``DNSProxyPortInUseError`` (EADDRINUSE) while other OSErrors still
propagate as raw OSError subclasses (not masked by the new exception).
"""

from __future__ import annotations

import errno
import socket
import unittest
from unittest.mock import AsyncMock, patch

from dsm.net.dns_proxy import DNSProxyPortInUseError, LocalDNSProxy


class _StubResolver:
    """Minimal resolver stub — tests here never reach the resolver."""

    async def resolve(self, hostname: str) -> list[str]:  # pragma: no cover
        return []

    async def close(self) -> None:  # pragma: no cover
        pass


class TestDNSProxyPortConflict(unittest.IsolatedAsyncioTestCase):
    async def test_raises_typed_error_when_port_already_in_use(self) -> None:
        """Binding a blocked port raises DNSProxyPortInUseError."""
        blocker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        blocker.bind(("127.0.0.1", 0))
        try:
            port = blocker.getsockname()[1]
            proxy = LocalDNSProxy(
                _StubResolver(),  # type: ignore[arg-type]
                bind_ip="127.0.0.1",
                bind_port=port,
            )
            with self.assertRaises(DNSProxyPortInUseError) as ctx:
                await proxy.start()
            self.assertIn("resolver", str(ctx.exception))
        finally:
            blocker.close()

    async def test_non_eaddrinuse_oserror_not_wrapped(self) -> None:
        """An OSError that is NOT EADDRINUSE propagates as-is, not wrapped."""
        proxy = LocalDNSProxy(
            _StubResolver(),  # type: ignore[arg-type]
            bind_ip="127.0.0.1",
            bind_port=0,
        )
        eacces = OSError(errno.EACCES, "Permission denied")
        loop_mock = AsyncMock()
        loop_mock.create_datagram_endpoint.side_effect = eacces

        with patch("asyncio.get_running_loop", return_value=loop_mock):
            with self.assertRaises(OSError) as ctx:
                await proxy.start()
        # Must NOT be wrapped as the typed subclass
        self.assertNotIsInstance(ctx.exception, DNSProxyPortInUseError)
        self.assertEqual(ctx.exception.errno, errno.EACCES)


if __name__ == "__main__":
    unittest.main()
