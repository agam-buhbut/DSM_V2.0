"""Regression test: handshake survives a brief link outage during msg1.

The locked Phase-2 plan calls for "verify handshake survives 5 s cellular
outage". The current retry budget is ``MAX_RETRIES = 3`` × backoff (1+2+4 s)
+ ``HANDSHAKE_TIMEOUT = 5 s`` per attempt = up to ~22 s of tolerance for
the worst-case retry. A 5 s outage is well within budget.

This test exercises the retry path end-to-end via a UDPTransport subclass
that silently drops the first N ``send()`` calls. It's a regression lock:
if a future change breaks the retry loop, this test fails before the
demo runs into it on real cellular. Tests run with shortened timeouts so
the suite stays fast.

Limitation: only the **client's first sends** can safely be dropped in
the current protocol. Snow-based Noise XX can't recover from msg2 / msg3
drops because peer state advances past the lost message; that's a
deeper protocol design constraint (see TODO in handshake.py).
"""

from __future__ import annotations

import asyncio
import unittest
from unittest.mock import patch

from cryptography.x509.oid import ExtendedKeyUsageOID

from dsm.crypto.cert_allowlist import CNAllowlist
from dsm.crypto.handshake import (
    HandshakeError,
    client_handshake,
    server_handshake,
)
from dsm.net.transport.udp import UDPTransport

from tests.cert_helpers import (
    CLIENT_AUTH_OID,
    SERVER_AUTH_OID,
    IssuingCA,
    make_enrolled_device,
    make_test_ca,
)


class _DroppingUDPTransport(UDPTransport):
    """UDPTransport that silently drops the first ``drop_initial_sends``
    send() calls. Used to simulate a cellular outage at the start of the
    handshake."""

    def __init__(self, drop_initial_sends: int = 0) -> None:
        super().__init__()
        self._sends_remaining_to_drop = drop_initial_sends
        self.sends_dropped = 0
        self.sends_passed = 0

    async def send(self, data: bytes, addr: tuple[str, int]) -> None:
        if self._sends_remaining_to_drop > 0:
            self._sends_remaining_to_drop -= 1
            self.sends_dropped += 1
            return  # drop on the floor
        self.sends_passed += 1
        await super().send(data, addr)


class TestHandshakeRetryUnderOutage(unittest.IsolatedAsyncioTestCase):
    """Cellular-outage regression suite. Speeds up retry timing so each
    case completes in a few seconds rather than ~22 s."""

    async def asyncSetUp(self) -> None:
        # Speed up the retry loop. HANDSHAKE_TIMEOUT 0.3s + BACKOFF_BASE
        # 0.05s gives delays of 0.05/0.1/0.2 s between retries — total
        # worst case ≈ 1.25 s.
        self._patches = [
            patch("dsm.crypto.handshake.HANDSHAKE_TIMEOUT", 0.3),
            patch("dsm.crypto.handshake.BACKOFF_BASE", 0.05),
            patch("dsm.net.transport.udp.apply_so_mark", lambda sock: None),
            patch("dsm.net.transport.tcp.apply_so_mark", lambda sock: None),
        ]
        for p in self._patches:
            p.start()

        self.ca: IssuingCA = make_test_ca()
        self.client = make_enrolled_device(
            self.ca,
            subject_cn="dsm-client01-client",
            eku=CLIENT_AUTH_OID,
        )
        self.server = make_enrolled_device(
            self.ca,
            subject_cn="dsm-server01-server",
            eku=SERVER_AUTH_OID,
        )
        self.allowlist = CNAllowlist(cns=frozenset({"dsm-client01-client"}))

    async def asyncTearDown(self) -> None:
        for p in self._patches:
            p.stop()

    async def _run(
        self,
        client_drop_first: int,
    ) -> tuple[_DroppingUDPTransport, object, object]:
        server_transport = UDPTransport()
        server_port = await server_transport.bind("127.0.0.1", 0)
        self.addAsyncCleanup(server_transport.aclose)

        client_transport = _DroppingUDPTransport(drop_initial_sends=client_drop_first)
        await client_transport.bind("127.0.0.1", 0)
        self.addAsyncCleanup(client_transport.aclose)

        server_addr = ("127.0.0.1", server_port)

        client_kwargs = dict(
            attest_key=self.client.attest_key,
            cert_der=self.client.cert_der,
            ca_root=self.ca.certificate,
            expected_server_cn="dsm-server01-server",
            required_server_eku=ExtendedKeyUsageOID.SERVER_AUTH,
        )
        server_kwargs = dict(
            attest_key=self.server.attest_key,
            cert_der=self.server.cert_der,
            ca_root=self.ca.certificate,
            cn_allowlist=self.allowlist,
            required_client_eku=ExtendedKeyUsageOID.CLIENT_AUTH,
        )

        client_result, server_result = await asyncio.wait_for(
            asyncio.gather(
                client_handshake(
                    client_transport,
                    self.client.identity,
                    server_addr,
                    **client_kwargs,
                ),
                server_handshake(
                    server_transport,
                    self.server.identity,
                    **server_kwargs,
                ),
            ),
            timeout=10.0,
        )
        return client_transport, client_result, server_result

    async def test_drop_first_msg1_completes_after_retry(self) -> None:
        """Drop only the FIRST send (msg1). Client's retransmit on
        timeout reaches the server; handshake completes."""
        transport, client_result, server_result = await self._run(client_drop_first=1)

        # We dropped exactly 1 send. Client must have retransmitted.
        self.assertEqual(transport.sends_dropped, 1)
        self.assertGreaterEqual(transport.sends_passed, 2)  # msg1 retry + msg3 + maybe bootstrap

        # Both sides converged on session keys.
        client_keys, _ = client_result
        server_keys, _ = server_result
        self.assertIsNotNone(client_keys)
        self.assertIsNotNone(server_keys)

    async def test_drop_two_msg1_attempts_completes(self) -> None:
        """Drop the first TWO sends. Client retransmits twice; the third
        attempt reaches the server. Handshake still completes within
        retry budget."""
        transport, client_result, server_result = await self._run(client_drop_first=2)
        self.assertEqual(transport.sends_dropped, 2)
        client_keys, _ = client_result
        server_keys, _ = server_result
        self.assertIsNotNone(client_keys)
        self.assertIsNotNone(server_keys)

    async def test_drop_all_retries_fails_with_typed_error(self) -> None:
        """Drop more sends than the retry budget. Client must raise
        HandshakeError, not some untyped runtime error."""
        # MAX_RETRIES=3 means 1 initial + 2 retries = 3 sends from the
        # client during msg1 phase. Drop all 4 to ensure no path through.
        # Use bare client_handshake (no server) so we don't deadlock the
        # server task waiting for a msg1 that never arrives.
        client_transport = _DroppingUDPTransport(drop_initial_sends=99)
        await client_transport.bind("127.0.0.1", 0)
        self.addAsyncCleanup(client_transport.aclose)

        # A bound but-unused server socket so the addr is valid.
        server_transport = UDPTransport()
        server_port = await server_transport.bind("127.0.0.1", 0)
        self.addAsyncCleanup(server_transport.aclose)

        with self.assertRaises(HandshakeError):
            await asyncio.wait_for(
                client_handshake(
                    client_transport,
                    self.client.identity,
                    ("127.0.0.1", server_port),
                    attest_key=self.client.attest_key,
                    cert_der=self.client.cert_der,
                    ca_root=self.ca.certificate,
                    expected_server_cn="dsm-server01-server",
                    required_server_eku=ExtendedKeyUsageOID.SERVER_AUTH,
                ),
                timeout=10.0,
            )


if __name__ == "__main__":
    unittest.main()
