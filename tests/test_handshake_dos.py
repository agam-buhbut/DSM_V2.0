"""Regression: malformed unauthenticated msg1 must surface as a typed
HandshakeError, not an untranslated Rust RuntimeError that escapes the
server retry loop and kills asyncio.run (finding C1, remote DoS)."""

from __future__ import annotations

import asyncio
import os
import unittest
from unittest.mock import patch

from cryptography.x509.oid import ExtendedKeyUsageOID

try:
    import tuncore  # noqa: F401

    _HAS_TUNCORE = True
except ImportError:
    tuncore = None  # type: ignore[assignment]
    _HAS_TUNCORE = False

from dsm.crypto.cert_allowlist import CNAllowlist
from dsm.crypto.handshake import (
    HANDSHAKE_FRAME_SIZE,
    HandshakeError,
    server_handshake,
)
from dsm.net.transport.udp import UDPTransport


@unittest.skipUnless(_HAS_TUNCORE, "requires tuncore")
class TestHandshakeMalformedMsg1(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        from tests.cert_helpers import (
            SERVER_AUTH_OID,
            make_enrolled_device,
            make_test_ca,
        )

        # SO_MARK needs CAP_NET_ADMIN, absent in CI/test — stub it out.
        self._patches = [
            patch("dsm.net.transport.udp.apply_so_mark", lambda sock: None),
        ]
        for p in self._patches:
            p.start()
        self.ca = make_test_ca()
        self.server = make_enrolled_device(
            self.ca,
            subject_cn="dsm-server01-server",
            eku=SERVER_AUTH_OID,
        )
        self.allowlist = CNAllowlist(cns=frozenset({"dsm-client01-client"}))

    async def asyncTearDown(self) -> None:
        for p in self._patches:
            p.stop()

    async def _bind_pair(self) -> tuple[UDPTransport, UDPTransport, int]:
        server_transport = UDPTransport()
        server_port = await server_transport.bind("127.0.0.1", 0)
        self.addAsyncCleanup(server_transport.aclose)
        attacker = UDPTransport()
        await attacker.bind("127.0.0.1", 0)
        self.addAsyncCleanup(attacker.aclose)
        return server_transport, attacker, server_port

    async def _run_server_once(self, server_transport: UDPTransport) -> None:
        await asyncio.wait_for(
            server_handshake(
                server_transport,
                self.server.identity,
                attest_key=self.server.attest_key,
                cert_der=self.server.cert_der,
                ca_root=self.ca.certificate,
                cn_allowlist=self.allowlist,
                required_client_eku=ExtendedKeyUsageOID.CLIENT_AUTH,
            ),
            timeout=10.0,
        )

    async def test_wrong_size_msg1_raises_handshake_error(self) -> None:
        server_transport, attacker, port = await self._bind_pair()
        # 100 bytes != HANDSHAKE_FRAME_SIZE: Rust unpack_handshake rejects.
        await attacker.send(b"\x00" * 100, ("127.0.0.1", port))
        with self.assertRaises(HandshakeError):
            await self._run_server_once(server_transport)

    async def test_low_order_msg1_raises_handshake_error(self) -> None:
        server_transport, attacker, port = await self._bind_pair()
        # 32 zero bytes is a low-order X25519 point; Rust rejects before ee.
        frame = b"\x00" * 32 + os.urandom(HANDSHAKE_FRAME_SIZE - 32)
        await attacker.send(frame, ("127.0.0.1", port))
        with self.assertRaises(HandshakeError):
            await self._run_server_once(server_transport)

    async def test_server_loop_survives_malformed_msg1(self) -> None:
        # Mimic run_server's retry loop: a malformed msg1 must be a caught
        # HandshakeError, not a RuntimeError that escapes the loop.
        server_transport, attacker, port = await self._bind_pair()
        survived = False
        for _ in range(2):
            await attacker.send(b"\x00" * 100, ("127.0.0.1", port))
            try:
                await self._run_server_once(server_transport)
            except HandshakeError:
                survived = True
                continue
        self.assertTrue(survived)


@unittest.skipUnless(_HAS_TUNCORE, "requires tuncore")
class TestBootstrapLowOrderKeyDos(unittest.IsolatedAsyncioTestCase):
    """Regression: a peer-supplied low-order X25519 bootstrap ephemeral
    makes tuncore.complete_bootstrap raise RuntimeError.  Without the
    _translate_noise_errors wrapper on the two complete_bootstrap call
    sites that RuntimeError escapes the daemon's
    ``except (HandshakeError, CertAuthError)`` retry boundary and kills
    asyncio.run (remote DoS, finding C1 follow-on).  After the fix,
    both sides must surface HandshakeError, not RuntimeError."""

    async def asyncSetUp(self) -> None:
        from tests.cert_helpers import (
            CLIENT_AUTH_OID,
            SERVER_AUTH_OID,
            make_enrolled_device,
            make_test_ca,
        )

        self._patches: list = [
            patch("dsm.net.transport.udp.apply_so_mark", lambda sock: None),
        ]
        for p in self._patches:
            p.start()

        self.ca = make_test_ca()
        self.client = make_enrolled_device(
            self.ca,
            subject_cn="dsm-client-bootstrap-dos-client",
            eku=CLIENT_AUTH_OID,
        )
        self.server = make_enrolled_device(
            self.ca,
            subject_cn="dsm-server-bootstrap-dos-server",
            eku=SERVER_AUTH_OID,
        )
        self.allowlist = CNAllowlist(cns=frozenset({"dsm-client-bootstrap-dos-client"}))

    async def asyncTearDown(self) -> None:
        for p in self._patches:
            p.stop()

    async def test_bootstrap_low_order_key_raises_handshake_error(self) -> None:
        """Both sides must surface HandshakeError (not RuntimeError) when
        complete_bootstrap is injected with the low-order-key RuntimeError."""
        import tuncore as _tuncore
        from dsm.crypto.handshake import client_handshake, server_handshake
        from dsm.net.transport.udp import UDPTransport

        _low_order_exc = RuntimeError(
            "bootstrap: non-contributory shared secret (low-order public key)"
        )

        server_t = UDPTransport()
        server_port = await server_t.bind("127.0.0.1", 0)
        self.addAsyncCleanup(server_t.aclose)

        client_t = UDPTransport()
        await client_t.bind("127.0.0.1", 0)
        self.addAsyncCleanup(client_t.aclose)

        server_addr = ("127.0.0.1", server_port)

        with patch.object(_tuncore, "complete_bootstrap", side_effect=_low_order_exc):
            results = await asyncio.wait_for(
                asyncio.gather(
                    client_handshake(
                        client_t,
                        self.client.identity,
                        server_addr,
                        attest_key=self.client.attest_key,
                        cert_der=self.client.cert_der,
                        ca_root=self.ca.certificate,
                        expected_server_cn="dsm-server-bootstrap-dos-server",
                    ),
                    server_handshake(
                        server_t,
                        self.server.identity,
                        attest_key=self.server.attest_key,
                        cert_der=self.server.cert_der,
                        ca_root=self.ca.certificate,
                        cn_allowlist=self.allowlist,
                    ),
                    return_exceptions=True,
                ),
                timeout=30.0,
            )

        # At least one side must have hit the injected failure; otherwise
        # the patch missed the call site and this test asserts nothing.
        self.assertTrue(
            any(isinstance(r, BaseException) for r in results),
            "complete_bootstrap patch was never reached",
        )
        for result in results:
            if isinstance(result, BaseException):
                self.assertIsInstance(
                    result,
                    HandshakeError,
                    f"expected HandshakeError, got {type(result).__name__}: {result}",
                )


if __name__ == "__main__":
    unittest.main()
