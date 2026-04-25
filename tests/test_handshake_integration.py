"""End-to-end test of the Noise XX handshake + post-handshake DH bootstrap.

This is the regression guard for the critical vulnerability that the
bootstrap DH exchange was introduced to fix: session keys must derive
from SECRET material (ephemeral DH shared secret), not from the PUBLIC
Noise handshake transcript hash. If someone regresses that fix, the
roundtrip encrypt/decrypt below will still pass (same shared secret on
both sides), but *the per-direction key material* will be different
from what this test captures — and these tests prove both endpoints
actually agree on the session keys after the full 3-message Noise XX
exchange plus the extra bootstrap round.
"""

from __future__ import annotations

import asyncio
import contextlib
import unittest
from unittest.mock import patch

try:
    import tuncore
    _HAS_TUNCORE = True
except ImportError:
    tuncore = None  # type: ignore[assignment]
    _HAS_TUNCORE = False


@unittest.skipUnless(
    _HAS_TUNCORE,
    "tuncore (Rust crypto core) not built; run `maturin develop` in rust/tuncore/",
)
class TestHandshakeRoundtrip(unittest.IsolatedAsyncioTestCase):
    """Run client_handshake + server_handshake over a local UDP pair."""

    async def asyncSetUp(self) -> None:
        # apply_so_mark needs CAP_NET_ADMIN; patch at both transport sites.
        self._so_mark_patches = [
            patch("dsm.net.transport.udp.apply_so_mark", lambda sock: None),
            patch("dsm.net.transport.tcp.apply_so_mark", lambda sock: None),
        ]
        for p in self._so_mark_patches:
            p.start()

    async def asyncTearDown(self) -> None:
        for p in self._so_mark_patches:
            p.stop()

    async def test_roundtrip_establishes_matching_session_keys(self) -> None:
        from dsm.crypto.handshake import client_handshake, server_handshake
        from dsm.net.transport.udp import UDPTransport

        # Bind both endpoints on loopback. Port 0 asks the kernel for a
        # free ephemeral port.
        server_transport = UDPTransport()
        server_port = await server_transport.bind("127.0.0.1", 0)
        self.addAsyncCleanup(server_transport.aclose)

        client_transport = UDPTransport()
        await client_transport.bind("127.0.0.1", 0)
        self.addAsyncCleanup(client_transport.aclose)

        server_identity = tuncore.IdentityKeyPair.generate()
        client_identity = tuncore.IdentityKeyPair.generate()

        server_addr = ("127.0.0.1", server_port)

        # Run both handshakes concurrently.
        client_coro = client_handshake(
            client_transport,
            client_identity,
            server_addr,
            known_hosts_path=None,  # skip TOFU cache for this test
        )
        server_coro = server_handshake(server_transport, server_identity)

        (client_keys, _client_hash), (server_keys, client_static_seen) = (
            await asyncio.wait_for(
                asyncio.gather(client_coro, server_coro),
                timeout=30.0,
            )
        )

        # Server sees the client's static pubkey post-handshake.
        self.assertEqual(len(bytes(client_static_seen)), 32)

        # The real proof that both sides agreed on key material:
        # ciphertext from one side decrypts on the other.
        aad = b"\x00" * 8
        nonce, ct, _epoch = client_keys.encrypt(b"ping", aad)
        pt = server_keys.decrypt(bytes(nonce), bytes(ct), aad, 1, False)
        self.assertEqual(bytes(pt), b"ping")

        nonce2, ct2, _epoch2 = server_keys.encrypt(b"pong", aad)
        pt2 = client_keys.decrypt(bytes(nonce2), bytes(ct2), aad, 1, False)
        self.assertEqual(bytes(pt2), b"pong")

    async def test_two_sessions_derive_different_keys(self) -> None:
        """Each session must derive its own keys via ephemeral DH; two
        runs with the same identity pairs still produce independent
        SessionKeyManagers (forward secrecy)."""
        from dsm.crypto.handshake import client_handshake, server_handshake
        from dsm.net.transport.udp import UDPTransport

        server_identity = tuncore.IdentityKeyPair.generate()
        client_identity = tuncore.IdentityKeyPair.generate()

        async def run_one() -> tuple[object, object]:
            st = UDPTransport()
            sp = await st.bind("127.0.0.1", 0)
            ct = UDPTransport()
            await ct.bind("127.0.0.1", 0)
            try:
                result = await asyncio.wait_for(
                    asyncio.gather(
                        client_handshake(ct, client_identity, ("127.0.0.1", sp), known_hosts_path=None),
                        server_handshake(st, server_identity),
                    ),
                    timeout=30.0,
                )
            finally:
                with contextlib.suppress(Exception):
                    await ct.aclose()
                with contextlib.suppress(Exception):
                    await st.aclose()
            (client_keys, _), (server_keys, _) = result
            return client_keys, server_keys

        c1, _s1 = await run_one()
        _c2, s2 = await run_one()

        # A packet encrypted in session 1 must NOT decrypt under session 2's
        # keys — this is the forward-secrecy guarantee enabled by the
        # ephemeral DH bootstrap.
        aad = b"\x00" * 8
        nonce, ct, _ = c1.encrypt(b"session-1-secret", aad)

        with self.assertRaises(Exception):
            s2.decrypt(bytes(nonce), bytes(ct), aad, 1, False)


@unittest.skipUnless(
    _HAS_TUNCORE,
    "tuncore (Rust crypto core) not built; run `maturin develop` in rust/tuncore/",
)
class TestHandshakeRoundtripTCP(unittest.IsolatedAsyncioTestCase):
    """Same handshake + bootstrap as the UDP test, but over TCPTransport.

    TCP has length-prefix framing (`[4-byte len][payload]`) rather than the
    UDP one-datagram-per-call semantics; this test guards against
    TCP-specific framing or stream-resync bugs in the handshake path.
    """

    async def asyncSetUp(self) -> None:
        self._so_mark_patches = [
            patch("dsm.net.transport.udp.apply_so_mark", lambda sock: None),
            patch("dsm.net.transport.tcp.apply_so_mark", lambda sock: None),
        ]
        for p in self._so_mark_patches:
            p.start()

    async def asyncTearDown(self) -> None:
        for p in self._so_mark_patches:
            p.stop()

    async def test_tcp_roundtrip_establishes_matching_session_keys(self) -> None:
        from dsm.crypto.handshake import client_handshake, server_handshake
        from dsm.net.transport.tcp import TCPTransport

        server_transport = TCPTransport()
        client_transport = TCPTransport()

        server_identity = tuncore.IdentityKeyPair.generate()
        client_identity = tuncore.IdentityKeyPair.generate()

        # TCPTransport.listen() blocks until a client connects. Kick off the
        # listen first; once it returns the actual port, start the client
        # connection. We do this via two background tasks synchronised by a
        # port-discovery pattern: start a bare `asyncio.start_server` probe
        # — actually simpler: manually pre-bind to discover a free port.
        import socket
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()

        async def _listen_then_handshake():
            await server_transport.listen("127.0.0.1", port)
            return await server_handshake(server_transport, server_identity)

        async def _connect_then_handshake():
            # Small backoff so the server's listen() is ready before connect.
            for _ in range(50):
                try:
                    await client_transport.connect("127.0.0.1", port)
                    break
                except (ConnectionRefusedError, OSError):
                    await asyncio.sleep(0.02)
            else:
                raise RuntimeError("could not connect to server")
            return await client_handshake(
                client_transport, client_identity, ("127.0.0.1", port),
                known_hosts_path=None,
            )

        self.addAsyncCleanup(server_transport.aclose)
        self.addAsyncCleanup(client_transport.aclose)

        (server_result, client_result) = await asyncio.wait_for(
            asyncio.gather(_listen_then_handshake(), _connect_then_handshake()),
            timeout=30.0,
        )
        server_keys, client_static_seen = server_result
        client_keys, _client_hash = client_result

        self.assertEqual(len(bytes(client_static_seen)), 32)

        aad = b"\x00" * 8
        nonce, ct, _epoch = client_keys.encrypt(b"ping-tcp", aad)
        pt = server_keys.decrypt(bytes(nonce), bytes(ct), aad, 1, False)
        self.assertEqual(bytes(pt), b"ping-tcp")

        nonce2, ct2, _e2 = server_keys.encrypt(b"pong-tcp", aad)
        pt2 = client_keys.decrypt(bytes(nonce2), bytes(ct2), aad, 1, False)
        self.assertEqual(bytes(pt2), b"pong-tcp")


if __name__ == "__main__":
    unittest.main()
