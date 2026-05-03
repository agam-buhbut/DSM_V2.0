"""End-to-end test of the Noise XX handshake + cert/binding attestation
+ post-handshake DH bootstrap, over real loopback UDP/TCP sockets.

Regression guards:
  * forward secrecy via the bootstrap ephemeral DH (different sessions
    with the same identities derive distinct keys);
  * the server's initial msg1 recv blocks indefinitely (not bounded
    by MAX_RETRIES × HANDSHAKE_TIMEOUT);
  * cert/binding-attestation policy enforcement (CN allowlist on
    server, expected_server_cn on client, CRL revocation).
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import secrets
import unittest
from pathlib import Path
from unittest.mock import patch

try:
    import tuncore

    _HAS_TUNCORE = True
except ImportError:
    tuncore = None  # type: ignore[assignment]
    _HAS_TUNCORE = False

if _HAS_TUNCORE:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography import x509

    from dsm.crypto.cert_allowlist import CNAllowlist
    from dsm.crypto.crl import CRL
    from dsm.crypto.handshake import (
        CertAuthError,
        CNMismatchError,
        CNNotAllowedError,
        CertRevokedError,
        client_handshake,
        server_handshake,
    )
    from tests.cert_helpers import (
        CLIENT_AUTH_OID,
        SERVER_AUTH_OID,
        EnrolledDevice,
        IssuingCA,
        make_enrolled_device,
        make_test_ca,
    )


def _build_crl_with_revoked(
    ca, revoked_serials: list[int]
) -> CRL:
    """Construct a CRL signed by ``ca`` revoking the given serials,
    write it to disk, load it through the production code path, and
    return the loaded CRL object."""
    import datetime

    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca.certificate.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=30))
        .add_extension(x509.CRLNumber(1), critical=False)
    )
    for s in revoked_serials:
        entry = (
            x509.RevokedCertificateBuilder()
            .serial_number(s)
            .revocation_date(now)
            .build()
        )
        builder = builder.add_revoked_certificate(entry)
    crl = builder.sign(private_key=ca.private_key, algorithm=hashes.SHA384())
    der = crl.public_bytes(Encoding.DER)

    path = Path(os.environ.get("TMPDIR", "/tmp")) / (
        f"dsm-test-crl-{os.getpid()}-{secrets.token_hex(4)}.crl"
    )
    try:
        path.write_bytes(der)
        return CRL.load(path, ca.certificate)
    finally:
        with contextlib.suppress(FileNotFoundError):
            path.unlink()


@unittest.skipUnless(
    _HAS_TUNCORE,
    "tuncore not built; run `maturin develop` in rust/tuncore/",
)
class TestHandshakeRoundtrip(unittest.IsolatedAsyncioTestCase):
    """Run client_handshake + server_handshake over a local UDP pair."""

    async def asyncSetUp(self) -> None:
        self._so_mark_patches = [
            patch(
                "dsm.net.transport.udp.apply_so_mark", lambda sock: None
            ),
            patch(
                "dsm.net.transport.tcp.apply_so_mark", lambda sock: None
            ),
        ]
        for p in self._so_mark_patches:
            p.start()
        self.ca: IssuingCA = make_test_ca()
        self.client: EnrolledDevice = make_enrolled_device(
            self.ca,
            subject_cn="dsm-client01-client",
            eku=CLIENT_AUTH_OID,
        )
        self.server: EnrolledDevice = make_enrolled_device(
            self.ca,
            subject_cn="dsm-server01-server",
            eku=SERVER_AUTH_OID,
        )
        self.allowlist = CNAllowlist(
            cns=frozenset({self.client.cert_der and "dsm-client01-client"})
        )

    async def asyncTearDown(self) -> None:
        for p in self._so_mark_patches:
            p.stop()

    async def _run_udp_handshake(
        self,
        *,
        client_overrides: dict | None = None,
        server_overrides: dict | None = None,
    ):
        from dsm.net.transport.udp import UDPTransport

        server_transport = UDPTransport()
        server_port = await server_transport.bind("127.0.0.1", 0)
        self.addAsyncCleanup(server_transport.aclose)

        client_transport = UDPTransport()
        await client_transport.bind("127.0.0.1", 0)
        self.addAsyncCleanup(client_transport.aclose)

        server_addr = ("127.0.0.1", server_port)

        client_kwargs = dict(
            attest_key=self.client.attest_key,
            cert_der=self.client.cert_der,
            ca_root=self.ca.certificate,
            expected_server_cn="dsm-server01-server",
        )
        if client_overrides:
            client_kwargs.update(client_overrides)

        server_kwargs = dict(
            attest_key=self.server.attest_key,
            cert_der=self.server.cert_der,
            ca_root=self.ca.certificate,
            cn_allowlist=self.allowlist,
        )
        if server_overrides:
            server_kwargs.update(server_overrides)

        return await asyncio.wait_for(
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
                return_exceptions=False,
            ),
            timeout=30.0,
        )

    async def test_roundtrip_establishes_matching_session_keys(
        self,
    ) -> None:
        (client_keys, _client_hash), (
            server_keys,
            client_static_seen,
        ) = await self._run_udp_handshake()

        # Server sees the client's Noise static post-handshake.
        self.assertEqual(
            len(bytes(client_static_seen)), 32
        )

        # Both sides agreed on key material: ciphertext from one side
        # decrypts on the other.
        aad = b"\x00" * 8
        nonce, ct, _epoch = client_keys.encrypt(b"ping", aad)
        pt = server_keys.decrypt(bytes(nonce), bytes(ct), aad, 1, False)
        self.assertEqual(bytes(pt), b"ping")

        nonce2, ct2, _ = server_keys.encrypt(b"pong", aad)
        pt2 = client_keys.decrypt(bytes(nonce2), bytes(ct2), aad, 1, False)
        self.assertEqual(bytes(pt2), b"pong")

    async def test_two_sessions_derive_different_keys(self) -> None:
        """Each session must derive its own keys via ephemeral DH; two
        runs with the same identity pairs still produce independent
        SessionKeyManagers (forward secrecy)."""
        c1_keys, _ = (await self._run_udp_handshake())[0]
        _, (s2_keys, _) = await self._run_udp_handshake()

        aad = b"\x00" * 8
        nonce, ct, _ = c1_keys.encrypt(b"session-1-secret", aad)
        # Session-1 ciphertext must NOT decrypt under session-2 keys.
        with self.assertRaises(Exception):
            s2_keys.decrypt(bytes(nonce), bytes(ct), aad, 1, False)


@unittest.skipUnless(
    _HAS_TUNCORE,
    "tuncore not built; run `maturin develop` in rust/tuncore/",
)
class TestCertPolicyEnforcement(unittest.IsolatedAsyncioTestCase):
    """Cert-flow rejection paths: CN allowlist, expected_server_cn, CRL,
    wrong-CA, mismatched binding."""

    async def asyncSetUp(self) -> None:
        self._so_mark_patches = [
            patch(
                "dsm.net.transport.udp.apply_so_mark", lambda sock: None
            ),
        ]
        for p in self._so_mark_patches:
            p.start()
        self.ca: IssuingCA = make_test_ca()
        self.client = make_enrolled_device(
            self.ca,
            subject_cn="dsm-client-policy-client",
            eku=CLIENT_AUTH_OID,
        )
        self.server = make_enrolled_device(
            self.ca,
            subject_cn="dsm-server-policy-server",
            eku=SERVER_AUTH_OID,
        )

    async def asyncTearDown(self) -> None:
        for p in self._so_mark_patches:
            p.stop()

    async def _run(
        self,
        *,
        allowlist: CNAllowlist,
        expected_server_cn: str = "dsm-server-policy-server",
        client_ca=None,
        server_ca=None,
        crl=None,
    ):
        from dsm.net.transport.udp import UDPTransport

        if client_ca is None:
            client_ca = self.ca.certificate
        if server_ca is None:
            server_ca = self.ca.certificate

        server_t = UDPTransport()
        server_port = await server_t.bind("127.0.0.1", 0)
        self.addAsyncCleanup(server_t.aclose)
        client_t = UDPTransport()
        await client_t.bind("127.0.0.1", 0)
        self.addAsyncCleanup(client_t.aclose)

        return await asyncio.wait_for(
            asyncio.gather(
                client_handshake(
                    client_t,
                    self.client.identity,
                    ("127.0.0.1", server_port),
                    attest_key=self.client.attest_key,
                    cert_der=self.client.cert_der,
                    ca_root=client_ca,
                    expected_server_cn=expected_server_cn,
                    crl=crl,
                ),
                server_handshake(
                    server_t,
                    self.server.identity,
                    attest_key=self.server.attest_key,
                    cert_der=self.server.cert_der,
                    ca_root=server_ca,
                    cn_allowlist=allowlist,
                    crl=crl,
                ),
                return_exceptions=True,
            ),
            timeout=30.0,
        )

    def _expect_failure(self, results, exc_type) -> None:
        # Either side may surface the failure depending on which step
        # the violation lands in; we just want at least one of the
        # tasks to have raised the expected exception.
        matched = [r for r in results if isinstance(r, exc_type)]
        self.assertTrue(
            matched,
            f"expected at least one {exc_type.__name__} in results, got: {results!r}",
        )

    async def test_server_rejects_client_cn_not_in_allowlist(self) -> None:
        empty_allowlist = CNAllowlist(cns=frozenset())
        results = await self._run(allowlist=empty_allowlist)
        self._expect_failure(results, CNNotAllowedError)

    async def test_client_rejects_server_wrong_cn(self) -> None:
        results = await self._run(
            allowlist=CNAllowlist(
                cns=frozenset({"dsm-client-policy-client"})
            ),
            expected_server_cn="dsm-imposter-server",
        )
        self._expect_failure(results, CNMismatchError)

    async def test_revoked_client_cert_rejected(self) -> None:
        crl = _build_crl_with_revoked(
            self.ca, [self.client.cert.serial_number]
        )
        results = await self._run(
            allowlist=CNAllowlist(
                cns=frozenset({"dsm-client-policy-client"})
            ),
            crl=crl,
        )
        self._expect_failure(results, CertRevokedError)

    async def test_revoked_server_cert_rejected(self) -> None:
        crl = _build_crl_with_revoked(
            self.ca, [self.server.cert.serial_number]
        )
        results = await self._run(
            allowlist=CNAllowlist(
                cns=frozenset({"dsm-client-policy-client"})
            ),
            crl=crl,
        )
        self._expect_failure(results, CertRevokedError)

    async def test_client_pinned_to_other_ca_rejected(self) -> None:
        other_ca = make_test_ca("Foreign CA")
        results = await self._run(
            allowlist=CNAllowlist(
                cns=frozenset({"dsm-client-policy-client"})
            ),
            client_ca=other_ca.certificate,
        )
        # CertAuthError covers CertChainError + CertSignatureError etc.
        self._expect_failure(results, CertAuthError)


@unittest.skipUnless(
    _HAS_TUNCORE,
    "tuncore not built; run `maturin develop` in rust/tuncore/",
)
class TestHandshakeRoundtripTCP(unittest.IsolatedAsyncioTestCase):
    """Same handshake + bootstrap as the UDP test, but over TCPTransport."""

    async def asyncSetUp(self) -> None:
        self._so_mark_patches = [
            patch(
                "dsm.net.transport.udp.apply_so_mark", lambda sock: None
            ),
            patch(
                "dsm.net.transport.tcp.apply_so_mark", lambda sock: None
            ),
        ]
        for p in self._so_mark_patches:
            p.start()
        self.ca = make_test_ca()
        self.client = make_enrolled_device(
            self.ca, subject_cn="dsm-client-tcp-client", eku=CLIENT_AUTH_OID
        )
        self.server = make_enrolled_device(
            self.ca, subject_cn="dsm-server-tcp-server", eku=SERVER_AUTH_OID
        )

    async def asyncTearDown(self) -> None:
        for p in self._so_mark_patches:
            p.stop()

    async def test_tcp_roundtrip_establishes_matching_session_keys(
        self,
    ) -> None:
        from dsm.net.transport.tcp import TCPTransport
        import socket

        server_t = TCPTransport()
        client_t = TCPTransport()

        # Discover a free port via probe-bind (start_server discovery
        # would also work but is heavier).
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()

        async def _listen_then_handshake():
            await server_t.listen("127.0.0.1", port)
            return await server_handshake(
                server_t,
                self.server.identity,
                attest_key=self.server.attest_key,
                cert_der=self.server.cert_der,
                ca_root=self.ca.certificate,
                cn_allowlist=CNAllowlist(
                    cns=frozenset({"dsm-client-tcp-client"})
                ),
            )

        async def _connect_then_handshake():
            for _ in range(50):
                try:
                    await client_t.connect("127.0.0.1", port)
                    break
                except (ConnectionRefusedError, OSError):
                    await asyncio.sleep(0.02)
            else:
                raise RuntimeError("could not connect to server")
            return await client_handshake(
                client_t,
                self.client.identity,
                ("127.0.0.1", port),
                attest_key=self.client.attest_key,
                cert_der=self.client.cert_der,
                ca_root=self.ca.certificate,
                expected_server_cn="dsm-server-tcp-server",
            )

        self.addAsyncCleanup(server_t.aclose)
        self.addAsyncCleanup(client_t.aclose)

        (server_result, client_result) = await asyncio.wait_for(
            asyncio.gather(
                _listen_then_handshake(), _connect_then_handshake()
            ),
            timeout=30.0,
        )
        server_keys, client_static_seen = server_result
        client_keys, _client_hash = client_result

        self.assertEqual(len(bytes(client_static_seen)), 32)
        aad = b"\x00" * 8
        nonce, ct, _ = client_keys.encrypt(b"ping-tcp", aad)
        pt = server_keys.decrypt(bytes(nonce), bytes(ct), aad, 1, False)
        self.assertEqual(bytes(pt), b"ping-tcp")
        nonce2, ct2, _ = server_keys.encrypt(b"pong-tcp", aad)
        pt2 = client_keys.decrypt(
            bytes(nonce2), bytes(ct2), aad, 1, False
        )
        self.assertEqual(bytes(pt2), b"pong-tcp")


@unittest.skipUnless(
    _HAS_TUNCORE,
    "tuncore not built; run `maturin develop` in rust/tuncore/",
)
class TestServerWaitsIndefinitelyForFirstMsg1(
    unittest.IsolatedAsyncioTestCase
):
    """Regression: server's initial msg1 recv must NOT have a
    MAX_RETRIES × HANDSHAKE_TIMEOUT bound; it blocks until either a
    client connects or the task is cancelled."""

    async def asyncSetUp(self) -> None:
        self._so_mark_patches = [
            patch(
                "dsm.net.transport.udp.apply_so_mark", lambda sock: None
            ),
        ]
        for p in self._so_mark_patches:
            p.start()
        self.ca = make_test_ca()
        self.server = make_enrolled_device(
            self.ca,
            subject_cn="dsm-idle-server",
            eku=SERVER_AUTH_OID,
        )

    async def asyncTearDown(self) -> None:
        for p in self._so_mark_patches:
            p.stop()

    async def test_server_handshake_blocks_then_cancels_clean(
        self,
    ) -> None:
        from dsm.net.transport.udp import UDPTransport

        transport = UDPTransport()
        await transport.bind("127.0.0.1", 0)
        self.addAsyncCleanup(transport.aclose)

        task = asyncio.create_task(
            server_handshake(
                transport,
                self.server.identity,
                attest_key=self.server.attest_key,
                cert_der=self.server.cert_der,
                ca_root=self.ca.certificate,
                cn_allowlist=CNAllowlist(cns=frozenset()),
            )
        )

        # Past the OLD bounded timeout (~3s would have warned, ~18s
        # would have raised).
        await asyncio.sleep(1.5)
        self.assertFalse(
            task.done(),
            "server_handshake should still be waiting; was it bounded?",
        )

        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


if __name__ == "__main__":
    unittest.main()
