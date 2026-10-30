"""A peer cert with a field cryptography cannot decode gives a CertError.

The handshakes catch only (AttestError, CertError) around
verify_attest_payload, so any other error type from a cert that came over
the network ends the client daemon (review finding #1).
"""

from __future__ import annotations

import asyncio
import base64
import secrets

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

import tuncore
from dsm.crypto.attest import PeerRole, build_attest_payload, verify_attest_payload
from dsm.crypto.cert import CertChainError, CertError, DeviceCert
from dsm.crypto.cert_allowlist import CNAllowlist
from dsm.crypto.handshake import CertAuthError, client_handshake, server_handshake
from dsm.net.transport.udp import UDPTransport
from tests.cert_helpers import (
    CLIENT_AUTH_OID,
    SERVER_AUTH_OID,
    IssuingCA,
    make_enrolled_device,
    make_leaf_cert,
    make_test_ca,
)

_CN_OID = bytes.fromhex("0603550403")  # 2.5.4.3 commonName
_ECDSA_SHA384_ALG = bytes.fromhex("300a06082a8648ce3d040303")
_RSA_PSS_NO_PARAMS_ALG = bytes.fromhex("300b06092a864886f70d01010a")

# Same-length byte swaps in a real CA-signed leaf: (old, new, error class).
_CASES = {
    "unknown curve OID": (
        bytes.fromhex("06082a8648ce3d030107"),  # prime256v1
        bytes.fromhex("06082a8648ce3d030109"),  # 1.2.840.10045.3.1.9
        CertError,
    ),
    "unknown key type OID": (
        bytes.fromhex("06072a8648ce3d0201"),  # id-ecPublicKey
        bytes.fromhex("06072a8648ce3d0209"),  # 1.2.840.10045.2.9
        CertError,
    ),
    "unknown signature OID": (
        bytes.fromhex("06082a8648ce3d040303"),  # ecdsa-with-SHA384, both copies
        bytes.fromhex("06082a8648ce3d040309"),  # 1.2.840.10045.4.3.9
        CertChainError,
    ),
    "X.509 version 5": (
        bytes.fromhex("a003020102"),
        bytes.fromhex("a003020105"),
        CertError,
    ),
    "issuer CN typed BIT STRING": (
        _CN_OID + b"\x0c\x0bDSM Test CA",
        _CN_OID + b"\x03\x0b\x00SM Test CA",
        CertError,
    ),
}


def _leaf_der(ca: IssuingCA, attest_key: tuncore.AttestKey) -> bytes:
    return make_leaf_cert(
        ca,
        subject_cn="srv",
        leaf_public_spki_der=attest_key.public_spki_der(),
        noise_static_pub=secrets.token_bytes(32),
        eku=SERVER_AUTH_OID,
    ).public_bytes(Encoding.DER)


def _tlv(tag: int, body: bytes) -> bytes:
    if len(body) < 0x80:
        return bytes([tag, len(body)]) + body
    size = len(body).to_bytes((len(body).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(size)]) + size + body


def _with_signature_alg(der: bytes, old: bytes, new: bytes) -> bytes:
    """Re-encode ``der`` with signature AlgorithmIdentifier ``new`` in the
    TBS and outside it, so the lengths stay right when the sizes differ."""
    cert = x509.load_der_x509_certificate(der)
    tbs = cert.tbs_certificate_bytes
    header = 2 + (tbs[1] & 0x7F if tbs[1] & 0x80 else 0)
    assert tbs[header:].count(old) == 1
    new_tbs = _tlv(0x30, tbs[header:].replace(old, new))
    return _tlv(0x30, new_tbs + new + _tlv(0x03, b"\x00" + cert.signature))


def _verify(ca: IssuingCA, attest_key: tuncore.AttestKey, cert_der: bytes) -> None:
    handshake_hash = secrets.token_bytes(32)
    static = secrets.token_bytes(32)
    payload = build_attest_payload(
        attest_key=attest_key,
        cert_der=cert_der,
        handshake_hash=handshake_hash,
        our_static_pub=static,
        our_role=PeerRole.RESPONDER,
    )
    verify_attest_payload(
        payload=payload,
        ca_root=ca.certificate,
        handshake_hash=handshake_hash,
        expected_remote_static=static,
        expected_peer_role=PeerRole.RESPONDER,
        required_eku=SERVER_AUTH_OID,
    )


@pytest.mark.parametrize("case", sorted(_CASES))
def test_verify_attest_payload_undecodable_cert_is_cert_error(case: str) -> None:
    old, new, error = _CASES[case]
    ca = make_test_ca()
    attest_key = tuncore.AttestKey.generate()
    der = _leaf_der(ca, attest_key)
    assert old in der
    with pytest.raises(error):
        _verify(ca, attest_key, der.replace(old, new))


def test_verify_attest_payload_rsa_pss_without_params_is_cert_chain_error() -> None:
    ca = make_test_ca()
    attest_key = tuncore.AttestKey.generate()
    der = _with_signature_alg(
        _leaf_der(ca, attest_key), _ECDSA_SHA384_ALG, _RSA_PSS_NO_PARAMS_ALG
    )
    with pytest.raises(CertChainError, match="signature algorithm"):
        _verify(ca, attest_key, der)


def test_from_pem_x509_version_5_is_cert_error() -> None:
    old, new, _ = _CASES["X.509 version 5"]
    der = _leaf_der(make_test_ca(), tuncore.AttestKey.generate()).replace(old, new)
    pem = (
        b"-----BEGIN CERTIFICATE-----\n"
        + base64.encodebytes(der)
        + b"-----END CERTIFICATE-----\n"
    )
    with pytest.raises(CertError, match="failed to parse cert PEM"):
        DeviceCert.from_pem(pem)


def test_client_handshake_turns_an_unreadable_server_cert_into_cert_auth_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A responder sends a cert with an unknown curve OID in msg2; the real
    client_handshake must raise CertAuthError, not a raw cryptography error."""
    monkeypatch.setattr("dsm.net.transport.udp.apply_so_mark", lambda sock: None)
    old, new, _ = _CASES["unknown curve OID"]

    async def run() -> None:
        ca = make_test_ca(common_name="DSM Root CA")
        client = make_enrolled_device(
            ca, subject_cn="dsm-c-client", eku=CLIENT_AUTH_OID
        )
        server = make_enrolled_device(
            ca, subject_cn="dsm-s-server", eku=SERVER_AUTH_OID
        )
        st = UDPTransport()
        port = await st.bind("127.0.0.1", 0)
        ct = UDPTransport()
        await ct.bind("127.0.0.1", 0)
        srv = asyncio.ensure_future(
            server_handshake(
                st,
                server.identity,
                attest_key=server.attest_key,
                cert_der=server.cert_der.replace(old, new),
                ca_root=ca.certificate,
                cn_allowlist=CNAllowlist(cns=frozenset({"dsm-c-client"})),
            )
        )
        try:
            await asyncio.wait_for(
                client_handshake(
                    ct,
                    client.identity,
                    ("127.0.0.1", port),
                    attest_key=client.attest_key,
                    cert_der=client.cert_der,
                    ca_root=ca.certificate,
                    expected_server_cn="dsm-s-server",
                    required_server_eku=SERVER_AUTH_OID,
                ),
                timeout=20,
            )
        finally:
            srv.cancel()
            await asyncio.gather(srv, return_exceptions=True)
            await st.aclose()
            await ct.aclose()

    with pytest.raises(CertAuthError):
        asyncio.run(run())
