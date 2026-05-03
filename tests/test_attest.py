"""Tests for ``dsm.crypto.attest``: build and verify the per-handshake
binding-attestation payload."""

from __future__ import annotations

import datetime
import os
import secrets
import struct
import unittest

import tuncore
from cryptography.hazmat.primitives.serialization import Encoding

from dsm.crypto.attest import (
    BINDING_DOMAIN,
    BINDING_VERSION,
    AttestBindingMismatchError,
    AttestPayloadFormatError,
    AttestSignatureError,
    AttestTimestampError,
    PeerRole,
    build_attest_payload,
    verify_attest_payload,
)
from dsm.crypto.cert import (
    CertChainError,
    CertExpiredError,
    DeviceCert,
)
from tests.cert_helpers import (
    CLIENT_AUTH_OID,
    SERVER_AUTH_OID,
    make_leaf_cert,
    make_test_ca,
)


def _enrolled_device(
    ca,
    *,
    subject_cn: str = "dsm-test01-client",
    eku=CLIENT_AUTH_OID,
    noise_static_pub: bytes | None = None,
    **leaf_kwargs,
):
    """Mint a fresh AttestKey + leaf cert pair as the enroll flow
    will: AttestKey generates → CA signs a leaf binding the attest
    pubkey + a freshly-generated Noise static."""
    attest_key = tuncore.AttestKey.generate()
    if noise_static_pub is None:
        noise_static_pub = secrets.token_bytes(32)
    leaf = make_leaf_cert(
        ca,
        subject_cn=subject_cn,
        leaf_public_spki_der=attest_key.public_spki_der(),
        noise_static_pub=noise_static_pub,
        eku=eku,
        **leaf_kwargs,
    )
    return attest_key, leaf, noise_static_pub


def _build_responder_payload(
    ca,
    *,
    subject_cn: str = "dsm-srv01-server",
    handshake_hash: bytes | None = None,
    noise_static_pub: bytes | None = None,
    timestamp: datetime.datetime | None = None,
):
    """Helper: end-to-end producer-side flow for the server (responder)
    cert in msg2."""
    attest_key, leaf, ns = _enrolled_device(
        ca,
        subject_cn=subject_cn,
        eku=SERVER_AUTH_OID,
        noise_static_pub=noise_static_pub,
    )
    if handshake_hash is None:
        handshake_hash = secrets.token_bytes(32)
    payload = build_attest_payload(
        attest_key=attest_key,
        cert_der=leaf.public_bytes(Encoding.DER),
        handshake_hash=handshake_hash,
        our_static_pub=ns,
        our_role=PeerRole.RESPONDER,
        timestamp=timestamp,
    )
    return attest_key, leaf, ns, payload, handshake_hash


class TestAttestRoundtrip(unittest.TestCase):
    def setUp(self) -> None:
        self.ca = make_test_ca()

    def test_payload_size_is_constant(self) -> None:
        _, _, _, payload, _ = _build_responder_payload(self.ca)
        self.assertEqual(
            len(payload), tuncore.HANDSHAKE_ATTEST_PAYLOAD_SIZE
        )

    def test_happy_path_responder(self) -> None:
        _, _, ns, payload, h = _build_responder_payload(self.ca)
        cert = verify_attest_payload(
            payload=payload,
            ca_root=self.ca.certificate,
            handshake_hash=h,
            expected_remote_static=ns,
            expected_peer_role=PeerRole.RESPONDER,
            required_eku=SERVER_AUTH_OID,
        )
        self.assertEqual(cert.noise_static_pub, ns)

    def test_happy_path_initiator(self) -> None:
        attest_key, leaf, ns = _enrolled_device(self.ca, eku=CLIENT_AUTH_OID)
        h = secrets.token_bytes(32)
        payload = build_attest_payload(
            attest_key=attest_key,
            cert_der=leaf.public_bytes(Encoding.DER),
            handshake_hash=h,
            our_static_pub=ns,
            our_role=PeerRole.INITIATOR,
        )
        cert = verify_attest_payload(
            payload=payload,
            ca_root=self.ca.certificate,
            handshake_hash=h,
            expected_remote_static=ns,
            expected_peer_role=PeerRole.INITIATOR,
            required_eku=CLIENT_AUTH_OID,
        )
        self.assertEqual(cert.subject_cn, "dsm-test01-client")


class TestAttestRejections(unittest.TestCase):
    def setUp(self) -> None:
        self.ca = make_test_ca()
        (
            self.attest_key,
            self.leaf,
            self.ns,
            self.payload,
            self.h,
        ) = _build_responder_payload(self.ca)

    def _verify(self, **overrides):
        kwargs = dict(
            payload=self.payload,
            ca_root=self.ca.certificate,
            handshake_hash=self.h,
            expected_remote_static=self.ns,
            expected_peer_role=PeerRole.RESPONDER,
        )
        kwargs.update(overrides)
        return verify_attest_payload(**kwargs)

    def test_wrong_handshake_hash_rejected(self) -> None:
        with self.assertRaises(AttestSignatureError):
            self._verify(handshake_hash=secrets.token_bytes(32))

    def test_wrong_expected_role_rejected(self) -> None:
        with self.assertRaises(AttestSignatureError):
            self._verify(expected_peer_role=PeerRole.INITIATOR)

    def test_binding_static_mismatch_rejected(self) -> None:
        with self.assertRaises(AttestBindingMismatchError):
            self._verify(expected_remote_static=secrets.token_bytes(32))

    def test_wrong_ca_root_rejected(self) -> None:
        other_ca = make_test_ca("Other CA")
        with self.assertRaises(CertChainError):
            self._verify(ca_root=other_ca.certificate)

    def test_required_eku_mismatch_rejected(self) -> None:
        # Built with serverAuth; require clientAuth.
        with self.assertRaises(CertChainError):
            self._verify(required_eku=CLIENT_AUTH_OID)

    def test_tampered_signature_byte_rejected(self) -> None:
        # Locate sig in the framed payload and flip a byte.
        ts_field_end = 8
        cert_len = struct.unpack(
            ">H", self.payload[ts_field_end : ts_field_end + 2]
        )[0]
        cert_end = ts_field_end + 2 + cert_len
        sig_len = struct.unpack(">H", self.payload[cert_end : cert_end + 2])[
            0
        ]
        sig_start = cert_end + 2
        # Flip a middle byte of the signature.
        bad = bytearray(self.payload)
        bad[sig_start + sig_len // 2] ^= 0xFF
        with self.assertRaises(AttestSignatureError):
            self._verify(payload=bytes(bad))

    def test_tampered_wire_timestamp_rejected(self) -> None:
        # Wire timestamp is signed-bound: changing it without re-signing
        # breaks the verify pre-image → AttestSignatureError.
        bad = bytearray(self.payload)
        bad[3] ^= 0xFF  # somewhere inside the 8-byte BE timestamp
        with self.assertRaises(AttestSignatureError):
            self._verify(payload=bytes(bad))

    def test_tampered_cert_byte_rejected(self) -> None:
        # Flip a byte inside the cert region.
        bad = bytearray(self.payload)
        cert_offset = 8 + 2 + 50  # ts(8) + len(2) + a few bytes in
        bad[cert_offset] ^= 0xFF
        # Could surface as CertError (parse) or CertChainError (sig).
        with self.assertRaises(Exception):
            self._verify(payload=bytes(bad))

    def test_payload_wrong_size_rejected(self) -> None:
        with self.assertRaises(AttestPayloadFormatError):
            self._verify(payload=self.payload[:-1])
        with self.assertRaises(AttestPayloadFormatError):
            self._verify(payload=self.payload + b"\x00")

    def test_cert_len_overflow_rejected(self) -> None:
        bad = bytearray(self.payload)
        # Overwrite the cert_len field with a value that overflows.
        bad[8:10] = struct.pack(
            ">H", tuncore.HANDSHAKE_ATTEST_PAYLOAD_SIZE
        )
        with self.assertRaises(AttestPayloadFormatError):
            self._verify(payload=bytes(bad))

    def test_clock_skew_too_large_rejected(self) -> None:
        # Build with timestamp 1h in the past; verify with default ±300s.
        past = datetime.datetime.now(
            datetime.timezone.utc
        ) - datetime.timedelta(hours=1)
        _, _, _, stale_payload, h = _build_responder_payload(
            self.ca, timestamp=past
        )
        with self.assertRaises(AttestTimestampError):
            verify_attest_payload(
                payload=stale_payload,
                ca_root=self.ca.certificate,
                handshake_hash=h,
                expected_remote_static=self._extract_ns(stale_payload),
                expected_peer_role=PeerRole.RESPONDER,
            )

    def test_expired_cert_rejected(self) -> None:
        # Build a cert that's already expired.
        old = datetime.datetime.now(
            datetime.timezone.utc
        ) - datetime.timedelta(days=400)
        attest_key = tuncore.AttestKey.generate()
        ns = secrets.token_bytes(32)
        expired_leaf = make_leaf_cert(
            self.ca,
            subject_cn="dsm-expired-server",
            leaf_public_spki_der=attest_key.public_spki_der(),
            noise_static_pub=ns,
            not_before=old,
            not_after=old + datetime.timedelta(days=30),
        )
        h = secrets.token_bytes(32)
        payload = build_attest_payload(
            attest_key=attest_key,
            cert_der=expired_leaf.public_bytes(Encoding.DER),
            handshake_hash=h,
            our_static_pub=ns,
            our_role=PeerRole.RESPONDER,
        )
        with self.assertRaises(CertExpiredError):
            verify_attest_payload(
                payload=payload,
                ca_root=self.ca.certificate,
                handshake_hash=h,
                expected_remote_static=ns,
                expected_peer_role=PeerRole.RESPONDER,
            )

    def test_replay_across_handshakes_rejected(self) -> None:
        # Capture a payload from "handshake 1"; verifier in
        # "handshake 2" computes a different handshake_hash → fails.
        h2 = secrets.token_bytes(32)
        with self.assertRaises(AttestSignatureError):
            self._verify(handshake_hash=h2)

    def _extract_ns(self, payload: bytes) -> bytes:
        ts_end = 8
        cert_len = struct.unpack(
            ">H", payload[ts_end : ts_end + 2]
        )[0]
        cert_der = payload[ts_end + 2 : ts_end + 2 + cert_len]
        return DeviceCert.from_der(cert_der).noise_static_pub


class TestBindingDomainConstants(unittest.TestCase):
    def test_domain_is_well_formed(self) -> None:
        # Trip-wire so a future change to the domain prefix doesn't
        # silently re-version the protocol without breaking tests.
        self.assertEqual(BINDING_DOMAIN, b"DSM-BIND-v1\x00")
        self.assertEqual(BINDING_VERSION, 0x01)


if __name__ == "__main__":
    unittest.main()
