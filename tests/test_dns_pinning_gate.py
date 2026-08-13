"""SPKI pin-gate coverage for dsm.net.dns_pinning.

The pin gate is the property that stops a MitM whose forged certificate
chains to a trusted CA but presents a *different* public key: even with a
valid chain, the SPKI hash won't match the pin and the connection is
rejected. The PRODUCTION_REVIEW found this path had ZERO coverage.

These tests exercise the real ``compute_spki_sha256`` /
``verify_pin`` / ``verify_pin_on_ssl_object`` functions against genuine
DER certificates built with ``cryptography`` (mirroring tests/cert_helpers).
No network: a fake SSL object stands in for the only I/O boundary
(``getpeercert``).

The discriminating test is ``test_wrong_pin_rejected`` — a cert with a
different key MUST raise PinMismatchError (fail-closed).
"""

from __future__ import annotations

import datetime
import hashlib
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import NameOID

from dsm.net.dns_pinning import (
    PinMismatchError,
    compute_spki_sha256,
    verify_pin,
    verify_pin_on_ssl_object,
)


def _self_signed_cert(common_name: str) -> tuple[bytes, bytes]:
    """Return ``(der_cert, expected_spki_pin)`` for a fresh P-256 cert.

    The pin is computed independently (load the cert's own public key,
    DER-encode its SubjectPublicKeyInfo, SHA-256) so the test does not
    merely re-call the function under test to derive the expected value.
    """
    priv = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.UTC) - datetime.timedelta(seconds=60)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(private_key=priv, algorithm=hashes.SHA256())
    )
    der = cert.public_bytes(Encoding.DER)
    spki_der = priv.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
    expected_pin = hashlib.sha256(spki_der).digest()
    return der, expected_pin


class _FakeSslObject:
    """Minimal stand-in for an ssl.SSLSocket exposing getpeercert only."""

    def __init__(self, der: bytes | None) -> None:
        self._der = der

    def getpeercert(self, binary_form: bool = False) -> bytes | None:
        # The production caller always passes binary_form=True.
        assert binary_form is True
        return self._der


class ComputeSpkiTest(unittest.TestCase):
    def test_spki_hash_matches_independent_computation(self) -> None:
        der, expected_pin = _self_signed_cert("compute.example")
        self.assertEqual(compute_spki_sha256(der), expected_pin)
        self.assertEqual(len(compute_spki_sha256(der)), 32)


class VerifyPinTest(unittest.TestCase):
    def test_correct_pin_passes(self) -> None:
        der, pin = _self_signed_cert("good.example")
        # Returns None (no exception) when the pin matches.
        self.assertIsNone(verify_pin(der, [pin], "good"))

    def test_correct_pin_among_several_passes(self) -> None:
        # Pin-set semantics: a match against ANY configured pin passes.
        der, pin = _self_signed_cert("multi.example")
        _other_der, other_pin = _self_signed_cert("other.example")
        self.assertIsNone(verify_pin(der, [other_pin, pin], "multi"))

    def test_wrong_pin_rejected(self) -> None:
        # A cert whose SPKI differs from every
        # configured pin is rejected. This is the MitM-with-a-different-cert
        # case — the gate must fail closed.
        der, _good_pin = _self_signed_cert("victim.example")
        _attacker_der, attacker_pin = _self_signed_cert("attacker.example")
        with self.assertRaises(PinMismatchError):
            verify_pin(der, [attacker_pin], "victim")

    def test_empty_pin_list_rejected(self) -> None:
        # No pins configured -> nothing can match -> fail closed.
        der, _pin = _self_signed_cert("nopins.example")
        with self.assertRaises(PinMismatchError):
            verify_pin(der, [], "nopins")

    def test_truncated_pin_does_not_spuriously_match(self) -> None:
        # A pin that is a prefix of the real hash must NOT pass: the
        # comparison is constant-time-equal on full digests, not a prefix
        # match.
        der, pin = _self_signed_cert("prefix.example")
        with self.assertRaises(PinMismatchError):
            verify_pin(der, [pin[:16]], "prefix")


class VerifyPinOnSslObjectTest(unittest.TestCase):
    def test_matching_peer_cert_passes(self) -> None:
        der, pin = _self_signed_cert("ssl-good.example")
        obj = _FakeSslObject(der)
        self.assertIsNone(verify_pin_on_ssl_object(obj, [pin], "ssl-good"))

    def test_mismatched_peer_cert_rejected(self) -> None:
        # The same fail-closed property, exercised through the SSL-object
        # extraction path used in production after the TLS handshake.
        der, _good = _self_signed_cert("ssl-victim.example")
        _att_der, att_pin = _self_signed_cert("ssl-attacker.example")
        obj = _FakeSslObject(der)
        with self.assertRaises(PinMismatchError):
            verify_pin_on_ssl_object(obj, [att_pin], "ssl-victim")

    def test_missing_peer_cert_rejected(self) -> None:
        # No peer certificate at all -> fail closed, not silent pass.
        obj = _FakeSslObject(None)
        with self.assertRaises(PinMismatchError):
            verify_pin_on_ssl_object(obj, [b"\x00" * 32], "no-cert")


if __name__ == "__main__":
    unittest.main()
