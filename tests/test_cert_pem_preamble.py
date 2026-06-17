"""Regression: ``DeviceCert.from_pem_or_der`` must accept a PEM certificate
that carries a human-readable text preamble, as emitted by ``openssl ca`` /
``openssl x509`` without ``-notext``.

A strict ``startswith(b"-----BEGIN")`` sniff previously mis-routed such certs to
the DER parser, so following deploy/GUIDE.md §3 (which signs with ``openssl ca``
and no ``-notext``) made ``dsm enroll --import`` fail on a clean-box deployment
with a cryptic ASN.1 ``UnexpectedTag`` error. Found via a real CA round-trip.
"""

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from dsm.crypto.cert import DeviceCert

# What `openssl ca`/`openssl x509` without -notext prepend before the PEM block.
_OPENSSL_TEXT_PREAMBLE = (
    b"Certificate:\n"
    b"    Data:\n"
    b"        Version: 3 (0x2)\n"
    b"        Serial Number: 4096 (0x1000)\n"
    b"    Signature Algorithm: ecdsa-with-SHA256\n"
)


def _make_cert() -> x509.Certificate:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "dsm-test-leaf")])
    not_before = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(4096)
        .not_valid_before(not_before)
        .not_valid_after(not_before + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )


class TestFromPemOrDerPreamble:
    def test_pem_with_text_preamble_parses(self) -> None:
        pem = _make_cert().public_bytes(serialization.Encoding.PEM)
        loaded = DeviceCert.from_pem_or_der(_OPENSSL_TEXT_PREAMBLE + pem)
        assert loaded.subject_cn == "dsm-test-leaf"

    def test_clean_pem_parses(self) -> None:
        pem = _make_cert().public_bytes(serialization.Encoding.PEM)
        assert DeviceCert.from_pem_or_der(pem).subject_cn == "dsm-test-leaf"

    def test_pure_der_parses(self) -> None:
        der = _make_cert().public_bytes(serialization.Encoding.DER)
        assert DeviceCert.from_pem_or_der(der).subject_cn == "dsm-test-leaf"
