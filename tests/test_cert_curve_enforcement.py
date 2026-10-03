"""CA curve enforcement in validate_chain: a CA whose public key is not on
P-384 (secp384r1) is rejected even if it is otherwise structurally valid.
"""

from __future__ import annotations

import datetime
import secrets
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from dsm.crypto.cert import (
    CertChainError,
    DeviceCert,
    validate_chain,
)
from tests.cert_helpers import (
    CLIENT_AUTH_OID,
    IssuingCA,
    make_leaf_cert,
    make_test_ca,
    public_spki_der_from_priv,
)


def _make_ca_on_curve(curve: ec.EllipticCurve) -> IssuingCA:
    """Build a self-signed CA with the given EC curve (otherwise valid)."""
    priv = ec.generate_private_key(curve)
    now = datetime.datetime.now(datetime.UTC) - datetime.timedelta(seconds=60)
    name = x509.Name(
        [x509.NameAttribute(x509.NameOID.COMMON_NAME, f"DSM Test CA ({curve.name})")]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365 * 10))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key=priv, algorithm=hashes.SHA384())
    )
    return IssuingCA(private_key=priv, certificate=cert)


def _fresh_leaf_for_ca(ca: IssuingCA) -> x509.Certificate:
    """Issue a valid leaf signed by ``ca``."""
    leaf_priv = ec.generate_private_key(ec.SECP256R1())
    _, cert = _make_leaf_for_ca_priv(ca, leaf_priv)
    return cert


def _make_leaf_for_ca_priv(
    ca: IssuingCA,
    leaf_priv: ec.EllipticCurvePrivateKey,
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    noise_static = secrets.token_bytes(32)
    cert = make_leaf_cert(
        ca,
        subject_cn="dsm-aabbcc-client",
        leaf_public_spki_der=public_spki_der_from_priv(leaf_priv),
        noise_static_pub=noise_static,
        eku=CLIENT_AUTH_OID,
    )
    return leaf_priv, cert


class TestCACurveEnforcement(unittest.TestCase):
    """validate_chain must enforce that the CA key is on P-384 (secp384r1)."""

    def test_p384_ca_accepted(self) -> None:
        """A CA on the approved P-384 curve must pass validate_chain."""
        ca = make_test_ca()  # always P-384 in cert_helpers
        leaf = _fresh_leaf_for_ca(ca)
        # Must NOT raise — P-384 is the approved curve.
        validate_chain(DeviceCert(leaf), ca.certificate)

    def test_p256_ca_rejected(self) -> None:
        """A CA on P-256 (secp256r1) must be rejected with CertChainError."""
        ca = _make_ca_on_curve(ec.SECP256R1())
        leaf = _fresh_leaf_for_ca(ca)
        with self.assertRaises(CertChainError) as ctx:
            validate_chain(DeviceCert(leaf), ca.certificate)
        self.assertIn("secp384r1", str(ctx.exception).lower())

    def test_p521_ca_rejected(self) -> None:
        """A CA on P-521 (secp521r1) must be rejected with CertChainError."""
        ca = _make_ca_on_curve(ec.SECP521R1())
        leaf = _fresh_leaf_for_ca(ca)
        with self.assertRaises(CertChainError) as ctx:
            validate_chain(DeviceCert(leaf), ca.certificate)
        self.assertIn("secp384r1", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
