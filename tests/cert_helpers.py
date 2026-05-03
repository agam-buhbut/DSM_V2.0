"""Test-only helpers for constructing CA + leaf cert pairs.

Mirrors the structure of certs that the production offline CA workflow
will produce, but kept in ``tests/`` (not in ``dsm/``) so the runtime
codebase doesn't ship CA-issuing code unnecessarily.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)
from cryptography.x509.oid import NameOID

from dsm.crypto.cert import (
    DSM_NOISE_STATIC_BINDING_OID,
    encode_noise_static_binding_value,
)

CLIENT_AUTH_OID = x509.ObjectIdentifier("1.3.6.1.5.5.7.3.2")
SERVER_AUTH_OID = x509.ObjectIdentifier("1.3.6.1.5.5.7.3.1")


@dataclass(frozen=True)
class IssuingCA:
    private_key: ec.EllipticCurvePrivateKey
    certificate: x509.Certificate

    @property
    def pem(self) -> bytes:
        return self.certificate.public_bytes(Encoding.PEM)


def make_test_ca(
    common_name: str = "DSM Test CA",
    validity_years: int = 10,
) -> IssuingCA:
    """Generate a self-signed P-384 CA. Validity starts ~1 minute in
    the past so freshly-issued leaves with ``not_before == now`` still
    chain inside the CA's validity window."""
    priv = ec.generate_private_key(ec.SECP384R1())
    now = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
        seconds=60
    )
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365 * validity_years))
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


def make_leaf_cert(
    ca: IssuingCA,
    *,
    subject_cn: str,
    leaf_public_spki_der: bytes,
    noise_static_pub: bytes,
    validity_days: int = 365,
    eku: x509.ObjectIdentifier = CLIENT_AUTH_OID,
    not_before: datetime.datetime | None = None,
    not_after: datetime.datetime | None = None,
    binding_critical: bool = True,
    omit_binding: bool = False,
) -> x509.Certificate:
    """Issue a leaf cert signed by ``ca`` with the DSM
    ``noiseStaticBinding`` extension."""
    if not_before is None:
        not_before = datetime.datetime.now(datetime.timezone.utc)
    if not_after is None:
        not_after = not_before + datetime.timedelta(days=validity_days)

    leaf_pub = _load_public_key_from_spki_der(leaf_public_spki_der)
    builder = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]
            )
        )
        .issuer_name(ca.certificate.subject)
        .public_key(leaf_pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([eku]),
            critical=False,
        )
    )
    if not omit_binding:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                DSM_NOISE_STATIC_BINDING_OID,
                encode_noise_static_binding_value(noise_static_pub),
            ),
            critical=binding_critical,
        )
    return builder.sign(
        private_key=ca.private_key, algorithm=hashes.SHA384()
    )


def _load_public_key_from_spki_der(
    spki_der: bytes,
) -> ec.EllipticCurvePublicKey:
    from cryptography.hazmat.primitives.serialization import (
        load_der_public_key,
    )

    pub = load_der_public_key(bytes(spki_der))
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        raise TypeError(
            f"expected EC pubkey, got {type(pub).__name__}"
        )
    return pub


def public_spki_der_from_priv(
    priv: ec.EllipticCurvePrivateKey,
) -> bytes:
    return priv.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )


@dataclass(frozen=True)
class EnrolledDevice:
    """One device's complete enrollment: identity (Noise X25519),
    attest key (ECDSA P-256, hardware-bound in production), and a
    CA-signed device cert binding both via the noiseStaticBinding
    extension."""

    identity: object  # tuncore.IdentityKeyPair (avoid import-time tuncore dep)
    attest_key: object  # tuncore.AttestKey
    cert: x509.Certificate

    @property
    def cert_der(self) -> bytes:
        return self.cert.public_bytes(Encoding.DER)

    @property
    def noise_static_pub(self) -> bytes:
        return bytes(self.identity.public_key)


def make_enrolled_device(
    ca: IssuingCA,
    *,
    subject_cn: str,
    eku: x509.ObjectIdentifier = CLIENT_AUTH_OID,
    validity_days: int = 365,
    not_before: datetime.datetime | None = None,
    not_after: datetime.datetime | None = None,
) -> EnrolledDevice:
    """Mint a fresh ``EnrolledDevice`` mirroring the production enroll
    flow: device generates a Noise identity + AttestKey, CA signs a
    leaf cert binding both."""
    import tuncore

    identity = tuncore.IdentityKeyPair.generate()
    attest_key = tuncore.AttestKey.generate()
    cert = make_leaf_cert(
        ca,
        subject_cn=subject_cn,
        leaf_public_spki_der=attest_key.public_spki_der(),
        noise_static_pub=bytes(identity.public_key),
        eku=eku,
        validity_days=validity_days,
        not_before=not_before,
        not_after=not_after,
    )
    return EnrolledDevice(
        identity=identity, attest_key=attest_key, cert=cert
    )
