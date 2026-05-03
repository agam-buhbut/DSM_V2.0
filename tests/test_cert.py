"""Tests for ``dsm.crypto.cert``: parse, validate, extract binding."""

from __future__ import annotations

import datetime
import os
import secrets
import unittest
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding

from dsm.crypto.cert import (
    DSM_NOISE_STATIC_BINDING_OID,
    CertBindingError,
    CertChainError,
    CertError,
    CertExpiredError,
    DeviceCert,
    encode_noise_static_binding_value,
    load_ca_root,
    validate_chain,
)
from tests.cert_helpers import (
    CLIENT_AUTH_OID,
    SERVER_AUTH_OID,
    make_leaf_cert,
    make_test_ca,
    public_spki_der_from_priv,
)


def _fresh_leaf(
    ca,
    *,
    subject_cn: str = "dsm-a3f29c81-client",
    noise_static_pub: bytes | None = None,
    eku=CLIENT_AUTH_OID,
    **kwargs,
):
    leaf_priv = ec.generate_private_key(ec.SECP256R1())
    if noise_static_pub is None:
        noise_static_pub = secrets.token_bytes(32)
    cert = make_leaf_cert(
        ca,
        subject_cn=subject_cn,
        leaf_public_spki_der=public_spki_der_from_priv(leaf_priv),
        noise_static_pub=noise_static_pub,
        eku=eku,
        **kwargs,
    )
    return leaf_priv, cert, noise_static_pub


class TestDeviceCertParsing(unittest.TestCase):
    def setUp(self) -> None:
        self.ca = make_test_ca()
        self.leaf_priv, self.leaf, self.noise_static = _fresh_leaf(self.ca)
        self.dc = DeviceCert(self.leaf)

    def test_subject_cn_matches(self) -> None:
        self.assertEqual(self.dc.subject_cn, "dsm-a3f29c81-client")

    def test_noise_static_pub_extracted(self) -> None:
        self.assertEqual(self.dc.noise_static_pub, self.noise_static)

    def test_public_key_is_ec(self) -> None:
        self.assertIsInstance(
            self.dc.public_key, ec.EllipticCurvePublicKey
        )

    def test_der_roundtrip(self) -> None:
        der = self.dc.to_der()
        rt = DeviceCert.from_der(der)
        self.assertEqual(
            rt.cert.tbs_certificate_bytes,
            self.dc.cert.tbs_certificate_bytes,
        )

    def test_pem_load(self) -> None:
        pem = self.leaf.public_bytes(Encoding.PEM)
        rt = DeviceCert.from_pem(pem)
        self.assertEqual(rt.subject_cn, "dsm-a3f29c81-client")

    def test_garbage_der_rejected(self) -> None:
        with self.assertRaises(CertError):
            DeviceCert.from_der(b"this is not a cert")


class TestNoiseStaticBindingExtension(unittest.TestCase):
    def setUp(self) -> None:
        self.ca = make_test_ca()

    def test_missing_extension_raises(self) -> None:
        _, leaf, _ = _fresh_leaf(self.ca, omit_binding=True)
        with self.assertRaises(CertBindingError):
            DeviceCert(leaf).noise_static_pub

    def test_non_critical_extension_rejected(self) -> None:
        _, leaf, _ = _fresh_leaf(self.ca, binding_critical=False)
        with self.assertRaises(CertBindingError):
            DeviceCert(leaf).noise_static_pub

    def test_extension_value_too_short_rejected(self) -> None:
        # Build a leaf with a malformed extnValue: claim OCTET STRING of 32
        # but only provide 16 bytes.
        leaf_priv = ec.generate_private_key(ec.SECP256R1())
        bad_value = bytes([0x04, 0x20]) + b"\x00" * 16
        now = datetime.datetime.now(datetime.timezone.utc)
        leaf = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name(
                    [x509.NameAttribute(x509.NameOID.COMMON_NAME, "x")]
                )
            )
            .issuer_name(self.ca.certificate.subject)
            .public_key(leaf_priv.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(
                x509.UnrecognizedExtension(
                    DSM_NOISE_STATIC_BINDING_OID, bad_value
                ),
                critical=True,
            )
            .sign(self.ca.private_key, hashes.SHA384())
        )
        with self.assertRaises(CertBindingError):
            DeviceCert(leaf).noise_static_pub

    def test_encode_rejects_wrong_length_input(self) -> None:
        with self.assertRaises(ValueError):
            encode_noise_static_binding_value(b"too short")


class TestValidateChain(unittest.TestCase):
    def setUp(self) -> None:
        self.ca = make_test_ca()
        _, self.leaf, _ = _fresh_leaf(self.ca)

    def test_happy_path(self) -> None:
        validate_chain(DeviceCert(self.leaf), self.ca.certificate)

    def test_eku_check_accepted_when_present(self) -> None:
        validate_chain(
            DeviceCert(self.leaf),
            self.ca.certificate,
            required_eku=CLIENT_AUTH_OID,
        )

    def test_eku_check_rejects_wrong_eku(self) -> None:
        with self.assertRaises(CertChainError):
            validate_chain(
                DeviceCert(self.leaf),
                self.ca.certificate,
                required_eku=SERVER_AUTH_OID,
            )

    def test_wrong_ca_rejects(self) -> None:
        other_ca = make_test_ca("Other CA")
        with self.assertRaises(CertChainError):
            validate_chain(DeviceCert(self.leaf), other_ca.certificate)

    def test_signature_under_wrong_key_rejected(self) -> None:
        # Build a leaf that NAMES the test CA as issuer but is signed
        # by a different key. Exercises the ECDSA verify path
        # specifically (the issuer-DN-match check would let this
        # through; only the signature check catches it).
        other_priv = ec.generate_private_key(ec.SECP384R1())
        leaf_priv = ec.generate_private_key(ec.SECP256R1())
        now = datetime.datetime.now(datetime.timezone.utc)
        forged = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name(
                    [x509.NameAttribute(x509.NameOID.COMMON_NAME, "forged")]
                )
            )
            .issuer_name(self.ca.certificate.subject)
            .public_key(leaf_priv.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(
                x509.UnrecognizedExtension(
                    DSM_NOISE_STATIC_BINDING_OID,
                    encode_noise_static_binding_value(
                        secrets.token_bytes(32)
                    ),
                ),
                critical=True,
            )
            .sign(other_priv, hashes.SHA384())
        )
        with self.assertRaises(CertChainError):
            validate_chain(DeviceCert(forged), self.ca.certificate)

    def test_not_yet_valid_rejected(self) -> None:
        future = datetime.datetime.now(
            datetime.timezone.utc
        ) + datetime.timedelta(days=10)
        _, leaf, _ = _fresh_leaf(
            self.ca,
            not_before=future,
            not_after=future + datetime.timedelta(days=365),
        )
        with self.assertRaises(CertExpiredError):
            validate_chain(DeviceCert(leaf), self.ca.certificate)

    def test_expired_rejected(self) -> None:
        old_start = datetime.datetime.now(
            datetime.timezone.utc
        ) - datetime.timedelta(days=400)
        _, leaf, _ = _fresh_leaf(
            self.ca,
            not_before=old_start,
            not_after=old_start + datetime.timedelta(days=30),
        )
        with self.assertRaises(CertExpiredError):
            validate_chain(DeviceCert(leaf), self.ca.certificate)

    def test_validate_chain_now_override(self) -> None:
        # Pin "now" inside the validity window even after real-clock
        # expiry to confirm the override path works.
        old_start = datetime.datetime.now(
            datetime.timezone.utc
        ) - datetime.timedelta(days=400)
        _, leaf, _ = _fresh_leaf(
            self.ca,
            not_before=old_start,
            not_after=old_start + datetime.timedelta(days=30),
        )
        pinned_now = old_start + datetime.timedelta(days=10)
        validate_chain(
            DeviceCert(leaf), self.ca.certificate, now=pinned_now
        )

    def test_missing_binding_extension_rejected(self) -> None:
        _, leaf, _ = _fresh_leaf(self.ca, omit_binding=True)
        with self.assertRaises(CertBindingError):
            validate_chain(DeviceCert(leaf), self.ca.certificate)


class TestLoadCARoot(unittest.TestCase):
    def setUp(self) -> None:
        self.ca = make_test_ca()
        self.tmp = Path(os.environ.get("TMPDIR", "/tmp")) / (
            f"dsm-test-ca-{os.getpid()}-{secrets.token_hex(4)}.pem"
        )
        self.tmp.write_bytes(self.ca.pem)

    def tearDown(self) -> None:
        try:
            self.tmp.unlink()
        except FileNotFoundError:
            pass

    def test_loads_from_disk(self) -> None:
        loaded = load_ca_root(self.tmp)
        self.assertEqual(loaded.subject, self.ca.certificate.subject)

    def test_sha256_pin_matches(self) -> None:
        import hashlib

        digest = hashlib.sha256(self.ca.pem).digest()
        loaded = load_ca_root(self.tmp, expected_sha256=digest)
        self.assertEqual(loaded.subject, self.ca.certificate.subject)

    def test_sha256_pin_mismatch_raises(self) -> None:
        with self.assertRaises(CertChainError):
            load_ca_root(self.tmp, expected_sha256=b"\x00" * 32)

    def test_non_ca_pem_rejected(self) -> None:
        # Write a leaf (not a CA) to disk; load_ca_root must reject.
        _, leaf, _ = _fresh_leaf(self.ca)
        leaf_path = self.tmp.with_suffix(".leaf.pem")
        leaf_path.write_bytes(leaf.public_bytes(Encoding.PEM))
        try:
            with self.assertRaises(CertChainError):
                load_ca_root(leaf_path)
        finally:
            leaf_path.unlink()


if __name__ == "__main__":
    unittest.main()
