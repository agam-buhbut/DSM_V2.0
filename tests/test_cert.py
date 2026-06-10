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
        self.assertIsInstance(self.dc.public_key, ec.EllipticCurvePublicKey)

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
        now = datetime.datetime.now(datetime.UTC)
        leaf = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "x")])
            )
            .issuer_name(self.ca.certificate.subject)
            .public_key(leaf_priv.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(
                x509.UnrecognizedExtension(DSM_NOISE_STATIC_BINDING_OID, bad_value),
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
        now = datetime.datetime.now(datetime.UTC)
        forged = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "forged")])
            )
            .issuer_name(self.ca.certificate.subject)
            .public_key(leaf_priv.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(
                x509.UnrecognizedExtension(
                    DSM_NOISE_STATIC_BINDING_OID,
                    encode_noise_static_binding_value(secrets.token_bytes(32)),
                ),
                critical=True,
            )
            .sign(other_priv, hashes.SHA384())
        )
        with self.assertRaises(CertChainError):
            validate_chain(DeviceCert(forged), self.ca.certificate)

    def test_not_yet_valid_rejected(self) -> None:
        future = datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=10)
        _, leaf, _ = _fresh_leaf(
            self.ca,
            not_before=future,
            not_after=future + datetime.timedelta(days=365),
        )
        with self.assertRaises(CertExpiredError):
            validate_chain(DeviceCert(leaf), self.ca.certificate)

    def test_expired_rejected(self) -> None:
        old_start = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=400)
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
        old_start = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=400)
        _, leaf, _ = _fresh_leaf(
            self.ca,
            not_before=old_start,
            not_after=old_start + datetime.timedelta(days=30),
        )
        pinned_now = old_start + datetime.timedelta(days=10)
        validate_chain(DeviceCert(leaf), self.ca.certificate, now=pinned_now)

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


def _ca_keyusage(*, key_cert_sign: bool) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=False,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=key_cert_sign,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False,
    )


def _build_ca(
    *,
    not_before: datetime.datetime,
    not_after: datetime.datetime,
    key_usage: x509.KeyUsage | None,
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """Hand-build a self-signed CA with caller-controlled validity +
    keyUsage (or no keyUsage when ``key_usage`` is None). basicConstraints
    is CA:TRUE so the DSM-010 keyUsage / validity gates are what fails,
    not the CA:TRUE check that precedes them in ``load_ca_root``."""
    priv = ec.generate_private_key(ec.SECP384R1())
    name = x509.Name(
        [x509.NameAttribute(x509.NameOID.COMMON_NAME, "DSM Hand-Built CA")]
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
    )
    if key_usage is not None:
        builder = builder.add_extension(key_usage, critical=True)
    cert = builder.sign(private_key=priv, algorithm=hashes.SHA384())
    return priv, cert


def _write_ca_pem_600(cert: x509.Certificate) -> Path:
    path = Path(os.environ.get("TMPDIR", "/tmp")) / (
        f"dsm-handbuilt-ca-{os.getpid()}-{secrets.token_hex(4)}.pem"
    )
    path.write_bytes(cert.public_bytes(Encoding.PEM))
    os.chmod(path, 0o600)
    return path


def _leaf_with_keyusage(
    ca,
    *,
    key_usage: x509.KeyUsage | None,
) -> x509.Certificate:
    """Hand-build a leaf signed by ``ca`` carrying a critical CA:FALSE,
    the noiseStaticBinding extension, and a caller-supplied keyUsage (or
    none). Issuer/signature/validity/binding/basicConstraints are all
    valid so ``validate_chain`` reaches — and fails at — the DSM-010
    keyUsage gate specifically."""
    leaf_priv = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "dsm-ku-leaf")])
        )
        .issuer_name(ca.certificate.subject)
        .public_key(leaf_priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.UnrecognizedExtension(
                DSM_NOISE_STATIC_BINDING_OID,
                encode_noise_static_binding_value(secrets.token_bytes(32)),
            ),
            critical=True,
        )
    )
    if key_usage is not None:
        builder = builder.add_extension(key_usage, critical=True)
    return builder.sign(ca.private_key, hashes.SHA384())


class TestStrictLeafKeyUsage(unittest.TestCase):
    """DSM-010: ``validate_chain`` requires a leaf keyUsage that asserts
    digitalSignature (the leaf signs the per-handshake binding attestation)."""

    def setUp(self) -> None:
        self.ca = make_test_ca()

    def test_leaf_keyusage_without_digital_signature_rejected(self) -> None:
        ku = x509.KeyUsage(
            digital_signature=False,
            content_commitment=True,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        )
        leaf = _leaf_with_keyusage(self.ca, key_usage=ku)
        with self.assertRaises(CertChainError):
            validate_chain(DeviceCert(leaf), self.ca.certificate)

    def test_leaf_missing_keyusage_rejected(self) -> None:
        leaf = _leaf_with_keyusage(self.ca, key_usage=None)
        with self.assertRaises(CertChainError) as ctx:
            validate_chain(DeviceCert(leaf), self.ca.certificate)
        self.assertIn("leaf missing keyUsage", str(ctx.exception))


class TestStrictCaKeyUsageAndValidity(unittest.TestCase):
    """DSM-010: ``load_ca_root`` requires keyUsage keyCertSign and enforces
    the CA's own validity window (a pinned root is otherwise trusted
    forever). ``now`` is injectable for deterministic expiry testing."""

    def test_ca_keyusage_without_key_cert_sign_rejected(self) -> None:
        now = datetime.datetime.now(datetime.UTC)
        _, cert = _build_ca(
            not_before=now - datetime.timedelta(days=1),
            not_after=now + datetime.timedelta(days=3650),
            key_usage=_ca_keyusage(key_cert_sign=False),
        )
        path = _write_ca_pem_600(cert)
        try:
            with self.assertRaises(CertChainError):
                load_ca_root(path)
        finally:
            path.unlink()

    def test_ca_missing_keyusage_rejected(self) -> None:
        now = datetime.datetime.now(datetime.UTC)
        _, cert = _build_ca(
            not_before=now - datetime.timedelta(days=1),
            not_after=now + datetime.timedelta(days=3650),
            key_usage=None,
        )
        path = _write_ca_pem_600(cert)
        try:
            with self.assertRaises(CertChainError):
                load_ca_root(path)
        finally:
            path.unlink()

    def test_expired_ca_rejected_with_pinned_now(self) -> None:
        # CA whose validity ended well in the past; pin `now` after it.
        base = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=400)
        _, cert = _build_ca(
            not_before=base,
            not_after=base + datetime.timedelta(days=30),
            key_usage=_ca_keyusage(key_cert_sign=True),
        )
        path = _write_ca_pem_600(cert)
        pinned_now = base + datetime.timedelta(days=200)  # past not_after
        try:
            with self.assertRaises(CertExpiredError):
                load_ca_root(path, now=pinned_now)
        finally:
            path.unlink()


class TestStrictKeyUsageRegression(unittest.TestCase):
    """DSM-010 regression: a valid CA + valid leaf (correct keyUsage /
    validity) still pass both ``validate_chain`` and ``load_ca_root``.
    Guards against the strict checks over-rejecting good material."""

    def test_valid_ca_and_leaf_still_pass(self) -> None:
        ca = make_test_ca()
        _, leaf, _ = _fresh_leaf(ca)

        # validate_chain accepts the well-formed leaf.
        validate_chain(DeviceCert(leaf), ca.certificate)

        # load_ca_root accepts the well-formed CA (and pin still works).
        path = _write_ca_pem_600(ca.certificate)
        try:
            loaded = load_ca_root(path)
            self.assertEqual(loaded.subject, ca.certificate.subject)
        finally:
            path.unlink()


if __name__ == "__main__":
    unittest.main()
