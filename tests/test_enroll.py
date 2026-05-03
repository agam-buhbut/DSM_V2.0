"""Tests for dsm.crypto.enroll: CSR generation + signed-cert import.

Covers the round-trip: enroll device → CA signs CSR → import cert.
Also exercises mismatch detection: cert binding mismatch, wrong attest
key SPKI, foreign CA, expired cert, malformed cert input.
"""

from __future__ import annotations

import datetime
import os
import tempfile
import unittest
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from dsm.crypto.attest_store import AttestStore
from dsm.crypto.cert import (
    DSM_NOISE_STATIC_BINDING_OID,
    encode_noise_static_binding_value,
)
from dsm.crypto.enroll import (
    EnrollError,
    build_csr,
    derive_default_cn,
    generate_enrollment,
    import_signed_cert,
)
from dsm.crypto.keystore import KeyStore

from tests.cert_helpers import IssuingCA, make_leaf_cert, make_test_ca


def _sign_csr(ca: IssuingCA, csr_der: bytes, *, validity_days: int = 365) -> bytes:
    """Sandbox CA: parse a CSR, mint a leaf cert that copies its CN +
    binding extension, return the cert PEM."""
    csr = x509.load_der_x509_csr(csr_der)
    if not csr.is_signature_valid:
        raise AssertionError("CSR signature does not verify (CA must reject)")

    cn_attr = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    assert len(cn_attr) == 1
    cn = cn_attr[0].value

    bind_ext = csr.extensions.get_extension_for_oid(
        DSM_NOISE_STATIC_BINDING_OID
    )
    assert bind_ext.critical
    raw = bind_ext.value.value
    assert raw[0] == 0x04 and raw[1] == 0x20 and len(raw) == 34
    noise_static_pub = bytes(raw[2:])

    csr_pubkey_spki = csr.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    cert = make_leaf_cert(
        ca,
        subject_cn=cn,
        leaf_public_spki_der=csr_pubkey_spki,
        noise_static_pub=noise_static_pub,
        validity_days=validity_days,
    )
    return cert.public_bytes(serialization.Encoding.PEM)


class TestDeriveDefaultCN(unittest.TestCase):
    def test_format(self) -> None:
        pub = b"\x01" * 32
        self.assertEqual(
            derive_default_cn(pub, "client"),
            f"dsm-{__import__('hashlib').sha256(pub).digest()[:4].hex()}-client",
        )

    def test_role_must_be_valid(self) -> None:
        with self.assertRaises(ValueError):
            derive_default_cn(b"\x01" * 32, "relay")

    def test_pub_length_enforced(self) -> None:
        with self.assertRaises(ValueError):
            derive_default_cn(b"\x01" * 31, "client")


class TestEnrollRoundtrip(unittest.TestCase):
    """Full enroll → CA signs → import flow."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.identity_path = Path(self.tmpdir) / "identity.key"
        self.attest_path = Path(self.tmpdir) / "attest.key"
        self.cert_out = Path(self.tmpdir) / "device.crt"
        self.ca_path = Path(self.tmpdir) / "dsm_ca_root.pem"
        self.passphrase = b"correct-horse-battery-staple"

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _build_enrollment(self, role: str = "client"):
        keystore = KeyStore(str(self.identity_path))
        attest = AttestStore(str(self.attest_path))
        result = generate_enrollment(
            keystore=keystore,
            attest_store=attest,
            passphrase=self.passphrase,
            role=role,
        )
        return keystore, attest, result

    def test_round_trip(self) -> None:
        ca = make_test_ca()
        self.ca_path.write_bytes(ca.pem)

        keystore, attest, result = self._build_enrollment()
        # Persisted on disk, mode 0o600
        self.assertTrue(self.identity_path.is_file())
        self.assertTrue(self.attest_path.is_file())
        self.assertEqual(self.identity_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.attest_path.stat().st_mode & 0o777, 0o600)

        # CN derived from pubkey + role
        self.assertEqual(
            result.cn,
            derive_default_cn(result.noise_static_pub, "client"),
        )
        self.assertTrue(result.cn.endswith("-client"))

        # CSR is parseable + signature verifies
        csr = x509.load_der_x509_csr(result.csr_der)
        self.assertTrue(csr.is_signature_valid)
        self.assertEqual(
            csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
            result.cn,
        )

        # CA signs and we import
        cert_pem = _sign_csr(ca, result.csr_der)
        cert_path = Path(self.tmpdir) / "signed.pem"
        cert_path.write_bytes(cert_pem)

        leaf = import_signed_cert(
            cert_input_path=cert_path,
            cert_output_path=self.cert_out,
            ca_root_path=self.ca_path,
            keystore=keystore,
            attest_store=attest,
        )
        self.assertEqual(leaf.subject_cn, result.cn)
        self.assertTrue(self.cert_out.is_file())
        self.assertEqual(self.cert_out.stat().st_mode & 0o777, 0o600)

    def test_explicit_cn_override(self) -> None:
        keystore = KeyStore(str(self.identity_path))
        attest = AttestStore(str(self.attest_path))
        result = generate_enrollment(
            keystore=keystore,
            attest_store=attest,
            passphrase=self.passphrase,
            role="server",
            cn="dsm-custom-server",
        )
        self.assertEqual(result.cn, "dsm-custom-server")

    def test_refuses_to_overwrite_identity(self) -> None:
        # First enrollment writes identity.
        self._build_enrollment()
        # Second enrollment must refuse — we don't auto-clobber.
        keystore = KeyStore(str(self.identity_path))
        attest = AttestStore(str(self.attest_path))
        with self.assertRaises(EnrollError):
            generate_enrollment(
                keystore=keystore,
                attest_store=attest,
                passphrase=self.passphrase,
                role="client",
            )

    def test_csr_carries_critical_binding_extension(self) -> None:
        _, _, result = self._build_enrollment()
        csr = x509.load_der_x509_csr(result.csr_der)
        ext = csr.extensions.get_extension_for_oid(
            DSM_NOISE_STATIC_BINDING_OID
        )
        self.assertTrue(ext.critical)
        # Conventional OCTET STRING wrapping
        raw = ext.value.value
        self.assertEqual(raw[0], 0x04)
        self.assertEqual(raw[1], 0x20)
        self.assertEqual(bytes(raw[2:]), result.noise_static_pub)


class TestImportFailureModes(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.identity_path = Path(self.tmpdir) / "identity.key"
        self.attest_path = Path(self.tmpdir) / "attest.key"
        self.cert_out = Path(self.tmpdir) / "device.crt"
        self.ca_path = Path(self.tmpdir) / "dsm_ca_root.pem"
        self.cert_in = Path(self.tmpdir) / "signed.pem"
        self.passphrase = b"correct-horse-battery-staple"

        self.ca = make_test_ca()
        self.ca_path.write_bytes(self.ca.pem)

        self.keystore = KeyStore(str(self.identity_path))
        self.attest = AttestStore(str(self.attest_path))
        self.enrollment = generate_enrollment(
            keystore=self.keystore,
            attest_store=self.attest,
            passphrase=self.passphrase,
            role="client",
        )

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _import(self, cert_pem: bytes, *, ca_path: Path | None = None,
                now: datetime.datetime | None = None) -> None:
        self.cert_in.write_bytes(cert_pem)
        import_signed_cert(
            cert_input_path=self.cert_in,
            cert_output_path=self.cert_out,
            ca_root_path=ca_path or self.ca_path,
            keystore=self.keystore,
            attest_store=self.attest,
            now=now,
        )

    def test_foreign_ca_rejected(self) -> None:
        # A second CA signs a cert for our CSR — the leaf doesn't chain
        # to the pinned CA root we have on disk.
        other = make_test_ca("Other CA")
        cert_pem = _sign_csr(other, self.enrollment.csr_der)
        with self.assertRaises(EnrollError):
            self._import(cert_pem)

    def test_binding_mismatch_rejected(self) -> None:
        # CA signs a cert with the CORRECT CSR pubkey but a DIFFERENT
        # binding extension (someone else's Noise static).
        csr = x509.load_der_x509_csr(self.enrollment.csr_der)
        csr_pubkey_spki = csr.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        wrong_static = b"\x99" * 32
        cert = make_leaf_cert(
            self.ca,
            subject_cn=cn,
            leaf_public_spki_der=csr_pubkey_spki,
            noise_static_pub=wrong_static,
        )
        with self.assertRaises(EnrollError):
            self._import(cert.public_bytes(serialization.Encoding.PEM))

    def test_wrong_attest_pubkey_rejected(self) -> None:
        # CA signs a cert with our binding extension (our Noise static)
        # but a DIFFERENT subject pubkey — the cert is for someone else's
        # attest key.
        other_priv = ec.generate_private_key(ec.SECP256R1())
        other_spki = other_priv.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        cert = make_leaf_cert(
            self.ca,
            subject_cn=self.enrollment.cn,
            leaf_public_spki_der=other_spki,
            noise_static_pub=self.enrollment.noise_static_pub,
        )
        with self.assertRaises(EnrollError):
            self._import(cert.public_bytes(serialization.Encoding.PEM))

    def test_missing_input_rejected(self) -> None:
        nonexistent = Path(self.tmpdir) / "missing.pem"
        with self.assertRaises(EnrollError):
            import_signed_cert(
                cert_input_path=nonexistent,
                cert_output_path=self.cert_out,
                ca_root_path=self.ca_path,
                keystore=self.keystore,
                attest_store=self.attest,
            )

    def test_corrupted_pem_rejected(self) -> None:
        with self.assertRaises(EnrollError):
            self._import(b"not a real cert\n")

    def test_empty_input_rejected(self) -> None:
        with self.assertRaises(EnrollError):
            self._import(b"")


class TestBuildCsrUnit(unittest.TestCase):
    """Direct build_csr() exercises (don't depend on file system)."""

    def test_csr_subject_pubkey_matches_attest_key(self) -> None:
        import tuncore
        attest = tuncore.AttestKey.generate()
        noise_static = b"\x42" * 32
        csr_der = build_csr(
            attest_key=attest,
            noise_static_pub=noise_static,
            cn="dsm-test-client",
        )
        csr = x509.load_der_x509_csr(csr_der)
        self.assertTrue(csr.is_signature_valid)

        csr_spki = csr.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.assertEqual(csr_spki, bytes(attest.public_spki_der()))

    def test_csr_rejects_wrong_length_static(self) -> None:
        import tuncore
        attest = tuncore.AttestKey.generate()
        with self.assertRaises(EnrollError):
            build_csr(
                attest_key=attest,
                noise_static_pub=b"\x42" * 31,
                cn="dsm-test-client",
            )


if __name__ == "__main__":
    unittest.main()
