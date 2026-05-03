"""Tests for ``dsm.crypto.crl``."""

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

from dsm.crypto.crl import (
    CRL,
    CRLIssuerMismatchError,
    CRLLoadError,
    CRLSignatureError,
    CRLStaleError,
)
from tests.cert_helpers import make_test_ca


def _build_crl(
    ca,
    *,
    revoked_serials: list[int] | None = None,
    this_update: datetime.datetime | None = None,
    next_update: datetime.datetime | None = None,
    signing_key: ec.EllipticCurvePrivateKey | None = None,
    issuer_name: x509.Name | None = None,
    crl_number: int = 1,
) -> bytes:
    """Build a DER CRL signed by ``ca`` (or the override keys/issuer)."""
    if revoked_serials is None:
        revoked_serials = []
    if this_update is None:
        this_update = datetime.datetime.now(datetime.timezone.utc)
    if next_update is None:
        next_update = this_update + datetime.timedelta(days=30)
    if signing_key is None:
        signing_key = ca.private_key
    if issuer_name is None:
        issuer_name = ca.certificate.subject

    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer_name)
        .last_update(this_update)
        .next_update(next_update)
        .add_extension(x509.CRLNumber(crl_number), critical=False)
    )
    for s in revoked_serials:
        entry = (
            x509.RevokedCertificateBuilder()
            .serial_number(s)
            .revocation_date(this_update)
            .build()
        )
        builder = builder.add_revoked_certificate(entry)
    crl = builder.sign(private_key=signing_key, algorithm=hashes.SHA384())
    return crl.public_bytes(Encoding.DER)


def _write_tmp(data: bytes) -> Path:
    path = Path(os.environ.get("TMPDIR", "/tmp")) / (
        f"dsm-crl-{os.getpid()}-{secrets.token_hex(4)}.crl"
    )
    path.write_bytes(data)
    return path


class TestCRLLoad(unittest.TestCase):
    def setUp(self) -> None:
        self.ca = make_test_ca()
        self.serial_a = 0xAA00
        self.serial_b = 0xBB00
        self.serial_c = 0xCC00
        self.crl_der = _build_crl(
            self.ca, revoked_serials=[self.serial_a, self.serial_b]
        )
        self.tmp = _write_tmp(self.crl_der)

    def tearDown(self) -> None:
        try:
            self.tmp.unlink()
        except FileNotFoundError:
            pass

    def test_load_der(self) -> None:
        crl = CRL.load(self.tmp, self.ca.certificate)
        self.assertEqual(len(crl), 2)
        self.assertTrue(crl.is_revoked(self.serial_a))
        self.assertTrue(crl.is_revoked(self.serial_b))
        self.assertFalse(crl.is_revoked(self.serial_c))
        self.assertEqual(crl.crl_number, 1)

    def test_load_pem(self) -> None:
        # cryptography's CRL.public_bytes accepts both encodings.
        crl_obj = x509.load_der_x509_crl(self.crl_der)
        pem = crl_obj.public_bytes(Encoding.PEM)
        path = _write_tmp(pem)
        try:
            crl = CRL.load(path, self.ca.certificate)
            self.assertTrue(crl.is_revoked(self.serial_a))
        finally:
            path.unlink()

    def test_freshness_check_at_load(self) -> None:
        # Build a CRL whose nextUpdate is yesterday.
        now = datetime.datetime.now(datetime.timezone.utc)
        stale_der = _build_crl(
            self.ca,
            this_update=now - datetime.timedelta(days=10),
            next_update=now - datetime.timedelta(days=1),
        )
        path = _write_tmp(stale_der)
        try:
            with self.assertRaises(CRLStaleError):
                CRL.load(path, self.ca.certificate, now=now)
            # Same CRL with no `now=` arg: load passes; stale visible via
            # is_stale().
            crl = CRL.load(path, self.ca.certificate)
            self.assertTrue(crl.is_stale(now))
        finally:
            path.unlink()


class TestCRLRejections(unittest.TestCase):
    def setUp(self) -> None:
        self.ca = make_test_ca()

    def test_wrong_signing_key_rejected(self) -> None:
        # Build a CRL named for our CA but signed by a different key.
        wrong_key = ec.generate_private_key(ec.SECP384R1())
        bad = _build_crl(self.ca, signing_key=wrong_key)
        path = _write_tmp(bad)
        try:
            with self.assertRaises(CRLSignatureError):
                CRL.load(path, self.ca.certificate)
        finally:
            path.unlink()

    def test_wrong_issuer_rejected(self) -> None:
        other_ca = make_test_ca("Other CA")
        bad = _build_crl(
            self.ca,
            issuer_name=other_ca.certificate.subject,
        )
        path = _write_tmp(bad)
        try:
            with self.assertRaises(CRLIssuerMismatchError):
                CRL.load(path, self.ca.certificate)
        finally:
            path.unlink()

    def test_garbage_file_rejected(self) -> None:
        path = _write_tmp(b"this is not a CRL")
        try:
            with self.assertRaises(CRLLoadError):
                CRL.load(path, self.ca.certificate)
        finally:
            path.unlink()

    def test_missing_file_rejected(self) -> None:
        with self.assertRaises(CRLLoadError):
            CRL.load(
                Path("/nonexistent/path/dsm.crl"), self.ca.certificate
            )

    def test_empty_revocation_list(self) -> None:
        empty = _build_crl(self.ca, revoked_serials=[])
        path = _write_tmp(empty)
        try:
            crl = CRL.load(path, self.ca.certificate)
            self.assertEqual(len(crl), 0)
            self.assertFalse(crl.is_revoked(0xAA00))
        finally:
            path.unlink()


if __name__ == "__main__":
    unittest.main()
