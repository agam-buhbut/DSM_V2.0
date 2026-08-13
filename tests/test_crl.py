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
    CRLRollbackError,
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
        this_update = datetime.datetime.now(datetime.UTC)
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


def _build_crl_no_number(ca, *, revoked_serials: list[int] | None = None) -> bytes:
    """Build a DER CRL with NO crl_number extension (for rollback tests)."""
    if revoked_serials is None:
        revoked_serials = []
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca.certificate.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=30))
    )
    for s in revoked_serials:
        entry = (
            x509.RevokedCertificateBuilder()
            .serial_number(s)
            .revocation_date(now)
            .build()
        )
        builder = builder.add_revoked_certificate(entry)
    crl = builder.sign(private_key=ca.private_key, algorithm=hashes.SHA384())
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
        self.assertEqual(len(crl.crl), 2)
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
        now = datetime.datetime.now(datetime.UTC)
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
            CRL.load(Path("/nonexistent/path/dsm.crl"), self.ca.certificate)

    def test_empty_revocation_list(self) -> None:
        empty = _build_crl(self.ca, revoked_serials=[])
        path = _write_tmp(empty)
        try:
            crl = CRL.load(path, self.ca.certificate)
            self.assertEqual(len(crl.crl), 0)
            self.assertFalse(crl.is_revoked(0xAA00))
        finally:
            path.unlink()


class TestCRLRollback(unittest.TestCase):
    def setUp(self) -> None:
        self.ca = make_test_ca()
        self.dir = Path(
            os.path.join(
                os.environ.get("TMPDIR", "/tmp"),
                f"dsm-crl-rb-{os.getpid()}-{secrets.token_hex(4)}",
            )
        )
        self.dir.mkdir(parents=True)
        self.store = self.dir / "crl_number.seen"

    def tearDown(self) -> None:
        for p in self.dir.glob("*"):
            p.unlink()
        self.dir.rmdir()

    def _load(self, crl_number: int | None) -> CRL:
        if crl_number is None:
            der = _build_crl_no_number(self.ca)
        else:
            der = _build_crl(self.ca, crl_number=crl_number)
        path = _write_tmp(der)
        try:
            return CRL.load(path, self.ca.certificate)
        finally:
            path.unlink()

    def test_accept_then_reject_older(self) -> None:
        # Accept #5, then an older but genuinely-signed #3 must be rejected.
        self._load(5).reject_if_rolled_back(self.store)
        self.assertEqual(self.store.read_text().strip(), "5")
        with self.assertRaises(CRLRollbackError):
            self._load(3).reject_if_rolled_back(self.store)
        # Floor is unchanged after the rejection.
        self.assertEqual(self.store.read_text().strip(), "5")

    def test_equal_and_newer_accepted(self) -> None:
        self._load(5).reject_if_rolled_back(self.store)
        # Same number is fine (idempotent re-load).
        self._load(5).reject_if_rolled_back(self.store)
        # Newer advances the floor.
        self._load(6).reject_if_rolled_back(self.store)
        self.assertEqual(self.store.read_text().strip(), "6")

    def test_downgrade_to_unnumbered_rejected(self) -> None:
        self._load(5).reject_if_rolled_back(self.store)
        with self.assertRaises(CRLRollbackError):
            self._load(None).reject_if_rolled_back(self.store)

    def test_corrupt_store_fails_closed(self) -> None:
        self.store.write_text("not-an-int")
        with self.assertRaises(CRLRollbackError):
            self._load(5).reject_if_rolled_back(self.store)


if __name__ == "__main__":
    unittest.main()
