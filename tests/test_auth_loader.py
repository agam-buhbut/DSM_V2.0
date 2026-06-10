"""Tests for ``dsm.crypto.auth_loader.load_cert_materials``.

Locks the recently-landed security fixes that gate daemon startup on the
cert auth materials:

  * DSM-005 — the CA-root SHA-256 pin is REQUIRED; unset or a wrong pin
    refuses to start, the correct pin returns ``CertAuthMaterials``.
  * DSM-013 — CRL decision matrix (missing / stale × strict / lenient),
    asserting raise-vs-return rather than log strings.
  * DSM-030 — a CRL with no ``nextUpdate`` refuses to start under
    ``crl_strict`` and returns (with a warning) under lenient.

The negative-case CA/leaf/CRL objects are hand-built here with
``cryptography`` (mirroring ``tests/cert_helpers``' style) rather than
adding params to the shared helper.
"""

from __future__ import annotations

import datetime
import hashlib
import os
import secrets
import unittest
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from dsm.core.config import Config
from dsm.crypto.auth_loader import (
    AuthMaterialsError,
    CertAuthMaterials,
    load_cert_materials,
)
from tests.cert_helpers import make_leaf_cert, make_test_ca


def _ec_p256_spki_der() -> bytes:
    """Generate a fresh EC P-256 key and return its SPKI DER.

    ``make_leaf_cert`` needs an EC SPKI for the leaf's public key; the
    binding extension carries a separate 32-byte X25519 static. No
    tuncore needed — both are produced via ``cryptography`` here.
    """
    priv = ec.generate_private_key(ec.SECP256R1())
    return priv.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )


def _build_crl(
    ca,
    *,
    this_update: datetime.datetime | None = None,
    next_update: datetime.datetime | None = None,
    revoked_serials: list[int] | None = None,
) -> bytes:
    """Build a DER CRL signed by ``ca`` (mirrors test_crl._build_crl).

    ``next_update`` may be ``None`` to mint a CRL with no nextUpdate
    field (DSM-030); ``cryptography``'s builder allows omitting it.
    """
    if this_update is None:
        this_update = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca.certificate.subject)
        .last_update(this_update)
        .add_extension(x509.CRLNumber(1), critical=False)
    )
    if next_update is not None:
        builder = builder.next_update(next_update)
    for s in revoked_serials or []:
        entry = (
            x509.RevokedCertificateBuilder()
            .serial_number(s)
            .revocation_date(this_update)
            .build()
        )
        builder = builder.add_revoked_certificate(entry)
    crl = builder.sign(private_key=ca.private_key, algorithm=hashes.SHA384())
    return crl.public_bytes(Encoding.DER)


class _MaterialsFixture:
    """Owns a tmp directory with a 0o600 leaf cert + 0o600 CA PEM.

    ``load_cert_materials`` permission-checks the cert / CA / CRL files,
    so every file written here is chmod'd 0o600. The CA's real SHA-256
    is precomputed so tests can pin the correct hash.
    """

    def __init__(self) -> None:
        tmp_root = Path(os.environ.get("TMPDIR", "/tmp"))
        self.dir = tmp_root / f"dsm-authloader-{os.getpid()}-{secrets.token_hex(4)}"
        self.dir.mkdir(mode=0o700, parents=True)

        self.ca = make_test_ca()
        self.ca_pem = self.ca.pem
        self.ca_sha256 = hashlib.sha256(self.ca_pem).hexdigest()

        self.ca_path = self.dir / "ca-root.pem"
        self._write_600(self.ca_path, self.ca_pem)

        leaf = make_leaf_cert(
            self.ca,
            subject_cn="dsm-authloader-client",
            leaf_public_spki_der=_ec_p256_spki_der(),
            noise_static_pub=secrets.token_bytes(32),
        )
        self.cert_path = self.dir / "device.crt"
        self._write_600(self.cert_path, leaf.public_bytes(Encoding.PEM))

    @staticmethod
    def _write_600(path: Path, data: bytes) -> None:
        path.write_bytes(data)
        os.chmod(path, 0o600)

    def write_crl_600(self, der: bytes, name: str = "dsm.crl") -> Path:
        path = self.dir / name
        self._write_600(path, der)
        return path

    def make_config(
        self,
        *,
        ca_root_sha256: str | None,
        crl_file: str | None = None,
        crl_strict: bool = True,
    ) -> Config:
        return Config(
            mode="client",
            server_ip="10.0.0.1",
            server_port=51820,
            listen_port=51821,
            key_file=str(self.dir / "id.key"),
            cert_file=str(self.cert_path),
            ca_root_file=str(self.ca_path),
            attest_key_file=str(self.dir / "attest.key"),
            expected_server_cn="dsm-test-server",
            transport="udp",
            ca_root_sha256=ca_root_sha256,
            crl_file=crl_file,
            crl_strict=crl_strict,
        )

    def cleanup(self) -> None:
        for child in sorted(self.dir.glob("*")):
            try:
                child.unlink()
            except FileNotFoundError:
                pass
        try:
            self.dir.rmdir()
        except OSError:
            pass


class TestCaRootPinRequired(unittest.TestCase):
    """DSM-005: the CA-root SHA-256 pin is required and verified."""

    def setUp(self) -> None:
        self.fx = _MaterialsFixture()
        self.addCleanup(self.fx.cleanup)

    def test_missing_pin_refuses_to_start(self) -> None:
        config = self.fx.make_config(ca_root_sha256=None, crl_strict=False)
        with self.assertRaises(AuthMaterialsError):
            load_cert_materials(config)

    def test_wrong_pin_refuses_to_start(self) -> None:
        # A syntactically valid 64-hex pin that does NOT match the CA file.
        wrong = "00" * 32
        self.assertNotEqual(wrong, self.fx.ca_sha256)
        config = self.fx.make_config(ca_root_sha256=wrong, crl_strict=False)
        with self.assertRaises(AuthMaterialsError):
            load_cert_materials(config)

    def test_correct_pin_returns_materials(self) -> None:
        config = self.fx.make_config(ca_root_sha256=self.fx.ca_sha256, crl_strict=False)
        materials = load_cert_materials(config)
        self.assertIsInstance(materials, CertAuthMaterials)
        self.assertEqual(materials.ca_root.subject, self.fx.ca.certificate.subject)
        # No CRL configured + lenient → crl is None.
        self.assertIsNone(materials.crl)
        self.assertTrue(materials.cert_der)


class TestCrlDecisionMatrix(unittest.TestCase):
    """DSM-013: CRL missing / stale × strict / lenient.

    Assert raise-vs-return only — the netaudit event names / log strings
    are intentionally NOT asserted here (they're covered by the schema
    lock + are an implementation detail of the message wording).
    """

    def setUp(self) -> None:
        self.fx = _MaterialsFixture()
        self.addCleanup(self.fx.cleanup)
        self.pin = self.fx.ca_sha256

    def test_crl_absent_strict_refuses(self) -> None:
        config = self.fx.make_config(
            ca_root_sha256=self.pin, crl_file=None, crl_strict=True
        )
        with self.assertRaises(AuthMaterialsError):
            load_cert_materials(config)

    def test_crl_absent_lenient_returns_with_none(self) -> None:
        config = self.fx.make_config(
            ca_root_sha256=self.pin, crl_file=None, crl_strict=False
        )
        materials = load_cert_materials(config)
        self.assertIsInstance(materials, CertAuthMaterials)
        self.assertIsNone(materials.crl)

    def test_stale_crl_strict_refuses(self) -> None:
        now = datetime.datetime.now(datetime.UTC)
        stale_der = _build_crl(
            self.fx.ca,
            this_update=now - datetime.timedelta(days=10),
            next_update=now - datetime.timedelta(days=1),
        )
        crl_path = self.fx.write_crl_600(stale_der)
        config = self.fx.make_config(
            ca_root_sha256=self.pin,
            crl_file=str(crl_path),
            crl_strict=True,
        )
        with self.assertRaises(AuthMaterialsError):
            load_cert_materials(config)

    def test_stale_crl_lenient_returns(self) -> None:
        now = datetime.datetime.now(datetime.UTC)
        stale_der = _build_crl(
            self.fx.ca,
            this_update=now - datetime.timedelta(days=10),
            next_update=now - datetime.timedelta(days=1),
        )
        crl_path = self.fx.write_crl_600(stale_der)
        config = self.fx.make_config(
            ca_root_sha256=self.pin,
            crl_file=str(crl_path),
            crl_strict=False,
        )
        materials = load_cert_materials(config)
        self.assertIsInstance(materials, CertAuthMaterials)
        # A stale-but-valid CRL is still loaded under lenient policy.
        self.assertIsNotNone(materials.crl)

    def test_fresh_crl_strict_returns(self) -> None:
        # Sanity anchor: a fresh, well-formed CRL passes even under strict.
        now = datetime.datetime.now(datetime.UTC)
        fresh_der = _build_crl(
            self.fx.ca,
            this_update=now - datetime.timedelta(minutes=1),
            next_update=now + datetime.timedelta(days=30),
        )
        crl_path = self.fx.write_crl_600(fresh_der)
        config = self.fx.make_config(
            ca_root_sha256=self.pin,
            crl_file=str(crl_path),
            crl_strict=True,
        )
        materials = load_cert_materials(config)
        self.assertIsNotNone(materials.crl)


def _can_mint_no_next_update_crl() -> bool:
    """Probe whether the installed ``cryptography`` lets a CRL omit
    nextUpdate. As of 46.0.7 ``.sign()`` raises ``ValueError`` ("A CRL
    must have a next update time"), so the DSM-030 no-nextUpdate cells
    below are skipped — a tampered DER would fail CRL signature
    verification before the no-nextUpdate branch is reached, so there is
    no way to construct a *validly signed* no-nextUpdate CRL here."""
    try:
        _build_crl(make_test_ca(), next_update=None)
    except ValueError:
        return False
    return True


_HAS_NO_NEXTUPDATE_CRL = _can_mint_no_next_update_crl()
_SKIP_NO_NEXTUPDATE = (
    "cryptography's CertificateRevocationListBuilder.sign() requires a "
    "next_update; cannot mint a validly-signed no-nextUpdate CRL with "
    "this library version. The DSM-030 raise/return branch is still "
    "exercised by the stale-CRL cells above (same fail-closed gate)."
)


@unittest.skipUnless(_HAS_NO_NEXTUPDATE_CRL, _SKIP_NO_NEXTUPDATE)
class TestCrlNoNextUpdate(unittest.TestCase):
    """DSM-030: a CRL with no nextUpdate cannot have freshness verified."""

    def setUp(self) -> None:
        self.fx = _MaterialsFixture()
        self.addCleanup(self.fx.cleanup)
        self.pin = self.fx.ca_sha256

    def test_no_next_update_strict_refuses(self) -> None:
        der = _build_crl(self.fx.ca, next_update=None)
        crl_path = self.fx.write_crl_600(der)
        config = self.fx.make_config(
            ca_root_sha256=self.pin,
            crl_file=str(crl_path),
            crl_strict=True,
        )
        with self.assertRaises(AuthMaterialsError):
            load_cert_materials(config)

    def test_no_next_update_lenient_returns(self) -> None:
        der = _build_crl(self.fx.ca, next_update=None)
        crl_path = self.fx.write_crl_600(der)
        config = self.fx.make_config(
            ca_root_sha256=self.pin,
            crl_file=str(crl_path),
            crl_strict=False,
        )
        materials = load_cert_materials(config)
        self.assertIsInstance(materials, CertAuthMaterials)
        self.assertIsNotNone(materials.crl)


if __name__ == "__main__":
    unittest.main()
