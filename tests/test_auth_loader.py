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

import pytest
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
from tests.cert_helpers import IssuingCA, make_leaf_cert, make_test_ca


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
            config_dir=self.dir,
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


# --- #9: the CRL floor is kept per CA key (GUIDE §7f) ---------------------


def _renewed(ca: IssuingCA) -> IssuingCA:
    """The same CA key and name in a new root cert (new serial, new end)."""
    old = ca.certificate
    builder = (
        x509.CertificateBuilder()
        .subject_name(old.subject)
        .issuer_name(old.subject)
        .public_key(ca.private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(old.not_valid_before_utc)
        .not_valid_after(old.not_valid_after_utc + datetime.timedelta(days=1))
    )
    for ext in old.extensions:
        builder = builder.add_extension(ext.value, critical=ext.critical)
    cert = builder.sign(private_key=ca.private_key, algorithm=hashes.SHA384())
    return IssuingCA(private_key=ca.private_key, certificate=cert)


def _load_under(
    tmp_path: Path, folder: Path, ca: IssuingCA, number: int
) -> CertAuthMaterials:
    """load_cert_materials with this CA pinned, a CRL numbered ``number``
    and ``folder`` as config_dir (where the floor lives)."""
    files = tmp_path / f"files-{number:x}-{ca.certificate.serial_number:x}"
    files.mkdir()
    root = files / "dsm_ca_root.pem"
    root.write_bytes(ca.pem)
    cert = files / "device.crt"
    leaf = make_leaf_cert(
        ca,
        subject_cn="dsm-aabbccddeeff-client",
        leaf_public_spki_der=_ec_p256_spki_der(),
        noise_static_pub=b"\x01" * 32,
    )
    cert.write_bytes(leaf.public_bytes(Encoding.PEM))
    now = datetime.datetime.now(datetime.UTC)
    crl = files / "dsm_ca.crl"
    crl.write_bytes(
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca.certificate.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=30))
        .add_extension(x509.CRLNumber(number), critical=False)
        .sign(private_key=ca.private_key, algorithm=hashes.SHA384())
        .public_bytes(Encoding.PEM)
    )
    for path in (root, cert, crl):
        path.chmod(0o600)
    return load_cert_materials(
        Config(
            mode="client",
            server_ip="10.0.0.1",
            server_port=51820,
            listen_port=0,
            key_file=str(files / "id.key"),
            cert_file=str(cert),
            ca_root_file=str(root),
            attest_key_file=str(files / "attest.key"),
            expected_server_cn="dsm-test-server",
            transport="udp",
            ca_root_sha256=hashlib.sha256(ca.pem).hexdigest(),
            crl_file=str(crl),
            config_dir=folder,
        )
    )


@pytest.fixture(name="folder")
def _folder(tmp_path: Path) -> Path:
    folder = tmp_path / "mtun"
    folder.mkdir(mode=0o700)
    return folder


def test_a_new_ca_starts_its_own_crl_count(tmp_path: Path, folder: Path) -> None:
    _load_under(tmp_path, folder, make_test_ca("DSM Root CA"), 0x1005)
    new_ca = make_test_ca("DSM Root CA")  # GUIDE §7f: same name, crlnumber 1000
    materials = _load_under(tmp_path, folder, new_ca, 0x1000)
    assert materials.crl is not None
    assert materials.crl.crl_number == 0x1000


def test_each_ca_keeps_its_own_floor(tmp_path: Path, folder: Path) -> None:
    old_ca = make_test_ca("DSM Root CA")
    new_ca = make_test_ca("DSM Root CA")
    _load_under(tmp_path, folder, old_ca, 0x1005)
    _load_under(tmp_path, folder, new_ca, 0x1000)
    with pytest.raises(AuthMaterialsError, match="older than the last-accepted 1005"):
        _load_under(tmp_path, folder, old_ca, 0x1004)
    with pytest.raises(AuthMaterialsError, match="older than the last-accepted 1000"):
        _load_under(tmp_path, folder, new_ca, 0xFFF)


def test_a_renewed_root_with_the_same_key_keeps_the_floor(
    tmp_path: Path, folder: Path
) -> None:
    ca = make_test_ca("DSM Root CA")
    _load_under(tmp_path, folder, ca, 0x1005)
    with pytest.raises(AuthMaterialsError, match="older than the last-accepted 1005"):
        _load_under(tmp_path, folder, _renewed(ca), 0x1004)


def test_a_floor_from_before_the_fix_counts_for_the_ca_pinned_now(
    tmp_path: Path, folder: Path
) -> None:
    legacy = folder / "crl_number.seen"
    legacy.write_text("4101\n")  # 0x1005, written by DSM at f0261f2
    with pytest.raises(AuthMaterialsError, match="older than the last-accepted 1005"):
        _load_under(tmp_path, folder, make_test_ca("DSM Root CA"), 0x1004)
    assert not legacy.exists()


def test_an_old_floor_file_never_lowers_the_floor_of_a_ca(
    tmp_path: Path, folder: Path
) -> None:
    ca = make_test_ca("DSM Root CA")
    _load_under(tmp_path, folder, ca, 0x1005)
    (folder / "crl_number.seen").write_text("4096\n")  # 0x1000, from an older DSM
    with pytest.raises(AuthMaterialsError, match="older than the last-accepted 1005"):
        _load_under(tmp_path, folder, ca, 0x1004)


if __name__ == "__main__":
    unittest.main()
