"""Load the cert auth materials referenced from ``Config`` at startup.

Both client and server need the same shape of inputs to the new
cert-based handshake (this device's cert DER + the pinned CA root + an
optional CRL). This module concentrates that loading so each runtime
caller can express it as a single call. Per-role policy
(``expected_server_cn`` for clients, ``allowed_cns_file`` for servers)
stays in the role's own runtime module.
"""

from __future__ import annotations

import datetime
import logging
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from dsm.core import netaudit
from dsm.core.config import Config
from dsm.core.path_security import (
    InsecureFilePermissionsError,
    check_user_file_permissions,
)
from dsm.crypto.attest_store import AttestStore
from dsm.crypto.cert import CertError, DeviceCert, load_ca_root
from dsm.crypto.crl import CRL, CRLError
from dsm.crypto.keystore import KeyStore

log = logging.getLogger(__name__)


class AuthMaterialsError(Exception):
    """A required auth material file is missing, malformed, or fails policy."""


@dataclass(frozen=True)
class CertAuthMaterials:
    """Parsed cert/CA/CRL materials ready to hand to the handshake."""

    cert_der: bytes
    ca_root: x509.Certificate
    crl: CRL | None


def _check_perms_or_raise(path: Path, label: str) -> None:
    """Reject paths that are symlinks, owned by another uid, or
    group/world readable. Defence-in-depth: cert/CA/CRL files are
    integrity-critical (substitution = wrong trust anchor / unrevoked
    cert), even though their content is signed."""
    try:
        check_user_file_permissions(path)
    except InsecureFilePermissionsError as e:
        raise AuthMaterialsError(
            f"refusing to load {label} with insecure permissions: {e}"
        ) from e


def _load_cert_der(cert_file: Path) -> bytes:
    """Read a leaf cert from disk in either PEM or DER form, return DER."""
    _check_perms_or_raise(cert_file, "cert_file")
    raw = cert_file.read_bytes()
    try:
        cert = DeviceCert.from_pem_or_der(raw)
    except CertError as e:
        raise AuthMaterialsError(f"failed to parse cert at {cert_file}: {e}") from e
    return cert.to_der()


def load_cert_materials(config: Config) -> CertAuthMaterials:
    """Load this device's cert + pinned CA root + optional CRL.

    Raises ``AuthMaterialsError`` on any I/O or parse failure.
    """
    cert_file = Path(config.cert_file)
    ca_root_file = Path(config.ca_root_file)

    if not cert_file.is_file():
        raise AuthMaterialsError(
            f"cert_file missing at {cert_file}; run `dsm enroll` to " "provision one"
        )
    if not ca_root_file.is_file():
        raise AuthMaterialsError(
            f"ca_root_file missing at {ca_root_file}; copy the pinned "
            "CA root cert into place per deploy/GUIDE.txt §2e"
        )

    cert_der = _load_cert_der(cert_file)

    _check_perms_or_raise(ca_root_file, "ca_root_file")
    # DSM-005: the CA-root SHA-256 pin is REQUIRED for the daemon. Without
    # it, an attacker who can overwrite the on-disk CA PEM (within file
    # perms) substitutes the trust anchor undetected. Refuse to start when
    # unset, and verify the file against the pin on load.
    if not config.ca_root_sha256:
        netaudit.emit("ca_pin_missing", action="refused_start")
        raise AuthMaterialsError(
            "ca_root_sha256 is required but not set in config; refusing to "
            "start. Compute it with `sha256sum <ca_root_file> | cut -d' ' -f1` "
            'and set ca_root_sha256 = "<hex>" in config.toml '
            "(see deploy/GUIDE.txt)."
        )
    try:
        expected_ca_sha256 = bytes.fromhex(config.ca_root_sha256)
    except ValueError as e:
        raise AuthMaterialsError(
            f"ca_root_sha256 is not valid hex: {config.ca_root_sha256!r}"
        ) from e
    try:
        ca_root = load_ca_root(ca_root_file, expected_sha256=expected_ca_sha256)
    except CertError as e:
        raise AuthMaterialsError(
            f"CA root at {ca_root_file} failed validation: {e}"
        ) from e

    crl: CRL | None = None
    if not config.crl_file:
        # CRL absent means revoked certs are silently accepted. Under
        # crl_strict (the default), refuse to start; under crl_strict=
        # false, log a WARNING and continue. A separate netaudit event
        # from "crl_stale" so monitoring can distinguish "no CRL at all"
        # from "CRL is past its next_update".
        if config.crl_strict:
            netaudit.emit("crl_missing", action="refused_start")
            raise AuthMaterialsError(
                "no crl_file configured and crl_strict=true; refusing to "
                "start. Either provision a CRL via the CA workflow per "
                "deploy/GUIDE.txt §7e, or set crl_strict=false in config "
                "to accept revoked certs (NOT recommended for production)."
            )
        log.warning(
            "no crl_file configured and crl_strict=false; revoked "
            "client/server certs will be accepted. Wire a CRL via "
            "deploy/GUIDE.txt §7e for revocation enforcement."
        )
        netaudit.emit("crl_missing", action="warned")
    if config.crl_file:
        crl_path = Path(config.crl_file)
        if not crl_path.is_file():
            raise AuthMaterialsError(f"crl_file configured but missing at {crl_path}")
        _check_perms_or_raise(crl_path, "crl_file")
        try:
            # Pass now=None so a stale CRL surfaces via is_stale() rather
            # than refusing startup outright; we apply the freshness
            # policy below based on config.crl_strict.
            crl = CRL.load(crl_path, ca_root, now=None)
        except CRLError as e:
            raise AuthMaterialsError(f"CRL at {crl_path} failed validation: {e}") from e
        log.info("loaded CRL crl_number=%s", crl.crl_number)
        _now = datetime.datetime.now(datetime.UTC)
        # DSM-030: a CRL with no nextUpdate is never reported "stale"
        # (is_stale returns False without the field), so it would slip past
        # crl_strict's freshness gate and be trusted forever. Treat a
        # missing nextUpdate as its own fail-closed / warn case.
        try:
            _next_update = crl.next_update
        except CRLError:
            _next_update = None
        if _next_update is None:
            if config.crl_strict:
                netaudit.emit(
                    "crl_no_nextupdate",
                    path=str(crl_path),
                    action="refused_start",
                )
                raise AuthMaterialsError(
                    f"CRL at {crl_path} has no nextUpdate and crl_strict=true; "
                    "refusing to start — CRL freshness cannot be verified. "
                    "Issue a CRL with a nextUpdate via the CA workflow, or set "
                    "crl_strict=false to accept it with a warning."
                )
            log.warning(
                "CRL at %s has no nextUpdate; freshness cannot be checked and "
                "revocation may be arbitrarily stale. Set crl_strict=true to "
                "refuse to start in this case.",
                crl_path,
            )
            netaudit.emit("crl_no_nextupdate", path=str(crl_path), action="warned")
        elif crl.is_stale(_now):
            if config.crl_strict:
                # Fail closed: refuse to start under a stale CRL. The
                # daemon's revocation surface is incomplete and a
                # security-paranoid operator opted into hard-fail.
                netaudit.emit(
                    "crl_stale",
                    path=str(crl_path),
                    next_update=crl.next_update.isoformat(),
                    action="refused_start",
                )
                raise AuthMaterialsError(
                    f"CRL at {crl_path} is stale (next_update="
                    f"{crl.next_update.isoformat()}) and crl_strict=true; "
                    "refusing to start. Refresh the CRL via the CA workflow "
                    "or set crl_strict=false in config to fall back to a "
                    "warning."
                )
            log.warning(
                "CRL at %s is stale (next_update=%s); revocation checks "
                "will miss certs revoked since that date. Set crl_strict=true "
                "in config to refuse to start under a stale CRL.",
                crl_path,
                crl.next_update.isoformat(),
            )
            netaudit.emit(
                "crl_stale",
                path=str(crl_path),
                next_update=crl.next_update.isoformat(),
                action="warned",
            )

    return CertAuthMaterials(cert_der=cert_der, ca_root=ca_root, crl=crl)


def verify_cert_matches_identity(
    cert_der: bytes,
    keystore: KeyStore,
    attest_store: AttestStore,
) -> None:
    """Assert that the loaded cert binds the loaded identity + attest keys.

    Call AFTER `load_daemon_stores` succeeds. Catches the failure mode
    where ``cert_file`` was swapped (by a typo or a co-resident attacker
    with file-write access but no key access) for a syntactically valid
    different cert — without this check the daemon would happily start,
    broadcast the wrong cert's CN / serial / Noise-binding-extension on
    every handshake attempt, and only fail at the peer's
    ``AttestBindingMismatchError`` / ``AttestSignatureError`` boundary,
    with no clear local symptom.

    Raises ``AuthMaterialsError`` on mismatch.
    """
    cert = DeviceCert.from_der(cert_der)

    bound_noise_static = cert.noise_static_pub
    local_noise_static = keystore.identity.public_key
    if bytes(bound_noise_static) != bytes(local_noise_static):
        raise AuthMaterialsError(
            "cert_file noiseStaticBinding extension does not match the "
            "loaded identity key — cert was issued for a different X25519 "
            "static. Re-enroll, or restore the matching cert from backup."
        )

    cert_spki_der = cert.public_key.public_bytes(
        Encoding.DER,
        PublicFormat.SubjectPublicKeyInfo,
    )
    local_attest_spki = attest_store.public_spki_der()
    if bytes(cert_spki_der) != bytes(local_attest_spki):
        raise AuthMaterialsError(
            "cert_file SubjectPublicKeyInfo does not match the loaded "
            "attest key — cert was issued for a different ECDSA pubkey. "
            "Re-enroll, or restore the matching cert from backup."
        )
