"""Load the cert auth materials referenced from ``Config`` at startup.

Both client and server need the same shape of inputs to the new
cert-based handshake (this device's cert DER + the pinned CA root + an
optional CRL). This module concentrates that loading so each runtime
caller can express it as a single call. Per-role policy
(``expected_server_cn`` for clients, ``allowed_cns_file`` for servers)
stays in the role's own runtime module.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509

from dsm.core.config import Config
from dsm.crypto.cert import CertError, DeviceCert, load_ca_root
from dsm.crypto.crl import CRL, CRLError

log = logging.getLogger(__name__)


class AuthMaterialsError(Exception):
    """A required auth material file is missing, malformed, or fails policy."""


@dataclass(frozen=True)
class CertAuthMaterials:
    """Parsed cert/CA/CRL materials ready to hand to the handshake."""

    cert_der: bytes
    ca_root: x509.Certificate
    crl: CRL | None


def _load_cert_der(cert_file: Path) -> bytes:
    """Read a leaf cert from disk in either PEM or DER form, return DER."""
    raw = cert_file.read_bytes()
    if not raw:
        raise AuthMaterialsError(f"cert file {cert_file} is empty")
    # Sniff PEM vs DER. PEM always starts with '-----BEGIN'.
    if raw.lstrip().startswith(b"-----BEGIN"):
        try:
            cert = DeviceCert.from_pem(raw)
        except CertError as e:
            raise AuthMaterialsError(
                f"failed to parse cert PEM at {cert_file}: {e}"
            ) from e
        return cert.to_der()
    try:
        cert = DeviceCert.from_der(raw)
    except CertError as e:
        raise AuthMaterialsError(
            f"failed to parse cert DER at {cert_file}: {e}"
        ) from e
    return cert.to_der()


def load_cert_materials(config: Config) -> CertAuthMaterials:
    """Load this device's cert + pinned CA root + optional CRL.

    Raises ``AuthMaterialsError`` on any I/O or parse failure.
    """
    cert_file = Path(config.cert_file)
    ca_root_file = Path(config.ca_root_file)

    if not cert_file.is_file():
        raise AuthMaterialsError(
            f"cert_file missing at {cert_file}; run `dsm enroll` to "
            "provision one"
        )
    if not ca_root_file.is_file():
        raise AuthMaterialsError(
            f"ca_root_file missing at {ca_root_file}; copy the pinned "
            "CA root cert into place per deploy/CA_RUNBOOK.md"
        )

    cert_der = _load_cert_der(cert_file)

    try:
        ca_root = load_ca_root(ca_root_file)
    except CertError as e:
        raise AuthMaterialsError(
            f"CA root at {ca_root_file} failed validation: {e}"
        ) from e

    crl: CRL | None = None
    if config.crl_file:
        crl_path = Path(config.crl_file)
        if not crl_path.is_file():
            raise AuthMaterialsError(
                f"crl_file configured but missing at {crl_path}"
            )
        try:
            # Pass now=None so a stale CRL surfaces via is_stale() rather
            # than refusing startup outright. The daemon logs the stale
            # state and continues — operationally a stale CRL is better
            # than a crashloop.
            crl = CRL.load(crl_path, ca_root, now=None)
        except CRLError as e:
            raise AuthMaterialsError(
                f"CRL at {crl_path} failed validation: {e}"
            ) from e
        log.info("loaded CRL crl_number=%s", crl.crl_number)

    return CertAuthMaterials(cert_der=cert_der, ca_root=ca_root, crl=crl)
