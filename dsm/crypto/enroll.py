"""Device enrollment: CSR generation + signed-cert import.

Two-step flow used by the offline-CA model:

  1. ``generate_enrollment(...)`` provisions a fresh identity keypair
     (X25519 Noise static) and a fresh attest key (ECDSA P-256), persists
     both encrypted under the operator's passphrase, and emits a CSR
     containing the device CN + the ``id-dsm-noiseStaticBinding``
     extension carrying the X25519 static pubkey.

  2. The operator walks the CSR over USB to the offline CA laptop, signs
     it (per ``deploy/CA_RUNBOOK.md``), walks the cert back, and runs
     ``import_signed_cert(...)`` to verify the cert matches the local
     identity + attest material and persist it.

The CSR is signed with the attest key (proof-of-possession of the
device's hardware-bound private key). The CA verifies that signature
before issuing.

Soft-backend only for now: the CSR signature is produced by exporting
the attest key's PKCS#8 DER and re-importing into ``cryptography`` —
TPM / Keystore backends will sign the CSR via platform APIs in their
own enroll path.
"""

from __future__ import annotations

import datetime
import hashlib
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from dsm.core.atomic_io import atomic_write
from dsm.crypto.attest_store import AttestStore
from dsm.crypto.cert import (
    CertError,
    DeviceCert,
    DSM_NOISE_STATIC_BINDING_OID,
    encode_noise_static_binding_value,
    load_ca_root,
    validate_chain,
)
from dsm.crypto.keystore import KeyStore

if TYPE_CHECKING:
    import tuncore

log = logging.getLogger(__name__)


class EnrollError(Exception):
    """Enrollment-time error (CSR build / cert import)."""


def derive_default_cn(noise_static_pub: bytes, role: str) -> str:
    """Derive the default device CN from the Noise static pubkey + role.

    Format: ``dsm-<8 hex>-<role>`` where the 8 hex come from
    ``SHA-256(noise_static_pub)[:4]``. Deterministic, globally unique
    without a name registry, and binds the human-readable name to the
    cryptographic identity.
    """
    if role not in ("client", "server"):
        raise ValueError(f"role must be 'client' or 'server', got {role!r}")
    if len(noise_static_pub) != 32:
        raise ValueError(
            f"noise_static_pub must be 32 bytes, got {len(noise_static_pub)}"
        )
    digest = hashlib.sha256(noise_static_pub).digest()
    return f"dsm-{digest[:4].hex()}-{role}"


def _attest_private_key_from_soft(
    attest_key: tuncore.AttestKey,
) -> ec.EllipticCurvePrivateKey:
    """Reconstruct a cryptography-library EC private key from a soft
    AttestKey, so the standard CSR builder can sign with it.

    Soft backend only. The TPM / Keystore enroll path will replace this
    with a CSR built and signed via platform APIs.
    """
    pkcs8_der = bytes(attest_key.private_pkcs8_der())
    priv = serialization.load_der_private_key(pkcs8_der, password=None)
    if not isinstance(priv, ec.EllipticCurvePrivateKey):
        raise EnrollError(
            f"attest key is not ECDSA (got {type(priv).__name__})"
        )
    return priv


def build_csr(
    *,
    attest_key: tuncore.AttestKey,
    noise_static_pub: bytes,
    cn: str,
) -> bytes:
    """Build and DER-encode a CSR for this device.

    The CSR's subject pubkey is the attest pubkey; the CSR is signed
    with the attest key (proof-of-possession). The custom critical
    ``id-dsm-noiseStaticBinding`` extension carries the X25519 Noise
    static pubkey wrapped per the conventional OCTET STRING form
    (see ``dsm.crypto.cert``).
    """
    if len(noise_static_pub) != 32:
        raise EnrollError(
            f"noise_static_pub must be 32 bytes, got {len(noise_static_pub)}"
        )

    priv = _attest_private_key_from_soft(attest_key)

    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ]))
    builder = builder.add_extension(
        x509.UnrecognizedExtension(
            DSM_NOISE_STATIC_BINDING_OID,
            encode_noise_static_binding_value(noise_static_pub),
        ),
        critical=True,
    )
    csr = builder.sign(priv, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.DER)


@dataclass(frozen=True)
class EnrollmentResult:
    cn: str
    noise_static_pub: bytes
    attest_spki_der: bytes
    csr_der: bytes


def generate_enrollment(
    *,
    keystore: KeyStore,
    attest_store: AttestStore,
    passphrase: bytes | bytearray,
    role: str,
    cn: str | None = None,
) -> EnrollmentResult:
    """Provision identity + attest key, persist them, return the CSR.

    Refuses to overwrite existing key files — the operator must remove
    them deliberately if re-enrollment is intended (post-compromise
    rotation walks an explicit checklist; we don't auto-clobber).
    """
    if keystore.exists():
        raise EnrollError(
            f"identity key already exists at {keystore._path}; "
            "re-enrollment must be explicit (remove the file by hand)"
        )
    if attest_store.exists():
        raise EnrollError(
            f"attest key already exists at {attest_store._path}; "
            "re-enrollment must be explicit (remove the file by hand)"
        )

    noise_static_pub = keystore.generate(passphrase)
    attest_spki_der = attest_store.generate(passphrase)

    if cn is None:
        cn = derive_default_cn(noise_static_pub, role)

    csr_der = build_csr(
        attest_key=attest_store.attest_key,
        noise_static_pub=noise_static_pub,
        cn=cn,
    )

    log.info("enrollment generated: cn=%s", cn)
    return EnrollmentResult(
        cn=cn,
        noise_static_pub=noise_static_pub,
        attest_spki_der=attest_spki_der,
        csr_der=csr_der,
    )


def _load_cert_any_format(raw: bytes) -> DeviceCert:
    if not raw:
        raise EnrollError("cert file is empty")
    if raw.lstrip().startswith(b"-----BEGIN"):
        try:
            return DeviceCert.from_pem(raw)
        except CertError as e:
            raise EnrollError(f"failed to parse cert PEM: {e}") from e
    try:
        return DeviceCert.from_der(raw)
    except CertError as e:
        raise EnrollError(f"failed to parse cert DER: {e}") from e


def import_signed_cert(
    *,
    cert_input_path: Path,
    cert_output_path: Path,
    ca_root_path: Path,
    keystore: KeyStore,
    attest_store: AttestStore,
    now: datetime.datetime | None = None,
) -> DeviceCert:
    """Verify a CA-signed cert matches the local enrollment and persist it.

    Checks performed (any failure refuses to write):
      * cert chains to the pinned CA root (``validate_chain``)
      * cert's ``id-dsm-noiseStaticBinding`` extension matches the
        loaded identity's Noise static pubkey
      * cert's subject pubkey SPKI matches the loaded attest key SPKI
      * cert is currently within its validity window

    Writes the cert to ``cert_output_path`` with mode 0o600.
    """
    if not cert_input_path.is_file():
        raise EnrollError(f"cert input not found: {cert_input_path}")
    if not ca_root_path.is_file():
        raise EnrollError(f"ca_root not found: {ca_root_path}")

    leaf = _load_cert_any_format(cert_input_path.read_bytes())
    ca_root = load_ca_root(ca_root_path)

    try:
        validate_chain(leaf, ca_root, now=now)
    except CertError as e:
        raise EnrollError(f"chain / validity check failed: {e}") from e

    expected_static = bytes(keystore.identity.public_key)
    if leaf.noise_static_pub != expected_static:
        raise EnrollError(
            "noiseStaticBinding extension does not match local identity "
            f"(cert={leaf.noise_static_pub.hex()[:16]}…, "
            f"local={expected_static.hex()[:16]}…)"
        )

    expected_spki = bytes(attest_store.attest_key.public_spki_der())
    leaf_spki = leaf.cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if leaf_spki != expected_spki:
        raise EnrollError(
            "cert subject pubkey SPKI does not match local attest key "
            "(cert was issued for a different attest key)"
        )

    der = leaf.to_der()
    atomic_write(cert_output_path, der)
    try:
        os.chmod(cert_output_path, 0o600)
    except OSError as e:
        log.warning("could not chmod %s to 0o600: %s", cert_output_path, e)
    log.info(
        "imported cert cn=%s serial=%s into %s",
        leaf.subject_cn,
        leaf.serial_number,
        cert_output_path,
    )
    return leaf
