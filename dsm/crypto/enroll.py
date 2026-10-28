"""Device enrollment: CSR generation + signed-cert import.

Two-step flow used by the offline-CA model:

  1. ``generate_enrollment(...)`` provisions a fresh identity keypair
     (X25519 Noise static) and a fresh attest key (ECDSA P-256), persists
     both encrypted under the operator's passphrase, and emits a CSR
     containing the device CN + the ``id-dsm-noiseStaticBinding``
     extension carrying the X25519 static pubkey.

  2. The operator walks the CSR over USB to the offline CA laptop, signs
     it (per ``deploy/GUIDE.md`` §3c), walks the cert back, and runs
     ``import_signed_cert(...)`` to verify the cert matches the local
     identity + attest material and persist it.

The CSR is signed with the attest key (proof-of-possession of the
device's hardware-bound private key). The CA verifies that signature
before issuing.

The CSR build is backend-aware (see ``build_csr``): the soft backend
builds and signs the CSR entirely inside Rust (``rcgen``), while the TPM
backend — whose private scalar cannot leave the chip — assembles the CSR
here and delegates the signature to the TPM. Both paths emit a
structurally identical PKCS#10 (same subject + same critical
``id-dsm-noiseStaticBinding`` extension), so the offline-CA workflow is
unchanged.
"""

from __future__ import annotations

import datetime
import hashlib
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtendedKeyUsageOID

from dsm.core.atomic_io import atomic_write
from dsm.crypto.attest_store import AttestStore
from dsm.crypto.cert import (
    CertError,
    DeviceCert,
    load_ca_root,
    validate_chain,
)
from dsm.crypto.keystore import KeyStore

if TYPE_CHECKING:
    import tuncore

log = logging.getLogger(__name__)


class EnrollError(Exception):
    """Enrollment-time error (CSR build / cert import)."""


def ca_root_reason(e: Exception) -> str:
    """One short reason for a CA root that ``load_ca_root`` refused. A parse
    error is cryptography's long text, which names the file again."""
    if isinstance(e.__cause__, ValueError):
        return "no PEM certificate in it"
    return str(e)


def derive_default_cn(noise_static_pub: bytes, role: str) -> str:
    """Derive the default device CN from the Noise static pubkey + role.

    Format: ``dsm-<12 hex>-<role>`` where the 12 hex come from
    ``SHA-256(noise_static_pub ‖ role)[:6]``. Deterministic, globally unique
    without a name registry, and binds the human-readable name to the
    cryptographic identity.
    """
    if role not in ("client", "server"):
        raise ValueError(f"role must be 'client' or 'server', got {role!r}")
    if len(noise_static_pub) != 32:
        raise ValueError(
            f"noise_static_pub must be 32 bytes, got {len(noise_static_pub)}"
        )
    # Bind role into the hash input so the same Noise static enrolled as
    # both client and server cannot produce the same hex prefix — and so
    # the role suffix isn't a non-binding decoration. Extend the prefix
    # to 12 hex (6 bytes) so collisions on a fleet are ~birthday-bounded
    # at ~2^24 devices per role instead of ~2^16 with the old 4-byte
    # truncation. CNs of either width parse identically by the allowlist.
    digest = hashlib.sha256(noise_static_pub + role.encode("ascii")).digest()
    return f"dsm-{digest[:6].hex()}-{role}"


def build_csr(
    *,
    attest_key: tuncore.AttestKey,
    noise_static_pub: bytes,
    cn: str,
) -> bytes:
    """Build and DER-encode a CSR for this device.

    Soft backend: the CSR is built and signed entirely inside the Rust
    attest backend (``rcgen``) — the PKCS#8 export of the signing scalar
    never crosses the FFI boundary (audit M4). TPM backend: the key cannot
    export a private scalar, so the ``CertificationRequestInfo`` (TBS) is
    built here with ``cryptography`` and the signature is delegated to the
    TPM via ``attest_key.sign``. Both paths produce a structurally identical
    CSR (same SPKI algorithm, same critical ``id-dsm-noiseStaticBinding``
    extension wrapped per the conventional OCTET STRING form — see
    ``dsm.crypto.cert``), so the offline-CA workflow is unchanged.
    """
    if len(noise_static_pub) != 32:
        raise EnrollError(
            f"noise_static_pub must be 32 bytes, got {len(noise_static_pub)}"
        )
    import tuncore

    if getattr(tuncore, "ATTEST_BACKEND_IS_SOFTWARE", True):
        return bytes(attest_key.build_csr(cn, bytes(noise_static_pub)))
    return _build_csr_tpm(
        attest_key=attest_key,
        noise_static_pub=bytes(noise_static_pub),
        cn=cn,
    )


def _build_csr_tpm(
    *,
    attest_key: tuncore.AttestKey,
    noise_static_pub: bytes,
    cn: str,
) -> bytes:
    """Assemble a PKCS#10 CSR whose signature is produced by the TPM.

    No private key is exported. ``cryptography`` shapes the TBS
    (``CertificationRequestInfo``) using a throwaway P-256 signer that
    yields the right subject + the same critical
    ``id-dsm-noiseStaticBinding`` extension the soft path emits. A P-256
    ``SubjectPublicKeyInfo`` is a fixed 91 bytes; the throwaway's SPKI is
    byte-substituted for the TPM key's exported SPKI, the TPM signs the
    substituted TBS, and the final ``CertificationRequest`` SEQUENCE is
    assembled with minimal hand-rolled DER. The result is re-parsed and its
    signature verified before it is handed to the caller (fail closed).
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    from dsm.crypto.cert import (
        DSM_NOISE_STATIC_BINDING_OID,
        encode_noise_static_binding_value,
    )

    tpm_spki = bytes(attest_key.public_spki_der())
    if len(tpm_spki) != 91:
        raise EnrollError(
            "TPM attest SPKI is not the expected 91-byte P-256 SPKI "
            f"(got {len(tpm_spki)}); cannot assemble CSR"
        )

    ext_value = encode_noise_static_binding_value(noise_static_pub)
    throwaway = ec.generate_private_key(ec.SECP256R1())
    throwaway_spki = throwaway.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    # A P-256 SPKI is always 91 bytes (fixed AlgorithmIdentifier + 0x04 ||
    # X(32) || Y(32) uncompressed point). The throwaway SPKI is freshly
    # generated, so a coincidental 91-byte collision elsewhere in the TBS
    # (e.g. inside the subject CN or the extension's 32-byte payload) is
    # astronomically unlikely — but we still require EXACTLY ONE occurrence
    # before substituting, so we can never silently overwrite the wrong span.
    csr0 = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .add_extension(
            x509.UnrecognizedExtension(DSM_NOISE_STATIC_BINDING_OID, ext_value),
            critical=True,
        )
        .sign(throwaway, hashes.SHA256())
    )
    tbs = csr0.tbs_certrequest_bytes
    occurrences = tbs.count(throwaway_spki)
    if occurrences != 1:
        raise EnrollError(
            "internal: throwaway SPKI not uniquely locatable in CSR TBS "
            f"(found {occurrences}); refusing to substitute the TPM key"
        )
    tbs = tbs.replace(throwaway_spki, tpm_spki)

    # The TPM signs the substituted TBS: SHA-256 + in-TPM ECDSA, returning a
    # standard ASN.1 DER ECDSA signature (the same contract the soft backend
    # and cryptography's verifier expect).
    sig = bytes(attest_key.sign(tbs))

    # AlgorithmIdentifier { algorithm ecdsa-with-SHA256 (1.2.840.10045.4.3.2) }
    # — a fixed 12-byte DER SEQUENCE with no parameters, identical to what
    # cryptography emits for an ECDSA-SHA256-signed P-256 CSR.
    sig_alg = bytes.fromhex("300a06082a8648ce3d040302")
    # signatureValue is a BIT STRING with 0 unused bits wrapping the DER sig.
    bitstring = b"\x03" + _der_len(len(sig) + 1) + b"\x00" + sig
    # CertificationRequest ::= SEQUENCE { TBS, sigAlg, signatureValue }.
    body = tbs + sig_alg + bitstring
    csr_der = b"\x30" + _der_len(len(body)) + body

    # Fail closed: re-parse and verify the signature against the TPM SPKI
    # before this CSR ever reaches the operator / CA.
    parsed = x509.load_der_x509_csr(csr_der)
    if not parsed.is_signature_valid:
        raise EnrollError("assembled TPM CSR failed signature self-verification")
    parsed_spki = parsed.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if parsed_spki != tpm_spki:
        raise EnrollError(
            "assembled TPM CSR public key does not match the TPM attest SPKI"
        )
    return csr_der


def _der_len(n: int) -> bytes:
    """DER definite-length encoding of a non-negative length ``n``."""
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


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
    again = (
        ": this host is already enrolled. To enroll it again, first remove "
        "identity.key, attest.key and device.crt by hand (deploy/GUIDE.md §7c)"
    )
    if keystore.exists():
        raise EnrollError(f"identity key already exists at {keystore.path}{again}")
    if attest_store.exists():
        raise EnrollError(f"attest key already exists at {attest_store.path}{again}")

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


def import_signed_cert(
    *,
    cert_input_path: Path,
    cert_output_path: Path,
    ca_root_path: Path,
    keystore: KeyStore,
    attest_store: AttestStore,
    now: datetime.datetime | None = None,
    role: Literal["client", "server"] | None = None,
) -> DeviceCert:
    """Verify a CA-signed cert matches the local enrollment and persist it.

    Checks performed (any failure refuses to write):
      * cert chains to the pinned CA root (``validate_chain``)
      * cert's ``id-dsm-noiseStaticBinding`` extension matches the
        loaded identity's Noise static pubkey
      * cert's subject pubkey SPKI matches the loaded attest key SPKI
      * cert is currently within its validity window
      * with ``role``, the cert's EKU fits it (clientAuth for a client,
        serverAuth for a server)

    Writes the cert to ``cert_output_path`` with mode 0o600.
    """
    if role not in (None, "client", "server"):
        raise ValueError(f"role must be 'client' or 'server', got {role!r}")
    if not cert_input_path.is_file():
        raise EnrollError(f"cert input not found: {cert_input_path}")
    if not ca_root_path.is_file():
        raise EnrollError(f"ca_root not found: {ca_root_path}")

    try:
        leaf = DeviceCert.from_pem_or_der(cert_input_path.read_bytes())
    except CertError as e:
        raise EnrollError(f"failed to parse cert: {e}") from e
    try:
        ca_root = load_ca_root(ca_root_path)
    except (CertError, ValueError) as e:
        # One line at `dsm enroll --import` and `dsm init --resume`, never a
        # traceback (QA2 Major 1).
        raise EnrollError(
            f"the CA root {ca_root_path} is not a CA certificate (PEM): "
            f"{ca_root_reason(e)}"
        ) from e

    try:
        validate_chain(leaf, ca_root, now=now)
    except CertError as e:
        raise EnrollError(f"chain / validity check failed: {e}") from e

    if role is not None:
        wanted = (
            ExtendedKeyUsageOID.CLIENT_AUTH
            if role == "client"
            else ExtendedKeyUsageOID.SERVER_AUTH
        )
        if not leaf.has_eku(wanted):
            # The easy slip: a client CSR signed with the server profile, or
            # the other way round (QA M3). Caught here, not at the server.
            raise EnrollError(
                f"this certificate is not a {role} certificate, and this host "
                f'is a {role} (mode = "{role}"). Sign its CSR again with '
                f"-extensions dsm_{role}_leaf (deploy/GUIDE.md §3c, §3f)."
            )

    expected_static = bytes(keystore.identity.public_key)
    if leaf.noise_static_pub != expected_static:
        # The noiseStaticBinding extension holds another device's key.
        raise EnrollError(
            "this certificate was made for another device: its key does not "
            "match this host's identity key"
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
