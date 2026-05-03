"""X.509 device certificate handling for DSM auth.

Replaces the HMAC-protected ``authorized_clients.json`` and TOFU
``known_hosts.json`` schemes with PKI-based authentication. A device
cert binds:

  * a subject CN identifying the device (e.g. ``dsm-a3f29c81-client``)
  * an ECDSA P-256 *signing* pubkey held in TPM 2.0 / Android Keystore
    (the SubjectPublicKeyInfo of the cert)
  * the device's X25519 *Noise static* pubkey, carried in our custom
    critical X.509v3 extension ``id-dsm-noiseStaticBinding``

The binding extension makes cert + Noise static inseparable: a stolen
Noise static does not match any cert's binding, and a stolen cert is
useless without (a) the matching Noise static and (b) live access to
the hardware signing key.

This module covers the verifier side only — load, parse, validate, and
extract the binding. CSR generation and CA-side signing live alongside
the ``dsm enroll`` workflow.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtensionOID, NameOID

# Custom OID for the X25519 Noise-static-key binding extension.
# Experimental arc — renumber to a registered IANA Private Enterprise
# Number before any rollout that interoperates with non-DSM software.
DSM_NOISE_STATIC_BINDING_OID = x509.ObjectIdentifier("1.3.6.1.4.1.99999.1.1")

# Length of an X25519 raw public key (RFC 7748 §5).
NOISE_STATIC_PUB_LEN = 32

# DER tag/length of the OCTET STRING wrapper in the binding extension.
# Following the RFC 5280 §4.2 convention (matches subjectAltName etc.):
# the extension's ``extnValue`` is the DER encoding of an inner type;
# ours is OCTET STRING containing the 32 raw X25519 pubkey bytes.
_OCTET_STRING_TAG = 0x04
_OCTET_STRING_PREFIX = bytes([_OCTET_STRING_TAG, NOISE_STATIC_PUB_LEN])


class CertError(Exception):
    """Base class for cert-handling failures."""


class CertChainError(CertError):
    """Issuer/signature/CA-trust failure."""


class CertExpiredError(CertError):
    """Cert is outside its validity window (or not yet valid)."""


class CertBindingError(CertError):
    """The Noise-static-binding extension is missing or malformed."""


def encode_noise_static_binding_value(noise_static_pub: bytes) -> bytes:
    """Build the conventional DER ``OCTET STRING (32)`` payload for the
    binding extension's ``extnValue``. Used by the issuing/CSR side."""
    if len(noise_static_pub) != NOISE_STATIC_PUB_LEN:
        raise ValueError(
            f"noise_static_pub must be {NOISE_STATIC_PUB_LEN} bytes, got {len(noise_static_pub)}"
        )
    return _OCTET_STRING_PREFIX + bytes(noise_static_pub)


def _decode_noise_static_binding_value(raw: bytes) -> bytes:
    """Inverse of ``encode_noise_static_binding_value``."""
    expected_total = 2 + NOISE_STATIC_PUB_LEN
    if (
        len(raw) != expected_total
        or raw[0] != _OCTET_STRING_TAG
        or raw[1] != NOISE_STATIC_PUB_LEN
    ):
        raise CertBindingError(
            "noiseStaticBinding extension malformed: "
            f"expected DER OCTET STRING ({_OCTET_STRING_TAG:#04x} {NOISE_STATIC_PUB_LEN:#04x} || 32 bytes)"
        )
    return bytes(raw[2:])


@dataclass(frozen=True)
class DeviceCert:
    """Wrapper around a parsed leaf cert with DSM-specific accessors.

    Construction validates structural integrity (forces the
    cryptography library's lazy DER decoders to actually decode every
    load-bearing field), so a tampered cert that survived
    ``load_*_x509_certificate`` cannot reach ``validate_chain`` only to
    explode there with a raw ``ValueError``. Construction does NOT
    validate the chain — call ``validate_chain`` separately.
    """

    cert: x509.Certificate

    def __post_init__(self) -> None:
        # Cf. cryptography's lazy DER decoding: several X.509 fields
        # are only decoded on first access. Touch the load-bearing ones
        # here so corruption surfaces as a clean CertError up front.
        try:
            _ = self.cert.subject
            _ = self.cert.issuer
            _ = self.cert.not_valid_before_utc
            _ = self.cert.not_valid_after_utc
            _ = self.cert.public_key()
            _ = self.cert.tbs_certificate_bytes
        except ValueError as e:
            raise CertError(
                f"cert structurally invalid (lazy field decode failed): {e}"
            ) from e

    @classmethod
    def from_der(cls, der: bytes) -> DeviceCert:
        try:
            cert = x509.load_der_x509_certificate(bytes(der))
        except ValueError as e:
            raise CertError(f"failed to parse cert DER: {e}") from e
        return cls(cert)

    @classmethod
    def from_pem(cls, pem: bytes) -> DeviceCert:
        try:
            cert = x509.load_pem_x509_certificate(bytes(pem))
        except ValueError as e:
            raise CertError(f"failed to parse cert PEM: {e}") from e
        return cls(cert)

    def to_der(self) -> bytes:
        return self.cert.public_bytes(Encoding.DER)

    @property
    def subject_cn(self) -> str:
        cns = self.cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if len(cns) != 1:
            raise CertError(
                f"cert subject must have exactly one CN, got {len(cns)}"
            )
        value = cns[0].value
        if not isinstance(value, str):
            raise CertError("cert CN must be a string attribute")
        return value

    @property
    def noise_static_pub(self) -> bytes:
        """Extract the 32-byte X25519 Noise static pubkey from the
        ``id-dsm-noiseStaticBinding`` extension. Raises on absent /
        non-critical / malformed extension."""
        try:
            ext = self.cert.extensions.get_extension_for_oid(
                DSM_NOISE_STATIC_BINDING_OID
            )
        except x509.ExtensionNotFound as e:
            raise CertBindingError(
                "cert missing noiseStaticBinding extension"
            ) from e
        if not ext.critical:
            raise CertBindingError(
                "noiseStaticBinding extension must be marked critical"
            )
        if not isinstance(ext.value, x509.UnrecognizedExtension):
            raise CertBindingError(
                f"unexpected binding extension value type: {type(ext.value).__name__}"
            )
        return _decode_noise_static_binding_value(ext.value.value)

    @property
    def public_key(self) -> EllipticCurvePublicKey:
        pk = self.cert.public_key()
        if not isinstance(pk, EllipticCurvePublicKey):
            raise CertError(
                "cert public key must be ECDSA (got "
                f"{type(pk).__name__})"
            )
        return pk

    @property
    def not_before(self) -> datetime.datetime:
        return self.cert.not_valid_before_utc

    @property
    def not_after(self) -> datetime.datetime:
        return self.cert.not_valid_after_utc

    @property
    def serial_number(self) -> int:
        return self.cert.serial_number


def load_ca_root(
    path: Path,
    *,
    expected_sha256: bytes | None = None,
) -> x509.Certificate:
    """Load and structurally validate a CA root from a PEM file.

    If ``expected_sha256`` is given, verify the file's SHA-256 matches
    it byte-for-byte. This pin defends against an attacker who can
    overwrite the on-disk CA cert: a hash mismatch refuses startup.

    Raises ``CertChainError`` on any failure.
    """
    raw = path.read_bytes()
    if expected_sha256 is not None:
        actual = hashlib.sha256(raw).digest()
        if not hmac.compare_digest(actual, expected_sha256):
            raise CertChainError(
                f"CA root file hash mismatch at {path}: "
                f"expected {expected_sha256.hex()}, got {actual.hex()}"
            )
    try:
        ca = x509.load_pem_x509_certificate(raw)
    except ValueError as e:
        raise CertChainError(
            f"failed to parse CA root at {path}: {e}"
        ) from e
    try:
        bc = ca.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
    except x509.ExtensionNotFound as e:
        raise CertChainError(
            "CA root missing basicConstraints extension"
        ) from e
    if not bc.ca:
        raise CertChainError(
            "CA root must have basicConstraints CA:TRUE"
        )
    return ca


def validate_chain(
    leaf: DeviceCert,
    ca_root: x509.Certificate,
    *,
    now: datetime.datetime | None = None,
    required_eku: x509.ObjectIdentifier | None = None,
) -> None:
    """Validate that ``leaf`` chains to ``ca_root`` and is currently
    valid. Does NOT check CRL or CN policy — caller applies those.

    Raises:
        CertChainError on issuer-mismatch, bad signature, or wrong
            issuer pubkey type.
        CertExpiredError on validity-period failures.
        CertBindingError if the binding extension is missing/malformed.
    """
    if now is None:
        now = datetime.datetime.now(datetime.timezone.utc)

    # 1. Issuer / subject DN match.
    if leaf.cert.issuer != ca_root.subject:
        raise CertChainError(
            "leaf issuer does not match CA subject: "
            f"{leaf.cert.issuer.rfc4514_string()!r} vs "
            f"{ca_root.subject.rfc4514_string()!r}"
        )

    # 2. Signature: cryptography's verify is constant-time on the MAC
    #    comparison; the chain-walk shape (single hop) is fixed here.
    ca_pub = ca_root.public_key()
    if not isinstance(ca_pub, EllipticCurvePublicKey):
        raise CertChainError(
            f"unsupported CA pubkey type {type(ca_pub).__name__}; "
            "only EC CAs are supported"
        )
    sig_alg = leaf.cert.signature_hash_algorithm
    if sig_alg is None:
        raise CertChainError("leaf cert has no signature hash algorithm")
    try:
        ca_pub.verify(
            leaf.cert.signature,
            leaf.cert.tbs_certificate_bytes,
            ECDSA(sig_alg),
        )
    except InvalidSignature as e:
        raise CertChainError(
            "leaf signature does not verify under CA pubkey"
        ) from e

    # 3. Validity window.
    if now < leaf.not_before:
        raise CertExpiredError(
            f"cert not yet valid (not_before={leaf.not_before.isoformat()}, "
            f"now={now.isoformat()})"
        )
    if now > leaf.not_after:
        raise CertExpiredError(
            f"cert expired (not_after={leaf.not_after.isoformat()}, "
            f"now={now.isoformat()})"
        )

    # 4. Required EKU (if asked — server checks clientAuth, client
    #    checks serverAuth; this lets us enforce role separation).
    if required_eku is not None:
        try:
            eku = leaf.cert.extensions.get_extension_for_class(
                x509.ExtendedKeyUsage
            ).value
        except x509.ExtensionNotFound as e:
            raise CertChainError(
                "leaf missing extendedKeyUsage extension"
            ) from e
        if required_eku not in list(eku):
            raise CertChainError(
                f"leaf EKU does not include {required_eku.dotted_string}"
            )

    # 5. Force binding-extension validation; this raises if absent or
    #    malformed, so callers downstream can rely on
    #    ``leaf.noise_static_pub``.
    _ = leaf.noise_static_pub
