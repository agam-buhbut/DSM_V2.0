"""Test-only builders for SYNTHETIC Android Key Attestation chains.

Builds a fake "Google hardware-attestation" hierarchy entirely offline:
``root (CA) -> intermediate (CA) -> leaf (attests a StrongBox key)``. The
leaf carries a hand-encoded ``KeyDescription`` under the real key-attestation
extension OID. No network, no real Google root. Kept in ``tests/`` so the
runtime never ships CA-issuing code.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import NameOID

from dsm.crypto.attest_android import KEY_ATTESTATION_EXTENSION_OID

# ── Minimal DER encoders (mirror the hand-rolled DER style in enroll.py) ──


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(content)) + content


def _der_int(value: int) -> bytes:
    if value < 0:
        raise ValueError("only non-negative INTEGERs are needed here")
    if value == 0:
        body = b"\x00"
    else:
        body = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if body[0] & 0x80:  # keep it positive
            body = b"\x00" + body
    return _tlv(0x02, body)


def _der_enum(value: int) -> bytes:
    return _tlv(0x0A, bytes([value]))


def _der_bool(value: bool) -> bytes:
    # DER BOOLEAN: TRUE must be 0xFF, FALSE is 0x00.
    return _tlv(0x01, b"\xff" if value else b"\x00")


def _der_octet(value: bytes) -> bytes:
    return _tlv(0x04, value)


def _der_seq(*parts: bytes) -> bytes:
    return _tlv(0x30, b"".join(parts))


def _der_ctx_explicit(tag_bytes: bytes, content: bytes) -> bytes:
    """Wrap ``content`` in a context-class EXPLICIT tag (raw tag bytes)."""
    return tag_bytes + _der_len(len(content)) + content


def _build_root_of_trust(device_locked: bool, verified_boot_state: int) -> bytes:
    """A keymaster ``RootOfTrust`` SEQUENCE (verifiedBootKey, deviceLocked,
    verifiedBootState, verifiedBootHash). Boot key/hash are opaque fillers."""
    return _der_seq(
        _der_octet(b"\x00" * 32),  # verifiedBootKey
        _der_bool(device_locked),  # deviceLocked
        _der_enum(verified_boot_state),  # verifiedBootState (0=Verified)
        _der_octet(b"\x00" * 32),  # verifiedBootHash (KeyMint)
    )


def _build_authorization_list(
    purposes: tuple[int, ...],
    origin: int | None,
    root_of_trust: tuple[bool, int] | None = None,
) -> bytes:
    """A keymaster ``AuthorizationList`` carrying ``purpose`` ([1]), ``origin``
    ([702]) and optionally ``rootOfTrust`` ([704]) — the fields the verifier
    reads. Emitted in ascending tag order, as DER requires."""
    fields: list[bytes] = []
    if purposes:  # purpose [1] EXPLICIT SET OF INTEGER
        purpose_set = _tlv(0x31, b"".join(_der_int(p) for p in purposes))
        fields.append(_der_ctx_explicit(b"\xa1", purpose_set))
    if origin is not None:  # origin [702] EXPLICIT INTEGER (tag 0xBF 0x85 0x3E)
        fields.append(_der_ctx_explicit(b"\xbf\x85\x3e", _der_int(origin)))
    if root_of_trust is not None:  # rootOfTrust [704] EXPLICIT (tag 0xBF 0x85 0x40)
        device_locked, verified_boot_state = root_of_trust
        rot = _build_root_of_trust(device_locked, verified_boot_state)
        fields.append(_der_ctx_explicit(b"\xbf\x85\x40", rot))
    return _der_seq(*fields)


def build_key_description(
    *,
    challenge: bytes,
    attestation_security_level: int = 2,
    keymaster_security_level: int = 2,
    attestation_version: int = 200,
    keymaster_version: int = 300,
    tee_purposes: tuple[int, ...] = (2,),  # KM_PURPOSE_SIGN
    tee_origin: int | None = 0,  # KM_ORIGIN_GENERATED
    tee_root_of_trust: tuple[bool, int] | None = None,  # (deviceLocked, vbState)
) -> bytes:
    """DER-encode a full ``KeyDescription`` the verifier reads.

    Security levels: 0=Software, 1=TrustedEnvironment, 2=StrongBox.
    ``softwareEnforced`` is left empty; the trust-relevant ``purpose`` and
    ``origin`` go in ``teeEnforced`` (the verifier reads them from there only).
    ``tee_origin=None`` omits origin; an empty ``tee_purposes`` omits purpose.
    ``tee_root_of_trust=None`` (default) omits rootOfTrust entirely; pass
    ``(device_locked, verified_boot_state)`` to include it (0=Verified).
    """
    return _der_seq(
        _der_int(attestation_version),
        _der_enum(attestation_security_level),
        _der_int(keymaster_version),
        _der_enum(keymaster_security_level),
        _der_octet(challenge),
        _der_octet(b""),  # uniqueId
        _der_seq(),  # softwareEnforced (empty; authz that matter are tee)
        _build_authorization_list(
            tee_purposes, tee_origin, tee_root_of_trust
        ),  # teeEnforced
    )


# ── Synthetic cert hierarchy ──────────────────────────────────────────────


@dataclass(frozen=True)
class SyntheticCA:
    private_key: CertificateIssuerPrivateKeyTypes
    certificate: x509.Certificate

    @property
    def der(self) -> bytes:
        return self.certificate.public_bytes(Encoding.DER)


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC) - datetime.timedelta(seconds=60)


def _gen_key(use_rsa: bool) -> CertificateIssuerPrivateKeyTypes:
    if use_rsa:
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return ec.generate_private_key(ec.SECP384R1())


def make_attestation_root(
    *,
    use_rsa: bool = False,
    common_name: str = "Synthetic Google HW Attestation Root",
    validity_years: int = 20,
) -> SyntheticCA:
    priv = _gen_key(use_rsa)
    start = _now()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(start + datetime.timedelta(days=365 * validity_years))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key=priv, algorithm=hashes.SHA256())
    )
    return SyntheticCA(private_key=priv, certificate=cert)


def make_attestation_intermediate(
    parent: SyntheticCA,
    *,
    use_rsa: bool = False,
    common_name: str = "Synthetic HW Attestation Intermediate",
) -> SyntheticCA:
    priv = _gen_key(use_rsa)
    start = _now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(parent.certificate.subject)
        .public_key(priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(start + datetime.timedelta(days=365 * 10))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key=parent.private_key, algorithm=hashes.SHA256())
    )
    return SyntheticCA(private_key=priv, certificate=cert)


def make_attestation_leaf(
    issuer: SyntheticCA,
    *,
    attested_public_key: ec.EllipticCurvePublicKey,
    key_description_der: bytes,
    common_name: str = "Android Keystore Key",
) -> x509.Certificate:
    start = _now()
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(issuer.certificate.subject)
        .public_key(attested_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(start + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.UnrecognizedExtension(
                KEY_ATTESTATION_EXTENSION_OID, key_description_der
            ),
            critical=False,
        )
        .sign(private_key=issuer.private_key, algorithm=hashes.SHA256())
    )


@dataclass(frozen=True)
class SyntheticChain:
    chain_der: list[bytes]  # leaf-first
    root: SyntheticCA
    intermediate: SyntheticCA
    leaf: x509.Certificate
    attested_priv: ec.EllipticCurvePrivateKey

    @property
    def attested_spki_der(self) -> bytes:
        return self.attested_priv.public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )


def make_synthetic_chain(
    *,
    challenge: bytes,
    attestation_security_level: int = 2,
    keymaster_security_level: int = 2,
    use_rsa_root: bool = False,
    include_root_in_chain: bool = False,
    root: SyntheticCA | None = None,
    attested_priv: ec.EllipticCurvePrivateKey | None = None,
    tee_purposes: tuple[int, ...] = (2,),  # KM_PURPOSE_SIGN
    tee_origin: int | None = 0,  # KM_ORIGIN_GENERATED
    tee_root_of_trust: tuple[bool, int] | None = None,  # (deviceLocked, vbState)
) -> SyntheticChain:
    """Build a full synthetic attestation chain for one StrongBox key.

    The attested (leaf) key is an EC P-256 private key — the same shape as the
    DSM device signing key. Returns the leaf-first DER chain plus the pieces a
    test needs to drive / pin the verifier. ``tee_root_of_trust`` (default
    ``None``) omits the teeEnforced RootOfTrust; pass ``(device_locked,
    verified_boot_state)`` to include it.
    """
    if root is None:
        root = make_attestation_root(use_rsa=use_rsa_root)
    intermediate = make_attestation_intermediate(root, use_rsa=use_rsa_root)
    if attested_priv is None:
        attested_priv = ec.generate_private_key(ec.SECP256R1())
    key_desc = build_key_description(
        challenge=challenge,
        attestation_security_level=attestation_security_level,
        keymaster_security_level=keymaster_security_level,
        tee_purposes=tee_purposes,
        tee_origin=tee_origin,
        tee_root_of_trust=tee_root_of_trust,
    )
    leaf = make_attestation_leaf(
        intermediate,
        attested_public_key=attested_priv.public_key(),
        key_description_der=key_desc,
    )
    chain_der = [leaf.public_bytes(Encoding.DER), intermediate.der]
    if include_root_in_chain:
        chain_der.append(root.der)
    return SyntheticChain(
        chain_der=chain_der,
        root=root,
        intermediate=intermediate,
        leaf=leaf,
        attested_priv=attested_priv,
    )
