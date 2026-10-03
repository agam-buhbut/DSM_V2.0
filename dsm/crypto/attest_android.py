"""Server/CA-side verifier for the Android Key Attestation profile.

This is the **mobile** counterpart to the TPM attestation profile. It is
verified ONCE, at CA-admission / enrollment time, BEFORE the offline CA
issues a DSM device cert for a phone: it proves that the device's ECDSA
P-256 *signing* key (the key that ends up in the DSM device cert's
SubjectPublicKeyInfo, and that signs the per-handshake binding at runtime)
is held in Android hardware (StrongBox / TEE) and is non-extractable.

The proof is an **Android Key Attestation** certificate chain, rooted in
Google's hardware-attestation root:

    leaf (attests the StrongBox key) -> intermediate(s) -> Google root

The leaf carries the Android key-attestation extension (OID
``1.3.6.1.4.1.11129.2.1.17``), a DER ``KeyDescription`` describing the
key's security level and the attestation challenge.

Binding (mirrors the TPM path's two-part binding):

  * the **attested key** (the leaf's SubjectPublicKeyInfo) MUST equal the
    device's DSM signing key being enrolled — so the hardware-backed key
    *is* the DSM signing key, not some unrelated StrongBox key;
  * the **attestation challenge** in the extension MUST equal the device's
    32-byte X25519 Noise static pubkey — so the StrongBox key generation
    was bound to this specific Noise identity (a generic StrongBox key
    cannot be re-pointed at a different identity).

This module is OPT-IN and default-OFF (``allow_android_keystore_attest``).
It does not touch, branch, or weaken the existing TPM / soft verification:
the runtime per-handshake binding (``dsm.crypto.attest.verify_attest_payload``,
ECDSA P-256) is backend-agnostic and unchanged. Fail closed throughout.

Security note: the chain is anchored at a *pinned* Google root (the trust
anchor is operator-provided, never fetched). RSA and EC issuer keys are
both supported (Google's roots/intermediates are historically RSA). Issuer
certs in the chain are required to assert ``basicConstraints CA:TRUE`` so a
genuine end-entity attestation leaf can never be smuggled in as an issuer.
"""

from __future__ import annotations

import datetime
import enum
import hmac
from collections.abc import Collection, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from dsm.crypto.cert import check_strong_signature_hash

if TYPE_CHECKING:
    from dsm.core.config import Config

# Android Key Attestation extension OID (RFC-style dotted form). The leaf
# attestation cert carries a DER ``KeyDescription`` under this OID.
KEY_ATTESTATION_EXTENSION_OID = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")

# DER tags used by the minimal KeyDescription reader below.
_TAG_BOOLEAN = 0x01
_TAG_INTEGER = 0x02
_TAG_OCTET_STRING = 0x04
_TAG_ENUMERATED = 0x0A
_TAG_SEQUENCE = 0x30
_TAG_SET = 0x31

# keymaster ``AuthorizationList`` context-tag numbers + the enum values the
# verifier enforces, read from ``teeEnforced`` ONLY. Without the GENERATED
# origin check an attacker can IMPORT a software-held key into a real TEE/
# StrongBox and pass the security-level gate while still holding the private
# key — so non-extractability must be proven by origin == GENERATED. The key
# must also be authorized to SIGN.
_AUTHZ_TAG_PURPOSE = 1
_AUTHZ_TAG_ORIGIN = 702
_KM_PURPOSE_SIGN = 2
_KM_ORIGIN_GENERATED = 0

# ``rootOfTrust`` ([704] EXPLICIT RootOfTrust) lives in the same teeEnforced
# ``AuthorizationList``. It is only parsed/enforced behind the opt-in
# ``require_locked`` flag; a locked device with a *Verified* boot state is the
# only acceptable state (fail closed on anything else, or on its absence).
_AUTHZ_TAG_ROOT_OF_TRUST = 704
_KM_VERIFIED_BOOT_STATE_VERIFIED = 0


class AndroidSecurityLevel(enum.IntEnum):
    """Android keymaster/keymint ``SecurityLevel`` (ASN.1 ENUMERATED).

    Ordered so a higher value is strictly more secure, which lets the
    minimum-level gate be a simple ``>=`` comparison.
    """

    SOFTWARE = 0
    TRUSTED_ENVIRONMENT = 1  # TEE
    STRONG_BOX = 2  # dedicated secure element


class AndroidAttestError(Exception):
    """Base class for Android Key Attestation verification failures."""


class AndroidAttestProfileDisabledError(AndroidAttestError):
    """The android-keystore profile is not enabled in config; the path is
    refused before any chain work is attempted (fail closed / default off)."""


class AndroidAttestConfigError(AndroidAttestError):
    """The android-keystore profile is enabled but mis-configured (e.g. no
    pinned Google root, or the root file is missing/unparseable)."""


class AndroidAttestChainError(AndroidAttestError):
    """The attestation cert chain is malformed, expired, or a signature /
    issuer link does not verify."""


class AndroidAttestUntrustedRootError(AndroidAttestChainError):
    """The attestation chain does not anchor to the pinned Google
    hardware-attestation root."""


class AndroidAttestRevokedError(AndroidAttestChainError):
    """A cert in the attestation chain (leaf or intermediate) has a serial
    number on the operator-supplied attestation revocation list — e.g. a
    leaked/revoked batch attestation key."""


class AndroidAttestExtensionError(AndroidAttestError):
    """The leaf's key-attestation extension is missing or malformed."""


class AndroidAttestSecurityLevelError(AndroidAttestError):
    """The attested key's security level is below the required minimum
    (e.g. software/TEE when StrongBox is required)."""


class AndroidAttestAuthorizationError(AndroidAttestError):
    """The attested key's hardware-enforced authorizations are unacceptable:
    it was not GENERATED in secure hardware (so it may be an imported,
    extractable key) or it is not authorized to SIGN."""


class AndroidAttestBindingError(AndroidAttestError):
    """The attested key or the attestation challenge does not match the
    device signing key / Noise static being enrolled."""


class AndroidAttestRootOfTrustError(AndroidAttestError):
    """The device's verified-boot state is unacceptable under
    ``require_locked``: the bootloader is unlocked, verified boot is not
    ``Verified``, or the RootOfTrust is absent while the gate demands it."""


@dataclass(frozen=True)
class AndroidKeyAttestation:
    """Result of a successful verification."""

    attestation_security_level: AndroidSecurityLevel
    keymaster_security_level: AndroidSecurityLevel
    attestation_challenge: bytes
    attested_spki_der: bytes


def _spki(cert: x509.Certificate) -> bytes:
    return cert.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )


def _require_ca(cert: x509.Certificate, label: str) -> None:
    """Reject a would-be issuer that is not a CA. Defends against a genuine
    end-entity attestation leaf being smuggled in as an issuer."""
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound as e:
        raise AndroidAttestChainError(
            f"{label} missing basicConstraints; cannot act as a CA issuer"
        ) from e
    if not bc.ca:
        raise AndroidAttestChainError(
            f"{label} is not a CA (basicConstraints CA:FALSE)"
        )


def _check_validity(cert: x509.Certificate, now: datetime.datetime, label: str) -> None:
    if now < cert.not_valid_before_utc:
        raise AndroidAttestChainError(
            f"{label} not yet valid (not_before="
            f"{cert.not_valid_before_utc.isoformat()}, now={now.isoformat()})"
        )
    if now > cert.not_valid_after_utc:
        raise AndroidAttestChainError(
            f"{label} expired (not_after="
            f"{cert.not_valid_after_utc.isoformat()}, now={now.isoformat()})"
        )


def _verify_link(child: x509.Certificate, issuer: x509.Certificate) -> None:
    """Verify ``child`` is validly signed by ``issuer`` (a CA), supporting
    both EC and RSA issuer keys."""
    if child.issuer != issuer.subject:
        raise AndroidAttestChainError(
            "issuer/subject DN mismatch: "
            f"{child.issuer.rfc4514_string()!r} vs "
            f"{issuer.subject.rfc4514_string()!r}"
        )
    _require_ca(issuer, "attestation issuer cert")
    sig_alg = child.signature_hash_algorithm
    if sig_alg is None:
        raise AndroidAttestChainError("attestation cert has no signature hash")
    check_strong_signature_hash(
        sig_alg, "attestation cert", exc_cls=AndroidAttestChainError
    )
    issuer_pub = issuer.public_key()
    try:
        if isinstance(issuer_pub, EllipticCurvePublicKey):
            issuer_pub.verify(
                child.signature, child.tbs_certificate_bytes, ECDSA(sig_alg)
            )
        elif isinstance(issuer_pub, RSAPublicKey):
            # Android attestation chains use RSASSA-PKCS1-v1_5.
            issuer_pub.verify(
                child.signature,
                child.tbs_certificate_bytes,
                padding.PKCS1v15(),
                sig_alg,
            )
        else:
            raise AndroidAttestChainError(
                f"unsupported issuer key type {type(issuer_pub).__name__}; "
                "only EC and RSA attestation issuers are supported"
            )
    except InvalidSignature as e:
        raise AndroidAttestChainError(
            "attestation cert signature does not verify under issuer pubkey"
        ) from e


def _read_der_tlv(data: bytes, offset: int) -> tuple[int, int, int]:
    """Read one DER TLV at ``offset``; return ``(tag, content_start,
    content_end)``. Strict: definite-length only, no truncation."""
    if offset + 2 > len(data):
        raise AndroidAttestExtensionError("truncated DER TLV header")
    tag = data[offset]
    length_byte = data[offset + 1]
    if length_byte < 0x80:
        content_start = offset + 2
        content_len = length_byte
    elif length_byte == 0x80:
        raise AndroidAttestExtensionError("indefinite-length DER is not allowed")
    else:
        num = length_byte & 0x7F
        if num > 4:
            raise AndroidAttestExtensionError("DER length field too large")
        if offset + 2 + num > len(data):
            raise AndroidAttestExtensionError("truncated DER long-form length")
        content_len = int.from_bytes(data[offset + 2 : offset + 2 + num], "big")
        content_start = offset + 2 + num
    content_end = content_start + content_len
    if content_end > len(data):
        raise AndroidAttestExtensionError("DER TLV content overruns buffer")
    return tag, content_start, content_end


def _read_der_len(data: bytes, offset: int) -> tuple[int, int]:
    """Read a DER definite length at ``offset`` (just past a tag); return
    ``(content_start, content_end)``. Strict: definite-length only."""
    if offset >= len(data):
        raise AndroidAttestExtensionError("truncated DER length")
    length_byte = data[offset]
    if length_byte < 0x80:
        content_start = offset + 1
        content_len = length_byte
    elif length_byte == 0x80:
        raise AndroidAttestExtensionError("indefinite-length DER is not allowed")
    else:
        num = length_byte & 0x7F
        if num > 4:
            raise AndroidAttestExtensionError("DER length field too large")
        if offset + 1 + num > len(data):
            raise AndroidAttestExtensionError("truncated DER long-form length")
        content_len = int.from_bytes(data[offset + 1 : offset + 1 + num], "big")
        content_start = offset + 1 + num
    content_end = content_start + content_len
    if content_end > len(data):
        raise AndroidAttestExtensionError("DER TLV content overruns buffer")
    return content_start, content_end


def _read_context_tlv(data: bytes, offset: int) -> tuple[int, int, int]:
    """Read one context-class TLV (possibly a multi-byte high tag number) at
    ``offset``; return ``(tag_number, content_start, content_end)``. Used to
    walk an ``AuthorizationList`` (``purpose [1]``, ``origin [702]``, …).
    Strict + bounded against a hostile, attacker-supplied leaf."""
    if offset >= len(data):
        raise AndroidAttestExtensionError("truncated AuthorizationList field")
    first = data[offset]
    if first & 0xC0 != 0x80:
        raise AndroidAttestExtensionError(
            "expected a context-class tag in AuthorizationList"
        )
    if first & 0x1F != 0x1F:
        tag_number = first & 0x1F
        len_off = offset + 1
    else:
        tag_number = 0
        i = offset + 1
        read = 0
        while True:
            if i >= len(data) or read >= 4:
                raise AndroidAttestExtensionError("malformed/over-long context tag")
            byte = data[i]
            tag_number = (tag_number << 7) | (byte & 0x7F)
            i += 1
            read += 1
            if not byte & 0x80:
                break
        len_off = i
    content_start, content_end = _read_der_len(data, len_off)
    return tag_number, content_start, content_end


def _parse_int_value(data: bytes, start: int, end: int) -> int:
    """Decode a small non-negative DER INTEGER body to ``int``."""
    content = data[start:end]
    if not content or len(content) > 8:
        raise AndroidAttestExtensionError(
            f"malformed AuthorizationList INTEGER ({len(content)} bytes)"
        )
    return int.from_bytes(content, "big")


def _parse_authorization_list(
    content: bytes,
) -> tuple[frozenset[int], int | None, bytes | None]:
    """Extract ``purpose`` (tag [1], SET OF INTEGER), ``origin`` (tag [702],
    INTEGER), and the raw ``rootOfTrust`` (tag [704] EXPLICIT, a SEQUENCE) from
    the *content* of a keymaster ``AuthorizationList`` SEQUENCE (the
    concatenated context-tagged fields, as returned for ``teeEnforced``).
    Returns ``(purposes, origin, root_of_trust_der)`` (``origin`` /
    ``root_of_trust_der`` are ``None`` if absent); every other field is
    skipped. Bounded — the leaf is attacker-controlled."""
    purposes: set[int] = set()
    origin: int | None = None
    root_of_trust: bytes | None = None
    pos = 0
    end = len(content)
    guard = 0
    while pos < end:
        guard += 1
        if guard > 128:  # ~50 defined tags; cap well above to reject a flood
            raise AndroidAttestExtensionError("AuthorizationList field count too high")
        tag_number, cstart, cend = _read_context_tlv(content, pos)
        if tag_number == _AUTHZ_TAG_PURPOSE:
            set_tag, set_start, set_end = _read_der_tlv(content, cstart)
            if set_tag != _TAG_SET:
                raise AndroidAttestExtensionError("purpose is not a SET")
            ipos = set_start
            iguard = 0
            while ipos < set_end:
                iguard += 1
                if iguard > 32:
                    raise AndroidAttestExtensionError("purpose SET too large")
                int_tag, int_start, int_end = _read_der_tlv(content, ipos)
                if int_tag != _TAG_INTEGER:
                    raise AndroidAttestExtensionError("purpose entry is not an INTEGER")
                purposes.add(_parse_int_value(content, int_start, int_end))
                ipos = int_end
        elif tag_number == _AUTHZ_TAG_ORIGIN:
            int_tag, int_start, int_end = _read_der_tlv(content, cstart)
            if int_tag != _TAG_INTEGER:
                raise AndroidAttestExtensionError("origin is not an INTEGER")
            origin = _parse_int_value(content, int_start, int_end)
        elif tag_number == _AUTHZ_TAG_ROOT_OF_TRUST:
            # [704] is EXPLICIT, so its content is the RootOfTrust SEQUENCE
            # itself. Captured raw here; only decoded under ``require_locked``.
            root_of_trust = content[cstart:cend]
        pos = cend
    return frozenset(purposes), origin, root_of_trust


def _parse_root_of_trust(der: bytes) -> tuple[bool, int]:
    """Parse a keymaster ``RootOfTrust`` SEQUENCE (the content of the
    teeEnforced ``rootOfTrust [704]`` field). Returns ``(device_locked,
    verified_boot_state)``; trailing/optional fields are skipped. Strict and
    bounded — the leaf is attacker-controlled.

    ::

        RootOfTrust ::= SEQUENCE {
            verifiedBootKey     OCTET_STRING,
            deviceLocked        BOOLEAN,
            verifiedBootState   ENUMERATED,
            verifiedBootHash    OCTET_STRING OPTIONAL,  -- KeyMint (KM4+)
        }
    """
    tag, start, end = _read_der_tlv(der, 0)
    if tag != _TAG_SEQUENCE:
        raise AndroidAttestExtensionError("RootOfTrust is not a SEQUENCE")

    pos = start
    # verifiedBootKey OCTET STRING — skipped (opaque to this verifier).
    if pos >= end:
        raise AndroidAttestExtensionError("RootOfTrust truncated at verifiedBootKey")
    t, _s, e = _read_der_tlv(der, pos)
    if t != _TAG_OCTET_STRING:
        raise AndroidAttestExtensionError(
            "RootOfTrust.verifiedBootKey is not an OCTET STRING"
        )
    pos = e

    # deviceLocked BOOLEAN — DER encodes TRUE as 0xFF; anything else fails
    # closed (treated as not-locked) so require_locked rejects it.
    if pos >= end:
        raise AndroidAttestExtensionError("RootOfTrust truncated at deviceLocked")
    t, s, e = _read_der_tlv(der, pos)
    if t != _TAG_BOOLEAN:
        raise AndroidAttestExtensionError("RootOfTrust.deviceLocked is not a BOOLEAN")
    body = der[s:e]
    if len(body) != 1:
        raise AndroidAttestExtensionError("RootOfTrust.deviceLocked is malformed")
    device_locked = body[0] == 0xFF
    pos = e

    # verifiedBootState ENUMERATED.
    if pos >= end:
        raise AndroidAttestExtensionError("RootOfTrust truncated at verifiedBootState")
    t, s, e = _read_der_tlv(der, pos)
    if t != _TAG_ENUMERATED:
        raise AndroidAttestExtensionError(
            "RootOfTrust.verifiedBootState is not an ENUMERATED"
        )
    verified_boot_state = _enum_to_int(der[s:e])
    return device_locked, verified_boot_state


def _enum_to_int(content: bytes) -> int:
    if not content or len(content) > 4:
        raise AndroidAttestExtensionError(
            f"malformed ENUMERATED ({len(content)} bytes)"
        )
    return int.from_bytes(content, "big")


def _to_level(value: int, field_name: str) -> AndroidSecurityLevel:
    try:
        return AndroidSecurityLevel(value)
    except ValueError as e:
        raise AndroidAttestExtensionError(
            f"{field_name} has unknown SecurityLevel value {value}"
        ) from e


def _parse_key_description(der: bytes) -> tuple[int, int, bytes, bytes]:
    """Parse a ``KeyDescription`` SEQUENCE.

    Returns ``(attestation_security_level, keymaster_security_level,
    attestation_challenge, tee_enforced_der)``. The KeyDescription is::

        attestationVersion         INTEGER
        attestationSecurityLevel   ENUMERATED
        keymasterVersion           INTEGER
        keymasterSecurityLevel     ENUMERATED
        attestationChallenge       OCTET STRING
        uniqueId                   OCTET STRING
        softwareEnforced           AuthorizationList (SEQUENCE) — skipped
        teeEnforced                AuthorizationList (SEQUENCE) — returned

    ``softwareEnforced`` is asserted by the (rootable) OS, so the
    trust-relevant authorizations are read by the caller from ``teeEnforced``.
    """
    tag, start, end = _read_der_tlv(der, 0)
    if tag != _TAG_SEQUENCE:
        raise AndroidAttestExtensionError("KeyDescription is not a SEQUENCE")
    if end != len(der):
        raise AndroidAttestExtensionError("trailing bytes after KeyDescription")

    pos = start

    def _next(expected_tag: int, name: str) -> bytes:
        nonlocal pos
        if pos >= end:
            raise AndroidAttestExtensionError(f"KeyDescription truncated at {name}")
        t, s, e = _read_der_tlv(der, pos)
        if t != expected_tag:
            raise AndroidAttestExtensionError(
                f"{name}: expected DER tag {expected_tag:#x}, got {t:#x}"
            )
        pos = e
        return der[s:e]

    _next(_TAG_INTEGER, "attestationVersion")
    asl = _enum_to_int(_next(_TAG_ENUMERATED, "attestationSecurityLevel"))
    _next(_TAG_INTEGER, "keymasterVersion")
    ksl = _enum_to_int(_next(_TAG_ENUMERATED, "keymasterSecurityLevel"))
    challenge = _next(_TAG_OCTET_STRING, "attestationChallenge")
    _next(_TAG_OCTET_STRING, "uniqueId")
    _next(_TAG_SEQUENCE, "softwareEnforced")
    tee_enforced = _next(_TAG_SEQUENCE, "teeEnforced")
    return asl, ksl, challenge, tee_enforced


def _extract_key_description(leaf: x509.Certificate) -> bytes:
    try:
        ext = leaf.extensions.get_extension_for_oid(KEY_ATTESTATION_EXTENSION_OID)
    except x509.ExtensionNotFound as e:
        raise AndroidAttestExtensionError(
            "leaf cert missing the Android key-attestation extension "
            f"({KEY_ATTESTATION_EXTENSION_OID.dotted_string})"
        ) from e
    value = ext.value
    if not isinstance(value, x509.UnrecognizedExtension):
        raise AndroidAttestExtensionError(
            f"unexpected key-attestation extension type: {type(value).__name__}"
        )
    return value.value


def verify_android_key_attestation(
    *,
    attestation_chain_der: Sequence[bytes],
    google_root: x509.Certificate,
    expected_attested_spki_der: bytes,
    expected_challenge: bytes,
    min_security_level: AndroidSecurityLevel = AndroidSecurityLevel.STRONG_BOX,
    now: datetime.datetime | None = None,
    revoked_serials: Collection[int] | None = None,
    require_locked: bool = False,
) -> AndroidKeyAttestation:
    """Verify an Android Key Attestation chain and its binding.

    ``attestation_chain_der`` is leaf-first (``[leaf, intermediate(s), ...]``)
    and MAY or MAY NOT include the pinned root as its last element. The chain
    is anchored to ``google_root`` (the pinned trust anchor), never to a root
    discovered from the chain itself.

    ``revoked_serials`` is an OPTIONAL operator-provided, offline, pinned set
    of revoked integer serial numbers (mirroring the DSM CRL model): if given,
    any chain cert (leaf or intermediate) whose serial is present is rejected —
    e.g. a leaked/revoked batch attestation key. ``None`` (the default) skips
    the check entirely, so existing callers are unaffected.

    ``require_locked`` (default ``False``) additionally decodes the teeEnforced
    ``RootOfTrust`` and demands a locked bootloader (``deviceLocked == True``)
    and a ``Verified`` boot state. Off by default; a missing RootOfTrust while
    the gate is on is rejected (fail closed).

    Verification order (all must pass; fail closed):
      1. parse every cert in the provided chain;
      2. if ``revoked_serials`` is given, no chain cert's serial is revoked;
      3. every cert (and the pinned root) is within its validity window;
      4. internal links verify (``chain[i]`` signed by ``chain[i+1]``, the
         issuer being a CA), EC or RSA;
      5. the top of the chain anchors to the pinned root (identity, or a
         valid signature by it);
      6. the leaf carries a well-formed key-attestation extension;
      7. both attestation- and keymaster-SecurityLevel are
         ``>= min_security_level``, and the teeEnforced authorizations
         require ``origin == GENERATED`` and ``purpose`` ⊇ SIGN;
      8. if ``require_locked``, the teeEnforced RootOfTrust reports a locked
         device with a Verified boot state;
      9. the attested key (leaf SPKI) equals ``expected_attested_spki_der``;
     10. the attestation challenge equals ``expected_challenge``.

    Returns the parsed :class:`AndroidKeyAttestation` on success.

    Raises:
        AndroidAttestChainError / AndroidAttestUntrustedRootError on chain
            structure, validity, signature, or anchoring failures.
        AndroidAttestRevokedError if a chain cert's serial is revoked.
        AndroidAttestExtensionError on a missing/malformed extension.
        AndroidAttestSecurityLevelError if below the required level.
        AndroidAttestAuthorizationError if not GENERATED / not SIGN-capable.
        AndroidAttestRootOfTrustError if ``require_locked`` and the device is
            unlocked / not Verified / has no RootOfTrust.
        AndroidAttestBindingError on key / challenge mismatch.
    """
    if now is None:
        now = datetime.datetime.now(datetime.UTC)
    if not attestation_chain_der:
        raise AndroidAttestChainError("attestation chain is empty")

    chain: list[x509.Certificate] = []
    for i, der in enumerate(attestation_chain_der):
        try:
            chain.append(x509.load_der_x509_certificate(bytes(der)))
        except ValueError as e:
            raise AndroidAttestChainError(
                f"failed to parse attestation cert #{i}: {e}"
            ) from e

    # Optional operator-supplied revocation check (mirrors the DSM CRL model:
    # a pinned, offline set of revoked integer serials). Fail closed early if
    # any provided chain cert (leaf or intermediate) is on it. ``None`` skips
    # the check, leaving behavior unchanged for existing callers.
    if revoked_serials is not None:
        revoked = frozenset(revoked_serials)
        for i, cert in enumerate(chain):
            if cert.serial_number in revoked:
                raise AndroidAttestRevokedError(
                    f"attestation cert #{i} serial {cert.serial_number:#x} is on "
                    "the operator-supplied attestation revocation list"
                )

    # The pinned root must itself be a CA and currently valid.
    _require_ca(google_root, "pinned Google attestation root")
    _check_validity(google_root, now, "pinned Google attestation root")

    for i, cert in enumerate(chain):
        _check_validity(cert, now, f"attestation cert #{i}")

    for i in range(len(chain) - 1):
        _verify_link(chain[i], chain[i + 1])

    # Anchor the top of the provided chain to the pinned root.
    top = chain[-1]
    same_key = hmac.compare_digest(_spki(top), _spki(google_root))
    if same_key and top.subject == google_root.subject:
        pass  # the chain explicitly terminates at the pinned root
    else:
        if top.issuer != google_root.subject:
            raise AndroidAttestUntrustedRootError(
                "attestation chain does not anchor to the pinned Google "
                "hardware-attestation root"
            )
        try:
            _verify_link(top, google_root)
        except AndroidAttestChainError as e:
            raise AndroidAttestUntrustedRootError(
                f"attestation chain top not validly signed by pinned root: {e}"
            ) from e

    leaf = chain[0]

    # Extension + hardware security level.
    key_desc_der = _extract_key_description(leaf)
    asl_int, ksl_int, challenge, tee_enforced = _parse_key_description(key_desc_der)
    asl = _to_level(asl_int, "attestationSecurityLevel")
    ksl = _to_level(ksl_int, "keymasterSecurityLevel")
    if asl < min_security_level or ksl < min_security_level:
        raise AndroidAttestSecurityLevelError(
            f"attested key security level too low: attestation={asl.name}, "
            f"keymaster={ksl.name}, required >= {min_security_level.name}"
        )

    # Hardware-enforced authorizations (read from teeEnforced ONLY —
    # softwareEnforced is asserted by the rootable OS, not the secure
    # environment). The key MUST have been GENERATED in secure hardware (an
    # imported key's private half is attacker-held, defeating non-
    # extractability) and MUST be authorized to SIGN.
    purposes, origin, root_of_trust_der = _parse_authorization_list(tee_enforced)
    if origin != _KM_ORIGIN_GENERATED:
        raise AndroidAttestAuthorizationError(
            f"attested key origin is not GENERATED (got {origin}); the key was "
            "not generated inside the secure hardware and may be extractable"
        )
    if _KM_PURPOSE_SIGN not in purposes:
        raise AndroidAttestAuthorizationError(
            "attested key is not authorized to SIGN "
            f"(teeEnforced purposes={sorted(purposes)})"
        )

    # Optional verified-boot / bootloader-lock gate (opt-in via require_locked
    # so existing callers/tests are unaffected). Fail closed: a missing
    # RootOfTrust cannot prove the device is locked, so it is rejected.
    if require_locked:
        if root_of_trust_der is None:
            raise AndroidAttestRootOfTrustError(
                "require_locked is set but teeEnforced carries no RootOfTrust "
                "(tag 704); cannot prove the device is locked / verified-boot"
            )
        device_locked, verified_boot_state = _parse_root_of_trust(root_of_trust_der)
        if not device_locked:
            raise AndroidAttestRootOfTrustError(
                "device bootloader is not locked (RootOfTrust.deviceLocked is false)"
            )
        if verified_boot_state != _KM_VERIFIED_BOOT_STATE_VERIFIED:
            raise AndroidAttestRootOfTrustError(
                "verified boot state is not Verified "
                f"(RootOfTrust.verifiedBootState={verified_boot_state})"
            )

    # Bind to the device's DSM signing key (the leaf's attested key).
    leaf_spki = _spki(leaf)
    if not hmac.compare_digest(leaf_spki, bytes(expected_attested_spki_der)):
        raise AndroidAttestBindingError(
            "attested key (leaf SubjectPublicKeyInfo) does not match the "
            "device signing key being enrolled"
        )

    # Bind to the Noise static via the attestation challenge.
    if not hmac.compare_digest(challenge, bytes(expected_challenge)):
        raise AndroidAttestBindingError(
            "attestation challenge does not match the expected Noise-static binding"
        )

    return AndroidKeyAttestation(
        attestation_security_level=asl,
        keymaster_security_level=ksl,
        attestation_challenge=challenge,
        attested_spki_der=leaf_spki,
    )


def _level_from_config(name: str) -> AndroidSecurityLevel:
    if name == "strongbox":
        return AndroidSecurityLevel.STRONG_BOX
    if name == "tee":
        return AndroidSecurityLevel.TRUSTED_ENVIRONMENT
    raise AndroidAttestConfigError(
        f"android_attest_min_security_level must be 'tee' or 'strongbox', "
        f"got {name!r}"
    )


def verify_mobile_enrollment(
    *,
    attestation_chain_der: Sequence[bytes],
    expected_attested_spki_der: bytes,
    expected_noise_static: bytes,
    config: Config,
    now: datetime.datetime | None = None,
) -> AndroidKeyAttestation:
    """Opt-in, config-gated CA-admission entry point for a mobile device.

    This is THE integration point: the offline CA / enrollment-admission
    step calls it before issuing a DSM device cert to a phone. It refuses
    (without touching the chain) unless ``allow_android_keystore_attest`` is
    set, then verifies the Android Key Attestation chain against the pinned
    Google root and binds it to the device signing key + the Noise static.

    The 32-byte X25519 Noise static pubkey is used directly as the expected
    attestation challenge: the Android app sets it via
    ``setAttestationChallenge`` at StrongBox key generation, tying the
    hardware key to this Noise identity.

    Raises:
        AndroidAttestProfileDisabledError if the profile is not enabled
            (default).
        AndroidAttestConfigError if enabled but the pinned root is missing
            or unparseable.
        the verification errors from :func:`verify_android_key_attestation`.
    """
    if not config.allow_android_keystore_attest:
        raise AndroidAttestProfileDisabledError(
            "android-keystore attestation profile is disabled "
            "(allow_android_keystore_attest=false); refusing to verify a "
            "mobile enrollment"
        )
    if not config.android_attest_root_file:
        raise AndroidAttestConfigError(
            "allow_android_keystore_attest=true but android_attest_root_file "
            "is not set; cannot pin the Google hardware-attestation root"
        )
    root_path = Path(config.android_attest_root_file)
    if not root_path.is_file():
        raise AndroidAttestConfigError(
            f"android_attest_root_file not found: {root_path}"
        )
    try:
        google_root = x509.load_pem_x509_certificate(root_path.read_bytes())
    except ValueError as e:
        raise AndroidAttestConfigError(
            f"failed to parse android_attest_root_file at {root_path}: {e}"
        ) from e

    min_level = _level_from_config(config.android_attest_min_security_level)
    return verify_android_key_attestation(
        attestation_chain_der=attestation_chain_der,
        google_root=google_root,
        expected_attested_spki_der=expected_attested_spki_der,
        expected_challenge=expected_noise_static,
        min_security_level=min_level,
        now=now,
    )


__all__ = [
    "KEY_ATTESTATION_EXTENSION_OID",
    "AndroidAttestBindingError",
    "AndroidAttestChainError",
    "AndroidAttestConfigError",
    "AndroidAttestError",
    "AndroidAttestExtensionError",
    "AndroidAttestProfileDisabledError",
    "AndroidAttestRevokedError",
    "AndroidAttestRootOfTrustError",
    "AndroidAttestSecurityLevelError",
    "AndroidAttestUntrustedRootError",
    "AndroidKeyAttestation",
    "AndroidSecurityLevel",
    "verify_android_key_attestation",
    "verify_mobile_enrollment",
]
