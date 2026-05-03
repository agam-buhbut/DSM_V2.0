"""Per-handshake binding-attestation payload for DSM auth.

Each side of the Noise XX handshake carries an attestation payload in
its msg2 / msg3 slot. The payload contains:

  * the device cert (CA-signed, binds CN + ECDSA signing pubkey + the
    device's X25519 Noise static pubkey via a critical extension)
  * an ECDSA signature, produced by the hardware-bound signing key,
    over a domain-separated binding pre-image that includes the
    Noise handshake hash captured at the point this message is sent.

The signature is freshness-bound to the handshake (the hash is
unique-per-handshake) and role-bound (the signed pre-image includes
the signer's role byte), so a captured payload cannot be replayed
into another handshake or against the opposite-role counterparty.

Wire framing inside ``tuncore.HANDSHAKE_ATTEST_PAYLOAD_SIZE`` bytes:

    cert_len(2 BE) || cert_der || sig_len(2 BE) || sig_der || random_pad

Signed binding pre-image (86 bytes total):

    "DSM-BIND-v1\\x00" (12)
    || version(1)               -- always 0x01 for v1
    || timestamp(8 BE)          -- seconds since Unix epoch, UTC
    || handshake_hash(32)       -- SHA-256-domain output from Snow
    || noise_static_pub(32)     -- signer's X25519 static pub
    || peer_role(1)             -- 0 initiator, 1 responder
"""

from __future__ import annotations

import datetime
import enum
import os
import struct

import tuncore
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.x509 import ObjectIdentifier
from cryptography.x509 import Certificate as X509Certificate

from dsm.crypto.cert import (
    NOISE_STATIC_PUB_LEN,
    CertBindingError,
    CertChainError,
    CertError,
    CertExpiredError,
    DeviceCert,
    validate_chain,
)

BINDING_DOMAIN = b"DSM-BIND-v1\x00"
BINDING_VERSION = 0x01
HANDSHAKE_HASH_LEN = 32

# Signed pre-image: 12 (domain) + 1 (version) + 8 (ts) + 32 (h) + 32 (s) + 1 (role) = 86.
_BINDING_PRE_IMAGE_LEN = (
    len(BINDING_DOMAIN) + 1 + 8 + HANDSHAKE_HASH_LEN + NOISE_STATIC_PUB_LEN + 1
)

DEFAULT_CLOCK_SKEW = datetime.timedelta(seconds=300)


class PeerRole(enum.IntEnum):
    """Which side of the handshake produced a given signature."""

    INITIATOR = 0  # client
    RESPONDER = 1  # server


class AttestError(Exception):
    """Base class for attest-payload failures."""


class AttestPayloadFormatError(AttestError):
    """Wire framing inside the attest payload is malformed."""


class AttestSignatureError(AttestError):
    """The binding signature did not verify under the cert's pubkey."""


class AttestBindingMismatchError(AttestError):
    """Cert's noise_static_pub, signed binding's noise_static_pub, and
    the static recovered from Noise do not agree (or role mismatch)."""


class AttestTimestampError(AttestError):
    """The signed timestamp is outside the allowed clock-skew window."""


def _binding_pre_image(
    *,
    timestamp: int,
    handshake_hash: bytes,
    noise_static_pub: bytes,
    role: PeerRole,
) -> bytes:
    if len(handshake_hash) != HANDSHAKE_HASH_LEN:
        raise ValueError(
            f"handshake_hash must be {HANDSHAKE_HASH_LEN} bytes, got {len(handshake_hash)}"
        )
    if len(noise_static_pub) != NOISE_STATIC_PUB_LEN:
        raise ValueError(
            f"noise_static_pub must be {NOISE_STATIC_PUB_LEN} bytes, got {len(noise_static_pub)}"
        )
    return (
        BINDING_DOMAIN
        + struct.pack(">B", BINDING_VERSION)
        + struct.pack(">Q", timestamp)
        + bytes(handshake_hash)
        + bytes(noise_static_pub)
        + struct.pack(">B", int(role))
    )


def _frame_payload(
    cert_der: bytes,
    sig_der: bytes,
    timestamp: int,
) -> bytes:
    """Build the full ``HANDSHAKE_ATTEST_PAYLOAD_SIZE``-byte wire
    payload: ``ts(8) || cert_len(2) || cert || sig_len(2) || sig || pad``.

    ``timestamp`` rides on the wire (in addition to being part of the
    signed pre-image) so the verifier can reconstruct the exact
    pre-image without having to guess it. The wire copy is bound to
    the signed copy because tampering with it would change the verify
    pre-image and break the signature.
    """
    payload_size = tuncore.HANDSHAKE_ATTEST_PAYLOAD_SIZE
    if len(cert_der) > 0xFFFF:
        raise AttestPayloadFormatError(
            f"cert too large to frame: {len(cert_der)} bytes"
        )
    if len(sig_der) > 0xFFFF:
        raise AttestPayloadFormatError(
            f"signature too large to frame: {len(sig_der)} bytes"
        )
    framed = (
        struct.pack(">Q", timestamp)
        + struct.pack(">H", len(cert_der))
        + bytes(cert_der)
        + struct.pack(">H", len(sig_der))
        + bytes(sig_der)
    )
    if len(framed) > payload_size:
        raise AttestPayloadFormatError(
            f"framed cert+sig exceeds attest payload size: "
            f"{len(framed)} > {payload_size}"
        )
    pad = os.urandom(payload_size - len(framed))
    return framed + pad


def _unframe_payload(payload: bytes) -> tuple[int, bytes, bytes]:
    """Inverse of ``_frame_payload``. Returns
    ``(timestamp, cert_der, sig_der)`` and ignores trailing pad."""
    payload_size = tuncore.HANDSHAKE_ATTEST_PAYLOAD_SIZE
    if len(payload) != payload_size:
        raise AttestPayloadFormatError(
            f"attest payload wrong size: {len(payload)} != {payload_size}"
        )
    if len(payload) < 8 + 2:
        raise AttestPayloadFormatError("attest payload truncated")
    (timestamp,) = struct.unpack(">Q", payload[:8])
    (cert_len,) = struct.unpack(">H", payload[8:10])
    cert_end = 10 + cert_len
    if cert_end + 2 > payload_size:
        raise AttestPayloadFormatError(
            "attest payload cert_len overflows frame"
        )
    cert_der = bytes(payload[10:cert_end])
    (sig_len,) = struct.unpack(">H", payload[cert_end : cert_end + 2])
    sig_end = cert_end + 2 + sig_len
    if sig_end > payload_size:
        raise AttestPayloadFormatError(
            "attest payload sig_len overflows frame"
        )
    sig_der = bytes(payload[cert_end + 2 : sig_end])
    return timestamp, cert_der, sig_der


def build_attest_payload(
    *,
    attest_key: tuncore.AttestKey,
    cert_der: bytes,
    handshake_hash: bytes,
    our_static_pub: bytes,
    our_role: PeerRole,
    timestamp: datetime.datetime | None = None,
) -> bytes:
    """Build the full ``HANDSHAKE_ATTEST_PAYLOAD_SIZE``-byte attest
    payload. ``attest_key`` produces the binding signature; the
    payload's binding extension on the cert MUST match
    ``our_static_pub`` (verified by the peer)."""
    if timestamp is None:
        timestamp = datetime.datetime.now(datetime.timezone.utc)
    ts_secs = int(timestamp.timestamp())
    pre_image = _binding_pre_image(
        timestamp=ts_secs,
        handshake_hash=handshake_hash,
        noise_static_pub=our_static_pub,
        role=our_role,
    )
    sig_der = bytes(attest_key.sign(pre_image))
    return _frame_payload(cert_der, sig_der, ts_secs)


def verify_attest_payload(
    *,
    payload: bytes,
    ca_root: X509Certificate,
    handshake_hash: bytes,
    expected_remote_static: bytes,
    expected_peer_role: PeerRole,
    now: datetime.datetime | None = None,
    allowed_clock_skew: datetime.timedelta = DEFAULT_CLOCK_SKEW,
    required_eku: ObjectIdentifier | None = None,
) -> DeviceCert:
    """Verify a peer's attestation payload. Returns the validated
    ``DeviceCert``. CN-policy and CRL checks are out of scope for this
    function — caller applies them separately on the returned cert.

    Raises:
        AttestPayloadFormatError on malformed wire framing.
        CertError / CertChainError / CertExpiredError on cert chain
            failures (re-raised from ``cert.validate_chain``).
        AttestBindingMismatchError if the cert's binding extension,
            the signed binding's noise_static_pub, and
            ``expected_remote_static`` disagree.
        AttestSignatureError on signature verification failure.
        AttestTimestampError on out-of-skew timestamps.
    """
    if now is None:
        now = datetime.datetime.now(datetime.timezone.utc)

    # 1. Unframe the wire payload.
    ts_secs, cert_der, sig_der = _unframe_payload(payload)
    if not cert_der or not sig_der:
        raise AttestPayloadFormatError(
            "attest payload missing cert or signature"
        )

    # 2. Cert chain.
    leaf = DeviceCert.from_der(cert_der)
    validate_chain(leaf, ca_root, now=now, required_eku=required_eku)

    # 3. Binding checks: cert ext == expected_remote_static.
    cert_binding = leaf.noise_static_pub
    if cert_binding != bytes(expected_remote_static):
        raise AttestBindingMismatchError(
            "cert noiseStaticBinding extension does not match the static "
            "key recovered from the Noise handshake"
        )

    # 4. Reconstruct + verify signature.
    pre_image = _binding_pre_image(
        timestamp=ts_secs,
        handshake_hash=handshake_hash,
        noise_static_pub=cert_binding,
        role=expected_peer_role,
    )
    try:
        leaf.public_key.verify(sig_der, pre_image, ECDSA(hashes.SHA256()))
    except InvalidSignature as e:
        raise AttestSignatureError(
            "binding signature does not verify under cert pubkey"
        ) from e

    # 5. Timestamp window.
    signed_ts = datetime.datetime.fromtimestamp(
        ts_secs, tz=datetime.timezone.utc
    )
    if abs(now - signed_ts) > allowed_clock_skew:
        raise AttestTimestampError(
            f"signed timestamp {signed_ts.isoformat()} is outside "
            f"±{allowed_clock_skew} of now {now.isoformat()}"
        )

    return leaf


__all__ = [
    "AttestBindingMismatchError",
    "AttestError",
    "AttestPayloadFormatError",
    "AttestSignatureError",
    "AttestTimestampError",
    "BINDING_DOMAIN",
    "BINDING_VERSION",
    "DEFAULT_CLOCK_SKEW",
    "PeerRole",
    "build_attest_payload",
    "verify_attest_payload",
]
