"""SPKI pinning for DoH/DoT.

Each configured provider has one or more SHA-256 hashes of its DER-encoded
SubjectPublicKeyInfo. After TLS handshake we extract the peer cert's SPKI
and reject the connection if no pin matches.

To compute a pin for a host:
    openssl s_client -connect <host>:<port> -servername <host> </dev/null \
      | openssl x509 -noout -pubkey \
      | openssl pkey -pubin -outform DER \
      | openssl dgst -sha256
"""

from __future__ import annotations

import hashlib
import hmac
import ssl
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization


class PinMismatchError(Exception):
    pass


def compute_spki_sha256(der_cert: bytes) -> bytes:
    """Return SHA-256 of the DER-encoded SubjectPublicKeyInfo."""
    cert = x509.load_der_x509_certificate(der_cert)
    spki_der = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki_der).digest()


def verify_pin(der_cert: bytes, expected_pins: list[bytes], provider: str) -> None:
    """Raise PinMismatchError if cert SPKI hash is not in expected_pins."""
    actual = compute_spki_sha256(der_cert)
    for pin in expected_pins:
        if hmac.compare_digest(actual, pin):
            return
    raise PinMismatchError(
        f"SPKI pin mismatch for {provider}: got {actual.hex()}, "
        f"expected one of {[p.hex() for p in expected_pins]}"
    )


def verify_pin_on_ssl_object(ssl_obj: Any, expected_pins: list[bytes], provider: str) -> None:
    """Extract peer cert from an SSL object and verify its SPKI pin."""
    der = ssl_obj.getpeercert(binary_form=True)
    if not der:
        raise PinMismatchError(f"no peer certificate for {provider}")
    verify_pin(der, expected_pins, provider)


def build_pinned_ssl_context() -> ssl.SSLContext:
    """Standard CA-verifying SSL context.

    Pinning is enforced separately by inspecting the peer cert after handshake;
    CA verification still runs so that a forged cert with a matching SPKI (via
    key compromise + issued-under-trusted-CA) is also bound to a trusted issuer.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx
