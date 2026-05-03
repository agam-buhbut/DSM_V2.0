"""Certificate Revocation List (CRL) handling for DSM auth.

The CRL is produced by the offline CA (signed with the CA private key)
and distributed to servers/clients via walked USB on the operator's
chosen cadence (monthly per the plan). Both ends consult their local
CRL on every handshake.

This module:
  * loads a CRL from disk in DER or PEM
  * verifies its signature against the pinned CA root
  * checks freshness (``next_update``) and surfaces stale CRLs
  * answers ``is_revoked(serial)`` for a leaf cert's serial number

CRL distribution and rotation are operational concerns (CA_RUNBOOK).
This module is the runtime check.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA,
    EllipticCurvePublicKey,
)


class CRLError(Exception):
    """Base class for CRL-handling failures."""


class CRLLoadError(CRLError):
    """The CRL file is missing, malformed, or has the wrong type."""


class CRLSignatureError(CRLError):
    """The CRL signature does not verify under the CA root."""


class CRLStaleError(CRLError):
    """The CRL's ``next_update`` lies in the past."""


class CRLIssuerMismatchError(CRLError):
    """The CRL's issuer does not match the CA root's subject."""


@dataclass(frozen=True)
class CRL:
    """Validated CRL ready for revocation lookups.

    Construction enforces: CRL parses, issuer DN matches CA subject,
    CRL signature verifies under CA pubkey. ``next_update`` freshness
    is checked at construction *if* ``now`` is supplied; pass
    ``now=None`` to skip the staleness check (caller surfaces it
    explicitly via ``is_stale(now)``).
    """

    crl: x509.CertificateRevocationList
    _revoked_serials: frozenset[int]

    @classmethod
    def load(
        cls,
        path: Path,
        ca_root: x509.Certificate,
        *,
        now: datetime.datetime | None = None,
    ) -> CRL:
        try:
            raw = path.read_bytes()
        except OSError as e:
            raise CRLLoadError(f"failed to read CRL {path}: {e}") from e
        return cls._from_bytes(raw, ca_root, now=now, source=str(path))

    @classmethod
    def _from_bytes(
        cls,
        raw: bytes,
        ca_root: x509.Certificate,
        *,
        now: datetime.datetime | None,
        source: str,
    ) -> CRL:
        crl = _parse_crl(raw, source)

        # Issuer DN match.
        if crl.issuer != ca_root.subject:
            raise CRLIssuerMismatchError(
                f"CRL issuer {crl.issuer.rfc4514_string()!r} does not "
                f"match CA subject {ca_root.subject.rfc4514_string()!r}"
            )

        # Signature verify.
        ca_pub = ca_root.public_key()
        if not isinstance(ca_pub, EllipticCurvePublicKey):
            raise CRLSignatureError(
                f"unsupported CA pubkey type {type(ca_pub).__name__}; "
                "only EC CAs are supported"
            )
        sig_alg = crl.signature_hash_algorithm
        if sig_alg is None:
            raise CRLSignatureError("CRL has no signature hash algorithm")
        try:
            ca_pub.verify(
                crl.signature,
                crl.tbs_certlist_bytes,
                ECDSA(sig_alg),
            )
        except InvalidSignature as e:
            raise CRLSignatureError(
                "CRL signature does not verify under CA pubkey"
            ) from e

        revoked: set[int] = set()
        for entry in crl:
            revoked.add(entry.serial_number)

        wrapped = cls(crl=crl, _revoked_serials=frozenset(revoked))

        if now is not None and wrapped.is_stale(now):
            raise CRLStaleError(
                f"CRL is stale: next_update={wrapped.next_update.isoformat()} "
                f"is in the past relative to now={now.isoformat()}"
            )
        return wrapped

    def is_revoked(self, serial: int) -> bool:
        return serial in self._revoked_serials

    @property
    def next_update(self) -> datetime.datetime:
        nu = self.crl.next_update_utc
        if nu is None:
            # RFC 5280 says nextUpdate SHOULD be present; if it isn't,
            # treat as a missing freshness signal — caller decides.
            raise CRLError("CRL has no nextUpdate; cannot check freshness")
        return nu

    @property
    def this_update(self) -> datetime.datetime:
        return self.crl.last_update_utc

    @property
    def crl_number(self) -> int | None:
        try:
            ext = self.crl.extensions.get_extension_for_class(
                x509.CRLNumber
            ).value
        except x509.ExtensionNotFound:
            return None
        return ext.crl_number

    def is_stale(self, now: datetime.datetime) -> bool:
        try:
            return now > self.next_update
        except CRLError:
            # No nextUpdate present — refuse to call it stale or
            # fresh; caller sees a CRLError if they ask.
            return False

    def __len__(self) -> int:
        return len(self._revoked_serials)


def _parse_crl(
    raw: bytes, source: str
) -> x509.CertificateRevocationList:
    # Try PEM first, then DER. Either is acceptable on disk.
    try:
        return x509.load_pem_x509_crl(raw)
    except ValueError:
        pass
    try:
        return x509.load_der_x509_crl(raw)
    except ValueError as e:
        raise CRLLoadError(
            f"failed to parse CRL at {source}: {e}"
        ) from e
