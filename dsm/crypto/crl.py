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

CRL distribution and rotation are operational concerns (deploy/GUIDE.md §7e).
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

from dsm.core.atomic_io import atomic_write
from dsm.crypto.cert import check_strong_signature_hash


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


class CRLRollbackError(CRLError):
    """The CRL's ``crl_number`` regresses below the last-accepted value.

    Signals a rollback/replay: an older but still genuinely-signed and
    still-fresh CRL was presented to un-revoke a cert that a newer CRL
    had already revoked.
    """


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

        if crl.issuer != ca_root.subject:
            raise CRLIssuerMismatchError(
                f"CRL issuer {crl.issuer.rfc4514_string()!r} does not "
                f"match CA subject {ca_root.subject.rfc4514_string()!r}"
            )

        ca_pub = ca_root.public_key()
        if not isinstance(ca_pub, EllipticCurvePublicKey):
            raise CRLSignatureError(
                f"unsupported CA pubkey type {type(ca_pub).__name__}; "
                "only EC CAs are supported"
            )
        sig_alg = crl.signature_hash_algorithm
        if sig_alg is None:
            raise CRLSignatureError("CRL has no signature hash algorithm")
        # Reject SHA-1 / MD5 / etc — share the same allowlist + helper used
        # by cert.validate_chain so an operator cannot accidentally accept
        # a CRL signed under a hash that's been chosen-prefix-attackable
        # for years.
        check_strong_signature_hash(sig_alg, "CRL", exc_cls=CRLSignatureError)
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
    def crl_number(self) -> int | None:
        try:
            ext = self.crl.extensions.get_extension_for_class(x509.CRLNumber).value
        except x509.ExtensionNotFound:
            return None
        return ext.crl_number

    def reject_if_rolled_back(self, store_path: Path) -> None:
        """Refuse this CRL if its ``crl_number`` is older than the last seen.

        ``load`` verifies the CA signature and freshness but nothing stops a
        co-resident attacker (or a MITM on the distribution channel) from
        replaying an older, still-genuinely-signed, still-fresh CRL to drop a
        revocation. This persists the highest ``crl_number`` ever accepted in
        ``store_path`` and rejects any CRL that regresses below it. A CRL with
        no ``crl_number`` after a numbered one was already accepted is treated
        as suspect (cannot prove it is newer) and rejected too. On accept, the
        store is advanced when this CRL's number exceeds the stored one.

        Call this *after* ``load``/``_from_bytes`` has validated signature and
        issuer — it is an additive, optional follow-up, not part of ``load``.

        Args:
            store_path: File under the config/state dir holding the last-seen
                ``crl_number`` as a decimal integer.

        Raises:
            CRLRollbackError: The CRL regresses (or drops) ``crl_number``
                relative to the last-accepted value, or the store is corrupt.
        """
        last_seen = _read_last_crl_number(store_path)
        current = self.crl_number
        if last_seen is not None:
            if current is None:
                raise CRLRollbackError(
                    "CRL has no crl_number but a numbered CRL "
                    f"(#{last_seen}) was previously accepted; refusing to "
                    "downgrade to an unnumbered CRL (possible rollback)"
                )
            if current < last_seen:
                raise CRLRollbackError(
                    f"CRL crl_number {current} is older than the last-accepted "
                    f"{last_seen}; refusing (possible rollback/replay)"
                )
        if current is not None and (last_seen is None or current > last_seen):
            _write_last_crl_number(store_path, current)

    def is_stale(self, now: datetime.datetime) -> bool:
        try:
            return now > self.next_update
        except CRLError:
            # No nextUpdate present — refuse to call it stale or
            # fresh; caller sees a CRLError if they ask.
            return False


def _read_last_crl_number(store_path: Path) -> int | None:
    """Return the last-accepted crl_number, or None if no store exists yet.

    A corrupt/unreadable store is treated as fail-closed (raises) rather than
    silently reset: a co-resident attacker who could clear the rollback floor
    would otherwise re-enable exactly the replay this store defends against.
    """
    try:
        raw = store_path.read_text(encoding="ascii").strip()
    except FileNotFoundError:
        return None
    except OSError as e:
        raise CRLRollbackError(
            f"failed to read CRL rollback store {store_path}: {e}"
        ) from e
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError as e:
        raise CRLRollbackError(
            f"CRL rollback store {store_path} is corrupt (not an integer): "
            f"{raw!r}; refusing to proceed. Remove the file to reset the "
            "rollback floor only if you are certain this is not tampering."
        ) from e


def _write_last_crl_number(store_path: Path, number: int) -> None:
    atomic_write(store_path, f"{number}\n".encode("ascii"))


def _parse_crl(raw: bytes, source: str) -> x509.CertificateRevocationList:
    # Try PEM first, then DER. Either is acceptable on disk.
    try:
        return x509.load_pem_x509_crl(raw)
    except ValueError:
        pass
    try:
        return x509.load_der_x509_crl(raw)
    except ValueError as e:
        raise CRLLoadError(f"failed to parse CRL at {source}: {e}") from e
