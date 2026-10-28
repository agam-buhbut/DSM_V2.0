"""Load the cert auth materials referenced from ``Config`` at startup.

Both client and server need the same shape of inputs to the new
cert-based handshake (this device's cert DER + the pinned CA root + an
optional CRL). This module concentrates that loading so each runtime
caller can express it as a single call. Per-role policy
(``expected_server_cn`` for clients, ``allowed_cns_file`` for servers)
stays in the role's own runtime module.
"""

from __future__ import annotations

import datetime
import logging
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from dsm.core import netaudit
from dsm.core.config import Config
from dsm.core.path_security import (
    InsecureFilePermissionsError,
    cannot_read,
    check_user_file_permissions,
)
from dsm.crypto.attest_store import AttestStore
from dsm.crypto.cert import (
    CertError,
    CertExpiredError,
    DeviceCert,
    load_ca_root,
    serial_hex,
)
from dsm.crypto.crl import CRL, CRLError, CRLRollbackError
from dsm.crypto.keystore import KeyStore

log = logging.getLogger(__name__)


class AuthMaterialsError(Exception):
    """A required auth material file is missing, malformed, or fails policy."""


class AuthMaterialsTimeError(AuthMaterialsError):
    """The materials are sound but their dates do not cover now: a CRL past
    its next update, or a cert not yet valid or run out. A fresh file or a
    right clock mends it, so the client keeps its block and tries again
    (R1). The server catches the base class and exits 1, as before."""


@dataclass(frozen=True)
class CertAuthMaterials:
    """Parsed cert/CA/CRL materials ready to hand to the handshake."""

    cert_der: bytes
    ca_root: x509.Certificate
    crl: CRL | None


def _check_perms_or_raise(path: Path, label: str) -> None:
    """Reject paths that are symlinks, owned by another uid, or
    group/world readable. Defence-in-depth: cert/CA/CRL files are
    integrity-critical (substitution = wrong trust anchor / unrevoked
    cert), even though their content is signed."""
    try:
        check_user_file_permissions(path)
    except InsecureFilePermissionsError as e:
        raise AuthMaterialsError(
            f"refusing to load {label} with insecure permissions: {e}"
        ) from e


def _is_file(path: Path) -> bool:
    """A regular file is there. A path DSM cannot reach is one line, not a
    traceback (QA2 N5)."""
    try:
        return stat.S_ISREG(path.stat().st_mode)
    except (FileNotFoundError, NotADirectoryError):
        return False
    except OSError as e:
        raise AuthMaterialsError(cannot_read(path, e)) from e


def _load_cert_der(cert_file: Path) -> bytes:
    """Read a leaf cert from disk in either PEM or DER form, return DER."""
    _check_perms_or_raise(cert_file, "cert_file")
    try:
        raw = cert_file.read_bytes()
    except OSError as e:
        raise AuthMaterialsError(cannot_read(cert_file, e)) from e
    try:
        cert = DeviceCert.from_pem_or_der(raw)
    except CertError as e:
        raise AuthMaterialsError(f"failed to parse cert at {cert_file}: {e}") from e
    return cert.to_der()


def _check_own_dates(cert_der: bytes) -> None:
    """Raise AuthMaterialsTimeError if this host's own cert is not valid now."""
    cert = DeviceCert.from_der(cert_der)
    now = datetime.datetime.now(datetime.UTC)
    if now < cert.not_before:
        raise AuthMaterialsTimeError(
            f"this host's cert is not valid before {cert.not_before.isoformat()}; "
            "check the clock"
        )
    if now > cert.not_after:
        raise AuthMaterialsTimeError(
            f"this host's cert ran out on {cert.not_after.isoformat()}; enroll "
            "this host again (deploy/GUIDE.md §3)"
        )


def load_cert_materials(
    config: Config,
    *,
    check_own_dates: bool = False,
    clock_synced: Callable[[], bool] | None = None,
) -> CertAuthMaterials:
    """Load this device's cert + pinned CA root + optional CRL.

    Raises ``AuthMaterialsError`` on any I/O or parse failure, and its
    subclass ``AuthMaterialsTimeError`` when the problem is only a date: a
    CRL past its next update (crl_strict), the CA cert outside its dates,
    and, with ``check_own_dates`` (the client), this host's own cert.

    ``clock_synced`` (both daemons pass it) is asked only when the CRL is
    past its next update under crl_strict. When it says the clock is
    synchronized, the CRL is used with a WARNING instead (re-decision
    4(i)): it is still signed by the CA and not older than the last one
    taken, so every revocation in it holds; only a newer CRL may exist
    that nobody has carried here yet.
    """
    cert_file = Path(config.cert_file)
    ca_root_file = Path(config.ca_root_file)

    if not _is_file(cert_file):
        raise AuthMaterialsError(
            f"cert_file missing at {cert_file}; enroll this host with `sudo dsm "
            "init` or `sudo dsm enroll --csr-out <csr file>` (deploy/GUIDE.md §3)"
        )
    if not _is_file(ca_root_file):
        raise AuthMaterialsError(
            f"ca_root_file missing at {ca_root_file}; copy the pinned "
            "CA root cert into place per deploy/GUIDE.md §2f"
        )

    cert_der = _load_cert_der(cert_file)

    _check_perms_or_raise(ca_root_file, "ca_root_file")
    # DSM-005: the CA-root SHA-256 pin is REQUIRED for the daemon. Without
    # it, an attacker who can overwrite the on-disk CA PEM (within file
    # perms) substitutes the trust anchor undetected. Refuse to start when
    # unset, and verify the file against the pin on load.
    if not config.ca_root_sha256:
        netaudit.emit("ca_pin_missing", action="refused_start")
        raise AuthMaterialsError(
            "ca_root_sha256 is required but not set in config; refusing to "
            "start. Compute it with `sha256sum <ca_root_file> | cut -d' ' -f1` "
            'and set ca_root_sha256 = "<hex>" in config.toml '
            "(see deploy/GUIDE.md)."
        )
    try:
        expected_ca_sha256 = bytes.fromhex(config.ca_root_sha256)
    except ValueError as e:
        raise AuthMaterialsError(
            f"ca_root_sha256 is not valid hex: {config.ca_root_sha256!r}"
        ) from e
    try:
        ca_root = load_ca_root(ca_root_file, expected_sha256=expected_ca_sha256)
    except OSError as e:
        raise AuthMaterialsError(cannot_read(ca_root_file, e)) from e
    except CertExpiredError as e:
        # A CA cert outside its dates may be a clock set wrong: a date
        # problem, so the client waits instead of failing open (fix 2).
        raise AuthMaterialsTimeError(
            f"CA root at {ca_root_file} failed validation: {e}"
        ) from e
    except CertError as e:
        raise AuthMaterialsError(
            f"CA root at {ca_root_file} failed validation: {e}"
        ) from e

    # Before the CRL, so a try that fails on these dates runs no CRL code and
    # logs nothing; the client tries again. A CRL mistake then shows once the
    # date problem is gone.
    if check_own_dates:
        _check_own_dates(cert_der)

    crl = _load_crl(config, ca_root, clock_synced)

    return CertAuthMaterials(cert_der=cert_der, ca_root=ca_root, crl=crl)


def _load_crl(
    config: Config,
    ca_root: x509.Certificate,
    clock_synced: Callable[[], bool] | None = None,
) -> CRL | None:
    """Load + freshness/rollback-check the optional CRL per crl_strict policy.

    Returns the loaded CRL, or None when no crl_file is configured (permitted
    only under crl_strict=false). Raises ``AuthMaterialsError`` on a missing,
    invalid, rolled-back, or (under crl_strict) stale / no-nextUpdate CRL.
    A stale CRL under crl_strict raises ``AuthMaterialsTimeError``, unless
    ``clock_synced`` says the clock is synchronized (see ``load_cert_materials``).
    """
    crl: CRL | None = None
    if not config.crl_file:
        # CRL absent means revoked certs are silently accepted. Under
        # crl_strict (the default), refuse to start; under crl_strict=
        # false, log a WARNING and continue. A separate netaudit event
        # from "crl_stale" so monitoring can distinguish "no CRL at all"
        # from "CRL is past its next_update".
        if config.crl_strict:
            netaudit.emit("crl_missing", action="refused_start")
            raise AuthMaterialsError(
                "no crl_file configured and crl_strict=true; refusing to "
                "start. Either provision a CRL via the CA workflow per "
                "deploy/GUIDE.md §7e, or set crl_strict=false in config "
                "to accept revoked certs (NOT recommended for production)."
            )
        log.warning(
            "no crl_file configured and crl_strict=false; revoked "
            "client/server certs will be accepted. Wire a CRL via "
            "deploy/GUIDE.md §7e for revocation enforcement."
        )
        netaudit.emit("crl_missing", action="warned")
    if config.crl_file:
        crl_path = Path(config.crl_file)
        if not _is_file(crl_path):
            raise AuthMaterialsError(f"crl_file configured but missing at {crl_path}")
        _check_perms_or_raise(crl_path, "crl_file")
        try:
            # Pass now=None so a stale CRL surfaces via is_stale() rather
            # than refusing startup outright; we apply the freshness
            # policy below based on config.crl_strict.
            crl = CRL.load(crl_path, ca_root, now=None)
        except CRLError as e:
            raise AuthMaterialsError(f"CRL at {crl_path} failed validation: {e}") from e
        # DSM-B1: reject a genuinely-signed but older CRL replayed to
        # un-revoke a cert. The last-accepted crl_number is persisted under
        # the config dir and must never regress.
        crl_number_store = config.config_dir / "crl_number.seen"
        try:
            crl.reject_if_rolled_back(crl_number_store)
        except CRLRollbackError as e:
            netaudit.emit("crl_rollback", path=str(crl_path), action="refused_start")
            raise AuthMaterialsError(f"CRL at {crl_path} rejected: {e}") from e
        _now = datetime.datetime.now(datetime.UTC)
        # DSM-030: a CRL with no nextUpdate is never reported "stale"
        # (is_stale returns False without the field), so it would slip past
        # crl_strict's freshness gate and be trusted forever. Treat a
        # missing nextUpdate as its own fail-closed / warn case.
        try:
            _next_update = crl.next_update
        except CRLError:
            _next_update = None
        if _next_update is None:
            if config.crl_strict:
                netaudit.emit(
                    "crl_no_nextupdate",
                    path=str(crl_path),
                    action="refused_start",
                )
                raise AuthMaterialsError(
                    f"CRL at {crl_path} has no nextUpdate and crl_strict=true; "
                    "refusing to start — CRL freshness cannot be verified. "
                    "Issue a CRL with a nextUpdate via the CA workflow, or set "
                    "crl_strict=false to accept it with a warning."
                )
            log.warning(
                "CRL at %s has no nextUpdate; freshness cannot be checked and "
                "revocation may be arbitrarily stale. Set crl_strict=true to "
                "refuse to start in this case.",
                crl_path,
            )
            netaudit.emit("crl_no_nextupdate", path=str(crl_path), action="warned")
        elif crl.is_stale(_now):
            next_update = crl.next_update.isoformat()
            clock_ok = config.crl_strict and clock_synced is not None and clock_synced()
            if config.crl_strict and not clock_ok:
                # Fail closed. A CRL reaches a host only when someone carries
                # it there, so the message says to do that, not to turn the
                # check off (QA M8).
                netaudit.emit(
                    "crl_stale",
                    path=str(crl_path),
                    next_update=next_update,
                    action="refused_start",
                )
                raise AuthMaterialsTimeError(
                    f"CRL at {crl_path} is past its next update ({next_update}). "
                    "Carry the CA's current CRL here (deploy/GUIDE.md §7e)"
                )
            if clock_ok:
                log.warning(
                    "CRL at %s is past its next update (%s); DSM uses it because "
                    "the clock is synchronized. Carry the CA's current CRL here "
                    "(deploy/GUIDE.md §7e).",
                    crl_path,
                    next_update,
                )
            else:
                log.warning(
                    "CRL at %s is stale (next_update=%s); revocation checks "
                    "will miss certs revoked since that date. Set crl_strict=true "
                    "in config to refuse to start under a stale CRL.",
                    crl_path,
                    next_update,
                )
            netaudit.emit(
                "crl_stale",
                path=str(crl_path),
                next_update=next_update,
                action="warned",
            )
        # After the date checks, so a stale CRL under crl_strict, which the
        # client tries again, logs nothing on each try.
        number = crl.crl_number
        # Hex, as openssl and ca/crlnumber show it.
        log.info(
            "loaded CRL crl_number=%s",
            "none" if number is None else f"{serial_hex(number)} (hex)",
        )
    return crl


def verify_cert_matches_identity(
    cert_der: bytes,
    keystore: KeyStore,
    attest_store: AttestStore,
) -> None:
    """Assert that the loaded cert binds the loaded identity + attest keys.

    Call AFTER `load_daemon_stores` succeeds. Catches the failure mode
    where ``cert_file`` was swapped (by a typo or a co-resident attacker
    with file-write access but no key access) for a syntactically valid
    different cert — without this check the daemon would happily start,
    broadcast the wrong cert's CN / serial / Noise-binding-extension on
    every handshake attempt, and only fail at the peer's
    ``AttestBindingMismatchError`` / ``AttestSignatureError`` boundary,
    with no clear local symptom.

    Raises ``AuthMaterialsError`` on mismatch.
    """
    cert = DeviceCert.from_der(cert_der)

    bound_noise_static = cert.noise_static_pub
    local_noise_static = keystore.identity.public_key
    if bytes(bound_noise_static) != bytes(local_noise_static):
        raise AuthMaterialsError(
            "cert_file noiseStaticBinding extension does not match the "
            "loaded identity key — cert was issued for a different X25519 "
            "static. Re-enroll, or restore the matching cert from backup."
        )

    cert_spki_der = cert.public_key.public_bytes(
        Encoding.DER,
        PublicFormat.SubjectPublicKeyInfo,
    )
    local_attest_spki = attest_store.public_spki_der()
    if bytes(cert_spki_der) != bytes(local_attest_spki):
        raise AuthMaterialsError(
            "cert_file SubjectPublicKeyInfo does not match the loaded "
            "attest key — cert was issued for a different ECDSA pubkey. "
            "Re-enroll, or restore the matching cert from backup."
        )
