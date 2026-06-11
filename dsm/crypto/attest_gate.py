"""Phase-0 gate: refuse to start on the extractable software attestation
backend unless the operator explicitly acknowledges it.

The dev-soft-attest backend keeps the ECDSA P-256 device-attestation
scalar in process memory in extractable form (Argon2id-wrapped at rest,
but recoverable by anyone who can read the running process). It is the
default Cargo feature and ships in release wheels until the TPM backend
lands, so starting on it without acknowledgement silently downgrades the
hardware-binding guarantee. Fail closed.
"""

from __future__ import annotations

import logging

from dsm.core import netaudit
from dsm.core.config import Config

log = logging.getLogger(__name__)


class SoftAttestNotAllowedError(Exception):
    """Active attest backend is software-based and ``allow_soft_attest``
    is not set; the daemon refuses to start."""


class MalformedAttestBuildError(Exception):
    """The ``tuncore`` extension does not expose
    ``ATTEST_BACKEND_IS_SOFTWARE``; the build is malformed (predates the
    Phase-0 gate). Refuse to start with an actionable diagnostic rather
    than mislabel it as a soft-backend refusal."""


def enforce_attest_backend_policy(config: Config) -> None:
    """Refuse to start on the extractable soft-attest backend unless
    ``config.allow_soft_attest`` is true.

    Raises:
        MalformedAttestBuildError: the extension is missing the backend
            constant (a valid build always defines it).
        SoftAttestNotAllowedError: software backend active and not
            acknowledged. When acknowledged, logs a prominent WARNING and
            emits a ``soft_attest_acknowledged`` netaudit event instead.
    """
    import tuncore

    # A valid build always defines this (the Rust side `compile_error!`s
    # if no backend feature is set). A missing constant therefore means a
    # stale/malformed wheel, not a backend choice — fail closed, but say
    # so precisely instead of mislabeling it a soft-backend refusal.
    sentinel = object()
    is_software = getattr(tuncore, "ATTEST_BACKEND_IS_SOFTWARE", sentinel)
    if is_software is sentinel:
        netaudit.emit("soft_attest_acknowledged", action="malformed_build")
        raise MalformedAttestBuildError(
            "tuncore is missing ATTEST_BACKEND_IS_SOFTWARE: the extension "
            "predates the Phase-0 attestation gate. Rebuild it (maturin "
            "build --release) and reinstall before starting the daemon."
        )

    if not is_software:
        return  # hardware-backed backend (TPM) — nothing to gate

    if not config.allow_soft_attest:
        netaudit.emit("soft_attest_acknowledged", action="refused_start")
        raise SoftAttestNotAllowedError(
            "active device-attestation backend is software-based "
            "(dev-soft-attest): the attestation key is extractable from "
            "process memory and provides no hardware binding. Refusing to "
            "start. Set allow_soft_attest = true in config.toml to run "
            "anyway (NOT recommended for production), or build tuncore with "
            "a hardware attest backend."
        )

    log.warning(
        "RUNNING WITH EXTRACTABLE SOFTWARE ATTESTATION BACKEND "
        "(dev-soft-attest): the device-attestation key is recoverable from "
        "process memory and provides NO hardware binding. allow_soft_attest "
        "is set, so startup continues. Do not use this in production."
    )
    netaudit.emit("soft_attest_acknowledged", action="warned")
