"""Python-side process-hardening backstop.

``tuncore.harden_process()`` is the primary hardener; when it fails the
daemon catches the error and continues best-effort. This module provides
an independent ctypes backstop for the single most security-critical bit
— ``prctl(PR_SET_DUMPABLE, 0)`` — so a crash after a partial Rust
hardening failure cannot write a core file containing X25519 / ECDSA key
material. No new dependency: ctypes is stdlib, mirroring the existing
ctypes use in ``dsm.core.passphrase``.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import logging
import os
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dsm.core.config import Config

log = logging.getLogger(__name__)

# include/uapi/linux/prctl.h
_PR_SET_DUMPABLE = 4


class ProcessHardeningError(Exception):
    """``prctl(PR_SET_DUMPABLE, 0)`` failed at the libc boundary."""


def set_process_nondumpable() -> None:
    """Clear the process dumpable flag via ``prctl(PR_SET_DUMPABLE, 0)``.

    No-op on non-Linux platforms (``PR_SET_DUMPABLE`` is Linux-specific).

    Raises:
        ProcessHardeningError: the syscall is reachable but returned
            non-zero, so the caller can log it at WARNING rather than
            silently proceeding with a dumpable process.
    """
    if not sys.platform.startswith("linux"):
        return
    # Resolve libc + the prctl symbol inside the typed-error boundary so a
    # CDLL load failure (OSError) or a missing symbol (AttributeError) on an
    # exotic libc surfaces as ProcessHardeningError — the caller catches
    # exactly that and must not be aborted by an unexpected exception type.
    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
        prctl = libc.prctl
    except (OSError, AttributeError) as e:
        raise ProcessHardeningError(f"libc prctl unavailable: {e}") from e
    # Pin the signature: prctl(int, unsigned long x4) -> int. With all-zero
    # args this is correct without argtypes, but pinning it guards against
    # future reuse with large argument values.
    prctl.argtypes = (
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    )
    prctl.restype = ctypes.c_int
    ret = prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0)
    if ret != 0:
        errno = ctypes.get_errno()
        raise ProcessHardeningError(
            f"prctl(PR_SET_DUMPABLE, 0) failed: errno={errno} "
            f"({os.strerror(errno)})"
        )


def harden_and_gate(config: Config) -> bool:
    """Harden the process (best-effort) and enforce the attest-backend policy.

    Shared client/server startup preamble: runs ``tuncore.harden_process()``
    plus the independent ctypes non-dumpable backstop (both best-effort,
    logged on failure), then enforces the attestation-backend policy.

    Returns ``False`` when the attest gate rejects the build (the caller
    should exit non-zero); ``True`` otherwise.
    """
    import tuncore

    try:
        tuncore.harden_process()
    except Exception as e:  # noqa: BLE001  # see linter report
        log.warning(
            "process hardening partially failed: %s — continuing without it. "
            "Ensure the service has CAP_SYS_RESOURCE and unrestricted prctl.",
            e,
        )

    # Independent ctypes backstop for the most security-critical bit, in
    # case harden_process() above failed partway: a crash must not dump
    # key material to a core file.
    try:
        set_process_nondumpable()
    except ProcessHardeningError as e:
        log.warning("core-dump backstop (PR_SET_DUMPABLE) failed: %s", e)

    from dsm.crypto.attest_gate import (
        MalformedAttestBuildError,
        SoftAttestNotAllowedError,
        enforce_attest_backend_policy,
    )

    try:
        enforce_attest_backend_policy(config)
    except (SoftAttestNotAllowedError, MalformedAttestBuildError) as e:
        log.error("%s", e)
        return False
    return True
