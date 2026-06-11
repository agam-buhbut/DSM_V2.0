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
