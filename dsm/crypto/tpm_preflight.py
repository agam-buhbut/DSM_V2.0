"""Enroll-time TPM reachability check (TPM attest backend only).

Surfaces an actionable error if the TPM is unreachable or misconfigured,
rather than letting a raw ``tss-esapi`` failure escape from deep inside
``AttestStore.generate`` with no operator guidance. A no-op on the soft
backend (there is no TPM to reach).
"""

from __future__ import annotations

import logging

log = logging.getLogger(__name__)


class TpmPreflightError(Exception):
    """The TPM is not reachable / usable for enrollment.

    Carries an operator-actionable message (missing device node, wrong
    group/permissions, non-empty Owner auth, or an unreachable TCTI).
    """


def _backend_is_software() -> bool:
    import tuncore

    return bool(getattr(tuncore, "ATTEST_BACKEND_IS_SOFTWARE", True))


def preflight_tpm(tcti: str | None) -> None:
    """Confirm the TPM responds before provisioning the attest key.

    No-op on the soft backend. On the TPM backend, runs the cheapest
    end-to-end probe — a throwaway ``generate`` + ``zeroize`` over the real
    provisioning path (create_primary/create/load) — which writes nothing to
    disk. Translates any failure into a typed, actionable
    :class:`TpmPreflightError`.

    Args:
        tcti: The configured TCTI (``config.attest_tpm_tcti``) or ``None`` for
            auto-resolution. Used only to make the error message name the
            endpoint the daemon will actually talk to; the live transport is
            selected by the ``TCTI`` env var the entry point sets.

    Raises:
        TpmPreflightError: If the TPM cannot be reached or used.
    """
    import tuncore

    if _backend_is_software():
        return  # soft backend: nothing to preflight

    where = tcti or "device:/dev/tpmrm0"
    try:
        probe = tuncore.AttestKey.generate()
        probe.zeroize()
    except Exception as e:  # noqa: BLE001 — enroll boundary; re-raised as typed
        # The Rust layer returns opaque RuntimeError/ValueError-shaped errors
        # for every TPM fault (no device, EACCES, non-empty ownerAuth, dead
        # TCTI), so we cannot narrow further without leaking backend internals
        # — translate the lot into one guidance string.
        raise TpmPreflightError(
            f"TPM not usable at {where}: {e}. Check that the TPM resource "
            "manager device exists (ls -l /dev/tpmrm0), that this user is in "
            "the 'tss' group (id -nG | grep tss) or the daemon runs with "
            "access to it, and that the Owner hierarchy has empty "
            "authorization (v1 requires empty ownerAuth). For a hermetic test "
            "TPM, point TCTI at a running swtpm, e.g. "
            "TCTI=swtpm:host=127.0.0.1,port=2321."
        ) from e
