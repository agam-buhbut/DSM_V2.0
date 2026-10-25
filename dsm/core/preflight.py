"""Startup preflight checks for DSM.

Checks that do NOT block startup but emit operator-facing warnings when
conditions that commonly cause connection failures are detected.
"""

from __future__ import annotations

import subprocess


def ntp_synchronized() -> bool | None:
    """True or False as ``timedatectl`` reports NTPSynchronized, or None
    when it cannot tell (no timedatectl, a timeout, other output). Never
    raises."""
    try:
        out = subprocess.run(
            ["timedatectl", "show", "-p", "NTPSynchronized", "--value"],
            capture_output=True,
            # Odd bytes must give "cannot tell", not a decode error.
            encoding="utf-8",
            errors="replace",
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    value = out.stdout.strip()
    if value == "yes":
        return True
    if value == "no":
        return False
    return None


def check_clock_sync() -> str | None:
    """Return a one-line warning if the system clock is not NTP-synchronized,
    else None. Best-effort; never raises.

    On non-systemd or headless boxes where ``timedatectl`` is absent this
    returns None silently — no warning is better than a spurious one.
    """
    if ntp_synchronized() is False:
        return (
            "system clock is NOT NTP-synchronized — DSM handshakes fail if the "
            "two peers' clocks differ by more than ~5 minutes. Enable NTP "
            "(e.g. `timedatectl set-ntp true`) on BOTH the client and server."
        )
    return None


__all__ = ["check_clock_sync", "ntp_synchronized"]
