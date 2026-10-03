"""Startup preflight checks for DSM.

Checks that do NOT block startup but emit operator-facing warnings when
conditions that commonly cause connection failures are detected.
"""

from __future__ import annotations

import subprocess


def check_clock_sync() -> str | None:
    """Return a one-line warning if the system clock is not NTP-synchronized,
    else None. Best-effort; never raises.

    Uses ``timedatectl show`` which is available on all systemd hosts. On
    non-systemd or headless boxes where the command is absent the function
    returns None silently — no warning is better than a spurious one.
    """
    try:
        out = subprocess.run(
            ["timedatectl", "show", "-p", "NTPSynchronized", "--value"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.stdout.strip() == "no":
        return (
            "system clock is NOT NTP-synchronized — DSM handshakes fail if the "
            "two peers' clocks differ by more than ~5 minutes. Enable NTP "
            "(e.g. `timedatectl set-ntp true`) on BOTH the client and server."
        )
    return None


__all__ = ["check_clock_sync"]
