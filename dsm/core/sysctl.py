"""Shared "capture/override/restore" /proc/sysctl helper.

Used by :class:`dsm.net.forwarding.IPForwardingManager` (server-side IPv4
forwarding + send_redirects + rp_filter) and
:class:`dsm.net.nftables.TcpTimestampsDisabler`. Both manage one or more
``/proc/sys/...`` keys for the lifetime of a tunnel session: capture
prior value, write new value, restore on teardown.

Both callers only override a key when its current value differs from
the requested one, emitting a ``sysctl K: old -> new`` log line on
change. Failures during the write are swallowed into a WARNING.
"""

from __future__ import annotations

import logging
from pathlib import Path

log = logging.getLogger(__name__)


def sysctl_path(key: str) -> Path:
    return Path("/proc/sys") / key.replace(".", "/")


class SysctlOverride:
    """Capture-and-restore manager for a set of /proc/sys keys.

    Designed for the lifetime of one session: call :meth:`set` for each
    key to override, then :meth:`restore_all` on teardown.

    Stores original values only when they differ from the requested new
    value (matches the historical IPForwardingManager behavior). On
    restore, iterates in insertion order — the order overrides were
    requested — which is sufficient because /proc/sys writes are
    independent.
    """

    def __init__(self) -> None:
        self._original: dict[str, str] = {}

    def set(self, key: str, value: str) -> str | None:
        """Override ``key`` to ``value``; return prior value (or None on failure).

        If the current value already equals ``value``, this is a no-op
        (no log line, nothing recorded for restore). On OSError the
        failure is logged at WARNING and ``None`` is returned.
        """
        path = sysctl_path(key)
        try:
            current = path.read_text().strip()
        except OSError as e:
            log.warning("could not read %s: %s", key, e)
            return None
        if current == value:
            return current
        try:
            path.write_text(f"{value}\n")
        except OSError as e:
            log.warning("could not set %s=%s: %s", key, value, e)
            return None
        # Only record originals we haven't already captured — re-setting
        # the same key twice in the lifetime of one manager must restore
        # back to the *first* observed value, not the second-most-recent.
        self._original.setdefault(key, current)
        log.info("sysctl %s: %s -> %s", key, current, value)
        return current

    def restore_all(self) -> None:
        for key, value in self._original.items():
            try:
                sysctl_path(key).write_text(f"{value}\n")
                log.info("sysctl %s restored to %s", key, value)
            except OSError as e:
                log.warning("could not restore %s: %s", key, e)
        self._original.clear()
