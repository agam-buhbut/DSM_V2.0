"""Client-side /etc/resolv.conf swap.

On tunnel up we replace the system resolver configuration with a single
``nameserver`` entry pointing at the server's TUN address, so every DNS
query the host generates travels through the tunnel and hits the server's
pinned DoH/DoT proxy. On tunnel down we put the original file (or symlink)
back exactly as we found it.

Without this the kill switch (which blocks port 53 on non-TUN interfaces)
turns every DNS query into a timeout — the host keeps asking its old
resolver and nftables keeps silently dropping it.
"""

from __future__ import annotations

import logging
import os
import tempfile
from pathlib import Path

log = logging.getLogger(__name__)

RESOLV_CONF = Path("/etc/resolv.conf")


class ResolvConfManager:
    """Own /etc/resolv.conf for the lifetime of the VPN session."""

    def __init__(self, nameserver: str) -> None:
        self._nameserver = nameserver
        self._original_contents: bytes | None = None
        self._original_symlink_target: str | None = None
        self._applied = False

    def apply(self) -> None:
        """Replace resolv.conf with a single-nameserver file."""
        if self._applied:
            return

        if RESOLV_CONF.is_symlink():
            self._original_symlink_target = os.readlink(RESOLV_CONF)
            RESOLV_CONF.unlink()
        elif RESOLV_CONF.exists():
            self._original_contents = RESOLV_CONF.read_bytes()
        # If the file simply didn't exist, both fields stay None and we
        # remove our override on teardown instead of restoring anything.

        payload = (
            f"# Managed by dsm while the VPN is up — original restored on teardown.\n"
            f"nameserver {self._nameserver}\n"
            f"options edns0 trust-ad\n"
        ).encode()
        _atomic_write(RESOLV_CONF, payload, mode=0o644)

        self._applied = True
        log.info("resolv.conf -> nameserver %s", self._nameserver)

    def remove(self) -> None:
        """Restore the original resolv.conf (symlink or contents)."""
        if not self._applied:
            return

        try:
            if RESOLV_CONF.exists() or RESOLV_CONF.is_symlink():
                RESOLV_CONF.unlink()

            if self._original_symlink_target is not None:
                os.symlink(self._original_symlink_target, RESOLV_CONF)
            elif self._original_contents is not None:
                _atomic_write(RESOLV_CONF, self._original_contents, mode=0o644)
            # else: no original to restore; leaving it absent matches the
            # pre-apply state.
        except OSError as e:
            log.error("failed to restore resolv.conf: %s", e)
        finally:
            self._applied = False
            self._original_contents = None
            self._original_symlink_target = None
            log.info("resolv.conf restored")


def _atomic_write(path: Path, data: bytes, mode: int) -> None:
    """Write atomically via tmpfile in the same directory, then rename."""
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".resolv.", suffix=".tmp")
    try:
        os.fchmod(fd, mode)
        os.write(fd, data)
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.rename(tmp, path)
    except BaseException:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
