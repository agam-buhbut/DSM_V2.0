"""Shared atomic-write helper.

Writes go to a sibling tempfile, are chmod'd + fsync'd, then renamed over
the target. A crash mid-write leaves either the old file intact or no
file at all — never a truncated one.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


def atomic_write(path: Path, data: bytes, *, mode: int = 0o600, mkdir: bool = True) -> None:
    """Write ``data`` to ``path`` atomically (tmpfile → fchmod → fsync → rename)."""
    if mkdir:
        path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent)
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
