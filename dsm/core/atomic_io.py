"""Shared atomic-write helper.

Writes go to a sibling tempfile, are chmod'd + fsync'd, then renamed over
the target. A crash mid-write leaves either the old file intact or no
file at all — never a truncated one.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


def atomic_write(
    path: Path,
    data: bytes,
    *,
    mode: int = 0o600,
    mkdir: bool = True,
    dir_mode: int = 0o700,
) -> None:
    """Write ``data`` to ``path`` atomically (tmpfile → fchmod → fsync → rename).

    Newly-created parent directories use ``dir_mode`` (default 0o700) so the
    secret-bearing file does not sit inside a world-readable directory that
    leaks even its existence. Pre-existing parent directories are not
    re-chmod'd (avoids breaking system layout like /etc/dsm).

    POSIX rename durability requires fsync'ing the parent directory after
    the rename — otherwise a crash can lose the directory entry update
    even though the tmpfile data is already on disk.
    """
    if mkdir:
        path.parent.mkdir(parents=True, exist_ok=True, mode=dir_mode)
    fd, tmp = tempfile.mkstemp(dir=path.parent)
    try:
        os.fchmod(fd, mode)
        os.write(fd, data)
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.rename(tmp, path)
        # fsync the parent dir so the rename is durable across crashes.
        dir_fd = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except BaseException:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
