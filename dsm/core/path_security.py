"""Shared filesystem permission checks for sensitive files."""

from __future__ import annotations

import os
import stat
from pathlib import Path


class InsecureFilePermissionsError(OSError):
    """Raised when a sensitive file is owned by another user or
    is readable/writable by anyone beyond the owner."""


def check_user_file_permissions(path: Path) -> None:
    """Reject a sensitive file that is not uid-owned and 0o0xx mode.

    The file must be owned by the current uid and carry no group/world
    permission bits. Raises :class:`InsecureFilePermissionsError` on any
    violation or if the file cannot be stat'd.
    """
    try:
        st = path.stat()
    except OSError as e:
        raise InsecureFilePermissionsError(f"cannot stat {path}: {e}") from e
    if st.st_uid != os.getuid():
        raise InsecureFilePermissionsError(
            f"{path} owned by uid {st.st_uid}, expected {os.getuid()}. "
            "Refusing to trust a file owned by another user."
        )
    if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise InsecureFilePermissionsError(
            f"{path} has group/world permissions (mode={st.st_mode & 0o777:o}). "
            f"Run: chmod 600 {path}"
        )
