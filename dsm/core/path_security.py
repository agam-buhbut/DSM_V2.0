"""Shared filesystem permission checks for sensitive files."""

from __future__ import annotations

import os
import stat
from pathlib import Path


class InsecureFilePermissionsError(OSError):
    """Raised when a sensitive file is owned by another user or
    is readable/writable by anyone beyond the owner."""


def cannot_read(path: Path | str, e: OSError) -> str:
    """One line for a file DSM cannot read (QA2 N5). Under the systemd
    units root has no CAP_DAC_OVERRIDE, so a folder of another user, or a
    0700 home folder, is closed to DSM: a permission error says so."""
    text = f"cannot read {path}: {e.strerror or e}"
    if isinstance(e, PermissionError):
        text += (
            " (the systemd unit runs without CAP_DAC_OVERRIDE: keep DSM's "
            "files in /opt/mtun, owned by root)"
        )
    return text


def cannot_write_in(folder: Path | str, e: OSError) -> str:
    """One line for a folder DSM cannot write in (QA2 box F1). Under the
    units root has no CAP_DAC_OVERRIDE, so a config folder owned by another
    user is closed to it."""
    text = f"cannot write in {folder}: {e.strerror or e}"
    if isinstance(e, PermissionError):
        text += (
            " (the systemd unit runs without CAP_DAC_OVERRIDE: the config "
            "folder must be owned by root)"
        )
    return text


def check_user_file_permissions(path: Path) -> None:
    """Reject a sensitive file that is not uid-owned and 0o0xx mode.

    The file must be owned by the current uid, carry no group/world
    permission bits, and NOT be a symlink. The symlink rejection blocks a
    defense-in-depth bypass: ``path.stat()`` follows symlinks, so a
    symlink at ``path`` pointing to a sensitive file owned by the same uid
    (when we run as root, /etc/shadow qualifies) would pass owner+mode
    checks and feed the linked content to the caller. Reject up front via
    ``lstat`` so the check actually inspects the path we're about to read.

    Raises :class:`InsecureFilePermissionsError` on any violation or if
    the file cannot be stat'd.
    """
    try:
        lst = path.lstat()
    except OSError as e:
        raise InsecureFilePermissionsError(f"cannot lstat {path}: {e}") from e
    if stat.S_ISLNK(lst.st_mode):
        raise InsecureFilePermissionsError(
            f"{path} is a symlink; refusing to follow. "
            "Replace with the actual file (cp --no-preserve=links) and "
            "set mode 0600."
        )
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
