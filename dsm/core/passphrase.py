"""Passphrase reading utilities shared by all on-disk encrypted stores
(keystore, attest store).

A passphrase that crosses Python's normal string machinery (``input``,
``getpass.getpass``) routes through immutable ``str`` / ``bytes`` that
CPython may intern or keep on its free-list, so we cannot reliably zero
those bytes after use. This module reads passphrases directly into a
mutable ``bytearray`` the caller can wipe with a libc ``memset`` after
they're no longer needed.
"""

from __future__ import annotations

import ctypes
import logging
import os
import sys
import termios
from pathlib import Path

from dsm.core.path_security import check_user_file_permissions

log = logging.getLogger(__name__)


def wipe_passphrase(buf: bytearray) -> None:
    """Zero a passphrase ``bytearray`` in place via a single libc memset.

    Using ``ctypes.memset`` avoids the per-byte Python loop (interpreted
    and interruptible) and sidesteps any future bytecode-level
    optimization that might elide a trivial zero loop.
    """
    if not buf:
        return
    addr = (ctypes.c_char * len(buf)).from_buffer(buf)
    ctypes.memset(ctypes.addressof(addr), 0, len(buf))


def _read_from_tty(prompt: str) -> bytearray:
    if not sys.stdin.isatty():
        line = sys.stdin.buffer.readline().rstrip(b"\r\n")
        return bytearray(line)

    fd = sys.stdin.fileno()
    sys.stderr.write(prompt)
    sys.stderr.flush()

    old_attrs = termios.tcgetattr(fd)
    buf = bytearray()
    try:
        new_attrs = termios.tcgetattr(fd)
        new_attrs[3] = new_attrs[3] & ~termios.ECHO
        termios.tcsetattr(fd, termios.TCSADRAIN, new_attrs)

        while True:
            ch = os.read(fd, 1)
            if not ch:
                break
            if ch in (b"\n", b"\r"):
                break
            if ch == b"\x03":
                raise KeyboardInterrupt
            if ch == b"\x04" and not buf:
                break
            buf.extend(ch)
    except BaseException:
        wipe_passphrase(buf)
        raise
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_attrs)
        sys.stderr.write("\n")
        sys.stderr.flush()

    return buf


def _read_from_fd(fd: int) -> bytearray:
    buf = bytearray()
    while True:
        ch = os.read(fd, 1)
        if not ch or ch in (b"\n", b"\r"):
            break
        buf.extend(ch)
    return buf


def _read_from_file(path: str | Path) -> bytearray:
    p = Path(path)
    check_user_file_permissions(p)
    return bytearray(p.read_bytes().rstrip(b"\r\n"))


def _read_noninteractive(
    passphrase_fd: int | None,
    passphrase_env_file: str | None,
) -> bytearray | None:
    """Try non-interactive sources in order:

    1. ``passphrase_fd`` arg
    2. ``passphrase_env_file`` arg
    3. ``DSM_PASSPHRASE_FILE`` env var (mode 0600 enforced)
    4. ``DSM_PASSPHRASE`` env var (weakest; visible in /proc)
    """
    if passphrase_fd is not None:
        try:
            return _read_from_fd(passphrase_fd)
        except (OSError, ValueError) as e:
            log.warning("failed to read from passphrase-fd %d: %s", passphrase_fd, e)
            return None

    if passphrase_env_file is not None:
        try:
            return _read_from_file(passphrase_env_file)
        except (OSError, FileNotFoundError) as e:
            log.warning("failed to read passphrase from %s: %s", passphrase_env_file, e)
            return None

    env_file = os.environ.get("DSM_PASSPHRASE_FILE")
    if env_file:
        try:
            return _read_from_file(env_file)
        except (OSError, FileNotFoundError) as e:
            log.warning("DSM_PASSPHRASE_FILE %s unreadable: %s", env_file, e)

    env_pass = os.environ.get("DSM_PASSPHRASE")
    if env_pass:
        log.debug("using passphrase from DSM_PASSPHRASE env var")
        return bytearray(env_pass.encode())

    return None


def read_passphrase(
    passphrase_fd: int | None = None,
    passphrase_env_file: str | None = None,
    *,
    prompt: str = "Key passphrase: ",
) -> bytearray:
    """Read a passphrase into a wipeable ``bytearray``.

    Tries non-interactive sources in order; falls back to an interactive
    tty prompt with ECHO disabled. The caller owns the returned buffer
    and MUST call ``wipe_passphrase`` on it after use.
    """
    p = _read_noninteractive(passphrase_fd, passphrase_env_file)
    if p is not None:
        return p
    return _read_from_tty(prompt)
