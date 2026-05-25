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
from collections.abc import Callable
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
        # The bytes-collection loop is the ONLY region where ``buf`` can
        # grow past empty, so it's the only region whose exception path
        # needs to wipe. tcsetattr/tcgetattr around it cannot leak the
        # passphrase even on failure, but the surrounding ``finally``
        # still restores terminal state.
        new_attrs = termios.tcgetattr(fd)
        new_attrs[3] = new_attrs[3] & ~termios.ECHO
        termios.tcsetattr(fd, termios.TCSADRAIN, new_attrs)

        try:
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
    # Read into a mutable bytearray without an intermediate immutable bytes
    # copy. p.read_bytes() would produce an unwipeable bytes object that may
    # linger on Python's heap. os.open + os.read into a pre-sized bytearray
    # keeps the passphrase wipeable end-to-end.
    fd = os.open(str(p), os.O_RDONLY | os.O_NOFOLLOW)
    try:
        size = os.fstat(fd).st_size
        buf = bytearray(size)
        view = memoryview(buf)
        offset = 0
        while offset < size:
            n = os.readv(fd, [view[offset:]])
            if n == 0:
                break
            offset += n
        del view
    finally:
        os.close(fd)
    while buf and buf[-1] in (0x0A, 0x0D):
        del buf[-1]
    return buf


def _try_source(
    fn: Callable[[], bytearray],
    warn_msg: str,
    *warn_args: object,
) -> bytearray | None:
    """Run ``fn()``; on OSError-family failure log ``warn_msg``-formatted
    with the exception appended and return None.

    The three file/fd sources share the same shape ("try read; on OS-level
    failure log and fall through"); centralising the try/except keeps the
    fallback chain readable without changing observable behavior (each
    source still emits its caller-supplied warning string).
    """
    try:
        return fn()
    except (OSError, ValueError) as e:
        log.warning("%s: %s", warn_msg % warn_args, e)
        return None


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
        return _try_source(
            lambda: _read_from_fd(passphrase_fd),
            "failed to read from passphrase-fd %d",
            passphrase_fd,
        )

    if passphrase_env_file is not None:
        return _try_source(
            lambda: _read_from_file(passphrase_env_file),
            "failed to read passphrase from %s",
            passphrase_env_file,
        )

    env_file = os.environ.get("DSM_PASSPHRASE_FILE")
    if env_file:
        result = _try_source(
            lambda: _read_from_file(env_file),
            "DSM_PASSPHRASE_FILE %s unreadable",
            env_file,
        )
        if result is not None:
            return result
        # Note: fall through to DSM_PASSPHRASE (matches the original
        # behavior — DSM_PASSPHRASE_FILE failure did NOT stop the chain).

    # os.environb returns bytes (one fewer immutable str copy than
    # os.environ.get + .encode). The fundamental limitation remains: the
    # interpreter's environment block carries the passphrase in memory we
    # cannot wipe — it lives at /proc/PID/environ for the process
    # lifetime and is visible to any same-uid reader, debugger, or core
    # dump. The returned bytearray is wipeable but the env block + the
    # internal `bytes` returned by os.environb.get are not.
    env_pass_b = os.environb.get(b"DSM_PASSPHRASE")
    if env_pass_b:
        log.warning(
            "DSM_PASSPHRASE env var is process-visible (readable via "
            "/proc/PID/environ for the process lifetime); prefer "
            "DSM_PASSPHRASE_FILE or --passphrase-fd. Continuing because "
            "the env var is set."
        )
        # Best-effort: unset env so subsequent reads (e.g. via fork+exec)
        # do not see it. Does NOT scrub the kernel-allocated env block
        # in this process — that lives until exit.
        try:
            os.unsetenv("DSM_PASSPHRASE")
            del os.environb[b"DSM_PASSPHRASE"]
        except KeyError:
            pass
        return bytearray(env_pass_b)

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
