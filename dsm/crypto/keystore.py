"""Python-side key store: loads identity from encrypted file, auto-locks."""

from __future__ import annotations

import ctypes
import logging
import os
import sys
import termios
from pathlib import Path
from typing import TYPE_CHECKING

from dsm.core.atomic_io import atomic_write
from dsm.core.path_security import check_user_file_permissions

if TYPE_CHECKING:
    import tuncore

log = logging.getLogger(__name__)


def _read_passphrase_into_bytearray(prompt: str) -> bytearray:
    """Read a passphrase from the controlling tty into a mutable bytearray.

    Unlike ``getpass.getpass`` — which routes the passphrase through an
    immutable ``str`` / ``bytes`` that CPython may intern or keep in its
    free-list — this reads bytes directly into a ``bytearray`` the caller
    can zero after use. Echo is disabled for the duration of the read.
    """
    # Fall back to a non-interactive read if we don't have a tty; the
    # caller's guarantees don't apply here but we keep working for tests.
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
        # lflags is index 3; clear ECHO but keep ICANON so the kernel still
        # handles line editing (backspace etc).
        new_attrs[3] = new_attrs[3] & ~termios.ECHO
        termios.tcsetattr(fd, termios.TCSADRAIN, new_attrs)

        while True:
            ch = os.read(fd, 1)
            if not ch:
                break
            if ch in (b"\n", b"\r"):
                break
            if ch == b"\x03":  # Ctrl-C
                raise KeyboardInterrupt
            if ch == b"\x04" and not buf:  # Ctrl-D on empty line
                break
            buf.extend(ch)
    except BaseException:
        # Wipe anything we collected before re-raising so a partial read
        # doesn't leave a plaintext fragment behind.
        _wipe(buf)
        raise
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_attrs)
        sys.stderr.write("\n")
        sys.stderr.flush()

    return buf


def _wipe(buf: bytearray) -> None:
    """Zero a bytearray in place via a single libc memset.

    Using ``ctypes.memset`` avoids the per-byte Python loop (which is
    interpreted and interruptible mid-wipe) and sidesteps any future
    bytecode-level optimization that might elide a trivial zero loop.
    """
    if not buf:
        return
    addr = (ctypes.c_char * len(buf)).from_buffer(buf)
    ctypes.memset(ctypes.addressof(addr), 0, len(buf))


def _read_passphrase_from_fd(fd: int) -> bytearray:
    """Read passphrase from a file descriptor into a bytearray."""
    buf = bytearray()
    while True:
        ch = os.read(fd, 1)
        if not ch or ch in (b"\n", b"\r"):
            break
        buf.extend(ch)
    return buf


def _read_passphrase_from_file(path: str | Path) -> bytearray:
    """Read passphrase from a file (must be mode 0600 for security)."""
    path = Path(path)
    check_user_file_permissions(path)
    buf = bytearray(path.read_bytes().rstrip(b"\r\n"))
    return buf


def _get_passphrase_noninteractive(
    passphrase_fd: int | None = None,
    passphrase_env_file: str | None = None,
    passphrase_env: str | None = None,
) -> bytearray | None:
    """Try non-interactive passphrase sources in order of precedence.

    Precedence:
    1. passphrase_fd (file descriptor number)
    2. DSM_PASSPHRASE_FILE env var (path, checked for mode 0600)
    3. DSM_PASSPHRASE env var (weakest, visible in /proc/*/environ)

    Returns bytearray if found, None if all sources exhausted.
    """
    # Explicit FD arg (e.g. from --passphrase-fd)
    if passphrase_fd is not None:
        try:
            return _read_passphrase_from_fd(passphrase_fd)
        except (OSError, ValueError) as e:
            log.warning("failed to read from passphrase-fd %d: %s", passphrase_fd, e)
            return None

    # Env file arg
    if passphrase_env_file is not None:
        try:
            return _read_passphrase_from_file(passphrase_env_file)
        except (OSError, FileNotFoundError) as e:
            log.warning("failed to read passphrase from %s: %s", passphrase_env_file, e)
            return None

    # DSM_PASSPHRASE_FILE env
    env_file = os.environ.get("DSM_PASSPHRASE_FILE")
    if env_file:
        try:
            return _read_passphrase_from_file(env_file)
        except (OSError, FileNotFoundError) as e:
            log.warning("DSM_PASSPHRASE_FILE %s unreadable: %s", env_file, e)
            # Don't return None; try next source

    # DSM_PASSPHRASE env (weakest; visible in /proc but works for CI)
    env_pass = os.environ.get("DSM_PASSPHRASE")
    if env_pass:
        log.debug("using passphrase from DSM_PASSPHRASE env var")
        return bytearray(env_pass.encode())

    return None


class KeyStore:
    """Manages identity keypair persistence.

    Keys are encrypted at rest with Argon2id + XChaCha20-Poly1305
    via the tuncore Rust module.
    """

    def __init__(self, key_file: str) -> None:
        self._path = Path(key_file)
        self._identity: tuncore.IdentityKeyPair | None = None

    @property
    def is_loaded(self) -> bool:
        return self._identity is not None

    @property
    def identity(self) -> tuncore.IdentityKeyPair:
        """Return the loaded identity keypair. Raises if not loaded."""
        if self._identity is None:
            raise RuntimeError("identity not loaded — call load() or generate()")
        return self._identity

    def generate(self, passphrase: bytes | bytearray) -> bytes:
        """Generate a new identity keypair and save to disk.

        ``passphrase`` may be either ``bytes`` or ``bytearray``. A transient
        immutable ``bytes`` copy is made to cross the FFI boundary (PyO3's
        ``&[u8]`` doesn't accept ``PyByteArray``); its lifetime is bounded
        by this call, so the caller's ``bytearray`` remains the only
        long-lived store and can be zeroized after return.

        Returns the public key bytes.
        """
        import tuncore

        kp = tuncore.IdentityKeyPair.generate()
        blob = kp.encrypt_to_store(bytes(passphrase))
        atomic_write(self._path, blob)
        self._identity = kp
        return bytes(kp.public_key)

    def load(self, passphrase: bytes | bytearray) -> bytes:
        """Load identity from encrypted file.

        See ``generate`` for notes on ``bytearray`` passphrase handling.

        Refuses to read the key file unless it is owned by the current user
        and carries no group/world permission bits.

        Returns the public key bytes.
        """
        check_user_file_permissions(self._path)

        import tuncore

        blob = self._path.read_bytes()
        kp = tuncore.IdentityKeyPair.decrypt_from_store(blob, bytes(passphrase))
        self._identity = kp
        return bytes(kp.public_key)

    def unload(self) -> None:
        """Zeroize and unload the identity from memory.

        Calls the Rust-side explicit zeroize before releasing the Python
        reference so any stale reference elsewhere also sees a scrubbed
        key, instead of relying on refcount-driven drop ordering.
        """
        if self._identity is not None:
            self._identity.zeroize()
            self._identity = None

    def exists(self) -> bool:
        return self._path.is_file()

    def load_or_generate(
        self,
        passphrase_fd: int | None = None,
        passphrase_env_file: str | None = None,
    ) -> bytes:
        """Load or generate identity, with non-interactive passphrase sources.

        Tries passphrase sources in order:
        1. passphrase_fd (file descriptor passed by caller)
        2. passphrase_env_file (path passed by caller)
        3. DSM_PASSPHRASE_FILE env var (path, must be mode 0600)
        4. DSM_PASSPHRASE env var (weakest, visible in /proc)
        5. Interactive tty prompt (fallback)

        Reads the passphrase into a mutable ``bytearray`` so it can be wiped
        after use — the usual ``getpass.getpass`` path routes the passphrase
        through immutable ``str``/``bytes`` that CPython can intern and will
        not reliably zero.

        Returns the public key bytes.
        """
        # Try non-interactive sources first
        passphrase = _get_passphrase_noninteractive(
            passphrase_fd=passphrase_fd,
            passphrase_env_file=passphrase_env_file,
        )

        # Fall back to interactive prompt
        if passphrase is None:
            passphrase = _read_passphrase_into_bytearray("Key passphrase: ")

        try:
            if self.exists():
                pub = self.load(passphrase)
            else:
                pub = self.generate(passphrase)
                log.info("generated new identity keypair")
        finally:
            _wipe(passphrase)
        log.info("identity loaded")
        return pub

    def load_or_generate_interactive(self) -> bytes:
        """Legacy name for load_or_generate (interactive fallback only)."""
        return self.load_or_generate()

