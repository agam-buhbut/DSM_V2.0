"""Python-side key store: loads identity from encrypted file, auto-locks."""

from __future__ import annotations

import logging
import os
import sys
import tempfile
import termios
from pathlib import Path
from typing import TYPE_CHECKING

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
        for i in range(len(buf)):
            buf[i] = 0
        raise
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_attrs)
        sys.stderr.write("\n")
        sys.stderr.flush()

    return buf


def _wipe(buf: bytearray) -> None:
    """Zero a bytearray in place."""
    for i in range(len(buf)):
        buf[i] = 0


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
        self._atomic_write(blob)
        self._identity = kp
        return bytes(kp.public_key)

    def load(self, passphrase: bytes | bytearray) -> bytes:
        """Load identity from encrypted file.

        See ``generate`` for notes on ``bytearray`` passphrase handling.

        Returns the public key bytes.
        """
        import tuncore

        blob = self._path.read_bytes()
        kp = tuncore.IdentityKeyPair.decrypt_from_store(blob, bytes(passphrase))
        self._identity = kp
        return bytes(kp.public_key)

    def unload(self) -> None:
        """Zeroize and unload the identity from memory."""
        self._identity = None

    def exists(self) -> bool:
        return self._path.is_file()

    def load_or_generate_interactive(self) -> bytes:
        """Prompt for passphrase and load or generate identity.

        Reads the passphrase into a mutable ``bytearray`` so it can be wiped
        after use — the usual ``getpass.getpass`` path routes the passphrase
        through immutable ``str``/``bytes`` that CPython can intern and will
        not reliably zero.

        Returns the public key bytes.
        """
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

    def _atomic_write(self, data: bytes) -> None:
        """Write data atomically to prevent partial writes on crash."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self._path.parent)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, data)
            os.fsync(fd)
            os.close(fd)
            fd = -1
            os.rename(tmp, self._path)
        except BaseException:
            if fd >= 0:
                os.close(fd)
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
