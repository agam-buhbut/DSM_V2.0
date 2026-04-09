"""Python-side key store: loads identity from encrypted file, auto-locks."""

from __future__ import annotations

import getpass
import logging
import os
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import tuncore

log = logging.getLogger(__name__)


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

    def generate(self, passphrase: bytes) -> bytes:
        """Generate a new identity keypair and save to disk.

        Returns the public key bytes.
        """
        import tuncore

        kp = tuncore.IdentityKeyPair.generate()
        blob = kp.encrypt_to_store(passphrase)
        self._atomic_write(blob)
        self._identity = kp
        return bytes(kp.public_key)

    def load(self, passphrase: bytes) -> bytes:
        """Load identity from encrypted file.

        Returns the public key bytes.
        """
        import tuncore

        blob = self._path.read_bytes()
        kp = tuncore.IdentityKeyPair.decrypt_from_store(blob, passphrase)
        self._identity = kp
        return bytes(kp.public_key)

    def unload(self) -> None:
        """Zeroize and unload the identity from memory."""
        self._identity = None

    def exists(self) -> bool:
        return self._path.is_file()

    def load_or_generate_interactive(self) -> bytes:
        """Prompt for passphrase and load or generate identity.

        Returns the public key bytes. Zeroizes the passphrase after use.
        """
        passphrase = bytearray(getpass.getpass("Key passphrase: ").encode())
        try:
            if self.exists():
                pub = self.load(bytes(passphrase))
            else:
                pub = self.generate(bytes(passphrase))
                log.info("generated new identity keypair")
        finally:
            passphrase[:] = b"\x00" * len(passphrase)
            del passphrase
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
