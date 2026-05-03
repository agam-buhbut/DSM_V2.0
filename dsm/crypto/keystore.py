"""Python-side key store: loads identity from encrypted file, auto-locks."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from dsm.core.atomic_io import atomic_write
from dsm.core.passphrase import read_passphrase, wipe_passphrase
from dsm.core.path_security import check_user_file_permissions

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
        # PyO3 returns Vec<u8> as Python list[int]; coerce to bytes before
        # handing to os.write via atomic_write.
        blob = bytes(kp.encrypt_to_store(bytes(passphrase)))
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

    def load_or_generate_with_passphrase(
        self, passphrase: bytes | bytearray
    ) -> bytes:
        """Load (or generate) the identity with a pre-read passphrase.

        Use this when the same passphrase must unlock multiple stores
        (e.g. identity + attest store) so the caller can read the
        passphrase once and pass it to each store.
        """
        if self.exists():
            pub = self.load(passphrase)
        else:
            pub = self.generate(passphrase)
            log.info("generated new identity keypair")
        log.info("identity loaded")
        return pub

    def load_or_generate(
        self,
        passphrase_fd: int | None = None,
        passphrase_env_file: str | None = None,
    ) -> bytes:
        """Load or generate identity, reading the passphrase once.

        Tries passphrase sources in order:
        1. ``passphrase_fd`` (fd passed by caller)
        2. ``passphrase_env_file`` (path passed by caller)
        3. ``DSM_PASSPHRASE_FILE`` env var (path, must be mode 0600)
        4. ``DSM_PASSPHRASE`` env var (weakest, visible in /proc)
        5. Interactive tty prompt (fallback)

        Returns the public key bytes.
        """
        passphrase = read_passphrase(
            passphrase_fd=passphrase_fd,
            passphrase_env_file=passphrase_env_file,
        )
        try:
            return self.load_or_generate_with_passphrase(passphrase)
        finally:
            wipe_passphrase(passphrase)

    def load_or_generate_interactive(self) -> bytes:
        """Legacy name for load_or_generate (interactive fallback only)."""
        return self.load_or_generate()
