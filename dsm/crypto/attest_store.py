"""Encrypted on-disk store for the device's hardware-bound attest key.

Soft attest backend only: the key is wrapped with Argon2id +
XChaCha20-Poly1305, identical to the identity store. TPM and Android
Keystore backends seal the key natively (TPM persistent handle, Keystore
alias) and do not produce a passphrase blob — those backends will live in
a sibling module.

Mirrors ``dsm.crypto.keystore.KeyStore`` so both stores can share the
same passphrase: caller reads the passphrase once via
``dsm.core.passphrase.read_passphrase`` and hands it to both stores.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from dsm.core.atomic_io import atomic_write
from dsm.core.path_security import check_user_file_permissions

if TYPE_CHECKING:
    import tuncore

log = logging.getLogger(__name__)


class AttestStore:
    """Manages the device attest key's on-disk persistence (soft backend)."""

    def __init__(self, attest_key_file: str) -> None:
        self._path = Path(attest_key_file)
        self._key: tuncore.AttestKey | None = None

    @property
    def path(self) -> Path:
        return self._path

    @property
    def is_loaded(self) -> bool:
        return self._key is not None

    @property
    def attest_key(self) -> tuncore.AttestKey:
        if self._key is None:
            raise RuntimeError("attest key not loaded — call load() or generate()")
        return self._key

    def public_spki_der(self) -> bytes:
        return bytes(self.attest_key.public_spki_der())

    def exists(self) -> bool:
        return self._path.is_file()

    def generate(self, passphrase: bytes | bytearray) -> bytes:
        """Generate a fresh attest key, encrypt to disk, return SPKI DER."""
        import tuncore

        ak = tuncore.AttestKey.generate()
        blob = bytes(ak.encrypt_to_store(bytes(passphrase)))
        atomic_write(self._path, blob)
        self._key = ak
        return bytes(ak.public_spki_der())

    def load(self, passphrase: bytes | bytearray) -> bytes:
        """Decrypt the attest key from disk, return SPKI DER.

        Refuses to read the file unless it is owned by the current user
        and carries no group/world permission bits.
        """
        check_user_file_permissions(self._path)

        import tuncore

        blob = self._path.read_bytes()
        ak = tuncore.AttestKey.decrypt_from_store(blob, bytes(passphrase))
        self._key = ak
        return bytes(ak.public_spki_der())

    def load_with_passphrase(self, passphrase: bytes | bytearray) -> bytes:
        """Load the existing attest key with a pre-read passphrase.

        Refuses to auto-generate at runtime: the daemon must never be
        the place a fresh attest key first appears (that's `dsm enroll`).
        Returns the SPKI DER.
        """
        if not self.exists():
            raise RuntimeError(
                f"attest key file missing at {self._path}; run "
                "`dsm enroll` to provision one"
            )
        return self.load(passphrase)

    def unload(self) -> None:
        """Zeroize and unload the attest key.

        Calls the Rust-side explicit ``zeroize`` before clearing the
        Python reference. ``ZeroizeOnDrop`` would also wipe on
        refcount-zero, but only after every Python holder drops it; an
        eager wipe ensures that even a stale reference held by an
        in-flight coroutine sees a scrubbed scalar. Mirrors
        ``KeyStore.unload``. Safe to call multiple times.
        """
        if self._key is not None:
            self._key.zeroize()
            self._key = None
