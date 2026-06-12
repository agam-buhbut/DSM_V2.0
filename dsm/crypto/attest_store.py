"""Encrypted on-disk store for the device's hardware-bound attest key.

The operator passphrase protects the attest key on BOTH backends (Task 3.12):

  * Soft backend: the signing scalar is wrapped with Argon2id +
    XChaCha20-Poly1305, identical to the identity store.
  * TPM backend: the key is TPM-resident and never leaves the chip, so the
    passphrase is bound as the key's TPM authorization value (via
    ``TPM2_ObjectChangeAuth`` at store time, re-installed via
    ``tr_set_auth`` at sign time). TPM residency AND the passphrase are then
    both required to sign — an attacker holding the on-disk ``DSMT`` blob and
    TPM access still cannot sign without the passphrase, and the TPM's
    dictionary-attack lockout rate-limits guessing.

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


def _store_passphrase(passphrase: bytes | bytearray) -> bytes:
    """Operator passphrase for the Rust store shim — load-bearing on BOTH
    backends (Task 3.12).

    The real passphrase is passed through unchanged regardless of backend:

      * Soft backend seals the signing scalar under it (Argon2id +
        XChaCha20-Poly1305).
      * TPM backend binds it as the key's TPM authorization value
        (``encrypt_to_store`` runs ``TPM2_ObjectChangeAuth``;
        ``decrypt_from_store`` caches the derived auth for ``sign``).

    The TCTI that selects which TPM to talk to is threaded via the ``TCTI``
    env var by the enroll/daemon entry points (the Rust backend reads it),
    not by this store.
    """
    return bytes(passphrase)


class AttestStore:
    """Manages the device attest key's on-disk persistence.

    Backend-agnostic: the operator passphrase protects the key on both the
    soft (Argon2id seal) and TPM (key TPM-auth) backends — see the module
    docstring. The active backend is selected at wheel build time.
    """

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
        blob = bytes(ak.encrypt_to_store(_store_passphrase(passphrase)))
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
        ak = tuncore.AttestKey.decrypt_from_store(blob, _store_passphrase(passphrase))
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
