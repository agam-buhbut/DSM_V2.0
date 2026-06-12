"""KeyStore wrong-passphrase path (untested per PRODUCTION_REVIEW).

``KeyStore.load`` decrypts the at-rest identity via tuncore's Argon2id +
XChaCha20-Poly1305 store. The security property under test: decrypting with
the WRONG passphrase fails LOUDLY with a typed error — it must not silently
return a bogus/empty key or crash the interpreter. The correct passphrase
round-trips back the same public key.

Exercised end-to-end through the real KeyStore + real tuncore store (no
mocking of the crypto): generate() writes an encrypted blob, load() reads
it. Files live under tmp_path with 0600 perms so the keystore's
permission gate (which runs before decrypt) does not short-circuit the
test. Argon2id is deliberately slow, so this keeps to a single
wrong-passphrase attempt plus one correct unlock.
"""

from __future__ import annotations

import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

try:
    import tuncore

    _HAS_TUNCORE = True
except ImportError:
    tuncore = None  # type: ignore[assignment]
    _HAS_TUNCORE = False

from dsm.crypto.keystore import KeyStore

CORRECT = b"correct-horse-battery-staple"
WRONG = b"wrong-passphrase-entirely"


@unittest.skipUnless(_HAS_TUNCORE, "tuncore extension not built")
class KeyStoreWrongPassphraseTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.key_path = Path(self._tmp.name) / "identity.key"

    def _make_store(self) -> tuple[KeyStore, bytes]:
        """Provision an encrypted identity; return (store, public_key)."""
        store = KeyStore(str(self.key_path))
        pub = store.generate(CORRECT)
        # generate() goes through atomic_write; pin 0600 so the load()
        # permission gate accepts the file (it runs before decrypt).
        os.chmod(self.key_path, 0o600)
        store.unload()
        return store, pub

    def test_correct_passphrase_round_trips_same_public_key(self) -> None:
        _store, original_pub = self._make_store()
        reloaded = KeyStore(str(self.key_path))
        pub = reloaded.load(CORRECT)
        self.assertEqual(pub, original_pub)
        self.assertTrue(reloaded.is_loaded)

    def test_wrong_passphrase_raises_typed_error(self) -> None:
        # KEY PROPERTY: a wrong passphrase fails closed with a typed,
        # non-silent error (AEAD tag rejection), not a bogus key and not a
        # crash. We assert the error class and that the identity stays
        # unloaded.
        self._make_store()
        reloaded = KeyStore(str(self.key_path))
        with self.assertRaises(RuntimeError) as ctx:
            reloaded.load(WRONG)
        # The message names the cause, distinguishing it from unrelated
        # RuntimeErrors (e.g. "identity not loaded").
        self.assertIn("passphrase", str(ctx.exception).lower())
        # Nothing was loaded into memory on the failed unlock.
        self.assertFalse(reloaded.is_loaded)
        with self.assertRaises(RuntimeError):
            _ = reloaded.identity


if __name__ == "__main__":
    unittest.main()
