"""KeyStore passphrase/blob error-recovery paths (untested gap).

Companion to ``test_keystore_wrong_pass.py``, which already locks the
*wrong passphrase* case (a valid blob that fails AEAD authentication). This
file covers the OTHER ways ``KeyStore.load`` can be fed bad input — a
malformed, truncated, or hostile on-disk blob, and a non-UTF-8 / empty
passphrase — and asserts each fails LOUDLY with a typed ``RuntimeError``
(tuncore maps every Rust store error to ``PyRuntimeError``) rather than
crashing the interpreter, returning a bogus key, or being mistaken for the
wrong-passphrase path.

Security property under test, made discriminating by the error MESSAGE:

  * A *structurally* invalid blob (too short, bad version byte, hostile
    out-of-bounds Argon2id parameters) is rejected by a cheap up-front
    check BEFORE the 512-MiB Argon2id KDF runs. The message is
    ``"blob too short"`` / ``"unsupported sealed-blob version"`` /
    ``"out of bounds"`` — NOT the ``"...wrong passphrase or corrupted
    data"`` string the AEAD path emits. A test that merely asserted
    ``RuntimeError`` would pass even if the cheap guard regressed into a
    full KDF run (a DoS amplification bug); asserting the distinct message
    proves the guard fired and the two failure classes stay separable.

  * An empty passphrase is refused with ``"passphrase must not be empty"``
    before any KDF/AEAD work.

  * A non-UTF-8 passphrase is a fully valid input (the store takes raw
    bytes, never decodes them): it round-trips a real identity and a
    *wrong* non-UTF-8 guess still fails closed — proving the byte path is
    not silently lossy.

Cost control: Argon2id is deliberately ~512 MiB / 4 iters per call. The
structural-rejection tests reach the failure BEFORE the KDF and cost
nothing. Exactly ONE real keystore blob is sealed (class-level, shared)
plus one extra seal+open for the non-UTF-8 round-trip — three KDF runs
total for the whole module.

All files live under ``tmp_path`` (pytest fixture) with 0600 perms so the
keystore's permission gate — which runs before any decrypt — does not
short-circuit these tests. No mocking of the crypto: the real KeyStore and
real tuncore store are exercised end to end.
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

# Sealed-blob wire constants (mirror passphrase_store.rs). Used only to
# build deliberately-malformed blobs; the values are a stable on-disk
# contract, not an implementation detail likely to drift.
_BLOB_MAGIC = b"DSMK"
_BLOB_VERSION_1 = 1
_V1_HEADER_LEN = 17
_SALT_LEN = 32
_NONCE_LEN = 24
_TAG_LEN = 16
# X25519 scalar length; decrypt_from_store does its OWN up-front length
# check tied to this expected plaintext before delegating to the store's
# open(), so a hostile blob must clear it to reach the header param guard.
_SECRET_LEN = 32
_MIN_V1_BLOB_LEN = _V1_HEADER_LEN + _SALT_LEN + _NONCE_LEN + _TAG_LEN
# Smallest blob that passes decrypt_from_store's identity-layer guard
# (salt + nonce + secret + tag, plus the v1 header) and thus reaches the
# in-header KDF-parameter bounds check.
_MIN_IDENTITY_V1_BLOB_LEN = (
    _V1_HEADER_LEN + _SALT_LEN + _NONCE_LEN + _SECRET_LEN + _TAG_LEN
)


def _chmod_0600(path: Path) -> None:
    """Pin 0600 so KeyStore.load's permission gate accepts the file.

    The gate runs BEFORE the file is read/decrypted, so without this it
    would mask the decrypt-path error we are actually testing.
    """
    os.chmod(path, 0o600)


@unittest.skipUnless(_HAS_TUNCORE, "tuncore extension not built")
class KeyStoreErrorPathsTest(unittest.TestCase):
    """Malformed-input recovery for KeyStore.load / .generate."""

    # One real Argon2id seal for the whole class — generated once and
    # reused read-only by the structural tests (which never decrypt it).
    _provisioned_blob: bytes

    @classmethod
    def setUpClass(cls) -> None:
        with TemporaryDirectory() as d:
            seed_path = Path(d) / "seed.key"
            store = KeyStore(str(seed_path))
            store.generate(CORRECT)  # one KDF run
            store.unload()
            cls._provisioned_blob = seed_path.read_bytes()
        # Sanity: a freshly sealed blob is a v1 blob.
        assert cls._provisioned_blob[:4] == _BLOB_MAGIC

    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)

    def _store_with_blob(self, blob: bytes, name: str = "id.key") -> KeyStore:
        """Write ``blob`` to a fresh 0600 file and return a KeyStore on it."""
        path = self.tmp / name
        path.write_bytes(blob)
        _chmod_0600(path)
        return KeyStore(str(path))

    # Structural rejections must fail before the Argon2id KDF runs.

    def test_truncated_blob_raises_blob_too_short(self) -> None:
        # A too-short blob is rejected by the up-front length
        # guard with the DISTINCT "blob too short" message — not the
        # wrong-passphrase / corruption string — and crucially before the
        # 512-MiB KDF runs. Truncate the real blob to one byte under the
        # v1 minimum so it is unambiguously short yet keeps the v1 magic.
        truncated = self._provisioned_blob[: _MIN_V1_BLOB_LEN - 1]
        store = self._store_with_blob(truncated)
        with self.assertRaises(RuntimeError) as ctx:
            store.load(CORRECT)
        msg = str(ctx.exception).lower()
        self.assertIn("too short", msg)
        # Discriminates from the wrong-passphrase path (which says
        # "passphrase or corrupted data"): this is a structural reject.
        self.assertNotIn("corrupted data", msg)
        self.assertFalse(store.is_loaded)

    def test_empty_blob_raises_typed_error_not_crash(self) -> None:
        # A zero-length file (e.g. an interrupted write) must surface a
        # typed RuntimeError, never an IndexError/panic from slicing.
        store = self._store_with_blob(b"")
        with self.assertRaises(RuntimeError):
            store.load(CORRECT)
        self.assertFalse(store.is_loaded)

    def test_bad_version_byte_raises_unsupported_version(self) -> None:
        # A blob carrying the v1 magic but an unknown version
        # byte is rejected with "unsupported sealed-blob version" — a
        # forward-compat guard distinct from both the short-blob and the
        # wrong-passphrase paths — again before any KDF work.
        b = bytearray(self._provisioned_blob)
        b[4] = 0xFE  # version 1 -> 0xFE
        store = self._store_with_blob(bytes(b))
        with self.assertRaises(RuntimeError) as ctx:
            store.load(CORRECT)
        msg = str(ctx.exception).lower()
        self.assertIn("version", msg)
        self.assertFalse(store.is_loaded)

    def test_hostile_oversize_kdf_params_rejected_before_kdf(self) -> None:
        # DoS guard: a hostile blob advertising
        # m_cost = u32::MAX in its header must be rejected by the bounds
        # check ("out of bounds") BEFORE the KDF — no multi-GiB allocation
        # is ever attempted. Asserting the bounds message (not a generic
        # RuntimeError) is what proves the cheap guard fired instead of the
        # process OOM-ing on a malicious key file. Build a minimal valid-
        # length v1 frame with a poisoned m_cost field.
        blob = bytearray()
        blob += _BLOB_MAGIC
        blob.append(_BLOB_VERSION_1)
        blob += (0xFFFFFFFF).to_bytes(4, "big")  # m_cost_kib = u32::MAX
        blob += (4).to_bytes(4, "big")  # t_cost (in-bounds)
        blob += (2).to_bytes(4, "big")  # parallelism (in-bounds)
        # Pad the body so the blob clears decrypt_from_store's own length
        # guard and the header param bounds check is the first thing hit.
        blob += b"\x00" * (_MIN_IDENTITY_V1_BLOB_LEN - _V1_HEADER_LEN)
        self.assertEqual(len(blob), _MIN_IDENTITY_V1_BLOB_LEN)
        store = self._store_with_blob(bytes(blob))
        with self.assertRaises(RuntimeError) as ctx:
            store.load(CORRECT)
        msg = str(ctx.exception).lower()
        self.assertIn("out of bounds", msg)
        self.assertFalse(store.is_loaded)

    def test_garbage_blob_raises_runtime_error(self) -> None:
        # A blob long enough to pass the length gate but with no valid
        # magic falls to the legacy path and fails AEAD auth — still a
        # typed RuntimeError, never a crash. Random-looking 0x42 fill.
        store = self._store_with_blob(b"\x42" * (_MIN_V1_BLOB_LEN + 16))
        with self.assertRaises(RuntimeError):
            store.load(CORRECT)
        self.assertFalse(store.is_loaded)

    def test_empty_passphrase_rejected_on_generate(self) -> None:
        # An empty passphrase is refused at seal time with
        # the explicit "must not be empty" message — it never produces a
        # weakly-protected blob on disk. (Reaches the cheap guard before
        # the KDF.)
        store = KeyStore(str(self.tmp / "empty.key"))
        with self.assertRaises(RuntimeError) as ctx:
            store.generate(b"")
        self.assertIn("empty", str(ctx.exception).lower())
        self.assertFalse(store.is_loaded)
        # And nothing was written to disk.
        self.assertFalse((self.tmp / "empty.key").exists())

    def test_empty_passphrase_rejected_on_load(self) -> None:
        # Loading a real blob with an empty passphrase is likewise refused
        # before the KDF with the "must not be empty" message — distinct
        # from a wrong-but-nonempty passphrase, which would fail AEAD auth.
        store = self._store_with_blob(self._provisioned_blob)
        with self.assertRaises(RuntimeError) as ctx:
            store.load(b"")
        self.assertIn("empty", str(ctx.exception).lower())
        self.assertFalse(store.is_loaded)

    def test_non_utf8_passphrase_round_trips_and_fails_closed(self) -> None:
        # The passphrase path is raw-bytes, never UTF-8
        # decoded. A non-UTF-8 passphrase (lone 0x80, NUL, 0xFF...) must
        # (a) successfully seal AND unlock a real identity round-trip, and
        # (b) when a DIFFERENT non-UTF-8 guess is used, fail closed with a
        # typed RuntimeError naming the passphrase — not crash on an
        # encoding error and not silently accept the wrong key. This is the
        # ONE non-structural test that pays for a seal + open KDF pair.
        non_utf8 = b"\x80\x00\xff\xfe-binary-pass\x81"
        with self.assertRaises(UnicodeDecodeError):
            non_utf8.decode("utf-8")  # confirm it is genuinely non-UTF-8

        path = self.tmp / "binary.key"
        store = KeyStore(str(path))
        original_pub = store.generate(non_utf8)
        _chmod_0600(path)
        store.unload()

        reloaded = KeyStore(str(path))
        recovered_pub = reloaded.load(non_utf8)
        self.assertEqual(recovered_pub, original_pub)
        self.assertTrue(reloaded.is_loaded)

        # A different non-UTF-8 guess fails the AEAD tag — fail closed.
        wrong_store = KeyStore(str(path))
        with self.assertRaises(RuntimeError) as ctx:
            wrong_store.load(b"\xff\xfe-wrong-binary\x00")
        self.assertIn("passphrase", str(ctx.exception).lower())
        self.assertFalse(wrong_store.is_loaded)


if __name__ == "__main__":
    unittest.main()
