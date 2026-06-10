"""Tests for ``dsm.crypto._stores.load_daemon_stores`` (DSM-012).

The daemon-variant store loader must FAIL CLOSED — log at ERROR and
return ``False`` — when a store file has insecure permissions, rather
than letting the ``InsecureFilePermissionsError`` (an ``OSError``
subclass) escape as an unhandled traceback out of ``asyncio.run``. The
widen-to-OSError fix is what this locks.

The first test (keystore is the insecure file) needs no tuncore: the
permission check in ``KeyStore.load`` runs BEFORE the file content is
read / the Rust decrypt is invoked, so a dummy 0o644 file is enough.

The second test (attest file is the insecure one) requires the keystore
to load SUCCESSFULLY first so the attest path is reached; that crosses
the Rust FFI to mint a real encrypted blob, so it is tuncore-gated.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

try:
    import tuncore

    _HAS_TUNCORE = True
except ImportError:
    tuncore = None  # type: ignore[assignment]
    _HAS_TUNCORE = False

from dsm.crypto._stores import load_daemon_stores
from dsm.crypto.attest_store import AttestStore
from dsm.crypto.keystore import KeyStore


class TestLoadDaemonStoresInsecureKeystore(unittest.TestCase):
    """Keystore file has insecure perms → load_daemon_stores returns False
    (does NOT raise) and logs at ERROR."""

    def setUp(self) -> None:
        self._tmpdir = Path(tempfile.mkdtemp())
        # Insecure key file. Perms are checked before any decrypt, so a
        # dummy 0o644 blob suffices — no valid Argon2id keystore needed.
        self.key_path = self._tmpdir / "id.key"
        self.key_path.write_bytes(b"\x00" * 64)
        os.chmod(self.key_path, 0o644)

        # A separate (secure) attest path; it should never be reached
        # because the keystore fails first.
        self.attest_path = self._tmpdir / "attest.key"

        # 0o600 passphrase env-file so read_passphrase has a source.
        self.pass_path = self._tmpdir / "pass"
        self.pass_path.write_bytes(b"hunter2\n")
        os.chmod(self.pass_path, 0o600)

    def tearDown(self) -> None:
        for p in (self.key_path, self.attest_path, self.pass_path):
            try:
                p.unlink()
            except FileNotFoundError:
                pass
        try:
            self._tmpdir.rmdir()
        except OSError:
            pass

    def test_returns_false_and_logs_error(self) -> None:
        keystore = KeyStore(str(self.key_path))
        attest_store = AttestStore(str(self.attest_path))

        with self.assertLogs("dsm.crypto._stores", level="ERROR") as cm:
            result = load_daemon_stores(
                keystore,
                attest_store,
                passphrase_env_file=str(self.pass_path),
            )

        self.assertFalse(result)
        # Logged against the identity store, not the attest store.
        self.assertTrue(
            any("identity store" in line for line in cm.output),
            cm.output,
        )
        # Keystore never became loaded.
        self.assertFalse(keystore.is_loaded)


@unittest.skipUnless(
    _HAS_TUNCORE,
    "tuncore (Rust crypto core) not built; run `maturin develop` in rust/tuncore/",
)
class TestLoadDaemonStoresInsecureAttest(unittest.TestCase):
    """Attest file has insecure perms → load_daemon_stores returns False
    AND unloads the already-loaded keystore before returning (DSM-012's
    documented partial-load cleanup)."""

    def setUp(self) -> None:
        self._tmpdir = Path(tempfile.mkdtemp())
        self.passphrase = b"correct horse battery staple"

        # A REAL keystore that loads cleanly: generate, then chmod 0o600.
        self.key_path = self._tmpdir / "id.key"
        ks = KeyStore(str(self.key_path))
        ks.generate(self.passphrase)
        ks.unload()
        os.chmod(self.key_path, 0o600)

        # The attest file is the INSECURE one. Perms are checked before
        # decrypt, so a dummy 0o644 blob is enough to trip the failure.
        self.attest_path = self._tmpdir / "attest.key"
        self.attest_path.write_bytes(b"\x00" * 64)
        os.chmod(self.attest_path, 0o644)

        self.pass_path = self._tmpdir / "pass"
        self.pass_path.write_bytes(self.passphrase + b"\n")
        os.chmod(self.pass_path, 0o600)

    def tearDown(self) -> None:
        for p in (self.key_path, self.attest_path, self.pass_path):
            try:
                p.unlink()
            except FileNotFoundError:
                pass
        try:
            self._tmpdir.rmdir()
        except OSError:
            pass

    def test_keystore_unloaded_before_false_return(self) -> None:
        keystore = KeyStore(str(self.key_path))
        attest_store = AttestStore(str(self.attest_path))

        # Spy on keystore.unload by wrapping the bound method.
        unload_calls: list[bool] = []
        real_unload = keystore.unload

        def _spy_unload() -> None:
            unload_calls.append(True)
            real_unload()

        keystore.unload = _spy_unload  # type: ignore[method-assign]

        with self.assertLogs("dsm.crypto._stores", level="ERROR") as cm:
            result = load_daemon_stores(
                keystore,
                attest_store,
                passphrase_env_file=str(self.pass_path),
            )

        self.assertFalse(result)
        # The failure was on the attest store (keystore loaded fine first).
        self.assertTrue(
            any("attest store" in line for line in cm.output),
            cm.output,
        )
        # The partial-load cleanup ran: keystore.unload was called and the
        # keystore is no longer loaded on the False return.
        self.assertEqual(len(unload_calls), 1)
        self.assertFalse(keystore.is_loaded)


if __name__ == "__main__":
    unittest.main()
