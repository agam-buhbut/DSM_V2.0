"""Tests for dsm.crypto.keystore — permission hardening."""

import os
import tempfile
import unittest
from pathlib import Path

from dsm.core.path_security import (
    InsecureFilePermissionsError,
    check_user_file_permissions,
)
from dsm.crypto.keystore import KeyStore


class TestPathPermissions(unittest.TestCase):
    def test_accepts_0o600_owned_file(self) -> None:
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = Path(f.name)
        try:
            os.chmod(path, 0o600)
            check_user_file_permissions(path)
        finally:
            path.unlink()

    def test_rejects_group_readable(self) -> None:
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = Path(f.name)
        try:
            os.chmod(path, 0o640)
            with self.assertRaises(InsecureFilePermissionsError):
                check_user_file_permissions(path)
        finally:
            path.unlink()

    def test_rejects_world_readable(self) -> None:
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = Path(f.name)
        try:
            os.chmod(path, 0o604)
            with self.assertRaises(InsecureFilePermissionsError):
                check_user_file_permissions(path)
        finally:
            path.unlink()

    def test_rejects_missing_file(self) -> None:
        with self.assertRaises(InsecureFilePermissionsError):
            check_user_file_permissions(Path("/nonexistent/does/not/exist"))


class TestKeyStorePermissionCheck(unittest.TestCase):
    def test_load_rejects_permissive_key_file(self) -> None:
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = Path(f.name)
            f.write(b"\x00" * 128)  # arbitrary bytes, load should not reach decrypt
        try:
            os.chmod(path, 0o644)
            store = KeyStore(str(path))
            with self.assertRaises(InsecureFilePermissionsError):
                store.load(b"any-passphrase")
        finally:
            path.unlink()


if __name__ == "__main__":
    unittest.main()
