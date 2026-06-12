"""Regression: ``read_passphrase`` must reject an EMPTY passphrase from any
operator source (DSM security audit, HIGH).

An empty passphrase (empty ``--passphrase-fd``, empty env-file, or a bare
Enter at the prompt) previously flowed through enroll/startup unchecked.
On the TPM attest backend that produces an UNPROTECTED empty-auth key,
while the soft backend already rejects empty (``passphrase_store.rs``).
``read_passphrase`` now enforces the same non-empty contract at the
single operator entry point so BOTH backends fail closed identically.

The non-interactive fd source (``os.pipe``) drives the exact final
emptiness check the tty path also hits, deterministically and without a
tty.
"""

from __future__ import annotations

import contextlib
import io
import os
import secrets
import tempfile
import unittest
from pathlib import Path

from dsm.core.passphrase import read_passphrase, wipe_passphrase


class TestReadPassphraseRejectsEmpty(unittest.TestCase):
    """An empty non-interactive source raises ValueError("must not be
    empty"); a non-empty source still returns the bytes."""

    def test_empty_fd_source_raises(self) -> None:
        # Writing only a newline (which _read_from_fd treats as the
        # terminator) yields a zero-length buffer — the empty case.
        r, w = os.pipe()
        try:
            os.write(w, b"\n")
            os.close(w)
            w = -1
            with self.assertRaises(ValueError) as ctx:
                read_passphrase(passphrase_fd=r)
        finally:
            os.close(r)
            if w != -1:
                os.close(w)
        self.assertIn("must not be empty", str(ctx.exception))

    def test_closed_empty_fd_source_raises(self) -> None:
        # An immediately-closed write end (EOF, no bytes at all) is also
        # the empty case.
        r, w = os.pipe()
        try:
            os.close(w)
            w = -1
            with self.assertRaises(ValueError) as ctx:
                read_passphrase(passphrase_fd=r)
        finally:
            os.close(r)
            if w != -1:
                os.close(w)
        self.assertIn("must not be empty", str(ctx.exception))

    def test_empty_env_file_source_raises(self) -> None:
        tmpdir = Path(tempfile.mkdtemp())
        try:
            pass_path = tmpdir / "pass"
            pass_path.write_bytes(b"")
            os.chmod(pass_path, 0o600)
            with self.assertRaises(ValueError) as ctx:
                read_passphrase(passphrase_env_file=str(pass_path))
            self.assertIn("must not be empty", str(ctx.exception))
        finally:
            for p in tmpdir.iterdir():
                p.unlink()
            tmpdir.rmdir()

    def test_nonempty_fd_source_returns_bytes(self) -> None:
        # Sanity: a 1+ byte passphrase still round-trips unchanged.
        r, w = os.pipe()
        try:
            os.write(w, b"hunter2\n")
            os.close(w)
            w = -1
            buf = read_passphrase(passphrase_fd=r)
        finally:
            os.close(r)
            if w != -1:
                os.close(w)
        try:
            self.assertEqual(bytes(buf), b"hunter2")
        finally:
            wipe_passphrase(buf)

    def test_nonempty_env_file_source_returns_bytes(self) -> None:
        tmpdir = Path(tempfile.mkdtemp())
        try:
            pass_path = tmpdir / "pass"
            pass_path.write_bytes(b"correct horse\n")
            os.chmod(pass_path, 0o600)
            buf = read_passphrase(passphrase_env_file=str(pass_path))
            try:
                self.assertEqual(bytes(buf), b"correct horse")
            finally:
                wipe_passphrase(buf)
        finally:
            for p in tmpdir.iterdir():
                p.unlink()
            tmpdir.rmdir()


class TestEnrollRejectsEmptyPassphrase(unittest.TestCase):
    """End-to-end (in-process, mirroring tests/test_cli.py): ``_run_enroll``
    with an empty passphrase exits 2 with a clean ``enroll:`` message on
    stderr and writes NO key files — fail closed before provisioning."""

    def setUp(self) -> None:
        self._tmpdir = Path(tempfile.mkdtemp())
        self.key_file = self._tmpdir / "id.key"
        self.attest_file = self._tmpdir / "attest.key"
        self.csr_out = self._tmpdir / "device.csr"

        self.config_path = self._tmpdir / "config.toml"
        self.config_path.write_bytes(
            b"".join(
                [
                    b'mode = "client"\n',
                    b'server_ip = "10.0.0.1"\n',
                    b"server_port = 51820\n",
                    b"listen_port = 51821\n",
                    b'key_file = "' + str(self.key_file).encode() + b'"\n',
                    b'cert_file = "/tmp/dsm-pp-'
                    + secrets.token_hex(4).encode()
                    + b'.crt"\n',
                    b'ca_root_file = "/tmp/dsm-pp-ca.pem"\n',
                    b'attest_key_file = "' + str(self.attest_file).encode() + b'"\n',
                    b'expected_server_cn = "dsm-test-server"\n',
                    b'transport = "udp"\n',
                ]
            )
        )
        os.chmod(self.config_path, 0o600)

    def tearDown(self) -> None:
        for p in self._tmpdir.iterdir():
            try:
                p.unlink()
            except FileNotFoundError:
                pass
        try:
            self._tmpdir.rmdir()
        except OSError:
            pass

    def test_enroll_empty_passphrase_exits_2_writes_nothing(self) -> None:
        from dsm.__main__ import _run_enroll

        # Empty passphrase via an fd (bare newline -> zero-length).
        r, w = os.pipe()
        try:
            os.write(w, b"\n")
            os.close(w)
            w = -1
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as ctx:
                    _run_enroll(
                        self.config_path,
                        csr_out=self.csr_out,
                        import_cert=None,
                        cn=None,
                        role="client",
                        passphrase_fd=r,
                        passphrase_env_file=None,
                    )
        finally:
            os.close(r)
            if w != -1:
                os.close(w)

        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("must not be empty", stderr.getvalue())
        # Fail closed: no key files / CSR were written.
        self.assertFalse(self.key_file.exists())
        self.assertFalse(self.attest_file.exists())
        self.assertFalse(self.csr_out.exists())


if __name__ == "__main__":
    unittest.main()
