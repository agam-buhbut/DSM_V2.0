"""Shared keystore + attest-store load/unload scaffolding.

The CLI and daemon entry points each duplicate the same shape of code:

  1. read the passphrase
  2. try to unlock keystore → if RuntimeError, surface + bail
  3. try to unlock attest store → if RuntimeError, unload keystore + bail
  4. wipe the passphrase in the outer ``finally``
  5. unload both stores at the end of the operation (the ``finally`` of
     whatever uses the unlocked keys)

The CLI variant exits with ``sys.exit(2)`` on failure; the daemon
variant ``return``s so the surrounding ``AsyncExitStack`` keeps
unwinding cleanly. Both variants share the load order (keystore first,
attest second) and the unload order (attest first, keystore second) —
that asymmetry exists because keystore loads first but unloads LAST in
the daemon's :class:`contextlib.AsyncExitStack` registration. Each
caller chooses the variant matching its exit shape.
"""

from __future__ import annotations

import contextlib
import logging
import os
import sys
from collections.abc import Callable, Generator
from pathlib import Path

from dsm.core.passphrase import read_passphrase, wipe_passphrase
from dsm.crypto.attest_store import AttestStore
from dsm.crypto.keystore import KeyStore

log = logging.getLogger(__name__)


def _unit_hint(passphrase_env_file: str | None) -> str:
    """Point at the real file when the passphrase comes from a systemd
    credential: the user fixes /etc/dsm/passphrase, not the copy."""
    creds = os.environ.get("CREDENTIALS_DIRECTORY")
    if not passphrase_env_file or not creds:
        return ""
    if Path(passphrase_env_file).parent != Path(creds):
        return ""
    unit = Path(creds).name  # the folder is named after the unit
    return (
        ". Under systemd this file is a copy of the unit's LoadCredential= "
        "file, /etc/dsm/passphrase unless you changed the unit: put the "
        "passphrase there (deploy/GUIDE.md §3e), then reset and restart the "
        f"unit: `sudo systemctl reset-failed {unit} && sudo systemctl "
        f"restart {unit}`"
    )


@contextlib.contextmanager
def loaded_stores_cli(
    keystore: KeyStore,
    attest_store: AttestStore,
    *,
    passphrase_fd: int | None = None,
    passphrase_env_file: str | None = None,
    prompt: str = "Key passphrase: ",
    key_file_label: str,
    attest_key_file_label: str,
    on_unlocked: Callable[[bytearray], None] | None = None,
) -> Generator[None, None, None]:
    """CLI variant: unlock both stores, ``sys.exit(2)`` on failure.

    The ``key_file_label`` / ``attest_key_file_label`` strings appear in
    operator-facing error text — caller passes the configured paths so a
    failure message names the actual file.

    On success, the ``with`` block runs with both stores loaded; on
    exit (success or exception), both stores are unloaded. The
    passphrase is wiped before yielding so the ``with`` body never sees
    it (handing it down would defeat the wipeable-bytearray invariant).

    ``on_unlocked``, when given, is called once with the passphrase after
    both stores opened with it, before it is wiped; it must not keep the
    buffer.
    """
    try:
        passphrase = read_passphrase(
            passphrase_fd=passphrase_fd,
            passphrase_env_file=passphrase_env_file,
            prompt=prompt,
        )
    except ValueError as e:
        # An empty, missing or unsafe passphrase source: one line (QA B2).
        print(f"cannot unlock the keys: {e}", file=sys.stderr)
        sys.exit(2)
    try:
        try:
            keystore.load_with_passphrase(passphrase)
        # CLI boundary: any unlock failure exits 2
        except Exception as e:  # noqa: BLE001
            print(
                f"failed to unlock identity at {key_file_label}: "
                f"{type(e).__name__}: {e}",
                file=sys.stderr,
            )
            sys.exit(2)
        try:
            attest_store.load_with_passphrase(passphrase)
        # CLI boundary: any unlock failure exits 2
        except Exception as e:  # noqa: BLE001
            print(
                f"failed to unlock attest key at {attest_key_file_label}: "
                f"{type(e).__name__}: {e}",
                file=sys.stderr,
            )
            keystore.unload()
            sys.exit(2)
        if on_unlocked is not None:
            # Both stores opened with it, so it is the right passphrase.
            try:
                on_unlocked(passphrase)
            except BaseException:
                attest_store.unload()
                keystore.unload()
                raise
    finally:
        wipe_passphrase(passphrase)

    try:
        yield
    finally:
        attest_store.unload()
        keystore.unload()


def load_daemon_stores(
    keystore: KeyStore,
    attest_store: AttestStore,
    *,
    passphrase_fd: int | None = None,
    passphrase_env_file: str | None = None,
) -> bool:
    """Daemon variant: unlock both stores, log + return False on failure.

    Returns True on success (both stores loaded; caller is responsible
    for arranging unload via the surrounding ``AsyncExitStack``).
    Returns False on failure, having already logged and unloaded any
    partially-loaded store. The passphrase is wiped before this function
    returns either way.
    """
    try:
        passphrase = read_passphrase(
            passphrase_fd=passphrase_fd,
            passphrase_env_file=passphrase_env_file,
        )
    except ValueError as e:
        # An empty, missing or unsafe passphrase source is a setup mistake:
        # one line, no traceback (QA B2). The caller exits 1, and the
        # client's kill switch follows its usual rule: down on a run by
        # hand, kept under dsm-client.service.
        log.error("cannot unlock the keys: %s%s", e, _unit_hint(passphrase_env_file))
        return False
    try:
        try:
            keystore.load_with_passphrase(passphrase)
        except (RuntimeError, OSError) as e:
            # DSM-012: widen from RuntimeError to also catch OSError so the
            # documented "log + return False" contract holds for the
            # insecure-permissions case. KeyStore.load →
            # check_user_file_permissions raises InsecureFilePermissionsError
            # (an OSError subclass) and read_bytes() raises OSError; neither is
            # a RuntimeError, so they previously escaped as an unhandled
            # traceback out of asyncio.run instead of failing closed. Still
            # narrow — ValueError/TypeError (programming bugs) propagate.
            log.error("identity store: %s", e)
            return False
        try:
            attest_store.load_with_passphrase(passphrase)
        except (RuntimeError, OSError) as e:
            # DSM-012: see the identity-store handler above — widen to OSError
            # so insecure-perms / read errors honor the return-False contract.
            log.error("attest store: %s", e)
            keystore.unload()
            return False
    finally:
        wipe_passphrase(passphrase)
    return True
