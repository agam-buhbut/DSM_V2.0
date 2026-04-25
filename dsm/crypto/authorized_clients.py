"""Authorized client public key management (TOFU + allowlist)."""

from __future__ import annotations

import hmac
import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING

from dsm.core.atomic_io import atomic_write
from dsm.core.path_security import check_user_file_permissions

if TYPE_CHECKING:
    import tuncore

log = logging.getLogger(__name__)


class AuthorizedClients:
    """Manage trusted client public keys with HMAC-SHA256 integrity."""

    def __init__(self, path: Path, identity: tuncore.IdentityKeyPair) -> None:
        """
        Args:
            path: Path to authorized_clients.json file
            identity: Rust identity keypair (for HMAC key derivation)
        """
        self._path = Path(path)
        self._identity = identity
        self._clients: set[bytes] = set()
        self._dirty = False

    def load(self) -> None:
        """Load authorized clients from disk.

        File format:
            {
              "version": 1,
              "entries": [
                {"pubkey_hex": "...", "hmac": "..."},
                ...
              ]
            }

        Rejects file if HMAC verification fails.
        """
        if not self._path.exists():
            log.info("authorized clients file does not exist yet")
            return

        check_user_file_permissions(self._path)

        try:
            blob = json.loads(self._path.read_text())
        except (json.JSONDecodeError, OSError) as e:
            raise RuntimeError(f"failed to load authorized_clients: {e}")

        if blob.get("version") != 1:
            raise RuntimeError("unsupported authorized_clients version")

        entries = blob.get("entries", [])
        for entry in entries:
            try:
                pubkey_hex = entry["pubkey_hex"]
                stored_hmac = bytes.fromhex(entry["hmac"])
                pubkey = bytes.fromhex(pubkey_hex)

                # Verify HMAC. compute_hmac returns a Python list[int] over
                # the FFI boundary; wrap in bytes() for constant-time compare.
                expected_hmac = bytes(self._identity.compute_hmac(
                    b"dsm-authorized-clients-v1-",
                    pubkey,
                ))
                if not hmac.compare_digest(stored_hmac, expected_hmac):
                    raise ValueError("HMAC verification failed")

                self._clients.add(pubkey)
            except (KeyError, ValueError) as e:
                log.warning("skipping malformed entry: %s", e)

        log.info("loaded %d authorized clients", len(self._clients))

    def save(self) -> None:
        """Save authorized clients to disk with HMAC integrity."""
        entries: list[dict[str, str]] = []
        for pubkey in sorted(self._clients):
            hmac_tag = bytes(self._identity.compute_hmac(
                b"dsm-authorized-clients-v1-",
                pubkey,
            ))
            entries.append({
                "pubkey_hex": pubkey.hex(),
                "hmac": hmac_tag.hex(),
            })

        blob: dict[str, object] = {
            "version": 1,
            "entries": entries,
        }
        atomic_write(self._path, json.dumps(blob, indent=2).encode())
        self._dirty = False

    def is_authorized(self, pubkey: bytes) -> bool:
        """Check if a client public key is authorized."""
        return pubkey in self._clients

    def add(self, pubkey: bytes) -> None:
        """Add a client public key to the allowlist."""
        if len(pubkey) != 32:
            raise ValueError("public key must be 32 bytes")
        if pubkey not in self._clients:
            self._clients.add(pubkey)
            self._dirty = True
            log.info("added client pubkey: %s", pubkey.hex()[:16])

    def __len__(self) -> int:
        return len(self._clients)
