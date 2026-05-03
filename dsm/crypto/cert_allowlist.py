"""CN-based allowlist for cert-authenticated peers.

Server-side: which client subject CNs are permitted to connect.
Replaces the HMAC-protected ``authorized_clients.json`` (which stored
raw 32-byte X25519 pubkeys) with a simple newline-delimited file of
device CNs. The cert chain plus the binding extension already prove
the connecting peer holds the matching hardware-bound signing key
*and* the matching X25519 Noise static; the allowlist's job is to say
"of the certs this CA legitimately issued, which CNs are permitted."

File format:
    # comments start with '#'
    dsm-a3f29c81-client
    dsm-9f001122-client
    ...

File permissions are enforced (mode 0o400/0o600/0o640) via the same
``check_user_file_permissions`` policy used by the keystore.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from dsm.core.path_security import check_user_file_permissions


class CNAllowlistError(Exception):
    """Allowlist file cannot be loaded or is malformed."""


@dataclass(frozen=True)
class CNAllowlist:
    cns: frozenset[str]

    @classmethod
    def from_file(cls, path: Path) -> CNAllowlist:
        try:
            check_user_file_permissions(path)
        except Exception as e:
            raise CNAllowlistError(
                f"refusing to load CN allowlist with insecure permissions: {e}"
            ) from e
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as e:
            raise CNAllowlistError(
                f"failed to read CN allowlist {path}: {e}"
            ) from e
        cns: set[str] = set()
        for lineno, raw in enumerate(text.splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if " " in line or "\t" in line:
                raise CNAllowlistError(
                    f"{path}:{lineno}: CN must not contain whitespace"
                )
            cns.add(line)
        return cls(cns=frozenset(cns))

    def is_allowed(self, cn: str) -> bool:
        return cn in self.cns

    def __len__(self) -> int:
        return len(self.cns)
