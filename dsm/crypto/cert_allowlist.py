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

import logging
import os
from dataclasses import dataclass
from pathlib import Path

from dsm.core.path_security import check_user_file_permissions

log = logging.getLogger(__name__)


class CNAllowlistError(Exception):
    """Allowlist file cannot be loaded or is malformed."""


@dataclass(frozen=True)
class CNAllowlist:
    cns: frozenset[str]
    # The file's order, each CN once at its first line: the n-th CN gets the
    # n-th tunnel address (multi-client spec §2.3). Built directly (tests):
    # the names sorted.
    order: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.order:
            # The dataclass is frozen; this is how a field is set after init.
            object.__setattr__(self, "order", tuple(sorted(self.cns)))

    @classmethod
    def from_file(cls, path: Path) -> CNAllowlist:
        try:
            check_user_file_permissions(path)
        except Exception as e:
            # Chained either way (tests/test_cert_allowlist_io.py wants the
            # OS error kept). Only a missing file is "not found": a dangling
            # symlink is there, and a folder that cannot be searched is not
            # missing, so both get the permission check's own text.
            try:
                os.lstat(path)
            except FileNotFoundError:
                raise CNAllowlistError(
                    f"{path} not found: create it with one client CN per line "
                    "(deploy/GUIDE.md §4)"
                ) from e
            except OSError:
                pass  # the permission check's text below says what failed
            raise CNAllowlistError(
                f"refusing to load CN allowlist with insecure permissions: {e}"
            ) from e
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as e:
            raise CNAllowlistError(f"failed to read CN allowlist {path}: {e}") from e
        names: list[str] = []
        first_line: dict[str, int] = {}
        for lineno, raw in enumerate(text.splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "#" in line:
                raise CNAllowlistError(
                    f"{path}:{lineno}: put a comment on a line of its own "
                    "(a CN has no '#')"
                )
            if " " in line or "\t" in line:
                raise CNAllowlistError(
                    f"{path}:{lineno}: CN must not contain whitespace"
                )
            if line in first_line:
                # Only the first line of a name counts, so it keeps its
                # tunnel address; say so, as a repeat is usually a slip.
                log.warning(
                    "%s:%d: %s is already on line %d; this line does not count",
                    path,
                    lineno,
                    line,
                    first_line[line],
                )
                continue
            first_line[line] = lineno
            names.append(line)
        order = tuple(names)
        return cls(cns=frozenset(order), order=order)

    def is_allowed(self, cn: str) -> bool:
        return cn in self.cns

    def __len__(self) -> int:
        return len(self.cns)
