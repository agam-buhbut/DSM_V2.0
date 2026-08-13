"""File-I/O error handling for ``dsm.crypto.cert_allowlist.CNAllowlist``.

The server uses ``CNAllowlist.from_file`` to decide *which* CA-issued
client CNs are permitted to connect. Every failure to load that file
must FAIL CLOSED: raise the typed :class:`CNAllowlistError` rather than
returning an empty/partial allowlist or letting an OSError escape
untyped. A silently-empty allowlist would deny everyone (DoS), but a
silently *successful* load of attacker-influenced/garbage content, or a
raw OSError that a caller might paper over, is the real hazard this
covers.

Gaps targeted (complementing ``tests/test_cert_allowlist.py``):

  * missing file            -> typed error, no partial result
  * read denied (OSError)   -> typed error, original errno chained
  * malformed CN (tab/space)-> typed error, file NOT accepted
  * symlink rejection        -> typed error (path-security fail-closed)

All filesystem state is under ``tmp_path``; no network, no sleeps.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from dsm.core.path_security import InsecureFilePermissionsError
from dsm.crypto.cert_allowlist import CNAllowlist, CNAllowlistError

# The read-denied and symlink-bypass cases rely on the kernel actually
# enforcing DAC. root bypasses mode bits, so the negative assertions
# would not hold; skip rather than report a misleading pass.
_running_as_root = os.getuid() == 0


def _write_allowlist(path: Path, text: str, mode: int = 0o600) -> None:
    """Write an allowlist file owned by us with secure (no group/world)
    perms so it passes ``check_user_file_permissions`` and exercises the
    parse/read path under test."""
    path.write_text(text, encoding="utf-8")
    os.chmod(path, mode)


def test_missing_file_raises_typed_error_not_empty_allowlist(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "does-not-exist.txt"
    assert not missing.exists()

    with pytest.raises(CNAllowlistError) as exc:
        CNAllowlist.from_file(missing)

    # A missing file must NOT degrade into an empty (deny-all but
    # silently-loaded) allowlist object — it must raise, fail-closed,
    # and the typed error must chain the underlying stat/permission
    # failure rather than swallowing it.
    assert exc.value.__cause__ is not None
    assert isinstance(exc.value.__cause__, OSError)


@pytest.mark.skipif(
    _running_as_root, reason="root bypasses DAC; read-denied path untestable"
)
def test_read_denied_raises_typed_error_chaining_oserror(tmp_path: Path) -> None:
    # Mode 0o000 is owner-only with NO group/world bits, so it PASSES
    # check_user_file_permissions (owner == us, no shared bits) yet
    # read_text() is denied. This isolates the read-failure branch
    # (the genuine gap) from the permission-policy branch.
    path = tmp_path / "allowlist.txt"
    _write_allowlist(path, "dsm-a3f29c81-client\n", mode=0o000)

    try:
        with pytest.raises(CNAllowlistError) as exc:
            CNAllowlist.from_file(path)
    finally:
        os.chmod(path, 0o600)

    # A read failure must surface as the typed allowlist error with
    # the original PermissionError chained — never as a bare OSError that
    # a caller might mistake for "no clients configured", and never a
    # success.
    cause = exc.value.__cause__
    assert isinstance(cause, PermissionError)
    # Distinguish from the permission-POLICY rejection: that path chains
    # InsecureFilePermissionsError. Here the policy check PASSED and the
    # raw read is what failed.
    assert not isinstance(cause, InsecureFilePermissionsError)


def test_malformed_cn_with_internal_space_rejects_whole_file(
    tmp_path: Path,
) -> None:
    # A valid CN precedes the malformed one; a fail-open implementation
    # might accept the good line and skip the bad one.
    path = tmp_path / "allowlist.txt"
    _write_allowlist(path, "dsm-good-client\ndsm bad client\n")

    with pytest.raises(CNAllowlistError):
        CNAllowlist.from_file(path)


def test_malformed_cn_with_tab_rejects_whole_file(tmp_path: Path) -> None:
    path = tmp_path / "allowlist.txt"
    _write_allowlist(path, "dsm-good-client\ndsm\tbad-client\n")

    with pytest.raises(CNAllowlistError) as exc:
        CNAllowlist.from_file(path)

    # The malformed entry must abort the whole load — the otherwise
    # valid CN on the preceding line must NOT leak through into an
    # allowlist object. Prove no partial CNAllowlist is returned by
    # confirming the call raised (no object) and reporting the offending
    # line number, so a fail-open "skip bad lines" regression is caught.
    assert "dsm-good-client" not in str(exc.value)
    assert ":2:" in str(exc.value)


@pytest.mark.skipif(
    _running_as_root, reason="root may satisfy owner check on link target"
)
def test_symlink_to_valid_file_is_rejected(tmp_path: Path) -> None:
    # Defense in depth: even when the symlink target is a perfectly valid,
    # secure allowlist we own, the path-security layer refuses to follow
    # the link. A fail-open load here would let a swapped link feed
    # attacker-chosen content.
    real = tmp_path / "real_allowlist.txt"
    _write_allowlist(real, "dsm-a3f29c81-client\n")
    link = tmp_path / "allowlist_link.txt"
    link.symlink_to(real)

    with pytest.raises(CNAllowlistError) as exc:
        CNAllowlist.from_file(link)

    assert isinstance(exc.value.__cause__, InsecureFilePermissionsError)
    assert "symlink" in str(exc.value).lower()


def test_group_readable_file_is_rejected(tmp_path: Path) -> None:
    # Permission-POLICY branch (distinct from read-denied above): a file
    # we own but that is group-readable must be refused so a CN list
    # cannot be tampered with by group members.
    path = tmp_path / "allowlist.txt"
    _write_allowlist(path, "dsm-a3f29c81-client\n", mode=0o640)

    with pytest.raises(CNAllowlistError) as exc:
        CNAllowlist.from_file(path)

    assert isinstance(exc.value.__cause__, InsecureFilePermissionsError)


def test_valid_secure_file_loads_so_negatives_are_meaningful(
    tmp_path: Path,
) -> None:
    # Control: the SAME helper/perms the negative tests rely on must
    # actually produce a working allowlist, proving those tests fail for
    # the intended reason (the I/O fault) and not because every load
    # raises regardless.
    path = tmp_path / "allowlist.txt"
    _write_allowlist(path, "dsm-a3f29c81-client\ndsm-9f001122-client\n")

    allowlist = CNAllowlist.from_file(path)

    assert len(allowlist.cns) == 2
    assert allowlist.is_allowed("dsm-a3f29c81-client")
    assert not allowlist.is_allowed("dsm-deadbeef-client")
