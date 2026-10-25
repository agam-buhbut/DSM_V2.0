"""Allowlist messages a user can act on (QA Minor 6)."""

from __future__ import annotations

import logging
import os
from pathlib import Path

import pytest

from dsm.crypto.cert_allowlist import CNAllowlist, CNAllowlistError


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "allowed_cns.txt"
    path.write_text(text)
    path.chmod(0o600)
    return path


def test_a_missing_file_says_not_found(tmp_path: Path) -> None:
    path = tmp_path / "allowed_cns.txt"
    with pytest.raises(CNAllowlistError) as err:
        CNAllowlist.from_file(path)
    assert str(err.value) == (
        f"{path} not found: create it with one client CN per line "
        "(deploy/GUIDE.md §4)"
    )


def test_a_comment_after_a_name_says_where_comments_go(tmp_path: Path) -> None:
    path = _write(tmp_path, "dsm-aaaa-client\ndsm-bbbb-client  # laptop\n")
    with pytest.raises(CNAllowlistError) as err:
        CNAllowlist.from_file(path)
    assert str(err.value) == (
        f"{path}:2: put a comment on a line of its own (a CN has no '#')"
    )


def test_a_repeated_name_is_warned_about(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING, logger="dsm")
    path = _write(tmp_path, "dsm-aaaa-client\ndsm-bbbb-client\ndsm-aaaa-client\n")
    allowlist = CNAllowlist.from_file(path)
    assert allowlist.order == ("dsm-aaaa-client", "dsm-bbbb-client")
    assert [r.getMessage() for r in caplog.records] == [
        f"{path}:3: dsm-aaaa-client is already on line 1; this line does not count"
    ]


@pytest.mark.skipif(os.geteuid() == 0, reason="root can search any folder")
def test_a_file_in_a_folder_that_cannot_be_searched_is_not_called_missing(
    tmp_path: Path,
) -> None:
    locked = tmp_path / "locked"
    locked.mkdir()
    path = _write(locked, "dsm-aaaa-client\n")
    locked.chmod(0o000)
    try:
        with pytest.raises(CNAllowlistError) as err:
            CNAllowlist.from_file(path)
    finally:
        locked.chmod(0o700)
    assert "not found" not in str(err.value)
    assert "Permission denied" in str(err.value)
