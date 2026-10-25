"""Fixes from the QA round's final review that have no round test file to
go in. Files live in tmp_path."""

from __future__ import annotations

from pathlib import Path

import pytest

from dsm.core import preflight


def test_odd_bytes_from_timedatectl_mean_cannot_tell(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = tmp_path / "timedatectl"
    fake.write_text("#!/bin/sh\nprintf '\\377yes\\n'\n")
    fake.chmod(0o700)
    monkeypatch.setenv("PATH", str(tmp_path))
    assert preflight.ntp_synchronized() is None
    assert preflight.check_clock_sync() is None
