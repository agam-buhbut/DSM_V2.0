"""Regression: an explicitly-configured but unreadable ``DSM_PASSPHRASE_FILE``
must fail closed instead of silently downgrading to the weaker,
process-visible ``DSM_PASSPHRASE`` environment variable.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from dsm.core.passphrase import _read_noninteractive


class TestPassphraseFileFailsClosed:
    def test_unreadable_file_does_not_fall_back_to_env(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        missing = tmp_path / "missing-passphrase"
        monkeypatch.setenv("DSM_PASSPHRASE_FILE", str(missing))
        monkeypatch.setenv("DSM_PASSPHRASE", "weaker-fallback-secret")
        with pytest.raises(ValueError, match="DSM_PASSPHRASE_FILE is set"):
            _read_noninteractive(None, None)

    def test_env_var_used_when_no_file_configured(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("DSM_PASSPHRASE_FILE", raising=False)
        monkeypatch.setenv("DSM_PASSPHRASE", "env-secret")
        got = _read_noninteractive(None, None)
        assert got is not None
        assert bytes(got) == b"env-secret"
