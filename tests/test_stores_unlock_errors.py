"""Key unlock with a bad passphrase source: one line, never a traceback
(QA B2). The stores are mocks; the passphrase files live in tmp_path."""

from __future__ import annotations

import logging
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from dsm.crypto._stores import load_daemon_stores, loaded_stores_cli


def _pass_file(folder: Path, data: bytes) -> Path:
    folder.mkdir(exist_ok=True)
    path = folder / "passphrase"
    path.write_bytes(data)
    path.chmod(0o600)
    return path


@pytest.fixture(autouse=True)
def _no_unit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    monkeypatch.delenv("DSM_PASSPHRASE", raising=False)
    monkeypatch.delenv("DSM_PASSPHRASE_FILE", raising=False)


def test_an_empty_file_is_one_error_line(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.ERROR, logger="dsm")
    keystore = MagicMock()
    path = _pass_file(tmp_path, b"")

    assert (
        load_daemon_stores(keystore, MagicMock(), passphrase_env_file=str(path))
        is False
    )

    assert [r.getMessage() for r in caplog.records] == [
        f"cannot unlock the keys: passphrase must not be empty: {path} is empty"
    ]
    assert caplog.records[0].exc_info is None
    keystore.load_with_passphrase.assert_not_called()


def test_a_missing_file_is_one_error_line(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.ERROR, logger="dsm")
    missing = tmp_path / "passphrase"

    assert (
        load_daemon_stores(MagicMock(), MagicMock(), passphrase_env_file=str(missing))
        is False
    )

    assert [r.getMessage() for r in caplog.records] == [
        f"cannot unlock the keys: passphrase file {missing} not found"
    ]


def test_under_systemd_the_line_names_the_real_file(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    creds = tmp_path / "credentials"
    path = _pass_file(creds, b"")
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds))
    caplog.set_level(logging.ERROR, logger="dsm")

    assert (
        load_daemon_stores(MagicMock(), MagicMock(), passphrase_env_file=str(path))
        is False
    )

    (line,) = [r.getMessage() for r in caplog.records]
    assert line.startswith("cannot unlock the keys: passphrase must not be empty")
    assert "/etc/dsm/passphrase" in line
    assert "restart the unit" in line


def test_the_cli_variant_exits_2_with_one_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = _pass_file(tmp_path, b"")
    with pytest.raises(SystemExit) as err:
        with loaded_stores_cli(
            MagicMock(),
            MagicMock(),
            passphrase_env_file=str(path),
            key_file_label="identity.key",
            attest_key_file_label="attest.key",
        ):
            pass
    assert err.value.code == 2
    assert capsys.readouterr().err.startswith(
        "cannot unlock the keys: passphrase must not be empty"
    )


def test_on_unlocked_gets_the_passphrase_that_opened_both_stores(
    tmp_path: Path,
) -> None:
    path = _pass_file(tmp_path, b"hunter2hunter2\n")
    seen: list[bytes] = []
    with loaded_stores_cli(
        MagicMock(),
        MagicMock(),
        passphrase_env_file=str(path),
        key_file_label="identity.key",
        attest_key_file_label="attest.key",
        on_unlocked=lambda pw: seen.append(bytes(pw)),
    ):
        pass
    assert seen == [b"hunter2hunter2"]


def test_on_unlocked_is_not_called_when_a_store_does_not_open(tmp_path: Path) -> None:
    path = _pass_file(tmp_path, b"hunter2hunter2\n")
    keystore = MagicMock()
    keystore.load_with_passphrase.side_effect = RuntimeError("wrong passphrase")
    seen: list[bytearray] = []
    with pytest.raises(SystemExit):
        with loaded_stores_cli(
            keystore,
            MagicMock(),
            passphrase_env_file=str(path),
            key_file_label="identity.key",
            attest_key_file_label="attest.key",
            on_unlocked=seen.append,
        ):
            pass
    assert seen == []
