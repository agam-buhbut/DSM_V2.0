"""Where the key passphrase comes from (QA B2, M10).

A passphrase file named with --passphrase-env-file is the only source DSM
tries: a missing, unsafe or empty file stops with one clear line and never
falls back to the terminal (under systemd stdin is /dev/null, so a prompt
reads nothing and hides the cause). A new passphrase typed at a terminal is
asked twice. No real terminal is read: the tty reader is faked.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from dsm.core import passphrase
from dsm.core.passphrase import PassphraseError, read_passphrase, wipe_passphrase


@pytest.fixture(autouse=True)
def _no_env_sources(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.delenv("DSM_PASSPHRASE", raising=False)
    monkeypatch.delenv("DSM_PASSPHRASE_FILE", raising=False)
    yield


def _no_tty(*_a: object, **_k: object) -> bytearray:
    raise AssertionError("fell back to the terminal")


def _file(tmp_path: Path, data: bytes, mode: int = 0o600) -> Path:
    path = tmp_path / "passphrase"
    path.write_bytes(data)
    path.chmod(mode)
    return path


def test_a_missing_file_says_not_found(tmp_path: Path) -> None:
    missing = tmp_path / "passphrase"
    with patch.object(passphrase, "_read_from_tty", _no_tty):
        with pytest.raises(PassphraseError) as err:
            read_passphrase(passphrase_env_file=str(missing))
    assert str(err.value) == f"passphrase file {missing} not found"


def test_an_unsafe_file_says_how_to_fix_it(tmp_path: Path) -> None:
    path = _file(tmp_path, b"secret\n", mode=0o644)
    with patch.object(passphrase, "_read_from_tty", _no_tty):
        with pytest.raises(PassphraseError) as err:
            read_passphrase(passphrase_env_file=str(path))
    assert str(err.value).startswith(f"cannot read the passphrase file {path}: ")
    assert f"chmod 600 {path}" in str(err.value)


def test_an_empty_file_names_the_file(tmp_path: Path) -> None:
    path = _file(tmp_path, b"\n")
    with patch.object(passphrase, "_read_from_tty", _no_tty):
        with pytest.raises(PassphraseError) as err:
            read_passphrase(passphrase_env_file=str(path))
    assert str(err.value) == f"passphrase must not be empty: {path} is empty"


def test_a_good_file_is_read(tmp_path: Path) -> None:
    buf = read_passphrase(passphrase_env_file=str(_file(tmp_path, b"correct horse\n")))
    try:
        assert bytes(buf) == b"correct horse"
    finally:
        wipe_passphrase(buf)


def test_the_error_is_still_a_value_error() -> None:
    # dsm enroll and dsm init catch ValueError.
    assert issubclass(PassphraseError, ValueError)


def _tty(*answers: bytes) -> MagicMock:
    return MagicMock(side_effect=[bytearray(a) for a in answers])


def _stdin(*, tty: bool) -> MagicMock:
    stdin = MagicMock()
    stdin.isatty.return_value = tty
    return stdin


def test_a_new_passphrase_is_asked_twice_at_a_terminal() -> None:
    tty = _tty(b"one secret", b"one secret")
    with (
        patch.object(passphrase, "_read_from_tty", tty),
        patch.object(passphrase.sys, "stdin", _stdin(tty=True)),
    ):
        buf = read_passphrase(prompt="New passphrase: ", confirm=True)
    try:
        assert bytes(buf) == b"one secret"
    finally:
        wipe_passphrase(buf)
    assert tty.call_count == 2


def test_two_different_answers_stop_with_one_line() -> None:
    tty = _tty(b"one secret", b"one secrte")
    with (
        patch.object(passphrase, "_read_from_tty", tty),
        patch.object(passphrase.sys, "stdin", _stdin(tty=True)),
        pytest.raises(PassphraseError, match="the two passphrases do not match"),
    ):
        read_passphrase(prompt="New passphrase: ", confirm=True)


def test_without_confirm_the_terminal_is_asked_once() -> None:
    tty = _tty(b"one secret")
    with (
        patch.object(passphrase, "_read_from_tty", tty),
        patch.object(passphrase.sys, "stdin", _stdin(tty=True)),
    ):
        wipe_passphrase(read_passphrase())
    assert tty.call_count == 1


def test_piped_input_is_not_asked_twice() -> None:
    # A script that pipes the passphrase in sends it once.
    tty = _tty(b"one secret")
    with (
        patch.object(passphrase, "_read_from_tty", tty),
        patch.object(passphrase.sys, "stdin", _stdin(tty=False)),
    ):
        wipe_passphrase(read_passphrase(confirm=True))
    assert tty.call_count == 1
