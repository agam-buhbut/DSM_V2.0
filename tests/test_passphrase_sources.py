"""Where the key passphrase comes from (QA B2, M10).

A passphrase file named with --passphrase-env-file is the only source DSM
tries: a missing, unsafe or empty file stops with one clear line and never
falls back to the terminal (under systemd stdin is /dev/null, so a prompt
reads nothing and hides the cause). A new passphrase typed at a terminal is
asked twice. No real terminal is read: the tty reader is faked, and its own
tests fake termios and os.read. Ctrl-C at the prompt stops the read at once.
"""

from __future__ import annotations

import contextlib
import os
import signal
import termios
import threading
from collections.abc import Callable, Generator, Iterator
from pathlib import Path
from types import FrameType, SimpleNamespace
from typing import Any
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
    answers = [bytearray(b"one secret"), bytearray(b"one secrte")]
    tty = MagicMock(side_effect=answers)
    with (
        patch.object(passphrase, "_read_from_tty", tty),
        patch.object(passphrase.sys, "stdin", _stdin(tty=True)),
        pytest.raises(PassphraseError, match="the two passphrases do not match"),
    ):
        read_passphrase(prompt="New passphrase: ", confirm=True)
    assert all(not any(a) for a in answers)


def test_a_cut_off_second_prompt_wipes_the_first_answer() -> None:
    first = bytearray(b"one secret")
    tty = MagicMock(side_effect=[first, KeyboardInterrupt()])
    with (
        patch.object(passphrase, "_read_from_tty", tty),
        patch.object(passphrase.sys, "stdin", _stdin(tty=True)),
        pytest.raises(KeyboardInterrupt),
    ):
        read_passphrase(prompt="New passphrase: ", confirm=True)
    assert not any(first)


def test_a_bare_enter_with_confirm_asks_only_once() -> None:
    tty = _tty(b"")
    with (
        patch.object(passphrase, "_read_from_tty", tty),
        patch.object(passphrase.sys, "stdin", _stdin(tty=True)),
        pytest.raises(PassphraseError, match="must not be empty"),
    ):
        read_passphrase(confirm=True)
    assert tty.call_count == 1


def test_env_sources_do_not_rescue_a_missing_named_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    other = _file(tmp_path, b"from the env file\n")
    monkeypatch.setenv("DSM_PASSPHRASE_FILE", str(other))
    monkeypatch.setenv("DSM_PASSPHRASE", "from the env")
    missing = tmp_path / "nope"
    with patch.object(passphrase, "_read_from_tty", _no_tty):
        with pytest.raises(PassphraseError, match="not found"):
            read_passphrase(passphrase_env_file=str(missing))


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory modes")
def test_a_file_in_an_unreadable_folder_is_not_called_missing(tmp_path: Path) -> None:
    folder = tmp_path / "locked"
    folder.mkdir()
    path = folder / "passphrase"
    path.write_bytes(b"secret\n")
    path.chmod(0o600)
    folder.chmod(0o000)
    try:
        with patch.object(passphrase, "_read_from_tty", _no_tty):
            with pytest.raises(PassphraseError) as err:
                read_passphrase(passphrase_env_file=str(path))
    finally:
        folder.chmod(0o700)
    assert str(err.value).startswith(f"cannot read the passphrase file {path}: ")


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


# --- the terminal read itself -------------------------------------------------

_ATTRS: list[Any] = [0, 0, 0, termios.ECHO | termios.ICANON | termios.ISIG, 0, 0, []]


def _noted(_signum: int, _frame: FrameType | None) -> None:
    """A SIGINT handler that only notes the signal, as the client's asyncio
    handler does."""


@pytest.fixture
def loop_sigint() -> Iterator[None]:
    old = signal.signal(signal.SIGINT, _noted)
    try:
        yield
    finally:
        signal.signal(signal.SIGINT, old)


class _Terminal:
    """termios and os.read for _read_from_tty. Each read returns the next
    typed byte, or runs the next callable (a Ctrl-C), and notes the SIGINT
    handler in place."""

    def __init__(self, *typed: bytes | Callable[[], bytes]) -> None:
        self.typed = list(typed)
        self.attrs_set: list[list[Any]] = []
        self.handlers: list[object] = []

    def tcgetattr(self, _fd: int) -> list[Any]:
        return [*_ATTRS[:6], []]

    def tcsetattr(self, _fd: int, _when: int, attrs: list[Any]) -> None:
        self.attrs_set.append(list(attrs))

    def read(self, _fd: int, _n: int) -> bytes:
        self.handlers.append(signal.getsignal(signal.SIGINT))
        step = self.typed.pop(0)
        return step() if callable(step) else step


@contextlib.contextmanager
def _at(term: _Terminal) -> Generator[list[tuple[bytes, bytearray]], None, None]:
    """Run _read_from_tty on ``term``; yields each buffer it wiped, with
    what it held first."""
    wiped: list[tuple[bytes, bytearray]] = []

    def wipe(buf: bytearray) -> None:
        wiped.append((bytes(buf), buf))
        wipe_passphrase(buf)

    fake_termios = SimpleNamespace(
        ECHO=termios.ECHO,
        TCSADRAIN=termios.TCSADRAIN,
        tcgetattr=term.tcgetattr,
        tcsetattr=term.tcsetattr,
    )
    stdin = _stdin(tty=True)
    stdin.fileno.return_value = 0
    with (
        patch.object(passphrase, "termios", fake_termios),
        patch.object(passphrase, "os", SimpleNamespace(read=term.read)),
        patch.object(passphrase, "wipe_passphrase", wipe),
        patch.object(passphrase.sys, "stdin", stdin),
    ):
        yield wiped


def _ctrl_c() -> bytes:
    signal.raise_signal(signal.SIGINT)  # what the terminal sends
    return b"x"  # reached only if the handler in place did not raise


@pytest.mark.usefixtures("loop_sigint")
@pytest.mark.parametrize(
    "ctrl_c",
    # As the terminal sends it, and as a byte (with `stty -isig`).
    [_ctrl_c, lambda: b"\x03"],
    ids=["signal", "byte"],
)
def test_ctrl_c_at_the_prompt_stops_the_read_at_once(
    ctrl_c: Callable[[], bytes],
) -> None:
    term = _Terminal(b"a", b"b", ctrl_c, b"c", b"\n")
    with _at(term) as wiped, pytest.raises(KeyboardInterrupt):
        passphrase._read_from_tty("Key passphrase: ")
    assert term.typed == [b"c", b"\n"]  # no read after the Ctrl-C
    assert wiped == [(b"ab", bytearray(2))]
    assert signal.getsignal(signal.SIGINT) is _noted
    assert term.attrs_set[-1] == _ATTRS


@pytest.mark.usefixtures("loop_sigint")
def test_the_read_sets_the_default_ctrl_c_handler_only_while_it_runs() -> None:
    term = _Terminal(b"s", b"e", b"\n")
    with _at(term) as wiped:
        buf = passphrase._read_from_tty("Key passphrase: ")
    assert buf == bytearray(b"se")
    assert term.handlers == [signal.default_int_handler] * 3
    assert signal.getsignal(signal.SIGINT) is _noted
    # Only echo goes off: the terminal still edits the line.
    no_echo = [*_ATTRS[:3], _ATTRS[3] & ~termios.ECHO, *_ATTRS[4:]]
    assert term.attrs_set == [no_echo, _ATTRS]
    assert wiped == []
    wipe_passphrase(buf)


@pytest.mark.usefixtures("loop_sigint")
def test_off_the_main_thread_the_ctrl_c_handler_is_left_alone() -> None:
    term = _Terminal(b"s", b"\n")
    out: list[bytearray | ValueError] = []

    def read() -> None:
        try:
            out.append(passphrase._read_from_tty("Key passphrase: "))
        except ValueError as e:  # signal.signal off the main thread
            out.append(e)

    with _at(term):
        worker = threading.Thread(target=read)
        worker.start()
        worker.join(timeout=10)
    assert out == [bytearray(b"s")]
    assert term.handlers == [_noted, _noted]
    assert term.attrs_set[-1] == _ATTRS
