"""The client remembers the last address it found for a server name (F3).

Once a handshake with a looked-up address works, the client saves the name
and the address in /run/dsm/server-endpoint.json; a run with no good
handshake leaves the file alone. A later start whose lookup fails (a kill
switch left up blocks it) uses the saved address instead of exiting. A
working lookup always wins, and a file that cannot be trusted counts as no
file. The file lives in ``tmp_path``; besides the host parts the ``_Run``
harness of tests/test_client_fail_closed.py fakes, only the lookup is faked.
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

import dsm.client as client_mod
from dsm.crypto.handshake import HandshakeError
from tests.test_client_fail_closed import _config, _Run

NAME = "vpn.example.org"
_USING = "could not look up the server name; using the last address it had"


@pytest.fixture
def saved(tmp_path: Path) -> Iterator[Path]:
    """Points the client at a file in a folder of ``tmp_path`` not made yet."""
    path = tmp_path / "dsm" / "server-endpoint.json"
    with patch("dsm.client._SERVER_ENDPOINT_FILE", path):
        yield path


def _write(path: Path, data: object) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text(json.dumps(data))
    path.chmod(0o600)


def _text(path: Path) -> str | None:
    return path.read_text() if path.exists() else None


async def _start(
    run: _Run, lookup: AsyncMock, *, handshake_works: bool = False
) -> tuple[int, list[tuple[object, str | None]]]:
    """Start DSM with a name in server_ip.

    Each handshake notes the address it was given and what the saved file
    held at that moment. With ``handshake_works`` a session comes up and the
    user stops DSM in it; without, the handshake fails and the user stops
    DSM in the first wait.
    """
    tried: list[tuple[object, str | None]] = []

    async def handshake(*args: object, **_k: object) -> tuple[Any, bytes, bytes, Any]:
        # args[2] is (server IP, port).
        tried.append((args[2], _text(client_mod._SERVER_ENDPOINT_FILE)))
        if not handshake_works:
            raise HandshakeError("lost")
        return await run.handshake()

    if handshake_works:
        run.stop_in_session = [True]
    else:
        run.stop_at_wait = 1
    with patch("dsm.client._resolve_server_endpoint", lookup):
        rc = await run.run(_config(server_ip=NAME), handshake=handshake)
    return rc, tried


async def test_an_address_is_saved_once_its_handshake_works(saved: Path) -> None:
    rc, tried = await _start(
        _Run(), AsyncMock(return_value="10.0.0.1"), handshake_works=True
    )

    assert rc == 0
    # Nothing was written before the handshake; the address is saved after.
    assert tried == [(("10.0.0.1", 51820), None)]
    assert json.loads(saved.read_text()) == {"name": NAME, "ip": "10.0.0.1"}
    assert saved.stat().st_mode & 0o777 == 0o600
    assert saved.parent.stat().st_mode & 0o777 == 0o700


@pytest.mark.parametrize("old", [None, {"name": NAME, "ip": "10.0.0.9"}])
async def test_a_run_with_no_good_handshake_writes_nothing(
    saved: Path, old: dict[str, str] | None
) -> None:
    if old is not None:
        _write(saved, old)
    before = _text(saved)

    rc, tried = await _start(_Run(), AsyncMock(return_value="10.0.0.1"))

    assert rc == 0
    assert [address for address, _ in tried] == [("10.0.0.1", 51820)]
    assert _text(saved) == before


async def test_nothing_is_saved_for_an_ip_address(saved: Path) -> None:
    run = _Run()
    run.stop_in_session = [True]  # a good handshake and a session

    rc = await run.run()  # server_ip is 10.0.0.1

    assert rc == 0
    assert run.events.count("session") == 1
    assert not saved.parent.exists()


async def test_a_failed_lookup_uses_the_saved_address_and_logs_no_address(
    saved: Path, caplog: pytest.LogCaptureFixture
) -> None:
    _write(saved, {"name": NAME, "ip": "10.0.0.9"})
    caplog.set_level(logging.INFO, logger="dsm")

    rc, tried = await _start(_Run(), AsyncMock(side_effect=OSError("timed out")))

    assert rc == 0
    assert [address for address, _ in tried] == [("10.0.0.9", 51820)]
    using = [r for r in caplog.records if r.getMessage() == _USING]
    assert [r.levelno for r in using] == [logging.WARNING]
    messages = [r.getMessage() for r in caplog.records]
    assert not any("10.0.0.9" in m or NAME in m for m in messages)


async def test_a_working_lookup_wins_and_is_saved_after_its_handshake(
    saved: Path, caplog: pytest.LogCaptureFixture
) -> None:
    _write(saved, {"name": NAME, "ip": "10.0.0.9"})
    old = _text(saved)
    caplog.set_level(logging.WARNING, logger="dsm")

    rc, tried = await _start(
        _Run(), AsyncMock(return_value="10.0.0.1"), handshake_works=True
    )

    assert rc == 0
    assert tried == [(("10.0.0.1", 51820), old)]  # still the old file then
    assert json.loads(saved.read_text()) == {"name": NAME, "ip": "10.0.0.1"}
    assert _USING not in [r.getMessage() for r in caplog.records]


@pytest.mark.parametrize(
    "content",
    [
        json.dumps({"name": "old.example.org", "ip": "10.0.0.9"}),  # another name
        "{not json",
        json.dumps({"name": NAME, "ip": 167772169}),  # not a string
        json.dumps({"name": NAME, "ip": "10.0.0.999"}),  # not an address
        json.dumps({"name": NAME, "ip": "::1"}),  # not IPv4
        json.dumps([NAME, "10.0.0.9"]),  # not an object
    ],
)
async def test_a_failed_lookup_without_a_usable_saved_address_exits(
    saved: Path, caplog: pytest.LogCaptureFixture, content: str
) -> None:
    saved.parent.mkdir(mode=0o700)
    saved.write_text(content)
    saved.chmod(0o600)
    caplog.set_level(logging.ERROR, logger="dsm")
    run = _Run()
    lookup = AsyncMock(side_effect=OSError("timed out"))

    with patch("dsm.client._resolve_server_endpoint", lookup):
        rc = await run.run(_config(server_ip=NAME))

    assert rc == 1
    assert run.events == []  # nothing on the host changed
    assert any(
        r.getMessage().startswith("could not resolve server endpoint")
        for r in caplog.records
    )


def test_a_good_file_gives_its_address(saved: Path) -> None:
    _write(saved, {"name": NAME, "ip": "10.0.0.9"})
    assert client_mod._saved_server_ip(NAME) == "10.0.0.9"


def test_a_symlink_counts_as_no_file(saved: Path, tmp_path: Path) -> None:
    real = tmp_path / "real.json"
    _write(real, {"name": NAME, "ip": "10.0.0.9"})
    saved.parent.mkdir(mode=0o700)
    saved.symlink_to(real)
    assert client_mod._saved_server_ip(NAME) is None


def test_a_file_others_can_read_counts_as_no_file(saved: Path) -> None:
    _write(saved, {"name": NAME, "ip": "10.0.0.9"})
    saved.chmod(0o644)
    assert client_mod._saved_server_ip(NAME) is None


def test_a_file_owned_by_someone_else_counts_as_no_file(saved: Path) -> None:
    _write(saved, {"name": NAME, "ip": "10.0.0.9"})
    other_uid = os.getuid() + 1
    with patch("dsm.core.path_security.os.getuid", return_value=other_uid):
        assert client_mod._saved_server_ip(NAME) is None


async def test_a_failed_save_logs_one_warning_and_dsm_goes_on(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    not_a_folder = tmp_path / "not-a-folder"
    not_a_folder.write_text("")
    caplog.set_level(logging.WARNING, logger="dsm")

    with patch(
        "dsm.client._SERVER_ENDPOINT_FILE", not_a_folder / "server-endpoint.json"
    ):
        run = _Run()
        lookup = AsyncMock(return_value="10.0.0.1")
        rc, _ = await _start(run, lookup, handshake_works=True)

    assert rc == 0
    assert run.events.count("session") == 1  # DSM went on
    saves = [
        r.getMessage()
        for r in caplog.records
        if r.getMessage().startswith("could not save")
    ]
    assert len(saves) == 1
    assert "10.0.0.1" not in saves[0]
