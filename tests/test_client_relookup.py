"""A server name during an outage (re-decision 5): the address a handshake
proved stays a second address to try, and after 5 failed tries the name is
looked up again, at most every RELOOKUP_EVERY_S.

The host is faked as in tests/test_client_fail_closed.py (_Run) and
tests/test_client_start_block.py (_Start); the lookup is an AsyncMock and
each handshake notes the address it was given. Nothing sleeps.
"""

from __future__ import annotations

import asyncio
import functools
import json
import logging
from collections.abc import Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

import dsm.client as client_mod
from dsm.crypto.handshake import HandshakeError
from tests.test_client_fail_closed import _config, _Run
from tests.test_client_start_block import NAME, _Start


def _save(path: Path, ip: str) -> None:
    path.write_text(json.dumps({"name": NAME, "ip": ip}))
    path.chmod(0o600)


def _handshakes(run: _Run, works_for: str | None = None) -> tuple[list[str], Any]:
    tried: list[str] = []

    async def handshake(*args: Any, **_k: object) -> Any:
        tried.append(args[2][0])  # args[2] is (server IP, port)
        if args[2][0] == works_for:
            return await run.handshake()
        raise HandshakeError("lost")

    return tried, handshake


async def test_a_working_lookup_keeps_the_proven_address_second(tmp_path: Path) -> None:
    start = _Start(tmp_path / "server-endpoint.json")
    _save(start.endpoint_file, "10.0.0.9")
    rc = await start.run(server_ip=NAME)
    assert rc == 1
    assert start.events == [
        "block none",
        "materials",
        "lookup",
        "block 10.0.0.1,10.0.0.9",
        "stores",
        "unblock 10.0.0.1,10.0.0.9",
    ]


async def test_the_two_addresses_take_turns(tmp_path: Path) -> None:
    saved = tmp_path / "server-endpoint.json"
    _save(saved, "10.0.0.9")
    run = _Run()
    run.stop_at_wait = 3
    tried, handshake = _handshakes(run)
    with (
        patch("dsm.client._SERVER_ENDPOINT_FILE", saved),
        patch(
            "dsm.client._resolve_server_endpoint", AsyncMock(return_value="10.0.0.1")
        ),
    ):
        assert await run.run(_config(server_ip=NAME), handshake=handshake) == 0
    assert tried == ["10.0.0.1", "10.0.0.9", "10.0.0.1"]


async def test_a_good_handshake_with_the_proven_address_keeps_it(
    tmp_path: Path,
) -> None:
    saved = tmp_path / "server-endpoint.json"
    _save(saved, "10.0.0.9")
    before = saved.read_text()
    run = _Run()
    run.stop_in_session = [True]
    tried, handshake = _handshakes(run, works_for="10.0.0.9")
    with (
        patch("dsm.client._SERVER_ENDPOINT_FILE", saved),
        patch(
            "dsm.client._resolve_server_endpoint", AsyncMock(return_value="10.0.0.1")
        ),
    ):
        assert await run.run(_config(server_ip=NAME), handshake=handshake) == 0
    assert tried == ["10.0.0.1", "10.0.0.9"]
    assert saved.read_text() == before  # already the proven one: no write


async def test_after_five_failed_tries_the_name_is_looked_up_again(
    tmp_path: Path,
) -> None:
    run = _Run()
    run.stop_at_wait = 6
    tried, handshake = _handshakes(run)
    lookup = AsyncMock(side_effect=["10.0.0.1", "10.0.0.2", "10.0.0.2"])
    with (
        patch.object(client_mod, "RELOOKUP_EVERY_S", 0.0),
        patch("dsm.client._SERVER_ENDPOINT_FILE", tmp_path / "server-endpoint.json"),
        patch("dsm.client._resolve_server_endpoint", lookup),
    ):
        assert await run.run(_config(server_ip=NAME), handshake=handshake) == 0
    # At start, after the 5th failed try, after the 6th.
    assert lookup.await_count == 3
    assert tried == ["10.0.0.1"] * 5 + ["10.0.0.2"]


async def test_no_new_lookup_before_its_time(tmp_path: Path) -> None:
    run = _Run()
    run.stop_at_wait = 6
    _, handshake = _handshakes(run)
    lookup = AsyncMock(return_value="10.0.0.1")
    with (
        patch("dsm.client._SERVER_ENDPOINT_FILE", tmp_path / "server-endpoint.json"),
        patch("dsm.client._resolve_server_endpoint", lookup),
    ):
        assert await run.run(_config(server_ip=NAME), handshake=handshake) == 0
    lookup.assert_awaited_once()  # the tries took far less than 300 s


async def test_a_new_lookup_that_fails_keeps_the_old_address(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    run = _Run()
    run.stop_at_wait = 6
    tried, handshake = _handshakes(run)
    lookup = AsyncMock(
        side_effect=["10.0.0.1", OSError("no address"), OSError("no address")]
    )
    caplog.set_level(logging.WARNING, logger="dsm")
    with (
        patch.object(client_mod, "RELOOKUP_EVERY_S", 0.0),
        patch("dsm.client._SERVER_ENDPOINT_FILE", tmp_path / "server-endpoint.json"),
        patch("dsm.client._resolve_server_endpoint", lookup),
    ):
        assert await run.run(_config(server_ip=NAME), handshake=handshake) == 0
    assert tried == ["10.0.0.1"] * 6  # DSM went on trying after the failures
    assert run.events.count("pre.remove") == 1
    assert run.events[-1] == "pre.remove"
    again = [
        r
        for r in caplog.records
        if r.getMessage().startswith("looked the server name up again")
    ]
    assert [r.levelno for r in again] == [logging.WARNING] * 2


async def test_a_stop_during_the_new_lookup_ends_dsm(tmp_path: Path) -> None:
    run = _Run()
    _, handshake = _handshakes(run)
    calls: list[int] = []

    async def lookup(*_a: object, **_k: object) -> str:
        calls.append(1)
        if len(calls) == 1:
            return "10.0.0.1"
        run.stops[0].set()  # Ctrl-C while the new lookup waits
        await asyncio.Event().wait()
        raise AssertionError("not reached")

    with (
        patch.object(client_mod, "RELOOKUP_EVERY_S", 0.0),
        patch("dsm.client._SERVER_ENDPOINT_FILE", tmp_path / "server-endpoint.json"),
        patch("dsm.client._resolve_server_endpoint", lookup),
    ):
        assert await run.run(_config(server_ip=NAME), handshake=handshake) == 0
    assert len(calls) == 2
    assert run.events[-1] == "pre.remove"


async def test_an_ip_address_is_never_looked_up(tmp_path: Path) -> None:
    run = _Run()
    run.stop_at_wait = 6
    _, handshake = _handshakes(run)
    lookup = AsyncMock(return_value="10.0.0.1")
    with (
        patch.object(client_mod, "RELOOKUP_EVERY_S", 0.0),
        patch("dsm.client._resolve_server_endpoint", lookup),
    ):
        assert await run.run(_config(), handshake=handshake) == 0  # server_ip 10.0.0.1
    lookup.assert_not_awaited()


class _TableRun(_Run):
    """_Run, with each start-up table noted by the addresses it lets DSM try
    and its port-53 opening, as tests/test_client_start_block.py does."""

    def __init__(self) -> None:
        super().__init__()
        self.tables: list[str] = []

    def _recorder(self, name: str) -> type:
        if name != "pre":
            return super()._recorder(name)
        events, tables = self.events, self.tables

        class _Pre:
            def __init__(
                self,
                server_ips: str | Sequence[str] | None,
                _port: int,
                *,
                resolvers: Sequence[str] = (),
                ntp: object = None,
            ) -> None:
                del ntp  # no date problem in these runs
                ips = (
                    [server_ips]
                    if isinstance(server_ips, str)
                    else list(server_ips or ())
                )
                self.label = ",".join(ips) or "none"
                if resolvers:
                    self.label += " +dns"

            def apply(self) -> None:
                events.append("pre.apply")
                tables.append(self.label)

            def remove(self) -> None:
                events.append("pre.remove")

        return _Pre


async def test_a_new_lookup_opens_53_only_while_it_runs_and_lets_the_new_address_out(
    tmp_path: Path,
) -> None:
    run = _TableRun()
    run.stop_at_wait = 6
    tried, handshake = _handshakes(run)
    answers = ["10.0.0.1", "10.0.0.2", "10.0.0.2"]

    async def lookup(_name: str, _port: int, **kwargs: Any) -> str:
        kwargs["before_lookup"](["192.0.2.53"])  # port 53 opens, as for real
        return answers.pop(0)

    with (
        patch.object(client_mod, "RELOOKUP_EVERY_S", 0.0),
        patch("dsm.client._SERVER_ENDPOINT_FILE", tmp_path / "server-endpoint.json"),
        patch("dsm.client._resolve_server_endpoint", lookup),
    ):
        assert await run.run(_config(server_ip=NAME), handshake=handshake) == 0
    assert tried == ["10.0.0.1"] * 5 + ["10.0.0.2"]
    assert run.tables == [
        "none",
        "none +dns",
        "10.0.0.1",  # the start lookup is over: port 53 closed again
        "10.0.0.1 +dns",  # the new lookup, after the 5th failed try
        "10.0.0.2",  # closed again, and the new address let out
        "10.0.0.2 +dns",
        "10.0.0.2",
    ]


async def test_a_good_handshake_pins_its_address_as_the_only_candidate(
    tmp_path: Path,
) -> None:
    saved = tmp_path / "server-endpoint.json"
    _save(saved, "10.0.0.9")
    run = _Run()
    run.stop_in_session = [False, True]  # the first session drops
    tried, handshake = _handshakes(run, works_for="10.0.0.1")
    with (
        patch("dsm.client._SERVER_ENDPOINT_FILE", saved),
        patch(
            "dsm.client._resolve_server_endpoint", AsyncMock(return_value="10.0.0.1")
        ),
    ):
        assert await run.run(_config(server_ip=NAME), handshake=handshake) == 0
    assert tried == ["10.0.0.1", "10.0.0.1"]  # not 10.0.0.9 the second time
    assert json.loads(saved.read_text())["ip"] == "10.0.0.1"


async def test_a_stop_during_a_new_lookup_with_the_flag_keeps_the_plain_block(
    tmp_path: Path,
) -> None:
    run = _TableRun()
    _, handshake = _handshakes(run)
    calls: list[int] = []

    async def lookup(_name: str, _port: int, **kwargs: Any) -> str:
        calls.append(1)
        kwargs["before_lookup"](["192.0.2.53"])
        if len(calls) == 1:
            return "10.0.0.1"
        run.stops[0].set()  # Ctrl-C while port 53 is open
        await asyncio.Event().wait()
        raise AssertionError("not reached")

    with_flag = functools.partial(client_mod.run_client, stop_keeps_block=True)
    with (
        patch.object(client_mod, "run_client", with_flag),
        patch.object(client_mod, "RELOOKUP_EVERY_S", 0.0),
        patch("dsm.client._SERVER_ENDPOINT_FILE", tmp_path / "server-endpoint.json"),
        patch("dsm.client._resolve_server_endpoint", lookup),
    ):
        assert await run.run(_config(server_ip=NAME), handshake=handshake) == 0
    assert len(calls) == 2
    assert "pre.remove" not in run.events
    assert run.tables[-2:] == ["10.0.0.1 +dns", "10.0.0.1"]  # 53 closed again


async def test_a_new_lookup_keeps_the_proven_address_second(tmp_path: Path) -> None:
    saved = tmp_path / "server-endpoint.json"
    _save(saved, "10.0.0.9")
    run = _TableRun()
    run.stop_at_wait = 6
    tried, handshake = _handshakes(run)
    answers = ["10.0.0.1", "10.0.0.2", "10.0.0.2"]

    async def lookup(_name: str, _port: int, **kwargs: Any) -> str:
        kwargs["before_lookup"](["192.0.2.53"])
        return answers.pop(0)

    with (
        patch.object(client_mod, "RELOOKUP_EVERY_S", 0.0),
        patch("dsm.client._SERVER_ENDPOINT_FILE", saved),
        patch("dsm.client._resolve_server_endpoint", lookup),
    ):
        assert await run.run(_config(server_ip=NAME), handshake=handshake) == 0
    assert tried == ["10.0.0.1", "10.0.0.9"] * 2 + ["10.0.0.1", "10.0.0.2"]
    assert "10.0.0.2,10.0.0.9" in run.tables


async def test_new_lookups_are_spaced_by_the_time_since_the_last_one(
    tmp_path: Path,
) -> None:
    run = _Run()
    run.stop_at_wait = 9
    _, handshake = _handshakes(run)
    lookup = AsyncMock(return_value="10.0.0.1")
    ticks = iter(range(0, 100000, 600))  # 600 s pass at every look at the clock
    fake_time = SimpleNamespace(monotonic=lambda: float(next(ticks)))
    with (
        patch.object(client_mod, "RELOOKUP_EVERY_S", 1000.0),
        patch.object(client_mod, "time", fake_time),
        patch("dsm.client._SERVER_ENDPOINT_FILE", tmp_path / "server-endpoint.json"),
        patch("dsm.client._resolve_server_endpoint", lookup),
    ):
        assert await run.run(_config(server_ip=NAME), handshake=handshake) == 0
    assert lookup.await_count == 3
