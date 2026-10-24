"""The client's waits and its outage lines (re-decision 6, fix 4, Minor 8).

Every wait is the reconnect backoff (1 s doubling to 30 s) moved up to 25%
either way at random, so clients that lost one server do not all come back
in step. Nothing sleeps: the random draw and the wait are faked.
"""

from __future__ import annotations

import asyncio
import errno
import logging
from unittest.mock import patch

import pytest

import dsm.client as client_mod
from tests.test_client_fail_closed import _config, _Run


def test_the_waits_double_from_one_second_up_to_thirty() -> None:
    assert [client_mod._backoff_s(n) for n in range(8)] == [
        1.0,
        2.0,
        4.0,
        8.0,
        16.0,
        30.0,
        30.0,
        30.0,
    ]


@pytest.mark.parametrize(
    ("draw", "factor"), [(0.0, 0.75), (0.5, 1.0), (0.999999, 1.25)]
)
def test_every_wait_moves_up_to_a_quarter_either_way(
    draw: float, factor: float
) -> None:
    with patch.object(client_mod, "csprng_float", return_value=draw):
        assert client_mod._jittered(8.0) == pytest.approx(8.0 * factor, rel=1e-5)


async def test_wait_or_stop_waits_the_jittered_time() -> None:
    with patch.object(client_mod, "_jittered", return_value=0.0) as jittered:
        assert await client_mod._wait_or_stop(asyncio.Event(), 30.0) is False
    jittered.assert_called_once_with(30.0)


def test_the_failed_tries_are_counted_until_a_session_comes_up() -> None:
    reconnect = client_mod._Reconnect(looked_up_name=False)
    reconnect.failed()
    reconnect.failed()
    assert reconnect.failures == 2
    reconnect.connected()
    assert reconnect.failures == 0


def test_the_hint_says_dsm_looks_the_name_up_again() -> None:
    hint = client_mod._HOSTNAME_HINT
    assert hint.startswith("server IP may have changed")
    assert "looks the name up again" in hint


async def test_a_refused_tcp_connect_says_to_check_the_transport(
    caplog: pytest.LogCaptureFixture,
) -> None:
    run = _Run()
    run.connect_errors = [ConnectionRefusedError(errno.ECONNREFUSED, "refused")]
    run.stop_at_wait = 1
    caplog.set_level(logging.ERROR, logger="dsm")

    assert await run.run(_config(transport="tcp")) == 0

    lines = [r.getMessage() for r in caplog.records]
    assert any(
        line.startswith("cannot connect to the server: Connection refused. ")
        and "same transport (udp or tcp)" in line
        for line in lines
    )
