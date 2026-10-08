"""Building blocks of the client's reconnect loop (dsm/client.py).

The waits between tries, the once-per-outage log lines, the wait that a stop
ends at once, and the race that cancels a connect or handshake when the user
stops DSM. Nothing sleeps: clocks are fake, and waits end on events.
"""

from __future__ import annotations

import asyncio
import logging

import pytest

import dsm.client as client_mod

_NOTICE = "all traffic is blocked until DSM connects again"
_HINT = "server IP may have changed"


def _lines(caplog: pytest.LogCaptureFixture, text: str) -> list[str]:
    return [r.getMessage() for r in caplog.records if text in r.getMessage()]


def test_waits_double_from_one_second_up_to_thirty() -> None:
    reconnect = client_mod._Reconnect(looked_up_name=False)
    waits = [reconnect.next_wait() for _ in range(8)]
    assert waits == [1.0, 2.0, 4.0, 8.0, 16.0, 30.0, 30.0, 30.0]


def test_a_session_that_comes_up_starts_the_waits_again() -> None:
    reconnect = client_mod._Reconnect(looked_up_name=False)
    for _ in range(6):
        reconnect.next_wait()
    reconnect.connected()
    assert reconnect.next_wait() == 1.0


def test_the_notice_says_how_to_get_internet_back(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger="dsm")
    reconnect = client_mod._Reconnect(looked_up_name=False)
    reconnect.next_wait()
    reconnect.next_wait()

    notices = _lines(caplog, _NOTICE)
    assert len(notices) == 1  # once per outage
    for words in ("Ctrl-C", "sudo systemctl stop dsm-client", "sudo dsm cleanup"):
        assert words in notices[0]


def test_a_new_outage_gets_a_new_notice_at_most_once_a_minute(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger="dsm")
    now = [1000.0]
    reconnect = client_mod._Reconnect(looked_up_name=False, clock=lambda: now[0])
    reconnect.next_wait()
    reconnect.connected()
    now[0] += 5.0  # the session dropped again after 5 s
    reconnect.next_wait()
    assert len(_lines(caplog, _NOTICE)) == 1

    reconnect.connected()
    now[0] += 60.0
    reconnect.next_wait()
    notices = _lines(caplog, _NOTICE)
    assert len(notices) == 2
    assert notices[1].endswith("(1 more in the last 65 s)")


def test_the_address_hint_comes_once_after_five_failed_tries_for_a_name(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger="dsm")
    reconnect = client_mod._Reconnect(looked_up_name=True)
    for _ in range(4):
        reconnect.failed()
    assert _lines(caplog, _HINT) == []

    for _ in range(3):
        reconnect.failed()
    hints = _lines(caplog, _HINT)
    assert len(hints) == 1
    assert "stop and start DSM" in hints[0]

    reconnect.connected()  # a new outage may hint again
    for _ in range(5):
        reconnect.failed()
    assert len(_lines(caplog, _HINT)) == 2


def test_no_address_hint_for_an_ip_address(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING, logger="dsm")
    reconnect = client_mod._Reconnect(looked_up_name=False)
    for _ in range(10):
        reconnect.failed()
    assert _lines(caplog, _HINT) == []


async def test_a_stop_before_the_wait_ends_it_at_once() -> None:
    shutdown = asyncio.Event()
    shutdown.set()
    assert await client_mod._wait_or_stop(shutdown, 30.0) is True


async def test_a_stop_during_the_wait_ends_it_at_once() -> None:
    shutdown = asyncio.Event()
    asyncio.get_running_loop().call_soon(shutdown.set)
    assert await client_mod._wait_or_stop(shutdown, 30.0) is True


async def test_a_wait_with_no_stop_runs_out() -> None:
    assert await client_mod._wait_or_stop(asyncio.Event(), 0.0) is False


async def test_unless_stopped_returns_what_the_work_returns() -> None:
    async def work() -> str:
        return "keys"

    assert await client_mod._unless_stopped(asyncio.Event(), work()) == "keys"


async def test_unless_stopped_lets_an_error_through() -> None:
    async def work() -> str:
        raise OSError("refused")

    with pytest.raises(OSError, match="refused"):
        await client_mod._unless_stopped(asyncio.Event(), work())


async def test_a_stop_cancels_the_work_at_once() -> None:
    shutdown = asyncio.Event()
    cancelled: list[bool] = []

    async def stuck() -> str:
        shutdown.set()  # Ctrl-C while the handshake waits for the server
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancelled.append(True)
            raise
        return "never"

    assert await client_mod._unless_stopped(shutdown, stuck()) is None
    assert cancelled == [True]


async def test_set_when_passes_a_stop_on_and_cancel_leaves_nothing_pending() -> None:
    src, dst = asyncio.Event(), asyncio.Event()
    task = asyncio.ensure_future(client_mod._set_when(src, dst))
    src.set()
    await task
    assert dst.is_set()

    idle = asyncio.ensure_future(client_mod._set_when(asyncio.Event(), asyncio.Event()))
    await client_mod._cancel_and_wait(idle)
    assert idle.cancelled()
