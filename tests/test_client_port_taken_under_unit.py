"""A taken UDP port at the first try, with and without `--stop-keeps-block`.

dsm-client.service passes the flag, so every restart is a "first try" for
DSM. A fixed ``listen_port`` that a local program grabbed during a restart
must not open the host: with the flag the block stays and DSM tries again.
Without the flag (a run by hand) the user is there, so DSM still exits 1 and
removes the block. Uses the faked host of tests/test_client_fail_closed.py.
"""

from __future__ import annotations

import errno
import functools
import logging
import os
from unittest.mock import patch

import pytest

import dsm.client as client_mod
from tests.test_client_fail_closed import _config, _Run, _tables_after

_PORT = 51999


def _port_taken() -> OSError:
    return OSError(errno.EADDRINUSE, os.strerror(errno.EADDRINUSE))


async def _run_with_flag(run: _Run) -> int:
    # _Run calls client_mod.run_client; hand it the flag on the way.
    with_flag = functools.partial(client_mod.run_client, stop_keeps_block=True)
    with patch.object(client_mod, "run_client", with_flag):
        return await run.run(_config(listen_port=_PORT))


async def test_with_the_flag_a_taken_port_keeps_the_block_and_tries_again(
    caplog: pytest.LogCaptureFixture,
) -> None:
    run = _Run()
    run.bind_errors = [_port_taken()]  # the first try; the second binds
    run.stop_in_session = [True]  # `systemctl stop` during the second try
    caplog.set_level(logging.ERROR, logger="dsm")

    rc = await _run_with_flag(run)

    assert rc == 0
    assert run.events.count("transport.bind") == 2
    assert run.events.count("session") == 1
    # The start-up table was up during the wait, and nothing took it down.
    assert run.waits == [1.0]
    assert run.blocked_during_waits == [True]
    assert "pre.remove" not in run.events
    assert "nft.remove" not in run.events
    messages = [r.getMessage() for r in caplog.records]
    assert (
        f"cannot listen on UDP port {_PORT}: Address already in use; trying again"
        in messages
    )
    assert not any("exiting" in m for m in messages)


async def test_with_the_flag_a_port_that_stays_taken_never_opens_the_host() -> None:
    run = _Run()
    run.bind_errors = [_port_taken(), _port_taken(), _port_taken()]
    run.stop_at_wait = 3  # `systemctl stop` during the third wait

    rc = await _run_with_flag(run)

    assert rc == 0
    assert run.waits == [1.0, 2.0, 4.0]
    assert run.blocked_during_waits == [True, True, True]
    # Every step of the run had a kill switch table up.
    start = run.events.index("pre.apply")
    for i in range(start + 1, len(run.events) + 1):
        assert _tables_after(run.events[:i]), run.events[:i]


async def test_without_the_flag_a_taken_port_still_exits_and_removes_the_block(
    caplog: pytest.LogCaptureFixture,
) -> None:
    run = _Run()
    run.bind_errors = [_port_taken()]
    caplog.set_level(logging.ERROR, logger="dsm")

    rc = await run.run(_config(listen_port=_PORT))

    assert rc == 1
    assert run.waits == []
    assert run.events[-1] == "pre.remove"
    assert _tables_after(run.events) == set()
    messages = [r.getMessage() for r in caplog.records]
    assert (
        f"cannot listen on UDP port {_PORT}: Address already in use; exiting"
        in messages
    )
