"""Session labels (multi-client spec §2.13): a line logged inside a server
session's task, or a task it started, carries ``[sN] ``; any other line
carries nothing; message texts do not change; netaudit events inside a
session gain ``"session": N``.
"""

from __future__ import annotations

import asyncio
import io
import logging
import sys
from collections.abc import Awaitable, Callable

import pytest

from dsm.core import log as dsm_log
from dsm.core import netaudit
from dsm.core.log import SESSION_LABEL
from tests.test_netaudit import _Capture

NAME = "dsm.test_session_label"


async def _in_session(number: int, body: Callable[[], Awaitable[None]]) -> None:
    """Run ``body`` in its own task, labelled as a server session does."""

    async def _task() -> None:
        SESSION_LABEL.set(str(number))
        await body()

    await asyncio.create_task(_task())


async def test_a_line_inside_a_session_carries_its_label_and_others_do_not() -> None:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.addFilter(dsm_log._SessionLabel())
    handler.setFormatter(logging.Formatter("%(name)s: %(session)s%(message)s"))
    logger = logging.getLogger(NAME)
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    try:

        async def _body() -> None:
            logger.info("dead peer: no packet for %d s", 60)

            async def _child() -> None:
                logger.info("from a task the session started")

            await asyncio.create_task(_child())

        await _in_session(7, _body)
        logger.info("outside any session")
    finally:
        logger.removeHandler(handler)
    assert stream.getvalue().splitlines() == [
        f"{NAME}: [s7] dead peer: no packet for 60 s",
        f"{NAME}: [s7] from a task the session started",
        f"{NAME}: outside any session",
    ]


async def test_the_message_text_does_not_change(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger=NAME)

    async def _body() -> None:
        logging.getLogger(NAME).info("dead peer: no packet for %d s", 60)

    await _in_session(3, _body)
    assert [r.getMessage() for r in caplog.records] == ["dead peer: no packet for 60 s"]


async def test_configure_puts_the_label_in_the_human_log(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = io.StringIO()
    monkeypatch.setattr(sys, "stderr", stream)
    monkeypatch.setattr(dsm_log, "_configured", False)
    root = logging.getLogger("dsm")
    before, level = list(root.handlers), root.level
    dsm_log.configure("info")
    try:

        async def _body() -> None:
            logging.getLogger(NAME).info("inside")

        await _in_session(2, _body)
    finally:
        for handler in [h for h in root.handlers if h not in before]:
            root.removeHandler(handler)
        root.setLevel(level)
    assert stream.getvalue().rstrip().endswith(f"INFO {NAME}: [s2] inside")


async def test_netaudit_adds_the_session_number_inside_a_session_only() -> None:
    with _Capture() as capture:

        async def _body() -> None:
            netaudit.emit("dead_peer", role="server")

        await _in_session(5, _body)
        netaudit.emit("shutdown_signal", source="SIGTERM")
    inside, outside = capture.events()
    assert inside["session"] == 5
    assert "session" not in outside
