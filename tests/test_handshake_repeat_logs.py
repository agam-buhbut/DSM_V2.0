"""Handshake log lines that can repeat per packet or per connection go through
one RepeatLog each, and lines about a connection error name no address.

Fake receive, fake connections and fake clocks; nothing waits on the wall
clock.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import pytest

from dsm.core.log import RepeatLog
from dsm.crypto import handshake
from dsm.net import handshake_acceptor as hsa
from dsm.net.transport.tcp import FramingError
from tests.test_tcp_accept_concurrency import _Run, _Script, _spin

Addr = tuple[str, int]


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class _Copies:
    """Stands in for ``handshake._recv_one``: a run of copies, then a frame
    that is kept."""

    def __init__(self, copies: int) -> None:
        self.copies = copies
        self.left = copies

    async def __call__(self, _transport: Any, _timeout: float) -> tuple[bytes, Addr]:
        if self.left:
            self.left -= 1
            return b"copy", ("203.0.113.9", 5555)
        self.left = self.copies
        return b"keep", ("203.0.113.9", 5555)


async def test_skipped_copies_log_once_and_the_count_spans_attempts(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    clock = _Clock()
    monkeypatch.setattr(
        handshake, "_skip_log", RepeatLog(handshake.log, logging.DEBUG, clock=clock)
    )
    monkeypatch.setattr(handshake, "_recv_one", _Copies(copies=2))
    caplog.set_level(logging.DEBUG, logger=handshake.log.name)
    transport: Any = object()

    def skip(frame: bytes) -> bool:
        return frame == b"copy"

    # Two attempts, two copies each, all inside one window: one line.
    for _ in range(2):
        frame, _addr = await handshake._recv_one_skipping(transport, 5.0, skip)
        assert frame == b"keep"
    lines = [r.getMessage() for r in caplog.records]
    assert lines == ["handshake: skipped a copy of an earlier handshake message"]

    # The next copy after the window adds the three that were counted.
    clock.now += 11.0
    await handshake._recv_one_skipping(transport, 5.0, skip)
    lines = [r.getMessage() for r in caplog.records]
    assert len(lines) == 2
    assert lines[1].endswith("(3 more in the last 11 s)")
    assert all("203.0.113.9" not in line and "5555" not in line for line in lines)


async def test_a_flood_of_connections_on_a_full_pool_logs_one_line(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    clock = _Clock()
    monkeypatch.setattr(
        hsa, "_tcp_full_log", RepeatLog(hsa.log, logging.DEBUG, clock=clock)
    )
    caplog.set_level(logging.DEBUG, logger=hsa.log.name)
    busy: Addr = ("203.0.113.70", 1)
    script = _Script({busy: "stall"})

    def full_lines() -> list[str]:
        return [
            r.getMessage() for r in caplog.records if "pool saturated" in r.getMessage()
        ]

    async with _Run(script, max_inflight=1) as run:
        run.connect(busy)
        assert await _spin(lambda: busy in script.started)
        first = [run.connect((f"203.0.113.{80 + i}", 1)) for i in range(3)]
        assert await _spin(lambda: all(c.closed for c in first))
        assert len(full_lines()) == 1

        clock.now += 11.0
        later = run.connect(("203.0.113.90", 1))
        assert await _spin(lambda: later.closed)
        lines = full_lines()
    assert len(lines) == 2
    assert lines[1].endswith("(2 more in the last 11 s)")
    assert all("203.0.113" not in line for line in lines)


class _Fails:
    """Fake ``server_handshake`` that raises ``error``."""

    def __init__(self, error: Exception) -> None:
        self.error = error
        self.started: list[Addr] = []

    async def __call__(self, conn: Any, *_a: Any, **_k: Any) -> tuple[object, bytes]:
        self.started.append(conn.peer)
        raise self.error


@pytest.mark.parametrize(
    ("error", "detail"),
    [
        (
            # asyncio puts the peer's address into the text of some errors.
            ConnectionResetError(104, "read error from ('203.0.113.9', 5555)"),
            "ConnectionResetError: Connection reset by peer",
        ),
        (OSError("lost ('203.0.113.9', 5555)"), "OSError"),
        (FramingError("frame ('203.0.113.9', 5555) too long"), "FramingError"),
    ],
)
async def test_a_connection_error_logs_the_class_and_the_os_text_only(
    caplog: pytest.LogCaptureFixture, error: Exception, detail: str
) -> None:
    caplog.set_level(logging.DEBUG, logger=hsa.log.name)
    peer: Addr = ("203.0.113.9", 5555)
    script = _Fails(error)
    async with _Run(script) as run:  # type: ignore[arg-type]
        conn = run.connect(peer)
        assert await _spin(lambda: conn.closed)
        await asyncio.sleep(0)

    lines = [(r.levelno, r.getMessage()) for r in caplog.records]
    assert (
        logging.INFO,
        f"handshake transport error ({type(error).__name__})",
    ) in lines
    assert (logging.DEBUG, f"handshake transport error detail: {detail}") in lines
    assert all("203.0.113.9" not in text and "5555" not in text for _, text in lines)
