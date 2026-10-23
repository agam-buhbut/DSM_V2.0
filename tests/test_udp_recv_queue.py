"""The server's socket gets a bigger receive queue (multi-client spec §2.6):
``recv_queue_size`` sets the asyncio queue, and above the default ``bind()``
asks the kernel for a matching buffer, with SO_RCVBUFFORCE and then
SO_RCVBUF, and warns once when it gets less. The default asks for nothing.
Kernel calls go to a fake socket; the bind tests use a loopback port.
"""

from __future__ import annotations

import errno
import logging
import os
import socket
from typing import Any
from unittest.mock import patch

import pytest

from dsm.net.transport import udp
from dsm.net.transport.udp import RECV_QUEUE_SIZE, UDPTransport

SIZE = 4096 * 2048


class _Sock:
    """A socket's receive-buffer options. SO_RCVBUFFORCE is refused unless
    allowed; SO_RCVBUF is capped at ``rmem_max``; the kernel reports twice
    what it keeps."""

    def __init__(self, *, force_ok: bool, rmem_max: int = 212_992) -> None:
        self.force_ok = force_ok
        self.rmem_max = rmem_max
        self.asked: list[tuple[int, int]] = []
        self._kept = 0

    def setsockopt(self, level: int, option: int, value: int) -> None:
        assert level == socket.SOL_SOCKET
        self.asked.append((option, value))
        if option == udp._SO_RCVBUFFORCE:
            if not self.force_ok:
                raise PermissionError(errno.EPERM, os.strerror(errno.EPERM))
            self._kept = value
        else:
            self._kept = min(value, self.rmem_max)

    def getsockopt(self, level: int, option: int) -> int:
        assert (level, option) == (socket.SOL_SOCKET, socket.SO_RCVBUF)
        return 2 * self._kept


def _warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]


async def test_the_default_queue_is_unchanged() -> None:
    assert UDPTransport()._recv_queue.maxsize == RECV_QUEUE_SIZE == 256


async def test_recv_queue_size_sets_the_queue() -> None:
    assert UDPTransport(recv_queue_size=4096)._recv_queue.maxsize == 4096


def test_with_cap_net_admin_the_kernel_keeps_the_whole_buffer(
    caplog: pytest.LogCaptureFixture,
) -> None:
    sock = _Sock(force_ok=True)
    udp._ask_kernel_buffer(sock, SIZE)  # type: ignore[arg-type]
    assert sock.asked == [(udp._SO_RCVBUFFORCE, SIZE)]
    assert _warnings(caplog) == []


def test_without_it_falls_back_to_so_rcvbuf_and_warns(
    caplog: pytest.LogCaptureFixture,
) -> None:
    sock = _Sock(force_ok=False)
    udp._ask_kernel_buffer(sock, SIZE)  # type: ignore[arg-type]
    assert sock.asked == [(udp._SO_RCVBUFFORCE, SIZE), (socket.SO_RCVBUF, SIZE)]
    assert _warnings(caplog) == [
        f"asked for a {SIZE}-byte receive buffer, the kernel gave 212992"
    ]


def test_a_fallback_that_gets_enough_does_not_warn(
    caplog: pytest.LogCaptureFixture,
) -> None:
    udp._ask_kernel_buffer(_Sock(force_ok=False, rmem_max=SIZE), SIZE)  # type: ignore[arg-type]
    assert _warnings(caplog) == []


@pytest.mark.parametrize(("queue", "asked"), [(RECV_QUEUE_SIZE, []), (4096, [SIZE])])
async def test_bind_asks_for_the_buffer_only_above_the_default(
    queue: int, asked: list[int]
) -> None:
    seen: list[int] = []

    def _ask(_sock: Any, size: int) -> None:
        seen.append(size)

    transport = UDPTransport(recv_queue_size=queue)
    with (
        patch.object(udp, "_ask_kernel_buffer", _ask),
        patch.object(udp, "apply_so_mark", lambda _sock: None),
    ):
        await transport.bind("127.0.0.1", 0)
    transport.close()
    assert seen == asked


def test_the_bytes_per_queued_packet() -> None:
    assert udp._KERNEL_BYTES_PER_PACKET == 2048
