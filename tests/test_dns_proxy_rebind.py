"""The DNS proxy's address is free again one event-loop step after stop().

Pins why run_server yields once between a replaced session and the next one
(step R): LocalDNSProxy.stop() closes its asyncio transport, and asyncio
closes the socket one loop step later. The next session binds the same
address at once, and a port clash there stops the server. Real UDP sockets
on 127.0.0.1 only.
"""

from __future__ import annotations

import asyncio
import socket
from collections.abc import Iterator
from unittest.mock import patch

import pytest

from dsm.net.dns_proxy import DNSProxyPortInUseError, LocalDNSProxy


@pytest.fixture(autouse=True)
def _no_so_mark() -> Iterator[None]:
    with patch("dsm.net.transport._fwmark.apply_so_mark", lambda sock: None):
        yield


class _Resolver:
    async def close(self) -> None:
        pass


def _free_udp_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])
    finally:
        s.close()


def _proxy(port: int) -> LocalDNSProxy:
    return LocalDNSProxy(_Resolver(), bind_ip="127.0.0.1", bind_port=port)  # type: ignore[arg-type]


async def test_one_loop_step_after_stop_the_address_binds_again() -> None:
    port = _free_udp_port()
    first = _proxy(port)
    await first.start()
    first.stop()
    await asyncio.sleep(0)
    second = _proxy(port)
    await second.start()
    second.stop()
    await asyncio.sleep(0)


async def test_without_that_step_the_bind_fails() -> None:
    port = _free_udp_port()
    first = _proxy(port)
    await first.start()
    first.stop()
    second = _proxy(port)
    with pytest.raises(DNSProxyPortInUseError):
        await second.start()
    await asyncio.sleep(0)
