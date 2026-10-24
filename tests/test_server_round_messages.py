"""Server log lines a user can act on (QA Minors 7, 10, 19, Nit 4).

The host parts are faked as in tests/test_server_multi.py and
tests/test_server_dns_fatal.py; the DNS proxy runs on its real datagram
protocol with in-memory resolvers, as in tests/test_dns_proxy_per_client.py.
"""

from __future__ import annotations

import asyncio
import errno
import logging
from contextlib import AsyncExitStack
from dataclasses import replace
from pathlib import Path
from typing import Any
from unittest.mock import patch

import dns.message
import dns.rdatatype
import pytest

from dsm.net.dns_proxy import DNSProxyPortInUseError, LocalDNSProxy, _ProxyProtocol
from dsm.net.session_slot import SessionTable
from dsm.server import _set_up_host, run_server
from tests.test_dns_proxy_per_client import _Resolver, _Transport
from tests.test_server_dns_fatal import _base_patches, _run_until, _server_config
from tests.test_server_multi import A, _HostParts


async def test_one_client_is_one_address(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="dsm.server")
    with _HostParts() as parts:
        async with AsyncExitStack() as stack:
            await _set_up_host(_server_config(), stack, None, SessionTable([A]))
    assert "tunnel 10.8.0.1/24 up; an address for 1 client" in [
        r.getMessage() for r in caplog.records
    ]
    # The DNS proxy learns each address's CN, for its log lines.
    assert parts.proxy_args["client_names"] == {"10.8.0.2": A}


async def test_the_dns_cap_line_names_the_client(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger="dsm.net.dns_proxy")
    hold = asyncio.Event()
    proxy = LocalDNSProxy(
        _Resolver(hold),  # type: ignore[arg-type]
        bind_ip="10.8.0.1",
        per_client=lambda: _Resolver(hold),  # type: ignore[arg-type,return-value]
        client_names={"10.8.0.2": "dsm-a-client"},
    )
    proto = _ProxyProtocol(proxy)
    proto.connection_made(_Transport())  # type: ignore[arg-type]
    cap = LocalDNSProxy._MAX_TASKS_PER_CLIENT
    for i in range(cap + 1):
        wire = dns.message.make_query(f"n{i}.example", dns.rdatatype.A).to_wire()
        proto.datagram_received(wire, ("10.8.0.2", 5353))
    assert [r.getMessage() for r in caplog.records] == [
        f"DNS queries dropped: client_cn=dsm-a-client already has {cap} waiting"
    ]
    hold.set()
    await asyncio.gather(*list(proxy._tasks))


async def test_a_busy_dns_port_gives_no_tun_address_advice() -> None:
    proxy = LocalDNSProxy(_Resolver(), bind_ip="10.8.0.1")  # type: ignore[arg-type]

    async def busy(*_a: object, **_k: object) -> Any:
        raise OSError(errno.EADDRINUSE, "Address already in use")

    loop = asyncio.get_running_loop()
    with (
        patch.object(loop, "create_datagram_endpoint", busy),
        pytest.raises(DNSProxyPortInUseError) as err,
    ):
        await proxy.start()
    assert "another program already holds it" in str(err.value)
    assert "TUN address" not in str(err.value)


async def test_a_leftover_hosts_file_gets_one_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    (tmp_path / "hosts.txt").write_text("192.0.2.1 printer.lan\n")
    config = replace(_server_config(), config_dir=tmp_path, dns_blocklist=False)
    caplog.set_level(logging.WARNING, logger="dsm.server")
    captured: dict[str, Any] = {}
    with _base_patches(captured):
        assert await _run_until(config, captured) == 0
    lines = [r.getMessage() for r in caplog.records if "hosts.txt" in r.getMessage()]
    assert len(lines) == 1
    assert "is no longer read" in lines[0]


async def test_the_fatal_line_gives_no_tun_address_advice(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # QA Minor 7: run_server added its own "change the TUN address".
    text = (
        "DNS proxy cannot bind 10.8.0.1:53: another program already holds it "
        "(often a local DNS resolver: unbound, systemd-resolved or dnsmasq). "
        "Stop it, or make it listen on other addresses only."
    )

    async def busy(*_a: object) -> Any:
        raise DNSProxyPortInUseError(text)

    caplog.set_level(logging.ERROR, logger="dsm")
    with _base_patches({}), patch("dsm.server._set_up_host", busy):
        assert await asyncio.wait_for(run_server(_server_config()), 5.0) == 1
    errors = [r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR]
    assert errors == [f"FATAL: DNS proxy port conflict — {text} Then restart DSM."]
