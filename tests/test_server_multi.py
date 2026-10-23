"""run_server with several clients (multi-client spec §2.2, §2.7, §2.8, §5):
the host state every client shares, the acceptor's restarts, and the
sessions. Host I/O is faked at the boundary; no sockets, no root.
"""

from __future__ import annotations

import logging
from contextlib import AsyncExitStack, ExitStack
from typing import Any
from unittest.mock import patch

import pytest

from dsm.net.dns import DNSResolver
from dsm.net.dns_proxy import DNSProxyPortInUseError
from dsm.net.session_slot import SessionTable
from dsm.server import _set_up_host
from tests.test_server_dns_fatal import _server_config

A = "dsm-a-client"
B = "dsm-b-client"


class _HostParts:
    """The host managers ``_set_up_host`` uses, faked; each records what it
    did. With ``nat_loads`` False the NAT load fails as MasqueradeManager's
    does: no exception, ``applied`` False. Use as a context manager."""

    def __init__(self) -> None:
        self.events: list[str] = []
        self.nat_clients: dict[str, str] | None = None
        self.proxy_args: dict[str, Any] = {}
        self.configure_error: Exception | None = None
        self.dns_error: Exception | None = None
        self.nat_loads = True
        self._stack = ExitStack()

    def __enter__(self) -> _HostParts:
        parts = self

        class _Tun:
            def __init__(self, name: str) -> None:
                parts.events.append(f"tun {name}")

            def open(self) -> None:
                parts.events.append("tun open")

            def configure(self, *, local_ip: str, mtu: int, server_mode: bool) -> None:
                del mtu
                if parts.configure_error is not None:
                    raise parts.configure_error
                parts.events.append(f"tun up {local_ip} server_mode={server_mode}")

            def close(self) -> None:
                parts.events.append("tun close")

        class _Forwarding:
            def __init__(self, tun_name: str) -> None:
                del tun_name

            def apply(self) -> None:
                parts.events.append("forwarding on")

            def remove(self) -> None:
                parts.events.append("forwarding off")

        class _Nat:
            def __init__(self, tun_name: str, *, clients: dict[str, str]) -> None:
                del tun_name
                parts.nat_clients = clients
                self.applied = False

            def apply(self) -> None:
                # As MasqueradeManager.apply: a failed load never raises.
                self.applied = parts.nat_loads
                if self.applied:
                    parts.events.append("nat on")

            def remove(self) -> None:
                parts.events.append("nat off")

        class _Proxy:
            def __init__(self, resolver: Any, **kwargs: Any) -> None:
                parts.proxy_args = {"resolver": resolver, **kwargs}

            async def start(self) -> None:
                if parts.dns_error is not None:
                    raise parts.dns_error
                parts.events.append("dns on")

            def stop(self) -> None:
                parts.events.append("dns off")

        for target, fake in (
            ("dsm.server.TunDevice", _Tun),
            ("dsm.server.IPForwardingManager", _Forwarding),
            ("dsm.server.MasqueradeManager", _Nat),
            ("dsm.server.LocalDNSProxy", _Proxy),
        ):
            self._stack.enter_context(patch(target, fake))
        return self

    def __exit__(self, *exc: object) -> None:
        self._stack.close()


async def test_host_state_comes_up_in_order_and_goes_down_in_reverse(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="dsm.server")
    with _HostParts() as parts:
        async with AsyncExitStack() as stack:
            await _set_up_host(_server_config(), stack, None, SessionTable([A, B]))
            assert parts.events == [
                "tun mtun0",
                "tun open",
                "tun up 10.8.0.1 server_mode=True",
                "forwarding on",
                "nat on",
                "dns on",
            ]
            parts.events.clear()
    assert parts.events == ["dns off", "nat off", "forwarding off", "tun close"]
    assert "tunnel 10.8.0.1/24 up; addresses for 2 clients" in [
        r.getMessage() for r in caplog.records
    ]


async def test_the_nat_table_gets_every_clients_address() -> None:
    with _HostParts() as parts:
        async with AsyncExitStack() as stack:
            await _set_up_host(_server_config(), stack, None, SessionTable([A, B]))
    assert parts.nat_clients == {"10.8.0.2": A, "10.8.0.3": B}


async def test_the_dns_proxy_gets_a_resolver_per_client() -> None:
    # The run's blocklist reaching this proxy is §7 item 18's test, in
    # tests/test_dns_blocklist_server.py (Task 8 Step 6).
    with _HostParts() as parts:
        async with AsyncExitStack() as stack:
            await _set_up_host(_server_config(), stack, None, SessionTable([A]))
    args = parts.proxy_args
    assert (args["bind_ip"], args["bind_port"]) == ("10.8.0.1", 53)
    first, second = args["per_client"](), args["per_client"]()
    assert isinstance(args["resolver"], DNSResolver)
    assert isinstance(first, DNSResolver) and isinstance(second, DNSResolver)
    assert len({id(args["resolver"]), id(first), id(second)}) == 3


async def test_a_busy_dns_port_unwinds_what_was_built() -> None:
    with _HostParts() as parts:
        parts.dns_error = DNSProxyPortInUseError("10.8.0.1:53 is taken")
        with pytest.raises(DNSProxyPortInUseError):
            async with AsyncExitStack() as stack:
                await _set_up_host(_server_config(), stack, None, SessionTable([A]))
    assert parts.events[-3:] == ["nat off", "forwarding off", "tun close"]
    assert "dns off" not in parts.events


async def test_a_tun_that_fails_to_configure_is_closed_again() -> None:
    with _HostParts() as parts:
        parts.configure_error = RuntimeError(
            "TUN configure failed: ip link set mtun0 up"
        )
        with pytest.raises(RuntimeError, match="TUN configure failed"):
            async with AsyncExitStack() as stack:
                await _set_up_host(_server_config(), stack, None, SessionTable([A]))
    assert parts.events == ["tun mtun0", "tun open", "tun close"]


async def test_a_nat_table_that_does_not_load_stops_the_setup() -> None:
    # Fail closed (roadmap item 1.8): no DNS proxy is built; forwarding and
    # the TUN unwind.
    with _HostParts() as parts:
        parts.nat_loads = False
        with pytest.raises(RuntimeError, match="NAT table .* did not load"):
            async with AsyncExitStack() as stack:
                await _set_up_host(_server_config(), stack, None, SessionTable([A]))
    assert parts.proxy_args == {}
    assert parts.events == [
        "tun mtun0",
        "tun open",
        "tun up 10.8.0.1 server_mode=True",
        "forwarding on",
        "forwarding off",
        "tun close",
    ]
