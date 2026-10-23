"""The DNS proxy's per-client mode (multi-client spec §2.11, §3.4): each
client address gets its own resolver, so its own cache, and its own
in-flight table; the server's own address uses the shared resolver; forget
drops a client's state. Queries go through the real datagram protocol;
resolvers are in-memory fakes. Nothing touches the network.
"""

from __future__ import annotations

import asyncio

import dns.message
import dns.rcode
import dns.rdatatype

from dsm.net.dns import DnsResult
from dsm.net.dns_proxy import LocalDNSProxy, _ProxyProtocol

A = ("10.8.0.2", 5353)
B = ("10.8.0.3", 5353)
SERVER = ("10.8.0.1", 5353)


class _Resolver:
    """A resolver with its own cache: one upstream call per name, then the
    cached answer. With ``hold``, every upstream call waits for it."""

    def __init__(self, hold: asyncio.Event | None = None) -> None:
        self.calls: list[str] = []
        self._cache: set[str] = set()
        self._hold = hold

    async def resolve_detailed(self, hostname: str) -> DnsResult:
        if hostname not in self._cache:
            self.calls.append(hostname)
            if self._hold is not None:
                await self._hold.wait()
            self._cache.add(hostname)
        return DnsResult(
            addresses=["192.0.2.1"],
            ttl=60,
            rcode=int(dns.rcode.NOERROR),
            authoritative=True,
        )


class _Transport:
    def __init__(self) -> None:
        self.sent: list[tuple[bytes, tuple[str, int]]] = []

    def sendto(self, wire: bytes, to: tuple[str, int]) -> None:
        self.sent.append((wire, to))


class _Proxy:
    """A proxy on 10.8.0.1, fed through its real datagram protocol."""

    def __init__(
        self, *, per_client: bool = True, hold: asyncio.Event | None = None
    ) -> None:
        self.shared = _Resolver(hold)
        self.made: list[_Resolver] = []

        def _new() -> _Resolver:
            resolver = _Resolver(hold)
            self.made.append(resolver)
            return resolver

        self.proxy = LocalDNSProxy(
            self.shared,  # type: ignore[arg-type]
            bind_ip="10.8.0.1",
            per_client=_new if per_client else None,  # type: ignore[arg-type]
        )
        self.transport = _Transport()
        self._proto = _ProxyProtocol(self.proxy)
        self._proto.connection_made(self.transport)  # type: ignore[arg-type]

    def ask(self, name: str, src: tuple[str, int]) -> None:
        wire = dns.message.make_query(name, dns.rdatatype.A).to_wire()
        self._proto.datagram_received(wire, src)

    async def settle(self) -> None:
        await asyncio.gather(*list(self.proxy._tasks))

    def answered(self) -> list[tuple[str, int]]:
        return [to for _wire, to in self.transport.sent]


async def _yield(rounds: int = 50) -> None:
    for _ in range(rounds):
        await asyncio.sleep(0)


async def test_one_clients_cached_answer_is_not_used_for_another() -> None:
    run = _Proxy()
    run.ask("example.com", A)
    await run.settle()
    run.ask("example.com", A)
    await run.settle()
    run.ask("example.com", B)
    await run.settle()
    assert [r.calls for r in run.made] == [["example.com"], ["example.com"]]
    assert run.shared.calls == []
    assert run.answered() == [A, A, B]


async def test_identical_queries_coalesce_within_one_client_only() -> None:
    hold = asyncio.Event()
    run = _Proxy(hold=hold)
    run.ask("example.com", A)
    run.ask("example.com", A)
    run.ask("example.com", B)
    await _yield()
    # A's two queries make one upstream call; B's, at the same moment, its own.
    assert [r.calls for r in run.made] == [["example.com"], ["example.com"]]
    hold.set()
    await run.settle()
    assert sorted(run.answered()) == [A, A, B]


async def test_the_servers_own_address_uses_the_shared_resolver() -> None:
    run = _Proxy()
    run.ask("example.com", SERVER)
    await run.settle()
    assert run.shared.calls == ["example.com"]
    assert run.made == []


async def test_forget_drops_a_clients_cache() -> None:
    run = _Proxy()
    run.ask("example.com", A)
    await run.settle()
    run.proxy.forget("10.8.0.2")
    run.ask("example.com", A)
    await run.settle()
    assert [r.calls for r in run.made] == [["example.com"], ["example.com"]]
    run.proxy.forget("10.8.0.9")  # unknown: nothing to do


async def test_without_per_client_every_client_shares_one_resolver() -> None:
    run = _Proxy(per_client=False)
    run.ask("example.com", A)
    await run.settle()
    run.ask("example.com", B)
    await run.settle()
    assert run.shared.calls == ["example.com"]  # B got A's cached answer
    assert run.made == []
    assert run.answered() == [A, B]
