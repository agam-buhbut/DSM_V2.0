"""Regression: the local DNS proxy must answer only in-tunnel sources.
Off-subnet datagrams (open-resolver / reflection) get no reply and
allocate no pending state (_ProxyProtocol.datagram_received source-filter)."""

from __future__ import annotations

import asyncio
import unittest

import dns.message
import dns.rdatatype

from dsm.net.dns_proxy import LocalDNSProxy, _ProxyProtocol


class _StubResolver:
    async def resolve(self, hostname: str) -> list[str]:
        return ["10.0.0.99"]

    async def close(self) -> None:
        return None


class _FakeTransport:
    def __init__(self) -> None:
        self.sent: list[tuple[bytes, tuple[str, int]]] = []

    def sendto(self, wire: bytes, to: tuple[str, int]) -> None:
        self.sent.append((wire, to))


def _query_wire(qname: str) -> bytes:
    return dns.message.make_query(qname, dns.rdatatype.A).to_wire()


class TestDnsProxySourceFilter(unittest.IsolatedAsyncioTestCase):
    async def _make_proxy(self) -> tuple[LocalDNSProxy, _ProxyProtocol, _FakeTransport]:
        proxy = LocalDNSProxy(_StubResolver(), bind_ip="10.8.0.1")  # type: ignore[arg-type]
        proto = _ProxyProtocol(proxy)
        fake = _FakeTransport()
        proto.connection_made(fake)  # type: ignore[arg-type]
        return proxy, proto, fake

    async def test_off_subnet_source_dropped_no_state(self) -> None:
        proxy, proto, fake = await self._make_proxy()
        proto.datagram_received(_query_wire("example.com"), ("9.9.9.9", 5353))
        # No reply, no scheduled task, no inflight allocation.
        self.assertEqual(fake.sent, [])
        self.assertEqual(len(proxy._tasks), 0)
        self.assertEqual(proxy._inflight, {})
        # Drop counter must have incremented.
        self.assertEqual(proxy._dropped_offnet, 1)

    async def test_in_subnet_source_served(self) -> None:
        proxy, proto, fake = await self._make_proxy()
        proto.datagram_received(_query_wire("example.com"), ("10.8.0.2", 5353))
        # A task was scheduled; let it run and confirm a reply was sent.
        self.assertGreaterEqual(len(proxy._tasks), 1)
        await asyncio.gather(*list(proxy._tasks))
        self.assertEqual(len(fake.sent), 1)
        resp = dns.message.from_wire(fake.sent[0][0])
        self.assertTrue(resp.answer)

    async def test_boundary_last_in_subnet_served(self) -> None:
        """10.8.0.255 is the broadcast address of 10.8.0.0/24 — still inside
        the allowed network (ip_network membership includes broadcast)."""
        proxy, proto, fake = await self._make_proxy()
        proto.datagram_received(_query_wire("example.com"), ("10.8.0.255", 5353))
        self.assertGreaterEqual(len(proxy._tasks), 1)
        await asyncio.gather(*list(proxy._tasks))
        self.assertEqual(len(fake.sent), 1)

    async def test_boundary_first_outside_subnet_dropped(self) -> None:
        """10.8.1.1 is the first address of the adjacent /24 — outside tunnel."""
        proxy, proto, fake = await self._make_proxy()
        proto.datagram_received(_query_wire("example.com"), ("10.8.1.1", 5353))
        self.assertEqual(fake.sent, [])
        self.assertEqual(len(proxy._tasks), 0)
        self.assertEqual(proxy._inflight, {})
        self.assertEqual(proxy._dropped_offnet, 1)


if __name__ == "__main__":
    unittest.main()
