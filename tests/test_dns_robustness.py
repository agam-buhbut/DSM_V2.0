"""Phase 1.10: DNS robustness — IP-literal providers, NXDOMAIN distinction,
bounded cache heap, TTL clamp.
"""

from __future__ import annotations

import unittest
from typing import Any

import dns.message
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from dsm.core.config import Config
from dsm.net.dns import MAX_TTL, MIN_TTL, DNSResolver, _parse_dns_response


def _server_base(**overrides: Any) -> dict[str, Any]:
    d: dict[str, Any] = {
        "mode": "server",
        "server_ip": "10.0.0.1",
        "server_port": 51820,
        "listen_port": 51820,
        "key_file": "/tmp/k.key",
        "cert_file": "/tmp/c.crt",
        "ca_root_file": "/tmp/ca.pem",
        "attest_key_file": "/tmp/a.key",
        "expected_server_cn": None,
        "allowed_cns_file": "/tmp/cns.txt",
        "transport": "udp",
    }
    d.update(overrides)
    return d


class IpLiteralProviders(unittest.TestCase):
    def test_hostname_form_provider_rejected(self) -> None:
        with self.assertRaises(ValueError):
            Config(
                **_server_base(
                    dns_providers=["https://dns.example.com/dns-query"],
                    dns_provider_pins={"https://dns.example.com/dns-query": ["a" * 64]},
                )
            )

    def test_ip_literal_provider_accepted(self) -> None:
        c = Config(
            **_server_base(
                dns_providers=["https://1.1.1.1/dns-query"],
                dns_provider_pins={"https://1.1.1.1/dns-query": ["a" * 64]},
            )
        )
        self.assertEqual(c.mode, "server")

    def test_ipv6_literal_provider_accepted(self) -> None:
        c = Config(
            **_server_base(
                dns_providers=["tls://[2606:4700:4700::1111]:853"],
                dns_provider_pins={"tls://[2606:4700:4700::1111]:853": ["b" * 64]},
            )
        )
        self.assertEqual(c.mode, "server")

    def test_error_names_provider_and_ip_literal(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            Config(
                **_server_base(
                    dns_providers=["tls://dns.example.com:853"],
                    dns_provider_pins={"tls://dns.example.com:853": ["a" * 64]},
                )
            )
        msg = str(ctx.exception)
        self.assertIn("dns.example.com", msg)
        self.assertIn("IP literal", msg)


def _resp(qname: str, rcode: int, answers: bool) -> bytes:
    q = dns.message.make_query(qname, dns.rdatatype.A)
    r = dns.message.make_response(q)
    r.set_rcode(rcode)
    if answers:
        rr = dns.rrset.from_text_list(
            q.question[0].name,
            60,
            dns.rdataclass.IN,
            dns.rdatatype.A,
            ["1.2.3.4"],
        )
        r.answer.append(rr)
    return r.to_wire()


class NxdomainDistinction(unittest.TestCase):
    def test_nxdomain_is_authoritative_empty_not_failure(self) -> None:
        wire = _resp("nope.invalid", dns.rcode.NXDOMAIN, answers=False)
        result = _parse_dns_response(wire)
        self.assertEqual(result.addresses, [])
        self.assertEqual(result.rcode, int(dns.rcode.NXDOMAIN))
        self.assertTrue(result.authoritative)

    def test_noerror_with_answers_has_addresses(self) -> None:
        wire = _resp("ok.example", dns.rcode.NOERROR, answers=True)
        result = _parse_dns_response(wire)
        self.assertEqual(result.addresses, ["1.2.3.4"])
        self.assertEqual(result.rcode, int(dns.rcode.NOERROR))
        self.assertTrue(result.authoritative)

    def test_nodata_is_authoritative_empty(self) -> None:
        wire = _resp("ok.example", dns.rcode.NOERROR, answers=False)
        result = _parse_dns_response(wire)
        self.assertEqual(result.addresses, [])
        self.assertEqual(result.rcode, int(dns.rcode.NOERROR))
        self.assertTrue(result.authoritative)

    def test_servfail_is_not_authoritative(self) -> None:
        wire = _resp("flaky.example", dns.rcode.SERVFAIL, answers=False)
        result = _parse_dns_response(wire)
        self.assertEqual(result.addresses, [])
        self.assertEqual(result.rcode, int(dns.rcode.SERVFAIL))
        self.assertFalse(result.authoritative)

    def test_garbage_is_not_authoritative(self) -> None:
        result = _parse_dns_response(b"\x00\x01not-a-dns-message")
        self.assertEqual(result.addresses, [])
        self.assertFalse(result.authoritative)


class _ParseStubResolver(DNSResolver):
    """DNSResolver whose per-protocol transport is replaced by a canned wire.

    Counts how many provider attempts the fan-out makes so the test can
    assert that an authoritative NXDOMAIN stops the fan-out after one
    provider and that a cache hit issues no upstream call at all.
    """

    def __init__(self, wire: bytes, **kw: Any) -> None:
        super().__init__(**kw)
        self._wire = wire
        self.doh_calls = 0

    async def _resolve_doh(self, url: str, hostname: str):  # type: ignore[override]
        self.doh_calls += 1
        result = _parse_dns_response(self._wire)
        if result.authoritative:
            self._cache_result(hostname, result.addresses, result.ttl, result.rcode)
        return result


class NxdomainFanOutAndCache(unittest.IsolatedAsyncioTestCase):
    def _resolver(self, wire: bytes) -> _ParseStubResolver:
        return _ParseStubResolver(
            wire,
            providers=[
                "https://1.1.1.1/dns-query",
                "https://9.9.9.9/dns-query",
            ],
            provider_pins={
                "https://1.1.1.1/dns-query": ["a" * 64],
                "https://9.9.9.9/dns-query": ["b" * 64],
            },
            hosts_file="/nonexistent",
        )

    async def test_nxdomain_stops_fanout_and_relays_and_caches(self) -> None:
        wire = _resp("nope.invalid", dns.rcode.NXDOMAIN, answers=False)
        r = self._resolver(wire)

        result = await r.resolve_detailed("nope.invalid")
        # Authoritative NXDOMAIN stops fan-out after the FIRST provider.
        self.assertEqual(r.doh_calls, 1)
        self.assertTrue(result.authoritative)
        self.assertEqual(result.rcode, int(dns.rcode.NXDOMAIN))
        self.assertEqual(result.addresses, [])

        # Second query is served from the negative cache: no upstream call.
        cached = await r.resolve_detailed("nope.invalid")
        self.assertEqual(r.doh_calls, 1)
        self.assertTrue(cached.authoritative)
        self.assertEqual(cached.rcode, int(dns.rcode.NXDOMAIN))

    async def test_resolve_list_contract_preserved(self) -> None:
        wire = _resp("ok.example", dns.rcode.NOERROR, answers=True)
        r = self._resolver(wire)
        addresses = await r.resolve("ok.example")
        self.assertEqual(addresses, ["1.2.3.4"])


class CacheHeapBound(unittest.TestCase):
    def test_heap_does_not_grow_unboundedly_under_2000_names(self) -> None:
        r = DNSResolver(
            providers=["https://1.1.1.1/dns-query"],
            provider_pins={"https://1.1.1.1/dns-query": ["a" * 64]},
            hosts_file="/nonexistent",
        )
        # Re-resolve the SAME small set of names many times so each re-cache
        # pushes a heap entry. The heap must self-compact.
        for i in range(500):
            r._cache_result(f"h{i % 5}.example", ["1.2.3.4"], ttl=1)
        # The heap must never exceed ~2x the live cache (live cache is 5).
        self.assertLessEqual(len(r._cache_heap), 2 * len(r._cache) + 10)

    def test_expired_heads_are_reaped(self) -> None:
        r = DNSResolver(
            providers=["https://1.1.1.1/dns-query"],
            provider_pins={"https://1.1.1.1/dns-query": ["a" * 64]},
            hosts_file="/nonexistent",
        )
        # Insert a heap head whose expiry is already in the past, then trigger
        # a normal cache write which must opportunistically reap it.
        import heapq
        import time as _time

        from dsm.net.dns import _CacheEntry

        past = _time.monotonic() - 1.0
        r._cache["stale.example"] = _CacheEntry(
            addresses=["9.9.9.9"], expires=past, rcode=0
        )
        heapq.heappush(r._cache_heap, (past, "stale.example"))
        self.assertEqual(len(r._cache_heap), 1)

        r._cache_result("fresh.example", ["1.2.3.4"], ttl=60)
        # The stale head was reaped; only the fresh entry remains.
        self.assertNotIn("stale.example", r._cache)
        self.assertEqual(len(r._cache_heap), 1)


class TtlClamp(unittest.TestCase):
    def _resolver(self) -> DNSResolver:
        return DNSResolver(
            providers=["https://1.1.1.1/dns-query"],
            provider_pins={"https://1.1.1.1/dns-query": ["a" * 64]},
            hosts_file="/nonexistent",
        )

    def test_ttl_above_max_clamped_to_max(self) -> None:
        import time as _time

        r = self._resolver()
        before = _time.monotonic()
        r._cache_result("hi.example", ["1.2.3.4"], ttl=MAX_TTL + 100_000)
        entry = r._cache["hi.example"]
        # Expiry must be at most now + MAX_TTL (clamped), not the raw huge TTL.
        self.assertLessEqual(entry.expires, before + MAX_TTL + 1.0)
        self.assertGreaterEqual(entry.expires, before + MAX_TTL - 1.0)

    def test_ttl_below_min_clamped_to_min(self) -> None:
        import time as _time

        r = self._resolver()
        before = _time.monotonic()
        r._cache_result("lo.example", ["1.2.3.4"], ttl=1)
        entry = r._cache["lo.example"]
        self.assertGreaterEqual(entry.expires, before + MIN_TTL - 1.0)
        self.assertLessEqual(entry.expires, before + MIN_TTL + 1.0)

    def test_max_ttl_reachable_from_parse(self) -> None:
        # A response with a large TTL parses to MAX_TTL (not capped at 300).
        q = dns.message.make_query("big.example", dns.rdatatype.A)
        resp = dns.message.make_response(q)
        rr = dns.rrset.from_text_list(
            q.question[0].name,
            999_999,
            dns.rdataclass.IN,
            dns.rdatatype.A,
            ["1.2.3.4"],
        )
        resp.answer.append(rr)
        result = _parse_dns_response(resp.to_wire())
        self.assertEqual(result.ttl, MAX_TTL)


if __name__ == "__main__":
    unittest.main()
