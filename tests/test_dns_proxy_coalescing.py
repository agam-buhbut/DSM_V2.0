"""Tests for dsm.net.dns_proxy — in-flight deduplication and semaphore bounding.

Covers the M3 additions to ``LocalDNSProxy``:

* ``_inflight`` coalesces identical concurrent queries to a single upstream call.
* ``_sem`` bounds concurrent resolve tasks to ``_MAX_CONCURRENT_QUERIES``.
"""

from __future__ import annotations

import asyncio
import time
import unittest

import dns.message
import dns.rcode
import dns.rdatatype

from dsm.net.dns_proxy import LocalDNSProxy


def _build_query_wire(qname: str) -> bytes:
    """Build an A-record query wire format for ``qname``."""
    return dns.message.make_query(qname, dns.rdatatype.A).to_wire()


def _parse_response(wire: bytes) -> dns.message.Message:
    return dns.message.from_wire(wire)


class _CountingResolver:
    """Resolver stub that counts calls and sleeps briefly before returning.

    The sleep is essential: it lets concurrent callers reach ``_handle_query``
    and find the in-flight future before the first caller resolves it.
    """

    def __init__(self, addresses: list[str] | None = None, sleep: float = 0.01) -> None:
        self._addresses = addresses if addresses is not None else ["1.2.3.4"]
        self._sleep = sleep
        self.calls = 0
        self.closed = False

    async def resolve(self, hostname: str) -> list[str]:
        self.calls += 1
        await asyncio.sleep(self._sleep)
        return list(self._addresses)

    async def close(self) -> None:
        self.closed = True


class _RaisingResolver:
    """Resolver stub that sleeps briefly then raises RuntimeError."""

    def __init__(self, sleep: float = 0.01) -> None:
        self._sleep = sleep
        self.calls = 0
        self.closed = False

    async def resolve(self, hostname: str) -> list[str]:
        self.calls += 1
        await asyncio.sleep(self._sleep)
        raise RuntimeError("stub-upstream-fail")

    async def close(self) -> None:
        self.closed = True


class _SlowResolver:
    """Resolver stub with a longer configurable sleep for timing tests."""

    def __init__(self, sleep: float = 0.1) -> None:
        self._sleep = sleep
        self.calls = 0
        self.closed = False

    async def resolve(self, hostname: str) -> list[str]:
        self.calls += 1
        await asyncio.sleep(self._sleep)
        return ["9.9.9.9"]

    async def close(self) -> None:
        self.closed = True


class TestInflightCoalescing(unittest.IsolatedAsyncioTestCase):
    async def test_identical_concurrent_queries_coalesce(self) -> None:
        """10 concurrent identical queries should trigger exactly 1 resolve."""
        stub = _CountingResolver(addresses=["1.2.3.4"], sleep=0.02)
        proxy = LocalDNSProxy(stub, bind_ip="127.0.0.1")  # type: ignore[arg-type]
        sent: list[tuple[bytes, tuple[str, int]]] = []

        def _send(wire: bytes, to: tuple[str, int]) -> None:
            sent.append((wire, to))

        wire = _build_query_wire("example.com")
        # Fire 10 concurrent queries for the *same* qname.
        await asyncio.gather(
            *(
                proxy._handle_query(wire, ("127.0.0.1", 10000 + i), _send)
                for i in range(10)
            )
        )

        self.assertEqual(stub.calls, 1, "expected exactly one upstream resolve")
        self.assertEqual(len(sent), 10, "expected every caller to receive a response")

        # Every response must be a valid A-record answer, not SERVFAIL.
        for raw, _addr in sent:
            resp = _parse_response(raw)
            self.assertEqual(resp.rcode(), dns.rcode.NOERROR)
            self.assertTrue(resp.answer, "expected an A-record answer section")
            # Extract rdata text from the first rrset.
            rrset = resp.answer[0]
            addrs = [item.to_text() for item in rrset]
            self.assertIn("1.2.3.4", addrs)

    async def test_different_qnames_do_not_coalesce(self) -> None:
        """Distinct qnames should each produce their own upstream call."""
        stub = _CountingResolver(addresses=["1.2.3.4"], sleep=0.01)
        proxy = LocalDNSProxy(stub, bind_ip="127.0.0.1")  # type: ignore[arg-type]
        sent: list[tuple[bytes, tuple[str, int]]] = []

        def _send(wire: bytes, to: tuple[str, int]) -> None:
            sent.append((wire, to))

        await asyncio.gather(
            *(
                proxy._handle_query(
                    _build_query_wire(f"host-{i}.example"),
                    ("127.0.0.1", 10000 + i),
                    _send,
                )
                for i in range(10)
            )
        )

        self.assertEqual(stub.calls, 10, "expected one upstream resolve per distinct qname")
        self.assertEqual(len(sent), 10)

    async def test_coalesced_failure_propagates_to_all_callers(self) -> None:
        """Five concurrent identical queries should all get SERVFAIL from one failed call."""
        stub = _RaisingResolver(sleep=0.02)
        proxy = LocalDNSProxy(stub, bind_ip="127.0.0.1")  # type: ignore[arg-type]
        sent: list[tuple[bytes, tuple[str, int]]] = []

        def _send(wire: bytes, to: tuple[str, int]) -> None:
            sent.append((wire, to))

        wire = _build_query_wire("broken.example")
        await asyncio.gather(
            *(
                proxy._handle_query(wire, ("127.0.0.1", 10000 + i), _send)
                for i in range(5)
            )
        )

        self.assertEqual(stub.calls, 1, "expected exactly one upstream call despite 5 callers")
        self.assertEqual(len(sent), 5, "expected every caller to receive a response")
        for raw, _addr in sent:
            resp = _parse_response(raw)
            self.assertEqual(
                resp.rcode(), dns.rcode.SERVFAIL,
                "coalesced failure must propagate as SERVFAIL to every caller",
            )


class TestSemaphoreBounds(unittest.IsolatedAsyncioTestCase):
    async def test_semaphore_serializes_concurrent_queries(self) -> None:
        """With _MAX_CONCURRENT_QUERIES=2 and 0.1s per query, 10 queries take >=0.5s."""
        original_limit = LocalDNSProxy._MAX_CONCURRENT_QUERIES
        LocalDNSProxy._MAX_CONCURRENT_QUERIES = 2
        try:
            stub = _SlowResolver(sleep=0.1)
            proxy = LocalDNSProxy(stub, bind_ip="127.0.0.1")  # type: ignore[arg-type]
            sent: list[tuple[bytes, tuple[str, int]]] = []

            def _send(wire: bytes, to: tuple[str, int]) -> None:
                sent.append((wire, to))

            start = time.monotonic()
            await asyncio.gather(
                *(
                    proxy._handle_query(
                        _build_query_wire(f"bound-{i}.example"),
                        ("127.0.0.1", 10000 + i),
                        _send,
                    )
                    for i in range(10)
                )
            )
            elapsed = time.monotonic() - start

            # 10 tasks, 2 at a time, 0.1s each => 5 batches => ~0.5s floor.
            # Allow small slack for scheduler jitter.
            self.assertGreaterEqual(
                elapsed, 0.45,
                f"semaphore did not serialize: took {elapsed:.3f}s, expected >=0.45s",
            )
            self.assertEqual(stub.calls, 10)
            self.assertEqual(len(sent), 10)
        finally:
            LocalDNSProxy._MAX_CONCURRENT_QUERIES = original_limit


class TestInflightCleanup(unittest.IsolatedAsyncioTestCase):
    async def test_inflight_cleared_after_success(self) -> None:
        stub = _CountingResolver(addresses=["1.2.3.4"], sleep=0.0)
        proxy = LocalDNSProxy(stub, bind_ip="127.0.0.1")  # type: ignore[arg-type]
        sent: list[tuple[bytes, tuple[str, int]]] = []

        def _send(wire: bytes, to: tuple[str, int]) -> None:
            sent.append((wire, to))

        await proxy._handle_query(
            _build_query_wire("example.com"), ("127.0.0.1", 12345), _send,
        )

        # Key should have been removed in the finally block.
        self.assertNotIn(("example.com", dns.rdatatype.A), proxy._inflight)
        self.assertEqual(len(proxy._inflight), 0)

    async def test_inflight_cleared_after_failure(self) -> None:
        stub = _RaisingResolver(sleep=0.0)
        proxy = LocalDNSProxy(stub, bind_ip="127.0.0.1")  # type: ignore[arg-type]
        sent: list[tuple[bytes, tuple[str, int]]] = []

        def _send(wire: bytes, to: tuple[str, int]) -> None:
            sent.append((wire, to))

        await proxy._handle_query(
            _build_query_wire("broken.example"), ("127.0.0.1", 12345), _send,
        )

        # Even on upstream failure the finally clause must clear the entry.
        self.assertNotIn(("broken.example", dns.rdatatype.A), proxy._inflight)
        self.assertEqual(len(proxy._inflight), 0)


if __name__ == "__main__":
    unittest.main()
