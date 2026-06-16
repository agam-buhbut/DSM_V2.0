"""Regression: a DNS upstream-resolver failure must not orphan an exception on
the in-flight coalescing future.

Previously ``_resolve_with_dedup`` called ``set_exception`` on the shared
future and returned a SERVFAIL result without awaiting it; with zero coalesced
waiters the exception was never retrieved, producing asyncio "Future exception
was never retrieved" diagnostics. The fix publishes a SERVFAIL *result*.
"""

from __future__ import annotations

import asyncio
import gc
import unittest

import dns.rdatatype

from dsm.net.dns_proxy import LocalDNSProxy


class _RaisingResolver:
    """Upstream resolver stub that always fails."""

    def __init__(self) -> None:
        self.calls = 0

    async def resolve(self, hostname: str) -> list[str]:
        self.calls += 1
        raise RuntimeError("stub-upstream-fail")

    async def close(self) -> None:
        pass


class TestResolverFailureFuture(unittest.IsolatedAsyncioTestCase):
    async def test_failure_returns_servfail_without_orphaned_exception(
        self,
    ) -> None:
        proxy = LocalDNSProxy(_RaisingResolver(), bind_ip="127.0.0.1")  # type: ignore[arg-type]

        loop = asyncio.get_running_loop()
        captured: list[dict[str, object]] = []
        loop.set_exception_handler(lambda _loop, ctx: captured.append(ctx))

        # Single query, NO coalesced waiter — the owner returns directly.
        result = await proxy._resolve_with_dedup("broken.example", dns.rdatatype.A)

        # Owner still observes a SERVFAIL-equivalent result.
        self.assertEqual(result.rcode, -1)
        self.assertFalse(result.authoritative)
        self.assertEqual(result.addresses, [])

        # The inflight slot is cleared and the future carries no unretrieved
        # exception, so collecting it must not reach the loop exception handler.
        self.assertEqual(len(proxy._inflight), 0)
        gc.collect()
        messages = [str(c.get("message", "")) for c in captured]
        self.assertFalse(
            any("never retrieved" in m for m in messages),
            f"orphaned future exception(s): {captured}",
        )
