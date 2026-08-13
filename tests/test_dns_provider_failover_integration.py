"""Integration tests for DNS provider failover / fan-out in dsm.net.dns.

Covers the gap in ``DNSResolver.resolve_detailed`` provider fan-out that the
existing ``test_dns_robustness.py`` does not exercise:

  * **Failover order** — providers are tried in configured list order; a
    provider that fails (transport error, SPKI pin mismatch, or a
    non-authoritative SERVFAIL/REFUSED rcode) is skipped and the *next*
    provider is consulted.
  * **A failing provider is skipped, not fatal** — a raised exception from
    one provider must not abort the whole resolve; later providers still run.
  * **Protocol dispatch + scheme-mismatch** — ``https://`` providers route to
    DoH and ``tls://`` to DoT; ``_resolve_doh`` / ``_resolve_dot`` raise
    ``ValueError`` on a wrong-scheme URL, which the fan-out treats as a
    provider failure and skips.
  * **Negative-cache behaviour** — an authoritative NXDOMAIN reached after a
    failover stops fan-out and is negative-cached, so a repeat query issues
    zero upstream calls.
  * **Typed result** — the returned object is a ``DnsResult`` with the
    expected ``authoritative`` / ``rcode`` / ``addresses`` fields.

The mock boundary is ``DNSResolver._resolve_via_pinned_tls`` — the shared
connect → SPKI-pin-check → send/recv → close scaffold that is the single I/O
chokepoint (TLS socket plus wire send/recv). Everything above it — the
``resolve_detailed`` fan-out loop, the per-protocol ``_resolve_doh`` /
``_resolve_dot`` scheme dispatch, ``_parse_dns_response``, and the cache —
runs as real production code. A provider is selected per-call by the URL the
loop passes down, so the stub can return canned wire bytes or raise exactly
as a real upstream would.
"""

from __future__ import annotations

import asyncio
import unittest
from collections.abc import Awaitable, Callable

import dns.message
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from dsm.net.dns import DNSResolver, DnsResult
from dsm.net.dns_pinning import PinMismatchError

# Provider URLs in the exact order the resolver must try them.
DOH_A = "https://1.1.1.1/dns-query"
DOH_B = "https://9.9.9.9/dns-query"
DOT_C = "tls://8.8.8.8:853"

_PINS = {
    DOH_A: ["a" * 64],
    DOH_B: ["b" * 64],
    DOT_C: ["c" * 64],
}

# A send_recv body is opaque to the stub; resolve_via_pinned_tls in production
# would invoke it after the pin check. We never call it — the stub stands in
# for the whole connect+send/recv, returning the wire the real upstream would.
_SendRecv = Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[bytes]]


def _answer_wire(qname: str, address: str) -> bytes:
    """A NOERROR response with one A record."""
    q = dns.message.make_query(qname, dns.rdatatype.A)
    r = dns.message.make_response(q)
    r.set_rcode(dns.rcode.NOERROR)
    rr = dns.rrset.from_text_list(
        q.question[0].name,
        60,
        dns.rdataclass.IN,
        dns.rdatatype.A,
        [address],
    )
    r.answer.append(rr)
    return r.to_wire()


def _rcode_wire(qname: str, rcode: int) -> bytes:
    """An answer-less response carrying ``rcode`` (e.g. SERVFAIL, NXDOMAIN)."""
    q = dns.message.make_query(qname, dns.rdatatype.A)
    r = dns.message.make_response(q)
    r.set_rcode(rcode)
    return r.to_wire()


class _ScriptedResolver(DNSResolver):
    """DNSResolver whose TLS I/O boundary returns scripted per-provider wires.

    ``script`` maps a provider URL to either canned wire bytes (the upstream's
    response) or an exception instance to raise (a transport failure / pin
    mismatch). Every consultation of a provider is recorded in ``attempts`` so
    a test can assert the exact failover order and that a failed provider was
    visited exactly once before the loop moved on.
    """

    def __init__(
        self,
        providers: list[str],
        script: dict[str, bytes | Exception],
    ) -> None:
        super().__init__(
            providers=providers,
            provider_pins={p: _PINS[p] for p in providers},
            hosts_file="/nonexistent",
        )
        self._script = script
        self.attempts: list[str] = []

    async def _resolve_via_pinned_tls(  # type: ignore[override]
        self,
        provider: str,
        host: str,
        port: int,
        timeout: float,
        send_recv: _SendRecv,
        *,
        reverify_pin: bool = False,
    ) -> bytes:
        self.attempts.append(provider)
        outcome = self._script[provider]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class FailoverOrder(unittest.IsolatedAsyncioTestCase):
    async def test_failed_first_provider_skipped_second_answers(self) -> None:
        """A transport failure on provider A is skipped; B's answer wins.

        Discriminating assertion: the loop visits A *then* B in order, A's
        OSError does not abort the resolve, and the typed result carries B's
        address. A broken implementation that aborted on the first exception,
        or that did not preserve order, would fail here.
        """
        r = _ScriptedResolver(
            providers=[DOH_A, DOH_B],
            script={
                DOH_A: OSError("connection refused"),
                DOH_B: _answer_wire("ok.example", "9.9.9.9"),
            },
        )
        result = await r.resolve_detailed("ok.example")

        self.assertEqual(r.attempts, [DOH_A, DOH_B])
        self.assertIsInstance(result, DnsResult)
        self.assertTrue(result.authoritative)
        self.assertEqual(result.rcode, int(dns.rcode.NOERROR))
        self.assertEqual(result.addresses, ["9.9.9.9"])

    async def test_authoritative_answer_stops_fanout_before_later_providers(
        self,
    ) -> None:
        """Provider A answering authoritatively must short-circuit the loop.

        B is scripted to raise; if the resolver consulted it the test would
        error, proving fan-out stops on the first authoritative answer rather
        than always polling every provider.
        """
        r = _ScriptedResolver(
            providers=[DOH_A, DOH_B],
            script={
                DOH_A: _answer_wire("first.example", "1.1.1.1"),
                DOH_B: RuntimeError("must not be consulted"),
            },
        )
        result = await r.resolve_detailed("first.example")

        self.assertEqual(r.attempts, [DOH_A])
        self.assertEqual(result.addresses, ["1.1.1.1"])

    async def test_pin_mismatch_is_skipped_like_any_failure(self) -> None:
        """A PinMismatchError (possible MITM) on A must fall through to B.

        Assertion: a pin failure is a *skip*, never a propagated raise —
        a MITM on one provider cannot deny resolution when an honest provider
        follows. The result must come from B, and A must have been attempted.
        """
        r = _ScriptedResolver(
            providers=[DOH_A, DOH_B],
            script={
                DOH_A: PinMismatchError("SPKI pin mismatch for A"),
                DOH_B: _answer_wire("mitm.example", "9.9.9.9"),
            },
        )
        result = await r.resolve_detailed("mitm.example")

        self.assertEqual(r.attempts, [DOH_A, DOH_B])
        self.assertEqual(result.addresses, ["9.9.9.9"])
        self.assertTrue(result.authoritative)

    async def test_all_providers_fail_yields_non_authoritative_servfail(
        self,
    ) -> None:
        """Every provider failing → non-authoritative empty result (rcode -1).

        Distinguishes a transport-wide outage (caller emits SERVFAIL) from an
        authoritative NXDOMAIN. Both providers must be attempted in order.
        """
        r = _ScriptedResolver(
            providers=[DOH_A, DOH_B],
            script={
                DOH_A: OSError("timeout"),
                DOH_B: TimeoutError("timeout"),
            },
        )
        result = await r.resolve_detailed("down.example")

        self.assertEqual(r.attempts, [DOH_A, DOH_B])
        self.assertFalse(result.authoritative)
        self.assertEqual(result.rcode, -1)
        self.assertEqual(result.addresses, [])


class ProtocolMismatch(unittest.IsolatedAsyncioTestCase):
    async def test_servfail_rcode_fails_over_to_next_provider(self) -> None:
        """A non-authoritative SERVFAIL rcode from A fails over to B.

        SERVFAIL/REFUSED are *retryable* (non-authoritative) per
        ``_parse_dns_response``: the loop must keep going. Assertion: A is
        attempted, its SERVFAIL is not returned, and B's authoritative answer
        is the result.
        """
        r = _ScriptedResolver(
            providers=[DOH_A, DOH_B],
            script={
                DOH_A: _rcode_wire("flaky.example", int(dns.rcode.SERVFAIL)),
                DOH_B: _answer_wire("flaky.example", "9.9.9.9"),
            },
        )
        result = await r.resolve_detailed("flaky.example")

        self.assertEqual(r.attempts, [DOH_A, DOH_B])
        self.assertTrue(result.authoritative)
        self.assertEqual(result.addresses, ["9.9.9.9"])

    async def test_unparseable_wire_is_treated_as_failure_and_skipped(
        self,
    ) -> None:
        """Garbage wire bytes from A (not a DNS message) → skip, try B."""
        r = _ScriptedResolver(
            providers=[DOH_A, DOH_B],
            script={
                DOH_A: b"\x00\x01not-a-dns-message",
                DOH_B: _answer_wire("junk.example", "9.9.9.9"),
            },
        )
        result = await r.resolve_detailed("junk.example")

        self.assertEqual(r.attempts, [DOH_A, DOH_B])
        self.assertEqual(result.addresses, ["9.9.9.9"])

    async def test_mixed_scheme_doh_then_dot_dispatch(self) -> None:
        """A failing DoH provider fails over to a DoT provider.

        Proves the scheme dispatch in ``resolve_detailed`` (``https://`` →
        ``_resolve_doh``, ``tls://`` → ``_resolve_dot``) works across the
        protocol boundary: the DoT provider's answer is returned after the
        DoH provider errors.
        """
        r = _ScriptedResolver(
            providers=[DOH_A, DOT_C],
            script={
                DOH_A: OSError("doh down"),
                DOT_C: _answer_wire("mixed.example", "8.8.8.8"),
            },
        )
        result = await r.resolve_detailed("mixed.example")

        self.assertEqual(r.attempts, [DOH_A, DOT_C])
        self.assertTrue(result.authoritative)
        self.assertEqual(result.addresses, ["8.8.8.8"])

    async def test_unknown_scheme_provider_skipped_without_io(self) -> None:
        """A provider whose URL is neither https:// nor tls:// is skipped.

        ``resolve_detailed`` ``continue``s on an unknown scheme *before* any
        I/O, so the TLS boundary is never reached for it. Assertion: the
        bad-scheme provider never appears in ``attempts`` (no connection made),
        yet the valid provider still answers.
        """
        bad = "ftp://nope.invalid/dns-query"
        r = _ScriptedResolver(
            providers=[DOH_A],
            script={DOH_A: _answer_wire("scheme.example", "1.1.1.1")},
        )
        # Inject the unknown-scheme provider ahead of the good one without
        # giving it a pin (pins are only consulted at connect time, which the
        # unknown-scheme branch never reaches).
        r._providers = [bad, DOH_A]

        result = await r.resolve_detailed("scheme.example")

        self.assertNotIn(bad, r.attempts)
        self.assertEqual(r.attempts, [DOH_A])
        self.assertEqual(result.addresses, ["1.1.1.1"])


class WrongSchemeRaisesInsideProtocolResolver(unittest.IsolatedAsyncioTestCase):
    """A tls:// URL handed to _resolve_doh (and vice-versa) raises ValueError."""

    def _resolver(self) -> DNSResolver:
        return DNSResolver(
            providers=[DOH_A],
            provider_pins={DOH_A: _PINS[DOH_A]},
            hosts_file="/nonexistent",
        )

    async def test_resolve_doh_rejects_non_https_scheme(self) -> None:
        r = self._resolver()
        with self.assertRaises(ValueError):
            await r._resolve_doh("tls://8.8.8.8:853", "x.example")

    async def test_resolve_dot_rejects_non_tls_scheme(self) -> None:
        r = self._resolver()
        with self.assertRaises(ValueError):
            await r._resolve_dot("https://1.1.1.1/dns-query", "x.example")


class NegativeCacheAfterFailover(unittest.IsolatedAsyncioTestCase):
    async def test_nxdomain_from_second_provider_is_cached(self) -> None:
        """NXDOMAIN reached only after a failover is negative-cached.

        First query: A errors, B returns authoritative NXDOMAIN → fan-out
        stops, result is negative-cached. Second query: served from cache with
        ZERO new upstream attempts. Assertion: ``attempts`` does not grow
        on the repeat query, proving the negative-cache survives a failover
        path (not just a first-provider hit).
        """
        r = _ScriptedResolver(
            providers=[DOH_A, DOH_B],
            script={
                DOH_A: OSError("down"),
                DOH_B: _rcode_wire("nope.invalid", int(dns.rcode.NXDOMAIN)),
            },
        )

        first = await r.resolve_detailed("nope.invalid")
        self.assertEqual(r.attempts, [DOH_A, DOH_B])
        self.assertTrue(first.authoritative)
        self.assertEqual(first.rcode, int(dns.rcode.NXDOMAIN))
        self.assertEqual(first.addresses, [])

        attempts_after_first = list(r.attempts)
        second = await r.resolve_detailed("nope.invalid")
        # Served from the negative cache — no new provider consultation.
        self.assertEqual(r.attempts, attempts_after_first)
        self.assertTrue(second.authoritative)
        self.assertEqual(second.rcode, int(dns.rcode.NXDOMAIN))
        self.assertEqual(second.addresses, [])

    async def test_transport_failure_is_not_cached(self) -> None:
        """A total transport failure must NOT be cached as authoritative.

        After both providers error, a follow-up query must retry upstream
        rather than serve a bogus cached SERVFAIL. Assertion: the second
        query consults providers again (attempts grows).
        """
        r = _ScriptedResolver(
            providers=[DOH_A, DOH_B],
            script={
                DOH_A: OSError("down"),
                DOH_B: OSError("down"),
            },
        )

        first = await r.resolve_detailed("retry.example")
        self.assertFalse(first.authoritative)
        attempts_after_first = list(r.attempts)

        await r.resolve_detailed("retry.example")
        # Non-authoritative failure is not cached: the second call re-attempts.
        self.assertGreater(len(r.attempts), len(attempts_after_first))


if __name__ == "__main__":
    unittest.main()
