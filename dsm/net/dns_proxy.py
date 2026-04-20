"""Local UDP DNS proxy bound to the VPN's TUN address.

Clients' DNS queries arrive here via the tunnel (their resolv.conf points
at the TUN IP). Each query is forwarded to the pinned DoH/DoT resolver and
the answer is returned with a matching transaction ID. No DNS traffic ever
egresses on a clear-text link.

Fail-closed: if the upstream resolver returns no answers, we reply with
SERVFAIL rather than silently dropping (so the client gets a fast failure
instead of a timeout).
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from typing import Any

import dns.exception
import dns.flags
import dns.message
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from dsm.net.dns import DNSResolver

log = logging.getLogger(__name__)

DEFAULT_CACHED_TTL = 60


def _redact_qname(qname: str) -> str:
    """Return a short, stable pseudonym for a qname (truncated SHA-256 hex)."""
    return hashlib.sha256(qname.encode("utf-8", "replace")).hexdigest()[:16]


class LocalDNSProxy:
    """UDP DNS listener that resolves via the pinned DoH/DoT client.

    ``debug_dns`` controls whether resolve-failure logs include the plaintext
    qname. Default is ``False`` so a local log reader learns only an opaque
    hash, not the user's browsing history.
    """

    # Bound task semaphore prevents unbounded growth on DoS.
    # 256 concurrent queries is reasonable for typical DNS traffic.
    _MAX_CONCURRENT_QUERIES = 256

    def __init__(
        self,
        resolver: DNSResolver,
        bind_ip: str,
        bind_port: int = 53,
        debug_dns: bool = False,
    ) -> None:
        self._resolver = resolver
        self._bind_ip = bind_ip
        self._bind_port = bind_port
        self._debug_dns = debug_dns
        self._transport: asyncio.DatagramTransport | None = None
        self._tasks: set[asyncio.Task[None]] = set()
        self._sem = asyncio.Semaphore(self._MAX_CONCURRENT_QUERIES)
        # In-flight request deduplication: (qname, qtype) -> Future[addresses]
        self._inflight: dict[tuple[str, int], asyncio.Future[list[str]]] = {}

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        transport, _proto = await loop.create_datagram_endpoint(
            lambda: _ProxyProtocol(self),
            local_addr=(self._bind_ip, self._bind_port),
            reuse_port=False,
        )
        self._transport = transport  # type: ignore[assignment]
        log.info("DNS proxy listening on %s:%d", self._bind_ip, self._bind_port)

    def stop(self) -> None:
        if self._transport is not None:
            self._transport.close()
            self._transport = None
        for task in list(self._tasks):
            task.cancel()
        self._tasks.clear()

    def _schedule(self, coro: Any) -> None:
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _handle_query(
        self, data: bytes, addr: tuple[str, int], send: Any,
    ) -> None:
        # Semaphore bounds concurrent query tasks to prevent DoS.
        # On saturation, drop datagram silently (no SERVFAIL — avoid timing channel).
        if not self._sem._value:  # Check semaphore state
            log.warning("DNS query queue saturated, dropping datagram from %s", addr)
            return

        async with self._sem:
            try:
                query = dns.message.from_wire(data)
            except dns.exception.DNSException as e:
                log.debug("dropping malformed DNS query from %s: %s", addr, type(e).__name__)
                return

            if not query.question:
                send(_make_error(query, dns.rcode.FORMERR), addr)
                return

            q = query.question[0]
            qname = q.name.to_text(omit_final_dot=True).lower()
            qtype = q.rdtype

            # Only A records are resolved via the upstream client today; other
            # types return an empty NOERROR so stubs fall through gracefully.
            if qtype != dns.rdatatype.A:
                resp = dns.message.make_response(query)
                resp.flags |= dns.flags.RA
                send(resp.to_wire(), addr)
                return

            # In-flight deduplication: coalesce identical concurrent queries
            query_key = (qname, qtype)
            inflight_future = self._inflight.get(query_key)
            if inflight_future is None:
                # First request for this query — create future and resolve
                inflight_future = asyncio.get_event_loop().create_future()
                self._inflight[query_key] = inflight_future

                try:
                    addresses = await self._resolver.resolve(qname)
                    inflight_future.set_result(addresses)
                except Exception as e:
                    log_qname = qname if self._debug_dns else f"qname-sha256={_redact_qname(qname)}"
                    log.warning("DNS resolve failed for %s: %s", log_qname, type(e).__name__)
                    inflight_future.set_exception(e)
                finally:
                    del self._inflight[query_key]
            else:
                # Duplicate in-flight query — await the same future
                try:
                    addresses = await inflight_future
                except Exception:
                    # Upstream failed; re-raise to handle below
                    addresses = []

            # Send response
            try:
                if not addresses:
                    send(_make_error(query, dns.rcode.SERVFAIL), addr)
                    return

                resp = dns.message.make_response(query)
                resp.flags |= dns.flags.RA
                rrset = dns.rrset.from_text_list(
                    q.name, DEFAULT_CACHED_TTL, dns.rdataclass.IN, dns.rdatatype.A, addresses,
                )
                resp.answer.append(rrset)
                send(resp.to_wire(), addr)
            except Exception as e:
                log.exception("failed to send DNS response to %s: %s", addr, e)


class _ProxyProtocol(asyncio.DatagramProtocol):
    def __init__(self, proxy: LocalDNSProxy) -> None:
        self._proxy = proxy
        self._transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:  # type: ignore[override]
        self._transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str | Any, int]) -> None:
        if self._transport is None:
            return
        transport = self._transport

        def _send(wire: bytes, to: tuple[str, int]) -> None:
            transport.sendto(wire, to)

        self._proxy._schedule(self._proxy._handle_query(data, addr, _send))  # type: ignore[arg-type]

    def error_received(self, exc: Exception) -> None:  # pragma: no cover
        log.warning("DNS proxy socket error: %s", type(exc).__name__)


def _make_error(query: dns.message.Message, rcode: dns.rcode.Rcode) -> bytes:
    resp = dns.message.make_response(query)
    resp.set_rcode(rcode)
    resp.flags |= dns.flags.RA
    return resp.to_wire()
