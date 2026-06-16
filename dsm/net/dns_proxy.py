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
import ipaddress
import logging
import time
from typing import Any

import dns.exception
import dns.flags
import dns.message
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset

import dsm.net.dns as _dns
from dsm.net._addresses import TUN_PREFIX_LEN
from dsm.net.dns import DNSResolver

# _DnsResult is intentionally private in dsm.net.dns (Phase 1.10); the proxy is
# a sibling that relays its rcode, so this cross-module use of an underscore
# name is deliberate and the private-usage check is suppressed at the alias.
_DnsResult = _dns._DnsResult  # pyright: ignore[reportPrivateUsage]  # noqa: E501

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
    # Cap on the (qname, qtype) deduplication map. Without this an authenticated
    # peer inside the tunnel that floods unique qnames can grow the map until
    # the box runs out of memory; the semaphore alone only bounds *upstream*
    # fan-out, not the in-flight count of distinct queries.
    _MAX_INFLIGHT = 4096
    # Global cap on the total number of scheduled query-handling tasks.
    # The inflight map bounds *distinct* queries; this bounds *all* in-flight
    # tasks including duplicates. A malicious (or buggy) authenticated peer
    # inside the tunnel can spam millions of duplicate queries for the same
    # qname; each one schedules its own _handle_query task that awaits the
    # shared upstream future. Without a global cap, the task set + their
    # stack frames grow unboundedly even though no extra upstream queries
    # are issued. Drop-on-overflow with SERVFAIL is the right policy — the
    # cap is far above legitimate load.
    _MAX_TASKS = 8192

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
        # In-flight request deduplication: (qname, qtype) -> Future[_DnsResult]
        self._inflight: dict[tuple[str, int], asyncio.Future[_DnsResult]] = {}
        # Counter of dropped queries due to task-set saturation. Sampled into
        # the audit log so an operator can see when the proxy is shedding
        # load (rate-limited via _shed_log_throttle to avoid log flooding).
        self._tasks_shed: int = 0
        self._tasks_shed_last_log: float = 0.0
        # Restrict to the in-tunnel /24 derived from the bind address.
        # The proxy binds on the server's TUN IP (10.8.0.1) and clients
        # arrive from 10.8.0.0/24; any other source reaching this socket
        # (Linux weak host model + rp_filter=2) is an off-tunnel
        # open-resolver / reflection attempt and must be dropped before
        # any task / inflight state is allocated.
        self._allowed_source_net = ipaddress.ip_network(
            f"{bind_ip}/{TUN_PREFIX_LEN}", strict=False
        )
        self._dropped_offnet: int = 0
        self._dropped_offnet_last_log: float = 0.0
        # Fires a one-time WARNING on the very first off-tunnel drop so an
        # operator scanning logs at WARNING level always sees the guard is
        # active. All subsequent drops use the rate-limited DEBUG path.
        self._dropped_offnet_warned: bool = False

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        transport, _proto = await loop.create_datagram_endpoint(
            lambda: _ProxyProtocol(self),
            local_addr=(self._bind_ip, self._bind_port),
            reuse_port=False,
        )
        self._transport = transport  # type: ignore[assignment]
        # M-NET-2: mark the DNS-proxy socket with SO_MARK so any reply
        # we send out chooses the route by the marked policy rather than
        # by the default table. Without this, on hosts with weird
        # routing configurations a DNS reply destined for an inner-TUN
        # client could pick the wrong egress interface.
        try:
            from dsm.net.transport._fwmark import apply_so_mark

            sock = transport.get_extra_info("socket")
            if sock is not None:
                apply_so_mark(sock)
        except OSError as e:
            # Best-effort — SO_MARK requires CAP_NET_ADMIN; in test
            # environments we don't have it. Don't fail startup.
            log.debug("DNS proxy SO_MARK skipped: %s", e)
        log.info("DNS proxy listening on %s:%d", self._bind_ip, self._bind_port)

    def stop(self) -> None:
        if self._transport is not None:
            self._transport.close()
            self._transport = None
        for task in list(self._tasks):
            task.cancel()
        self._tasks.clear()

    def _schedule(self, coro: Any) -> bool:
        """Schedule a query-handling coroutine. Returns False (and closes
        the coroutine without scheduling) when the task set is saturated.

        Caller decides what to do with a False return; the protocol
        datagram_received path drops the UDP query in that case — by the
        nature of UDP the client retries, and once the proxy catches up
        the next retry succeeds. There is no in-band way to send SERVFAIL
        because the dropped path is the one that would have written it.
        """
        if len(self._tasks) >= self._MAX_TASKS:
            coro.close()
            self._tasks_shed += 1
            now = time.monotonic()
            if now - self._tasks_shed_last_log > 5.0:
                log.warning(
                    "DNS proxy task cap reached (%d tasks); "
                    "shed %d queries since last log",
                    self._MAX_TASKS,
                    self._tasks_shed,
                )
                self._tasks_shed_last_log = now
                self._tasks_shed = 0
            return False
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return True

    def _source_allowed(self, addr: tuple[str, int]) -> bool:
        """True iff ``addr`` is inside the in-tunnel source network."""
        try:
            src = ipaddress.ip_address(addr[0])
        except ValueError:
            return False
        return src in self._allowed_source_net

    def _note_dropped_source(self, addr: tuple[str, int]) -> None:
        """Count an off-tunnel drop; log at WARNING once, then DEBUG-rate-limited."""
        self._dropped_offnet += 1
        if not self._dropped_offnet_warned:
            self._dropped_offnet_warned = True
            log.warning(
                "off-tunnel DNS query dropped from %s (open-resolver guard); "
                "further drops logged at DEBUG",
                addr[0],
            )
            return
        now = time.monotonic()
        if now - self._dropped_offnet_last_log > 5.0:
            log.debug(
                "dropped %d off-tunnel DNS queries since last log "
                "(most recent source %s)",
                self._dropped_offnet,
                addr[0],
            )
            self._dropped_offnet_last_log = now
            self._dropped_offnet = 0

    def _parse_or_reject(
        self,
        data: bytes,
        addr: tuple[str, int],
        send: Any,
    ) -> tuple[dns.message.Message, str, int] | None:
        """Parse wire bytes; return (query, qname, qtype) or None if handled.

        Returns ``None`` when the request was malformed (dropped), had no
        question (FORMERR responded), or wasn't an A query (empty NOERROR
        responded — answered here so the orchestrator can skip dedup/resolve).
        """
        try:
            query = dns.message.from_wire(data)
        except dns.exception.DNSException as e:
            log.debug(
                "dropping malformed DNS query from %s: %s",
                addr,
                type(e).__name__,
            )
            return None

        if not query.question:
            send(_make_error(query, dns.rcode.FORMERR), addr)
            return None

        q = query.question[0]
        qname = q.name.to_text(omit_final_dot=True).lower()
        qtype = q.rdtype

        # Only A records are resolved via the upstream client today; other
        # types return an empty NOERROR so stubs fall through gracefully.
        if qtype != dns.rdatatype.A:
            resp = dns.message.make_response(query)
            resp.flags |= dns.flags.RA
            send(resp.to_wire(), addr)
            return None

        return query, qname, qtype

    async def _resolve_upstream(self, qname: str) -> _DnsResult:
        """Call the resolver, preferring the rcode-bearing ``resolve_detailed``.

        Resolvers that expose ``resolve_detailed`` (the real ``DNSResolver``)
        let the proxy relay NXDOMAIN/NODATA. Test/stub resolvers that only
        implement ``resolve() -> list[str]`` fall back to a non-authoritative
        wrapper so an empty list still maps to SERVFAIL (the historic
        fail-closed behavior).
        """
        detailed = getattr(self._resolver, "resolve_detailed", None)
        if detailed is not None:
            return await detailed(qname)
        addresses = await self._resolver.resolve(qname)
        return _DnsResult(
            addresses=addresses,
            ttl=DEFAULT_CACHED_TTL,
            rcode=int(dns.rcode.NOERROR) if addresses else -1,
            authoritative=bool(addresses),
        )

    async def _resolve_with_dedup(
        self,
        qname: str,
        qtype: int,
    ) -> _DnsResult:
        """Resolve ``qname`` for A records, coalescing concurrent duplicates.

        The first caller for a (qname, qtype) holds a semaphore slot while
        calling upstream; later callers await the shared future slot-free,
        so the semaphore actually bounds upstream fan-out (not total
        duplicates waiting).

        Returns a non-authoritative empty ``_DnsResult`` (signals SERVFAIL to
        the caller) on inflight-map saturation or on resolver failure.
        """
        query_key = (qname, qtype)
        inflight_future = self._inflight.get(query_key)
        if inflight_future is not None:
            try:
                return await inflight_future
            except Exception:  # noqa: BLE001  # see linter report
                return _DnsResult(addresses=[], ttl=0, rcode=-1, authoritative=False)

        if len(self._inflight) >= self._MAX_INFLIGHT:
            log.debug(
                "inflight map full (%d entries), SERVFAIL for %s",
                len(self._inflight),
                _redact_qname(qname),
            )
            return _DnsResult(addresses=[], ttl=0, rcode=-1, authoritative=False)

        inflight_future = asyncio.get_running_loop().create_future()
        self._inflight[query_key] = inflight_future
        try:
            async with self._sem:
                try:
                    result = await self._resolve_upstream(qname)
                    inflight_future.set_result(result)
                    return result
                except Exception as e:  # noqa: BLE001  # see linter report
                    log_qname = (
                        qname
                        if self._debug_dns
                        else f"qname-sha256={_redact_qname(qname)}"
                    )
                    log.warning(
                        "DNS resolve failed for %s: %s",
                        log_qname,
                        type(e).__name__,
                    )
                    # Publish a SERVFAIL RESULT (not set_exception): the owner
                    # returns directly below without awaiting this future, so a
                    # set_exception with zero coalesced waiters would be left
                    # unretrieved ("Future exception was never retrieved" loop
                    # diagnostics). Coalesced waiters receive the same SERVFAIL
                    # via the result instead of catching an exception.
                    servfail = _DnsResult(
                        addresses=[], ttl=0, rcode=-1, authoritative=False
                    )
                    inflight_future.set_result(servfail)
                    return servfail
        finally:
            del self._inflight[query_key]

    @staticmethod
    def _build_response(
        query: dns.message.Message,
        addresses: list[str],
    ) -> bytes:
        """Build an A-record response wire frame from upstream addresses.

        Caller decides what to do with an empty ``addresses`` (typically
        SERVFAIL) — this helper assumes there's at least one A record.
        """
        resp = dns.message.make_response(query)
        resp.flags |= dns.flags.RA
        q = query.question[0]
        rrset = dns.rrset.from_text_list(
            q.name,
            DEFAULT_CACHED_TTL,
            dns.rdataclass.IN,
            dns.rdatatype.A,
            addresses,
        )
        resp.answer.append(rrset)
        return resp.to_wire()

    async def _handle_query(
        self,
        data: bytes,
        addr: tuple[str, int],
        send: Any,
    ) -> None:
        """Orchestrate parse → dedup-resolve → respond for one DNS datagram.

        Each step is a separate helper; this method exists solely to
        glue them together. Parsing and trivial-response paths run
        outside the semaphore — the semaphore exists to bound concurrent
        upstream resolver calls, not cheap wire parsing.
        """
        parsed = self._parse_or_reject(data, addr, send)
        if parsed is None:
            return
        query, qname, qtype = parsed

        result = await self._resolve_with_dedup(qname, qtype)

        try:
            if result.addresses:
                send(self._build_response(query, result.addresses), addr)
            elif result.authoritative and result.rcode == int(dns.rcode.NXDOMAIN):
                # Relay the authoritative non-existent name as NXDOMAIN, not
                # SERVFAIL (Phase 1.10).
                send(_make_error(query, dns.rcode.NXDOMAIN), addr)
            elif result.authoritative:
                # NODATA: authoritative NOERROR with no A records.
                resp = dns.message.make_response(query)
                resp.flags |= dns.flags.RA
                send(resp.to_wire(), addr)
            else:
                # Transport failure across all providers — SERVFAIL as before.
                send(_make_error(query, dns.rcode.SERVFAIL), addr)
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
        if not self._proxy._source_allowed(addr):  # pylint: disable=protected-access  # pyright: ignore[reportPrivateUsage]  # intentional sibling-internal access  # fmt: skip
            self._proxy._note_dropped_source(addr)  # pylint: disable=protected-access  # pyright: ignore[reportPrivateUsage]  # intentional sibling-internal access  # fmt: skip
            return
        transport = self._transport

        def _send(wire: bytes, to: tuple[str, int]) -> None:
            transport.sendto(wire, to)

        self._proxy._schedule(self._proxy._handle_query(data, addr, _send))  # type: ignore[arg-type]  # pylint: disable=protected-access  # intentional sibling-internal access

    def error_received(self, exc: Exception) -> None:  # pragma: no cover
        log.warning("DNS proxy socket error: %s", type(exc).__name__)


def _make_error(query: dns.message.Message, rcode: dns.rcode.Rcode) -> bytes:
    resp = dns.message.make_response(query)
    resp.set_rcode(rcode)
    resp.flags |= dns.flags.RA
    return resp.to_wire()
