"""Local UDP DNS proxy bound to the VPN's TUN address.

Clients' DNS queries arrive here via the tunnel (their resolv.conf points
at the TUN IP). Each query is forwarded to the pinned DoH/DoT resolver and
the answer is returned with a matching transaction ID. No DNS traffic ever
egresses on a clear-text link.

Fail-closed: if the upstream resolver returns no answers, we reply with
SERVFAIL rather than silently dropping (so the client gets a fast failure
instead of a timeout).

Names on the server's DNS blocklist (dsm.net.dns_blocklist) get NXDOMAIN for
every query type, answered here without asking upstream.

On the server one proxy serves every client (multi-client spec §2.11). In
its per-client mode each client address gets its own resolver (so its own
cache), its own in-flight table and its own caps, so no client learns
another's names, answers or their timing, and no client can use up the
shared limits. The server's own queries use the shared resolver.
"""

from __future__ import annotations

import asyncio
import contextlib
import errno
import ipaddress
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import dns.exception
import dns.flags
import dns.message
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset

import dsm.net.dns as _dns
from dsm.core.log import RepeatLog
from dsm.net._addresses import TUN_PREFIX_LEN
from dsm.net.dns import DNSResolver, DnsResult
from dsm.net.dns_blocklist import NEGATIVE_TTL_S, DnsBlocklist

log = logging.getLogger(__name__)

DEFAULT_CACHED_TTL = 60
# The SOA record on a blocked answer. Its TTL and its last field tell the
# device how long to remember "no such name" (RFC 2308). dsm.invalid can never
# be a real zone.
_BLOCKED_SOA = f"dsm.invalid. hostmaster.dsm.invalid. 1 3600 600 86400 {NEGATIVE_TTL_S}"
# The blocklist has no length cap of its own. A legal name is at most 253
# characters as text, unless it holds escaped bytes (\001 is 4 characters).
_MAX_QNAME_LEN = 253


class DNSProxyPortInUseError(OSError):
    """The DNS-proxy bind address is already held by another process."""


@dataclass(eq=False)
class _Client:
    """One client's own DNS state in per-client mode (multi-client spec
    §2.11): its resolver, so its cache; its in-flight table, so no client
    learns from another's answers or their timing; and its own caps, so no
    client can use up the shared ones."""

    resolver: DNSResolver
    upstream: asyncio.Semaphore
    inflight: dict[tuple[str, int], asyncio.Future[DnsResult]] = field(
        default_factory=dict[tuple[str, int], asyncio.Future[DnsResult]]
    )
    tasks: set[asyncio.Task[None]] = field(default_factory=set[asyncio.Task[None]])


class LocalDNSProxy:
    """UDP DNS listener that resolves via the pinned DoH/DoT client.

    ``debug_dns`` controls whether resolve-failure logs include the plaintext
    qname. Default is ``False`` so a local log reader learns only an opaque
    hash, not the user's browsing history.

    ``blocklist``, when given (server with ``dns_blocklist = true``), answers
    blocked names with NXDOMAIN before anything else.

    ``per_client``, when given (the server), makes a fresh resolver for each
    client source address: each client then has its own cache and its own
    in-flight table. The positional ``resolver`` answers only the server's
    own address.
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
    # Per client, in per-client mode (multi-client spec §2.11): queries
    # waiting for an answer, and upstream lookups at once. A browser start-up
    # asks 50-100 names together, so real use never meets the first; the
    # second is an eighth of _MAX_CONCURRENT_QUERIES. The shared caps above
    # stay as a backstop.
    _MAX_TASKS_PER_CLIENT = 256
    _MAX_UPSTREAM_PER_CLIENT = 32

    def __init__(
        self,
        resolver: DNSResolver,
        bind_ip: str,
        bind_port: int = 53,
        debug_dns: bool = False,
        blocklist: DnsBlocklist | None = None,
        *,
        per_client: Callable[[], DNSResolver] | None = None,
    ) -> None:
        self._resolver = resolver
        self._bind_ip = bind_ip
        self._bind_port = bind_port
        self._debug_dns = debug_dns
        self._blocklist = blocklist
        self._per_client = per_client
        # Per-client mode: each client's own state, by its tunnel address.
        # The /24 source filter below bounds it to the clients' addresses.
        self._clients: dict[str, _Client] = {}
        # No address in the line: it would name the client.
        self._client_full_log = RepeatLog(log, logging.WARNING)
        # Distinct queries in flight across every client: _MAX_INFLIGHT caps
        # the total (spec §2.11 keeps the shared caps as a backstop).
        self._inflight_total = 0
        self._transport: asyncio.DatagramTransport | None = None
        self._tasks: set[asyncio.Task[None]] = set()
        self._sem = asyncio.Semaphore(self._MAX_CONCURRENT_QUERIES)
        # In-flight request deduplication: (qname, qtype) -> Future[DnsResult]
        self._inflight: dict[tuple[str, int], asyncio.Future[DnsResult]] = {}
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
        try:
            transport, _proto = await loop.create_datagram_endpoint(
                lambda: _ProxyProtocol(self),
                local_addr=(self._bind_ip, self._bind_port),
                reuse_port=False,
            )
        except OSError as e:
            if e.errno == errno.EADDRINUSE:
                raise DNSProxyPortInUseError(
                    f"DNS proxy cannot bind {self._bind_ip}:{self._bind_port} — "
                    f"another resolver (unbound / systemd-resolved / dnsmasq) is "
                    f"already bound there. Stop the host resolver, or change the "
                    f"TUN address."
                ) from e
            raise
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
            # abort(), not close(): close() keeps the socket open until a
            # waiting reply is sent. A dropped reply is like loss: the client
            # asks again.
            self._transport.abort()
            self._transport = None
        for task in list(self._tasks):
            task.cancel()
        self._tasks.clear()

    def forget(self, client_ip: str) -> None:
        """Drop a client's resolver and in-flight table (per-client mode).
        The server calls it when a client's last session ends. Queries still
        waiting finish on the dropped state."""
        self._clients.pop(client_ip, None)

    def _client_for(self, ip: str) -> _Client | None:
        """The client's own state in per-client mode; None for the server's
        own address and when the mode is off (the shared resolver answers)."""
        if self._per_client is None or ip == self._bind_ip:
            return None
        client = self._clients.get(ip)
        if client is None:
            client = _Client(
                self._per_client(), asyncio.Semaphore(self._MAX_UPSTREAM_PER_CLIENT)
            )
            self._clients[ip] = client
        return client

    def _schedule(self, coro: Any, client: _Client | None = None) -> None:
        """Schedule a query-handling coroutine, dropping it when the task
        set is saturated, or when ``client`` (per-client mode) already has
        ``_MAX_TASKS_PER_CLIENT`` queries waiting.

        The dropped UDP query is not answered — by the nature of UDP the
        client retries, and once the proxy catches up the next retry
        succeeds. There is no in-band way to send SERVFAIL because the
        dropped path is the one that would have written it.
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
            return
        if client is not None and len(client.tasks) >= self._MAX_TASKS_PER_CLIENT:
            coro.close()
            self._client_full_log.log(
                "DNS queries dropped: one client already has %d waiting",
                self._MAX_TASKS_PER_CLIENT,
            )
            return
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        if client is not None:
            client.tasks.add(task)
            task.add_done_callback(client.tasks.discard)

    def _source_allowed(self, addr: tuple[str, int]) -> bool:
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
        send: Callable[[bytes, tuple[str, int]], None],
    ) -> tuple[dns.message.Message, str, int] | None:
        """Parse wire bytes; return (query, qname, qtype) or None if handled.

        Returns ``None`` when the request was malformed or named something
        over-long (dropped), had no question (FORMERR responded), asked for a
        blocked name (NXDOMAIN responded), or wasn't an A query (empty NOERROR
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

        # Before the A-only shortcut below, so a blocked name gets NXDOMAIN
        # for every query type (AAAA, HTTPS, ...), not an empty answer.
        if self._blocklist is not None:
            if len(qname) > _MAX_QNAME_LEN:
                # Over 253 characters as text only happens with escaped bytes;
                # drop it like a malformed query.
                log.debug("dropping DNS query with an over-long name")
                return None
            if self._blocklist.is_blocked(qname):
                send(_make_blocked(query), addr)
                return None

        # Only A records are resolved via the upstream client today; other
        # types return an empty NOERROR so stubs fall through gracefully.
        if qtype != dns.rdatatype.A:
            resp = dns.message.make_response(query)
            resp.flags |= dns.flags.RA
            send(resp.to_wire(), addr)
            return None

        return query, qname, qtype

    async def _resolve_upstream(
        self, qname: str, client: _Client | None = None
    ) -> DnsResult:
        resolver = self._resolver if client is None else client.resolver
        return await resolver.resolve_detailed(qname)

    async def _resolve_with_dedup(
        self,
        qname: str,
        qtype: int,
        client: _Client | None = None,
    ) -> DnsResult:
        """Resolve ``qname`` for A records, coalescing concurrent duplicates.

        The first caller for a (qname, qtype) holds a semaphore slot while
        calling upstream; later callers await the shared future slot-free,
        so the semaphore actually bounds upstream fan-out (not total
        duplicates waiting). With ``client`` (per-client mode) it coalesces
        only that client's duplicates and asks that client's resolver.

        Returns a non-authoritative empty ``DnsResult`` (signals SERVFAIL to
        the caller) on inflight-map saturation or on resolver failure.
        """
        # One client's duplicates only: a fast answer must not tell a client
        # that another one is asking for the same name right now.
        inflight = self._inflight if client is None else client.inflight
        query_key = (qname, qtype)
        inflight_future = inflight.get(query_key)
        if inflight_future is not None:
            try:
                return await inflight_future
            # coalesced waiter: any failure maps to SERVFAIL
            except Exception:  # noqa: BLE001
                return DnsResult(addresses=[], ttl=0, rcode=-1, authoritative=False)

        if self._inflight_total >= self._MAX_INFLIGHT:
            log.debug(
                "inflight map full (%d entries), SERVFAIL for %s",
                self._inflight_total,
                _dns.redact(qname, self._debug_dns),
            )
            return DnsResult(addresses=[], ttl=0, rcode=-1, authoritative=False)

        inflight_future = asyncio.get_running_loop().create_future()
        inflight[query_key] = inflight_future
        self._inflight_total += 1
        try:
            # The client's own cap first, so a client that waits on it holds
            # no shared slot.
            own_cap = contextlib.nullcontext() if client is None else client.upstream
            async with own_cap, self._sem:
                try:
                    result = await self._resolve_upstream(qname, client)
                    inflight_future.set_result(result)
                    return result
                # any resolver failure maps to SERVFAIL
                except Exception as e:  # noqa: BLE001
                    log_qname = _dns.redact(qname, self._debug_dns)
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
                    servfail = DnsResult(
                        addresses=[], ttl=0, rcode=-1, authoritative=False
                    )
                    inflight_future.set_result(servfail)
                    return servfail
        finally:
            del inflight[query_key]
            self._inflight_total -= 1

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
        send: Callable[[bytes, tuple[str, int]], None],
        client: _Client | None = None,
    ) -> None:
        """Orchestrate parse → dedup-resolve → respond for one DNS datagram.

        Parsing and trivial-response paths run
        outside the semaphore — the semaphore exists to bound concurrent
        upstream resolver calls, not cheap wire parsing. ``client``: the
        sender's own state in per-client mode.
        """
        parsed = self._parse_or_reject(data, addr, send)
        if parsed is None:
            return
        query, qname, qtype = parsed

        result = await self._resolve_with_dedup(qname, qtype, client)

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
        client = self._proxy._client_for(addr[0])  # pylint: disable=protected-access  # pyright: ignore[reportPrivateUsage]  # intentional sibling-internal access  # fmt: skip
        transport = self._transport

        def _send(wire: bytes, to: tuple[str, int]) -> None:
            transport.sendto(wire, to)

        proxy = self._proxy
        proxy._schedule(proxy._handle_query(data, addr, _send, client), client)  # type: ignore[arg-type]  # pylint: disable=protected-access  # intentional sibling-internal access

    def error_received(self, exc: Exception) -> None:  # pragma: no cover
        log.warning("DNS proxy socket error: %s", type(exc).__name__)


def _make_error(query: dns.message.Message, rcode: dns.rcode.Rcode) -> bytes:
    resp = dns.message.make_response(query)
    resp.set_rcode(rcode)
    resp.flags |= dns.flags.RA
    return resp.to_wire()


def _make_blocked(query: dns.message.Message) -> bytes:
    """NXDOMAIN with an SOA, so the device remembers it for NEGATIVE_TTL_S."""
    resp = dns.message.make_response(query)
    resp.set_rcode(dns.rcode.NXDOMAIN)
    resp.flags |= dns.flags.RA
    resp.authority.append(
        dns.rrset.from_text(
            query.question[0].name,
            NEGATIVE_TTL_S,
            dns.rdataclass.IN,
            dns.rdatatype.SOA,
            _BLOCKED_SOA,
        )
    )
    return resp.to_wire()
