"""Server-side DNS resolution via DoH and DoT.

Resolution order: offline hosts -> primary (DoH) -> secondary (DoT) -> tertiary.
No DNS traffic ever leaves the client machine directly.
"""

from __future__ import annotations

import asyncio
import heapq
import ipaddress
import logging
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from collections.abc import Iterable
from typing import Any, cast

import dns.exception
import dns.message
import dns.rcode
import dns.rdata
import dns.rdatatype
import dns.rdtypes.IN.A

log = logging.getLogger(__name__)

# DNS record types
A_RECORD = 1

# Cache limits
MAX_CACHE_ENTRIES = 2_000
MIN_TTL = 60
MAX_TTL = 3600
DOH_TIMEOUT = 2.0
DOT_TIMEOUT = 2.0

# RFC 8467 §4.1: block-length policy. Clients pad queries to the next
# multiple of 128 bytes. Makes query size a coarse lattice a passive TLS
# observer can no longer use to fingerprint individual qnames.
EDNS_PADDING_BLOCK = 128


@dataclass(slots=True)
class _CacheEntry:
    addresses: list[str]
    expires: float


class DNSResolver:
    """Async DNS resolver with DoH/DoT and local cache.

    Every provider must carry one or more SPKI SHA-256 pins. Connections are
    rejected when the peer's SubjectPublicKeyInfo does not match. No default
    pins are shipped — operators supply them via config so stale hardcoded
    pins can never degrade to unpinned traffic.
    """

    def __init__(
        self,
        providers: list[str],
        provider_pins: dict[str, list[str]],
        hosts_file: str = "/opt/mtun/hosts.txt",
    ) -> None:
        if not providers:
            raise ValueError("DNSResolver requires at least one provider")
        self._pins: dict[str, list[bytes]] = {}
        for provider in providers:
            hex_pins = provider_pins.get(provider)
            if not hex_pins:
                raise ValueError(
                    f"DNSResolver: no SPKI pins configured for provider {provider!r}"
                )
            self._pins[provider] = [bytes.fromhex(h) for h in hex_pins]
        self._providers = list(providers)
        self._hosts_file = Path(hosts_file)
        self._cache: dict[str, _CacheEntry] = {}
        # Min-heap of (expires, hostname) for O(log n) eviction.
        self._cache_heap: list[tuple[float, str]] = []
        self._static_hosts: dict[str, str] = {}
        self._http_client: Any = None  # lazy httpx.AsyncClient
        self._load_hosts_file()

    def _load_hosts_file(self) -> None:
        """Load static host mappings from hosts file."""
        if not self._hosts_file.exists():
            return
        for line in self._hosts_file.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 2:
                ip, hostname = parts[0], parts[1]
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    log.warning("invalid IP in hosts file, skipping: %s", ip)
                    continue
                self._static_hosts[hostname.lower()] = ip

    async def resolve(self, hostname: str) -> list[str]:
        """Resolve hostname to IP addresses.

        Checks: static hosts -> cache -> DoH -> DoT -> custom.
        """
        hostname = hostname.lower().rstrip(".")

        # 1. Static hosts
        static = self._static_hosts.get(hostname)
        if static:
            return [static]

        # 2. Cache
        cached = self._cache.get(hostname)
        if cached and cached.expires > time.monotonic():
            return cached.addresses

        # 3. Query providers in order
        for provider in self._providers:
            try:
                if provider.startswith("https://"):
                    result = await self._resolve_doh(provider, hostname)
                elif provider.startswith("tls://"):
                    result = await self._resolve_dot(provider, hostname)
                else:
                    log.warning("unknown provider scheme: %s", provider)
                    continue

                if result:
                    return result
            except Exception:
                log.debug("DNS provider %s failed for %s", provider, hostname)
                continue

        log.error("all DNS providers failed for %s", hostname)
        return []

    def _get_http_client(self) -> Any:
        """Return a reusable httpx.AsyncClient (created on first use)."""
        if self._http_client is None:
            import httpx  # type: ignore[import-untyped]
            from dsm.net.dns_pinning import build_pinned_ssl_context
            self._http_client = httpx.AsyncClient(  # pyright: ignore[reportUnknownMemberType]
                verify=build_pinned_ssl_context(),
                timeout=DOH_TIMEOUT,
            )
        return self._http_client  # pyright: ignore[reportUnknownMemberType,reportUnknownVariableType]

    async def _resolve_doh(self, url: str, hostname: str) -> list[str]:
        """DNS-over-HTTPS query (wire format POST) with SPKI pin check."""
        from dsm.net.dns_pinning import verify_pin_on_ssl_object

        query = _build_dns_query(hostname, A_RECORD)
        client = self._get_http_client()
        req = client.build_request(
            "POST",
            url,
            content=query,
            headers={
                "Content-Type": "application/dns-message",
                "Accept": "application/dns-message",
            },
        )
        # Stream so we can inspect the live TLS object before the stream
        # is released back to the connection pool.
        resp = await client.send(req, stream=True)
        try:
            resp.raise_for_status()
            network_stream = resp.extensions.get("network_stream")
            ssl_obj = network_stream.get_extra_info("ssl_object") if network_stream else None
            if ssl_obj is None:
                raise RuntimeError(f"DoH connection to {url} did not negotiate TLS")
            verify_pin_on_ssl_object(ssl_obj, self._pins[url], url)
            body = await resp.aread()
        finally:
            await resp.aclose()

        addresses, ttl = _parse_dns_response(body)
        if addresses:
            self._cache_result(hostname, addresses, ttl)
        return addresses

    async def _resolve_dot(self, provider: str, hostname: str) -> list[str]:
        """DNS-over-TLS query with SPKI pin check."""
        from dsm.net.dns_pinning import build_pinned_ssl_context, verify_pin

        # Parse "tls://host:port"
        addr = provider.removeprefix("tls://")
        parts = addr.rsplit(":", 1)
        if len(parts) != 2:
            raise ValueError(f"invalid DoT provider format: {provider!r}")
        host, port_str = parts
        port = int(port_str)

        query = _build_dns_query(hostname, A_RECORD)
        # DoT uses TCP with 2-byte length prefix
        framed = struct.pack("!H", len(query)) + query

        ctx = build_pinned_ssl_context()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx),
            timeout=DOT_TIMEOUT,
        )
        try:
            ssl_obj = writer.get_extra_info("ssl_object")
            der = ssl_obj.getpeercert(binary_form=True) if ssl_obj else None
            if not der:
                raise RuntimeError(f"DoT connection to {provider} did not negotiate TLS")
            verify_pin(der, self._pins[provider], provider)

            writer.write(framed)
            await writer.drain()

            len_buf = await asyncio.wait_for(reader.readexactly(2), timeout=DOT_TIMEOUT)
            resp_len = struct.unpack("!H", len_buf)[0]
            resp_data = await asyncio.wait_for(
                reader.readexactly(resp_len), timeout=DOT_TIMEOUT
            )
            addresses, ttl = _parse_dns_response(resp_data)
            if addresses:
                self._cache_result(hostname, addresses, ttl)
            return addresses
        finally:
            writer.close()
            await writer.wait_closed()

    def _cache_result(self, hostname: str, addresses: list[str], ttl: int = 300) -> None:
        """Cache DNS results with TTL enforcement."""
        # Evict expired or soonest-expiring entries via min-heap (O(log n)).
        while len(self._cache) >= MAX_CACHE_ENTRIES and self._cache_heap:
            exp, key = heapq.heappop(self._cache_heap)
            entry = self._cache.get(key)
            # Only delete if this heap entry matches the current cache entry
            # (avoids deleting a newer entry for the same hostname).
            if entry is not None and entry.expires == exp:
                del self._cache[key]
                break

        clamped_ttl = max(MIN_TTL, min(MAX_TTL, ttl))
        expires = time.monotonic() + clamped_ttl
        self._cache[hostname] = _CacheEntry(
            addresses=addresses,
            expires=expires,
        )
        heapq.heappush(self._cache_heap, (expires, hostname))

    def flush_cache(self) -> None:
        """Flush the entire DNS cache."""
        self._cache.clear()
        self._cache_heap.clear()

    async def close(self) -> None:
        """Close the shared HTTP client (if any)."""
        if self._http_client is not None:
            await self._http_client.aclose()
            self._http_client = None


def _build_dns_query(hostname: str, qtype: int) -> bytes:
    """Build a DNS query padded per RFC 7830 / RFC 8467.

    The query carries an EDNS(0) OPT record with a Padding option sized so
    that the total wire length is a multiple of EDNS_PADDING_BLOCK. This
    masks qname length from a passive observer who sees the encrypted
    TLS record.
    """
    msg = dns.message.make_query(
        hostname,
        dns.rdatatype.RdataType(qtype),
        use_edns=0,
        pad=EDNS_PADDING_BLOCK,
    )
    return msg.to_wire()


def _parse_dns_response(data: bytes) -> tuple[list[str], int]:
    """Parse DNS response and extract A record addresses + minimum TTL."""
    try:
        msg = dns.message.from_wire(data)
    except dns.exception.DNSException:
        return [], 300

    if msg.rcode() != dns.rcode.NOERROR:
        return [], 300

    addresses: list[str] = []
    min_ttl = 300
    for rrset in msg.answer:
        if rrset.rdtype != dns.rdatatype.A:
            continue
        min_ttl = min(min_ttl, rrset.ttl)
        # dnspython's Rdataset.__iter__ is untyped; cast expresses the
        # guarantee (RRset yields Rdata) so pyright strict can narrow.
        for rdata in cast(Iterable[dns.rdata.Rdata], rrset):
            if isinstance(rdata, dns.rdtypes.IN.A.A):
                addresses.append(rdata.address)

    return addresses, min_ttl
