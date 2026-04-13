"""Server-side DNS resolution via DoH and DoT.

Resolution order: offline hosts -> primary (DoH) -> secondary (DoT) -> tertiary.
No DNS traffic ever leaves the client machine directly.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import socket
import ssl
import struct
import time
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

# DNS record types
A_RECORD = 1

# Cache limits
MAX_CACHE_ENTRIES = 2_000
MIN_TTL = 60
MAX_TTL = 3600
DOH_TIMEOUT = 2.0
DOT_TIMEOUT = 2.0


@dataclass(slots=True)
class _CacheEntry:
    addresses: list[str]
    expires: float


class DNSResolver:
    """Async DNS resolver with DoH/DoT and local cache."""

    def __init__(
        self,
        providers: list[str] | None = None,
        hosts_file: str = "/opt/mtun/hosts.txt",
    ) -> None:
        self._providers = providers or [
            "https://1.1.1.1/dns-query",
            "tls://9.9.9.9:853",
        ]
        self._hosts_file = Path(hosts_file)
        self._cache: dict[str, _CacheEntry] = {}
        self._static_hosts: dict[str, str] = {}
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

    async def _resolve_doh(self, url: str, hostname: str) -> list[str]:
        """DNS-over-HTTPS query (wire format POST)."""
        import httpx  # type: ignore[import-untyped]

        query = _build_dns_query(hostname, A_RECORD)
        async with httpx.AsyncClient(verify=True, timeout=DOH_TIMEOUT) as client:  # pyright: ignore[reportUnknownMemberType,reportUnknownVariableType]
            resp = await client.post(  # pyright: ignore[reportUnknownMemberType,reportUnknownVariableType]
                url,
                content=query,
                headers={
                    "Content-Type": "application/dns-message",
                    "Accept": "application/dns-message",
                },
            )
            resp.raise_for_status()  # pyright: ignore[reportUnknownMemberType]
            addresses, ttl = _parse_dns_response(resp.content)  # pyright: ignore[reportUnknownMemberType,reportUnknownArgumentType]
            if addresses:
                self._cache_result(hostname, addresses, ttl)
            return addresses

    async def _resolve_dot(self, provider: str, hostname: str) -> list[str]:
        """DNS-over-TLS query."""
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

        ctx = ssl.create_default_context()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx),
            timeout=DOT_TIMEOUT,
        )
        try:
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
        # Evict if at capacity (TTL-based: remove entry closest to expiration)
        if len(self._cache) >= MAX_CACHE_ENTRIES:
            oldest_key = min(self._cache, key=lambda k: self._cache[k].expires)
            del self._cache[oldest_key]

        clamped_ttl = max(MIN_TTL, min(MAX_TTL, ttl))
        self._cache[hostname] = _CacheEntry(
            addresses=addresses,
            expires=time.monotonic() + clamped_ttl,
        )

    def flush_cache(self) -> None:
        """Flush the entire DNS cache."""
        self._cache.clear()


def _build_dns_query(hostname: str, qtype: int) -> bytes:
    """Build a minimal DNS query message."""
    # Header: ID=random, flags=0x0100 (recursion desired), 1 question
    msg_id = int.from_bytes(os.urandom(2), "big")
    header = struct.pack("!HHHHHH", msg_id, 0x0100, 1, 0, 0, 0)

    # Question: encoded hostname + type + class
    question = b""
    for label in hostname.split("."):
        encoded = label.encode("ascii")
        if len(encoded) > 63:
            raise ValueError(f"DNS label too long: {label}")
        question += bytes([len(encoded)]) + encoded
    question += b"\x00"  # Root label
    question += struct.pack("!HH", qtype, 1)  # Type, Class IN

    return header + question


def _parse_dns_response(data: bytes) -> tuple[list[str], int]:
    """Parse DNS response and extract A record addresses + minimum TTL."""
    if len(data) < 12:
        return [], 300

    # Skip header
    flags = struct.unpack("!H", data[2:4])[0]
    rcode = flags & 0x0F
    if rcode != 0:
        return [], 300

    qdcount = struct.unpack("!H", data[4:6])[0]
    ancount = struct.unpack("!H", data[6:8])[0]

    # Skip questions
    offset = 12
    for _ in range(qdcount):
        offset = _skip_name(data, offset)
        offset += 4  # type + class

    # Parse answers
    addresses: list[str] = []
    min_ttl = 300
    for _ in range(ancount):
        offset = _skip_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, _, ttl, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        if rtype == A_RECORD and rdlength == 4:
            ip = socket.inet_ntoa(data[offset : offset + 4])
            addresses.append(ip)
            min_ttl = min(min_ttl, ttl)
        offset += rdlength

    return addresses, min_ttl


def _skip_name(data: bytes, offset: int) -> int:
    """Skip a DNS name in wire format (handles compression pointers)."""
    while offset < len(data):
        length = data[offset]
        if length == 0:
            return offset + 1
        if (length & 0xC0) == 0xC0:
            return offset + 2  # Compression pointer
        offset += 1 + length
    return offset
