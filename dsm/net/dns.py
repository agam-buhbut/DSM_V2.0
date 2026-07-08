"""Server-side DNS resolution via DoH and DoT.

Resolution order: offline hosts -> primary (DoH) -> secondary (DoT) -> tertiary.
No DNS traffic ever leaves the client machine directly.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import logging
import struct
import time
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import cast
from urllib.parse import urlparse

import dns.exception
import dns.message
import dns.rcode
import dns.rdata
import dns.rdatatype
import dns.rdtypes.IN.A

from dsm.net.transport._fwmark import apply_so_mark

log = logging.getLogger(__name__)

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
    # Wire rcode of the cached authoritative answer (NOERROR for positive and
    # NODATA, NXDOMAIN for a cached non-existent name) so a cache hit can be
    # relayed with the right rcode (RFC 2308 negative caching).
    rcode: int = 0


@dataclass(slots=True)
class _DnsResult:
    """Outcome of parsing an upstream DNS response (Phase 1.10).

    ``authoritative`` is True when the response was a well-formed DNS
    message with a definitive rcode (NOERROR / NXDOMAIN), so callers can
    stop provider fan-out and negative-cache instead of treating an empty
    answer as a transport failure. ``rcode`` is the wire rcode (or -1 for
    an unparseable / transport-level failure).
    """

    addresses: list[str]
    ttl: int
    rcode: int
    authoritative: bool


def redact(hostname: str, debug: bool) -> str:
    """Return ``hostname`` for logs, or an opaque sha256 pseudonym otherwise.

    When ``debug`` is False (the default) qnames are replaced with a
    truncated sha256 so an operator tailing journald cannot reconstruct the
    user's browsing history from pinning/fallthrough error logs.
    """
    if debug:
        return hostname
    digest = hashlib.sha256(hostname.encode("utf-8", "replace")).hexdigest()[:16]
    return f"qname-sha256={digest}"


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
        debug_dns: bool = False,
    ) -> None:
        if not providers:
            raise ValueError("DNSResolver requires at least one provider")
        # debug_dns mirrors the LocalDNSProxy flag — when False (the
        # default), qnames are replaced with an opaque sha256 prefix in
        # WARNING/ERROR-level logs so an operator tailing journald cannot
        # reconstruct the user's browsing history from pinning failures
        # or fallthrough errors.
        self._debug_dns = debug_dns
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
        self._static_hosts: dict[str, str] = {}
        self._load_hosts_file()

    # Cap the hosts file read so a 100 MiB symlink-to-some-other-file cannot
    # blow process memory at startup. 1 MiB fits ~30k entries which is well
    # beyond any realistic static-hosts use case.
    _HOSTS_FILE_MAX_BYTES = 1 << 20

    def _load_hosts_file(self) -> None:
        """Load static host mappings from hosts file.

        Refuses to follow symlinks so an attacker who plants a symlink at
        the hosts-file path cannot redirect reads to (e.g.) /etc/shadow or
        another sensitive file. Caps the read size to bound memory cost on
        startup. Parse errors are logged without echoing the offending line
        — the file might point to attacker content and we don't want
        unparseable bytes from it landing in the operator's journald.
        """
        if not self._hosts_file.exists():
            return
        if self._hosts_file.is_symlink():
            log.warning(
                "hosts file %s is a symlink; refusing to follow",
                self._hosts_file,
            )
            return
        try:
            raw = self._hosts_file.read_bytes()
        except OSError as e:
            log.warning("failed to read hosts file %s: %s", self._hosts_file, e)
            return
        if len(raw) > self._HOSTS_FILE_MAX_BYTES:
            log.warning(
                "hosts file %s exceeds %d bytes; refusing to load",
                self._hosts_file,
                self._HOSTS_FILE_MAX_BYTES,
            )
            return
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            log.warning(
                "hosts file %s is not valid UTF-8; refusing to load",
                self._hosts_file,
            )
            return
        for lineno, line in enumerate(text.splitlines(), start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 2:
                ip, hostname = parts[0], parts[1]
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    log.warning(
                        "hosts file %s line %d: invalid IP, skipping",
                        self._hosts_file,
                        lineno,
                    )
                    continue
                self._static_hosts[hostname.lower()] = ip

    async def resolve(self, hostname: str) -> list[str]:
        """Resolve hostname to A-record IP addresses.

        Backward-compatible ``list[str]`` contract (Phase 1.10): callers that
        only need the addresses keep using this. The richer outcome
        (NXDOMAIN/NODATA vs transport failure) is available via
        :meth:`resolve_detailed`. An empty list still means "no addresses",
        whether authoritative-empty or a failure — the proxy uses
        :meth:`resolve_detailed` to tell them apart.
        """
        return (await self.resolve_detailed(hostname)).addresses

    async def resolve_detailed(self, hostname: str) -> _DnsResult:
        """Resolve ``hostname``, distinguishing authoritative-empty from failure.

        Checks: static hosts -> cache -> DoH -> DoT -> custom. On an
        authoritative answer (addresses, NXDOMAIN, or NODATA) provider
        fan-out STOPS and the result is returned/negative-cached. Only a
        transport-level failure across every provider yields a
        non-authoritative empty result (rcode -1).
        """
        hostname = hostname.lower().rstrip(".")

        # 1. Static hosts
        static = self._static_hosts.get(hostname)
        if static:
            return _DnsResult(
                addresses=[static],
                ttl=MAX_TTL,
                rcode=int(dns.rcode.NOERROR),
                authoritative=True,
            )

        # 2. Cache (positive and negative entries; an empty address list is a
        # cached authoritative-empty answer per RFC 2308).
        cached = self._cache.get(hostname)
        if cached and cached.expires > time.monotonic():
            return _DnsResult(
                addresses=list(cached.addresses),
                ttl=MIN_TTL,
                rcode=int(cached.rcode),
                authoritative=True,
            )

        # 3. Query providers in order; stop on the first authoritative answer.
        for provider in self._providers:
            try:
                if provider.startswith("https://"):
                    result = await self._resolve_doh(provider, hostname)
                elif provider.startswith("tls://"):
                    result = await self._resolve_dot(provider, hostname)
                else:
                    log.warning("unknown provider scheme: %s", provider)
                    continue

                if result.authoritative:
                    # Authoritative NXDOMAIN/NODATA/answer: stop fan-out. The
                    # caching (positive or negative) already happened inside
                    # the per-protocol resolver.
                    return result
            except Exception as e:  # noqa: BLE001  # see linter report
                # SPKI pin failures surface as PinMismatchError and indicate
                # a possible MITM (cert chains to a trusted CA but is not
                # the pinned key). Promote those to WARNING so an operator
                # tailing journald can see them; lower-severity transient
                # network errors stay at DEBUG. Import locally to avoid a
                # top-level dependency cycle with dns_pinning.
                from dsm.net.dns_pinning import PinMismatchError

                redacted = redact(hostname, self._debug_dns)
                if isinstance(e, PinMismatchError):
                    log.warning(
                        "DNS provider %s SPKI pin MISMATCH for %s — possible MITM; "
                        "refusing and falling through",
                        provider,
                        redacted,
                    )
                else:
                    log.debug(
                        "DNS provider %s failed for %s: %s",
                        provider,
                        redacted,
                        type(e).__name__,
                    )
                continue

        redacted = redact(hostname, self._debug_dns)
        log.error("all DNS providers failed for %s", redacted)
        # Transport failure across every provider — non-authoritative so the
        # proxy returns SERVFAIL, not NXDOMAIN.
        return _DnsResult(addresses=[], ttl=MIN_TTL, rcode=-1, authoritative=False)

    async def _resolve_via_pinned_tls(
        self,
        provider: str,
        host: str,
        port: int,
        timeout: float,
        send_recv: Callable[
            [asyncio.StreamReader, asyncio.StreamWriter], Awaitable[bytes]
        ],
        *,
        reverify_pin: bool = False,
    ) -> bytes:
        """Shared connect → pin-check → send/recv → cleanup scaffold.

        ``send_recv`` is the per-protocol body: it receives the established
        (reader, writer) pair (with the SPKI pin already checked on the
        TLS handshake) and returns the response wire bytes. DoH wraps the
        DNS query in an HTTP/1.1 POST; DoT wraps it in a 2-byte length
        prefix. The connect/pin-recheck/close scaffold around that is
        identical and lives here.
        """
        from dsm.net.dns_pinning import verify_pin_on_ssl_object

        reader, writer = await _open_pinned_tls_connection(
            host,
            port,
            self._pins[provider],
            provider,
            timeout=timeout,
        )
        try:
            if reverify_pin:
                # Belt-and-braces: re-verify pin from this end of the
                # connection after _open_pinned_tls_connection has
                # already checked it. A second verify here catches any
                # future regression where the helper is refactored to
                # defer the check.
                ssl_obj = writer.get_extra_info("ssl_object")
                if ssl_obj is None:
                    raise RuntimeError(
                        f"connection to {provider} did not negotiate TLS"
                    )
                verify_pin_on_ssl_object(ssl_obj, self._pins[provider], provider)
            return await send_recv(reader, writer)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    async def _resolve_doh(self, url: str, hostname: str) -> _DnsResult:
        """DNS-over-HTTPS query with SPKI pin checked BEFORE the qname
        is sent.

        Uses a manual asyncio TLS + HTTP/1.1 path instead of httpx so the
        pin is verified on the live SSL object before any application
        bytes (the DNS query containing the qname) cross the wire. The
        underlying socket is marked with SO_MARK so the connection
        bypasses the VPN's ip-rule routing — otherwise the server's own
        DoH lookup would be routed back through its own TUN device and
        loop forever (the server's routing table sends all unmarked
        traffic via mtun0).
        """
        parsed = urlparse(url)
        if parsed.scheme != "https":
            raise ValueError(f"invalid DoH provider scheme: {url!r}")
        host = parsed.hostname
        port = parsed.port or 443
        path = parsed.path or "/dns-query"
        if not host:
            raise ValueError(f"invalid DoH provider format: {url!r}")
        if parsed.query:
            path = f"{path}?{parsed.query}"

        query = _build_dns_query(hostname)

        async def _doh_send_recv(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
        ) -> bytes:
            # Minimal HTTP/1.1 request. Connection: close so we don't
            # keep a pool — DNS resolutions are infrequent enough that
            # pool benefit is small, and each new query gets a fresh
            # connection with a fresh pin check.
            request = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                f"AppleWebKit/537.36 (KHTML, like Gecko) "
                f"Chrome/120.0.0.0 Safari/537.36\r\n"
                f"Content-Type: application/dns-message\r\n"
                f"Accept: application/dns-message\r\n"
                f"Content-Length: {len(query)}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode("ascii") + query
            writer.write(request)
            await writer.drain()
            return await asyncio.wait_for(
                _read_http_response(reader),
                timeout=DOH_TIMEOUT,
            )

        body = await self._resolve_via_pinned_tls(
            url,
            host,
            port,
            DOH_TIMEOUT,
            _doh_send_recv,
            reverify_pin=True,
        )
        return self._parse_and_cache(hostname, body)

    async def _resolve_dot(self, provider: str, hostname: str) -> _DnsResult:
        """DNS-over-TLS query with SPKI pin checked before the qname is
        sent. Underlying socket is SO_MARK'd so the connection bypasses
        the VPN's ip-rule routing (otherwise the lookup would loop
        through our own TUN device — see _resolve_doh for the explanation).
        """
        # Parse "tls://host:port" or "tls://[ipv6]:port"
        parsed = urlparse(provider)
        if parsed.scheme != "tls":
            raise ValueError(f"invalid DoT provider format: {provider!r}")
        host = parsed.hostname
        port = parsed.port
        if not host or not port:
            raise ValueError(f"invalid DoT provider format: {provider!r}")

        query = _build_dns_query(hostname)
        # DoT uses TCP with 2-byte length prefix
        framed = struct.pack("!H", len(query)) + query

        async def _dot_send_recv(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
        ) -> bytes:
            writer.write(framed)
            await writer.drain()
            len_buf = await asyncio.wait_for(
                reader.readexactly(2),
                timeout=DOT_TIMEOUT,
            )
            resp_len = struct.unpack("!H", len_buf)[0]
            return await asyncio.wait_for(
                reader.readexactly(resp_len),
                timeout=DOT_TIMEOUT,
            )

        resp_data = await self._resolve_via_pinned_tls(
            provider,
            host,
            port,
            DOT_TIMEOUT,
            _dot_send_recv,
        )
        return self._parse_and_cache(hostname, resp_data)

    def _parse_and_cache(self, hostname: str, wire: bytes) -> _DnsResult:
        """Parse an upstream response; cache authoritative answers (RFC 2308).

        Positive (addresses) and negative (NXDOMAIN/NODATA, empty list)
        authoritative answers are cached alike; a non-authoritative result
        (transport failure / retryable rcode) is returned uncached so the
        caller keeps trying other providers.
        """
        result = _parse_dns_response(wire)
        if result.authoritative:
            self._cache_result(hostname, result.addresses, result.ttl, result.rcode)
        return result

    def _cache_result(
        self,
        hostname: str,
        addresses: list[str],
        ttl: int = 300,
        rcode: int = 0,
    ) -> None:
        """Cache a DNS result with TTL enforcement (positive or negative).

        An empty ``addresses`` list with an authoritative ``rcode``
        (NXDOMAIN or NOERROR/NODATA) is a negative-cache entry per RFC 2308.

        Expiry is lazy: reads (:meth:`resolve_detailed`) already treat an
        expired entry as a miss, so stale entries need not be swept eagerly.
        Only when the cache reaches ``MAX_CACHE_ENTRIES`` do we drop expired
        entries and, if still full, evict the soonest-to-expire one — an O(n)
        pass that is fine at the 2000-entry cap.
        """
        now = time.monotonic()

        if len(self._cache) >= MAX_CACHE_ENTRIES:
            for key in [k for k, e in self._cache.items() if e.expires <= now]:
                del self._cache[key]
            if len(self._cache) >= MAX_CACHE_ENTRIES:
                victim = min(self._cache, key=lambda k: self._cache[k].expires)
                del self._cache[victim]

        clamped_ttl = max(MIN_TTL, min(MAX_TTL, ttl))
        self._cache[hostname] = _CacheEntry(
            addresses=addresses,
            expires=now + clamped_ttl,
            rcode=rcode,
        )


def _build_dns_query(hostname: str) -> bytes:
    """Build a DNS query padded per RFC 7830 / RFC 8467.

    The query carries an EDNS(0) OPT record with a Padding option sized so
    that the total wire length is a multiple of EDNS_PADDING_BLOCK. This
    masks qname length from a passive observer who sees the encrypted
    TLS record.
    """
    msg = dns.message.make_query(
        hostname,
        dns.rdatatype.A,
        use_edns=0,
        pad=EDNS_PADDING_BLOCK,
    )
    return msg.to_wire()


def _parse_dns_response(data: bytes) -> _DnsResult:
    """Parse a DNS response into a typed result (addresses + rcode).

    Distinguishes an authoritative NXDOMAIN/NODATA answer (rcode set,
    ``authoritative=True``, empty addresses) from a transport-level
    failure or a retryable rcode (SERVFAIL/REFUSED, ``authoritative=False``)
    so callers can stop provider fan-out and negative-cache instead of
    treating every empty answer as a failure (Phase 1.10).
    """
    try:
        msg = dns.message.from_wire(data)
    except dns.exception.DNSException:
        # Not a parseable DNS message — a transport-level failure, NOT
        # authoritative; the caller should keep trying other providers.
        return _DnsResult(addresses=[], ttl=MIN_TTL, rcode=-1, authoritative=False)

    rcode = msg.rcode()
    if rcode == dns.rcode.NXDOMAIN:
        return _DnsResult(
            addresses=[], ttl=MIN_TTL, rcode=int(rcode), authoritative=True
        )
    if rcode != dns.rcode.NOERROR:
        # SERVFAIL / REFUSED etc. — treat as a (non-authoritative) failure so
        # other providers are still tried.
        return _DnsResult(
            addresses=[], ttl=MIN_TTL, rcode=int(rcode), authoritative=False
        )

    addresses: list[str] = []
    # Phase 1.10: seed with MAX_TTL (was 300) so the clamp in _cache_result
    # can actually reach MAX_TTL — previously min(300, ttl) capped every
    # answer at 300 s, making MAX_TTL dead.
    min_ttl = MAX_TTL
    for rrset in msg.answer:
        if rrset.rdtype != dns.rdatatype.A:
            continue
        min_ttl = min(min_ttl, rrset.ttl)
        # dnspython's Rdataset.__iter__ is untyped; cast expresses the
        # guarantee (RRset yields Rdata) so pyright strict can narrow.
        for rdata in cast(Iterable[dns.rdata.Rdata], rrset):
            if isinstance(rdata, dns.rdtypes.IN.A.A):
                addresses.append(rdata.address)

    if not addresses:
        # NOERROR with no A records = NODATA, authoritative; negative-cache
        # at MIN_TTL.
        return _DnsResult(
            addresses=[], ttl=MIN_TTL, rcode=int(rcode), authoritative=True
        )
    return _DnsResult(
        addresses=addresses, ttl=min_ttl, rcode=int(rcode), authoritative=True
    )


# Hard caps on the manual HTTP/1.1 parser. DoH responses are tiny —
# headers fit in well under 8 KiB and body is bounded by the DNS reply
# size (~4 KiB EDNS). Caps prevent a malicious or buggy upstream from
# forcing unbounded reads.
_HTTP_HEADER_MAX_BYTES = 8 * 1024
_HTTP_BODY_MAX_BYTES = 64 * 1024


async def _open_pinned_tls_connection(
    host: str,
    port: int,
    expected_pins: list[bytes],
    provider_label: str,
    *,
    timeout: float,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Open a TLS connection, verify the SPKI pin, return (reader, writer).

    The underlying TCP socket is marked with SO_MARK so the connection
    bypasses the VPN's ip-rule routing (otherwise the server's own DNS
    upstream traffic would loop through its own TUN device). Pin
    verification happens AFTER the TLS handshake completes but BEFORE
    any application bytes are written by the caller — if the pin fails,
    the connection is closed without leaking the application payload
    (in DoH's case, the qname) to the peer.

    Raises:
        TimeoutError on connection / handshake timeout.
        PinMismatchError if the peer cert SPKI does not match any
            entry in expected_pins (connection is closed before raise).
        RuntimeError if TLS does not negotiate.
    """
    # Create the raw TCP socket first so we can set SO_MARK BEFORE
    # connect. asyncio.open_connection does not expose a pre-connect
    # socket-config hook, so we drive the connect + start_tls dance
    # manually using loop.sock_connect on a configured socket and then
    # asyncio.StreamReader/Writer over a transport.
    import socket as socket_mod

    from dsm.net.dns_pinning import build_pinned_ssl_context, verify_pin_on_ssl_object

    loop = asyncio.get_running_loop()

    # Resolve the host (may be IP literal or hostname). getaddrinfo is
    # blocking, so dispatch via the loop's resolver.
    infos = await loop.getaddrinfo(
        host,
        port,
        type=socket_mod.SOCK_STREAM,
    )
    if not infos:
        raise OSError(f"no addrinfo for {host}:{port}")
    family, sock_type, proto, _canon, sockaddr = infos[0]

    sock = socket_mod.socket(family, sock_type, proto)
    try:
        sock.setblocking(False)
        # Mark the socket BEFORE connect so the very first SYN bypasses
        # the VPN ip-rule routing. Without this the SYN itself could be
        # routed through mtun0 and cause the loop we're trying to avoid.
        apply_so_mark(sock)
        await asyncio.wait_for(
            loop.sock_connect(sock, sockaddr),
            timeout=timeout,
        )
    except BaseException:
        sock.close()
        raise

    ctx = build_pinned_ssl_context()
    try:
        # create_connection wraps the existing socket and then we
        # start_tls. We use open_connection + sock parameter to get
        # reader/writer.
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                sock=sock,
                ssl=ctx,
                server_hostname=host,
            ),
            timeout=timeout,
        )
    except BaseException:
        try:
            sock.close()
        except OSError:
            pass
        raise

    # Pin check happens here, before the caller is handed the writer.
    # If the pin fails the helper closes the connection and re-raises
    # the PinMismatchError so the caller never gets a writer they could
    # accidentally write the qname to.
    try:
        ssl_obj = writer.get_extra_info("ssl_object")
        if ssl_obj is None:
            raise RuntimeError(
                f"TLS connection to {provider_label} did not negotiate TLS"
            )
        verify_pin_on_ssl_object(ssl_obj, expected_pins, provider_label)
    except BaseException:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass
        raise

    return reader, writer


async def _read_http_response(reader: asyncio.StreamReader) -> bytes:
    """Read an HTTP/1.1 response and return the body bytes.

    Supports Content-Length-framed and Connection: close-framed
    responses. Chunked transfer encoding is rejected — DoH servers do
    not use chunked for /dns-query responses, and supporting it would
    add a lot of attack surface for no benefit.

    Raises:
        RuntimeError on malformed status, missing required headers, or
            size cap violation.
    """
    # Status line + headers terminated by \r\n\r\n.
    header_blob = await reader.readuntil(b"\r\n\r\n")
    if len(header_blob) > _HTTP_HEADER_MAX_BYTES:
        raise RuntimeError(
            f"HTTP response headers exceed cap ({_HTTP_HEADER_MAX_BYTES} B)"
        )

    # Parse just enough: status line + headers we care about. Case-
    # insensitive header lookup.
    head_text = header_blob.decode("ascii", errors="replace")
    lines = head_text.split("\r\n")
    if not lines:
        raise RuntimeError("HTTP response empty")
    status_line = lines[0]
    parts = status_line.split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/1."):
        raise RuntimeError(f"HTTP malformed status: {status_line!r}")
    try:
        status = int(parts[1])
    except ValueError as e:
        raise RuntimeError(f"HTTP malformed status code: {parts[1]!r}") from e
    if status != 200:
        raise RuntimeError(f"HTTP status {status} for DoH request")

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            continue
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()

    transfer = headers.get("transfer-encoding", "").lower()
    if transfer and transfer != "identity":
        raise RuntimeError(f"HTTP transfer-encoding {transfer!r} not supported")

    cl = headers.get("content-length")
    if cl is not None:
        try:
            length = int(cl)
        except ValueError as e:
            raise RuntimeError(f"HTTP malformed content-length {cl!r}") from e
        if length < 0 or length > _HTTP_BODY_MAX_BYTES:
            raise RuntimeError(
                f"HTTP content-length {length} out of bounds "
                f"(max {_HTTP_BODY_MAX_BYTES})"
            )
        body = await reader.readexactly(length)
        return body

    # No content-length: read until EOF (Connection: close framing).
    # Read in chunks with a hard cap to defend against an unbounded
    # peer.
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await reader.read(4096)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > _HTTP_BODY_MAX_BYTES:
            raise RuntimeError(f"HTTP body exceeds cap ({_HTTP_BODY_MAX_BYTES} B)")
    return b"".join(chunks)
