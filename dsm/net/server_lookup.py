"""The client's own lookup of the server name.

The start-up kill switch is already up when the name is looked up
(dsm.client.run_client). It lets out only DNS queries that carry DSM's
socket mark, from root, to the resolvers DSM chose, and only their replies
back in (pre_handshake.conf). So the client asks the host's IPv4 resolvers
itself, from marked sockets, instead of through libc: one A query over UDP,
and again over TCP when the answer is cut short.
"""

from __future__ import annotations

import ipaddress
import socket
import time
from collections.abc import Iterable
from pathlib import Path
from typing import cast

import dns.exception
import dns.flags
import dns.inet
import dns.message
import dns.query
import dns.rcode
import dns.rdata
import dns.rdatatype
import dns.rdtypes.IN.A

from dsm.net.resolv_conf import (
    DSM_MARKER,
    RESOLV_BACKUP,
    RESOLV_CONF,
    parse_symlink_backup,
)
from dsm.net.transport._fwmark import apply_so_mark

# The whole lookup may take this long, as before it moved here.
LOOKUP_TIMEOUT_S = 10.0
# One resolver gets this long, UDP and the TCP retry together, so the next
# one still has time.
_PER_SERVER_S = 3.0
# glibc reads at most three nameserver lines (MAXNS).
_MAX_NAMESERVERS = 3
_DNS_PORT = 53
# systemd-resolved answers on this loopback address but asks upstream from
# its own, unmarked sockets, which the kill switch drops. It lists those
# upstreams here, so DSM asks them directly.
_RESOLVED_STUB = "127.0.0.53"
_RESOLVED_UPSTREAMS = Path("/run/systemd/resolve/resolv.conf")


def system_nameservers() -> list[str]:
    """The host's own IPv4 resolvers, at most three, read fresh on each call.

    A crash can leave DSM's resolv.conf, which points into a tunnel that is
    gone: then the original that DSM saved is read instead. For
    systemd-resolved's stub, its upstreams are used. IPv6 resolvers are
    skipped: the kill switch opens port 53 for IPv4 only.
    """
    data = _read(RESOLV_CONF)
    if data.startswith(DSM_MARKER):
        data = _read(RESOLV_BACKUP)
        target = parse_symlink_backup(data)
        if target is not None:
            # The original was a symlink; a relative target is relative to
            # the folder of resolv.conf.
            data = _read(RESOLV_CONF.parent / target)
    servers = _nameservers(data)
    if _RESOLVED_STUB in servers:
        servers = _nameservers(_read(_RESOLVED_UPSTREAMS)) or servers
    return servers[:_MAX_NAMESERVERS]


def lookup_a(name: str, nameservers: list[str] | None = None) -> str:
    """The first A address for ``name``, asked from marked sockets.

    Asks each nameserver in turn (``system_nameservers()`` when None) until
    one answers with an address or LOOKUP_TIMEOUT_S runs out. Blocking: run
    it in a thread. Raises ``OSError`` otherwise; the text names neither the
    server name nor an address, so it can go in the log.
    """
    if nameservers is None:
        nameservers = system_nameservers()
    if not nameservers:
        raise OSError("no IPv4 nameserver found in /etc/resolv.conf")
    deadline = time.monotonic() + LOOKUP_TIMEOUT_S
    asked = 0
    reason = "out of time"
    for server in nameservers:
        now = time.monotonic()
        if now >= deadline:
            break
        asked += 1
        try:
            query = dns.message.make_query(name, dns.rdatatype.A)
            reply = _ask(query, server, min(deadline, now + _PER_SERVER_S))
        # dnspython raises the builtin EOFError when the far end closes the
        # TCP connection, which anyone on the path can do.
        except (OSError, EOFError, ValueError, dns.exception.DNSException) as e:
            reason = type(e).__name__
            continue
        if reply.rcode() != dns.rcode.NOERROR:
            reason = dns.rcode.to_text(reply.rcode())
            continue
        try:
            address = _first_a(reply)
        except dns.exception.DNSException:
            address = None
        if address is not None:
            return address
        reason = "no A record"
    raise OSError(f"no address (asked {asked} nameservers, last: {reason})")


def _ask(
    query: dns.message.Message, server: str, deadline: float
) -> dns.message.Message:
    """Ask ``server`` from a marked socket: UDP, then TCP if the answer is
    cut short (TC). Each step gets only the time left until ``deadline``."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        apply_so_mark(udp)
        udp.setblocking(False)
        try:
            reply = dns.query.udp(
                query,
                server,
                timeout=_left(deadline),
                port=_DNS_PORT,
                sock=udp,
                # A cut reply may end mid-record: that is the same signal.
                raise_on_truncation=True,
                # A stray or forged reply must not end the wait for the
                # real one.
                ignore_errors=True,
            )
        except dns.message.Truncated:
            reply = None
    if reply is not None and not reply.flags & dns.flags.TC:
        return reply
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp:
        apply_so_mark(tcp)
        # dnspython wants a connected, non-blocking socket. Connecting it
        # here puts the mark on the very first packet.
        tcp.settimeout(_left(deadline))
        tcp.connect(
            dns.inet.low_level_address_tuple((server, _DNS_PORT), socket.AF_INET)
        )
        tcp.setblocking(False)
        return dns.query.tcp(
            query, server, timeout=_left(deadline), port=_DNS_PORT, sock=tcp
        )


def _left(deadline: float) -> float:
    left = deadline - time.monotonic()
    if left <= 0:
        raise dns.exception.Timeout()
    return left


def _first_a(reply: dns.message.Message) -> str | None:
    # Only the answer chain for the asked name counts, not any A record
    # that came along.
    rrset = cast(dns.message.QueryMessage, reply).resolve_chaining().answer
    if rrset is None or rrset.rdtype != dns.rdatatype.A:
        return None
    # dnspython's Rdataset.__iter__ is untyped (as in dsm.net.dns).
    for rdata in cast(Iterable[dns.rdata.Rdata], rrset):
        if isinstance(rdata, dns.rdtypes.IN.A.A):
            return str(rdata.address)
    return None


def _read(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError:
        # A missing or unreadable file lists no nameserver; lookup_a says so.
        return b""


def _nameservers(data: bytes) -> list[str]:
    found: list[str] = []
    for line in data.decode(errors="replace").splitlines():
        fields = line.split()
        if len(fields) < 2 or fields[0] != "nameserver":
            continue
        try:
            ipaddress.IPv4Address(fields[1])
        except ValueError:
            continue  # not an address, or IPv6
        found.append(fields[1])
    return found
