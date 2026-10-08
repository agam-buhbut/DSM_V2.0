"""The DNS proxy answers blocked names with NXDOMAIN and a 5-minute SOA."""

from __future__ import annotations

import logging
from pathlib import Path

import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype
import pytest

from dsm.net.dns import DnsResult
from dsm.net.dns_blocklist import NEGATIVE_TTL_S, DnsBlocklist
from dsm.net.dns_proxy import LocalDNSProxy

_CLIENT = ("10.8.0.2", 53000)


class _RecordingResolver:
    """Answers every name with one address and records what it was asked."""

    def __init__(self) -> None:
        self.asked: list[str] = []

    async def resolve_detailed(self, hostname: str) -> DnsResult:
        self.asked.append(hostname)
        return DnsResult(addresses=["192.0.2.7"], ttl=60, rcode=0, authoritative=True)


class _RecordingBlocklist(DnsBlocklist):
    """A real blocklist that also records every name it is asked about."""

    def __init__(self, dns_dir: Path) -> None:
        super().__init__(dns_dir)
        self.asked: list[str] = []

    def is_blocked(self, qname: str) -> bool:
        self.asked.append(qname)
        return super().is_blocked(qname)


def _write(path: Path, body: bytes) -> None:
    path.write_bytes(body)
    path.chmod(0o600)


async def _blocklist(
    tmp_path: Path, *, block: bytes, allow: bytes | None = None
) -> _RecordingBlocklist:
    dns_dir = tmp_path / "dns"
    (dns_dir / "block").mkdir(parents=True)
    dns_dir.chmod(0o700)
    (dns_dir / "block").chmod(0o700)
    _write(dns_dir / "block" / "list.txt", block)
    if allow is not None:
        _write(dns_dir / "allow.txt", allow)
    blocklist = _RecordingBlocklist(dns_dir)
    await blocklist.refresh()
    return blocklist


async def _send(proxy: LocalDNSProxy, query: dns.message.Message) -> list[bytes]:
    sent: list[bytes] = []
    await proxy._handle_query(
        query.to_wire(), _CLIENT, lambda wire, _to: sent.append(wire)
    )
    return sent


async def _ask(
    proxy: LocalDNSProxy, qname: str, qtype: str = "A", *, edns: bool = False
) -> tuple[dns.message.Message, dns.message.Message]:
    query = dns.message.make_query(qname, qtype, use_edns=0 if edns else None)
    sent = await _send(proxy, query)
    assert len(sent) == 1
    return query, dns.message.from_wire(sent[0])


@pytest.mark.parametrize("qtype", ["A", "AAAA", "HTTPS", "TXT", "MX", "ANY"])
@pytest.mark.parametrize(
    "qname", ["ads.example.com", "x.ads.example.com", "ADS.Example.COM."]
)
async def test_a_blocked_name_gets_nxdomain_with_a_five_minute_soa(
    tmp_path: Path, qtype: str, qname: str
) -> None:
    resolver = _RecordingResolver()
    blocklist = await _blocklist(tmp_path, block=b"0.0.0.0 ads.example.com\n")
    proxy = LocalDNSProxy(resolver, bind_ip="10.8.0.1", blocklist=blocklist)  # type: ignore[arg-type]
    query, reply = await _ask(proxy, qname, qtype, edns=True)
    assert reply.id == query.id
    assert reply.rcode() == dns.rcode.NXDOMAIN
    assert reply.flags & dns.flags.QR
    assert reply.flags & dns.flags.RA
    assert reply.answer == []
    (soa,) = reply.authority
    assert soa.rdtype == dns.rdatatype.SOA
    assert soa.name == query.question[0].name
    assert soa.ttl == NEGATIVE_TTL_S == 300
    assert soa[0].minimum == 300
    assert resolver.asked == []


async def test_a_name_that_is_not_blocked_still_resolves(tmp_path: Path) -> None:
    resolver = _RecordingResolver()
    blocklist = await _blocklist(tmp_path, block=b"0.0.0.0 ads.example.com\n")
    proxy = LocalDNSProxy(resolver, bind_ip="10.8.0.1", blocklist=blocklist)  # type: ignore[arg-type]
    _query, reply = await _ask(proxy, "example.com")
    assert reply.rcode() == dns.rcode.NOERROR
    assert [rr.address for rr in reply.answer[0]] == ["192.0.2.7"]
    assert resolver.asked == ["example.com"]


async def test_an_allowed_name_under_a_blocked_one_resolves(tmp_path: Path) -> None:
    resolver = _RecordingResolver()
    blocklist = await _blocklist(
        tmp_path, block=b"||example.com^\n", allow=b"good.example.com\n"
    )
    proxy = LocalDNSProxy(resolver, bind_ip="10.8.0.1", blocklist=blocklist)  # type: ignore[arg-type]
    _query, allowed = await _ask(proxy, "cdn.good.example.com")
    _query, blocked = await _ask(proxy, "bad.example.com")
    assert allowed.rcode() == dns.rcode.NOERROR
    assert blocked.rcode() == dns.rcode.NXDOMAIN
    assert resolver.asked == ["cdn.good.example.com"]


async def test_other_types_for_an_allowed_name_keep_the_empty_answer(
    tmp_path: Path,
) -> None:
    resolver = _RecordingResolver()
    blocklist = await _blocklist(tmp_path, block=b"0.0.0.0 ads.example.com\n")
    proxy = LocalDNSProxy(resolver, bind_ip="10.8.0.1", blocklist=blocklist)  # type: ignore[arg-type]
    _query, reply = await _ask(proxy, "example.com", "AAAA")
    assert reply.rcode() == dns.rcode.NOERROR
    assert reply.answer == []
    assert reply.authority == []
    assert resolver.asked == []


@pytest.mark.parametrize("qtype", ["A", "AAAA", "HTTPS"])
async def test_the_firefox_canary_is_nxdomain_even_when_allowed(
    tmp_path: Path, qtype: str
) -> None:
    resolver = _RecordingResolver()
    blocklist = await _blocklist(
        tmp_path, block=b"", allow=b"use-application-dns.net\n"
    )
    proxy = LocalDNSProxy(resolver, bind_ip="10.8.0.1", blocklist=blocklist)  # type: ignore[arg-type]
    _query, reply = await _ask(proxy, "use-application-dns.net", qtype)
    assert reply.rcode() == dns.rcode.NXDOMAIN
    assert resolver.asked == []


async def test_without_a_blocklist_the_proxy_answers_as_before() -> None:
    resolver = _RecordingResolver()
    proxy = LocalDNSProxy(resolver, bind_ip="10.8.0.1")  # type: ignore[arg-type]
    _query, reply = await _ask(proxy, "use-application-dns.net")
    assert reply.rcode() == dns.rcode.NOERROR
    assert resolver.asked == ["use-application-dns.net"]


async def test_a_blocked_answer_logs_nothing_about_the_name(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    blocklist = await _blocklist(tmp_path, block=b"0.0.0.0 secret-ads.example.com\n")
    proxy = LocalDNSProxy(_RecordingResolver(), bind_ip="10.8.0.1", blocklist=blocklist)  # type: ignore[arg-type]
    caplog.set_level(logging.DEBUG)
    _query, reply = await _ask(proxy, "secret-ads.example.com")
    assert reply.rcode() == dns.rcode.NXDOMAIN
    assert "secret-ads" not in caplog.text


async def test_a_name_over_253_bytes_is_dropped_before_the_blocklist_sees_it(
    tmp_path: Path,
) -> None:
    resolver = _RecordingResolver()
    blocklist = await _blocklist(tmp_path, block=b"0.0.0.0 ads.example.com\n")
    proxy = LocalDNSProxy(resolver, bind_ip="10.8.0.1", blocklist=blocklist)  # type: ignore[arg-type]
    # 254 bytes on the wire (legal), but each \x01 reads back as the four
    # characters "\001", so the name's text is far over 253.
    labels = [b"\x01" * 63] * 3 + [b"\x01" * 60, b""]
    query = dns.message.make_query(dns.name.Name(labels), "A")
    assert await _send(proxy, query) == []
    assert blocklist.asked == []
    assert resolver.asked == []
