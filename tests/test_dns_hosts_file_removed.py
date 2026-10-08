"""DSM no longer reads /opt/mtun/hosts.txt: the owner removed that feature."""

from __future__ import annotations

import inspect
from pathlib import Path

import dsm.net.dns as dns_module
from dsm.net.dns import DNSResolver, DnsResult

_DOH = "https://1.1.1.1/dns-query"


def test_the_resolver_has_no_hosts_file_reader() -> None:
    source = inspect.getsource(dns_module)
    assert "_load_hosts_file" not in source
    assert "_static_hosts" not in source
    assert "read_bytes" not in source


async def test_a_hosts_file_no_longer_changes_answers(tmp_path: Path) -> None:
    # A resolver built the normal way has no way to be pointed at this file.
    (tmp_path / "hosts.txt").write_text("10.9.8.7 pinned.example\n", encoding="utf-8")

    class _Resolver(DNSResolver):
        def __init__(self) -> None:
            super().__init__(providers=[_DOH], provider_pins={_DOH: ["a" * 64]})
            self.asked: list[str] = []

        async def _resolve_doh(self, url: str, hostname: str) -> DnsResult:
            self.asked.append(hostname)
            return DnsResult(
                addresses=["192.0.2.1"], ttl=60, rcode=0, authoritative=True
            )

    resolver = _Resolver()
    result = await resolver.resolve_detailed("Pinned.Example.")
    assert resolver.asked == ["pinned.example"]
    assert result.addresses == ["192.0.2.1"]
    assert "10.9.8.7" not in result.addresses


def test_the_resolver_takes_no_hosts_file_argument() -> None:
    assert "hosts_file" not in inspect.signature(DNSResolver.__init__).parameters
