"""DSM's own lookup of the server name at start (R1, re-decision 1).

The start-up kill switch lets out only DNS queries that carry DSM's socket
mark, to the resolvers DSM chose, so the client asks the host's IPv4
resolvers itself. Nothing here touches the network: the resolv.conf files
live in tmp_path, dnspython's send calls are replaced, socket.connect is
replaced for the TCP case, and apply_so_mark (it needs CAP_NET_ADMIN) is a
recorder.
"""

from __future__ import annotations

import contextlib
import socket
from collections.abc import Callable, Generator, Iterator
from pathlib import Path
from typing import Any
from unittest.mock import patch

import dns.exception
import dns.flags
import dns.message
import dns.rcode
import dns.rrset
import pytest

from dsm.net import server_lookup
from dsm.net.resolv_conf import DSM_MARKER

NAME = "vpn.example.org"
Reply = Callable[[dns.message.Message], dns.message.Message]


@pytest.fixture
def files(tmp_path: Path) -> Iterator[dict[str, Path]]:
    paths = {
        "etc": tmp_path / "etc" / "resolv.conf",
        "backup": tmp_path / "var" / "resolv.conf.orig",
        "upstreams": tmp_path / "run" / "resolve" / "resolv.conf",
    }
    for path in paths.values():
        path.parent.mkdir(parents=True, exist_ok=True)
    with (
        patch.object(server_lookup, "RESOLV_CONF", paths["etc"]),
        patch.object(server_lookup, "RESOLV_BACKUP", paths["backup"]),
        patch.object(server_lookup, "_RESOLVED_UPSTREAMS", paths["upstreams"]),
    ):
        yield paths


def test_the_nameservers_come_from_resolv_conf(files: dict[str, Path]) -> None:
    files["etc"].write_text(
        "# from DHCP\nsearch home.arpa\nnameserver 192.0.2.53\n"
        "nameserver not-an-address\nnameserver 2001:db8::53\n"
        "nameserver 192.0.2.54\nnameserver 192.0.2.55\nnameserver 192.0.2.56\n"
    )
    # Bad lines and IPv6 ones are skipped (the block opens IPv4 only); at
    # most three are used, as glibc does.
    assert server_lookup.system_nameservers() == [
        "192.0.2.53",
        "192.0.2.54",
        "192.0.2.55",
    ]


def test_dsms_own_file_left_by_a_crash_is_skipped_for_the_saved_original(
    files: dict[str, Path],
) -> None:
    files["etc"].write_bytes(
        DSM_MARKER + b" while the VPN is up\nnameserver 10.8.0.1\n"
    )
    files["backup"].write_text("nameserver 192.0.2.53\n")
    assert server_lookup.system_nameservers() == ["192.0.2.53"]


def test_a_saved_symlink_is_followed_to_systemd_resolveds_upstreams(
    files: dict[str, Path],
) -> None:
    files["etc"].write_bytes(DSM_MARKER + b"\nnameserver 10.8.0.1\n")
    # What ResolvConfManager saves when resolv.conf was a relative symlink.
    files["backup"].write_text(
        "# dsm-resolv-symlink -> ../run/resolve/stub-resolv.conf\n"
    )
    (files["upstreams"].parent / "stub-resolv.conf").write_text(
        "nameserver 127.0.0.53\n"
    )
    files["upstreams"].write_text("nameserver 192.0.2.53\n")
    assert server_lookup.system_nameservers() == ["192.0.2.53"]


def test_systemd_resolveds_stub_is_replaced_by_its_upstreams(
    files: dict[str, Path],
) -> None:
    files["etc"].write_text("nameserver 127.0.0.53\noptions edns0 trust-ad\n")
    files["upstreams"].write_text("nameserver 192.0.2.53\nnameserver fe80::1%eth0\n")
    assert server_lookup.system_nameservers() == ["192.0.2.53"]


def test_a_stub_with_no_upstreams_listed_is_kept(files: dict[str, Path]) -> None:
    files["etc"].write_text("nameserver 127.0.0.53\n")
    assert server_lookup.system_nameservers() == ["127.0.0.53"]


def test_no_resolv_conf_means_no_lookup(files: dict[str, Path]) -> None:
    assert server_lookup.system_nameservers() == []
    with pytest.raises(OSError, match="no IPv4 nameserver"):
        server_lookup.lookup_a(NAME)


class _Resolver:
    """Stands in for dnspython's send calls (dns.query.udp and tcp)."""

    def __init__(
        self, udp: list[Reply | Exception], tcp: list[Reply | Exception] | None = None
    ) -> None:
        self._plans: dict[str, list[Any]] = {"udp": udp, "tcp": tcp or []}
        self.asked: list[tuple[str, str, str]] = []  # (proto, server, name)
        self.timeouts: list[float] = []

    def _answer(self, proto: str, query: Any, where: str, timeout: float) -> Any:
        self.asked.append((proto, where, query.question[0].name.to_text()))
        self.timeouts.append(timeout)
        step = self._plans[proto].pop(0)
        if isinstance(step, Exception):
            raise step
        return step(query)

    def udp(self, query: Any, where: str, timeout: float, port: int, sock: Any) -> Any:
        assert sock is not None and port == 53
        return self._answer("udp", query, where, timeout)

    def tcp(self, query: Any, where: str, timeout: float, port: int, sock: Any) -> Any:
        assert sock is not None and port == 53
        return self._answer("tcp", query, where, timeout)

    @contextlib.contextmanager
    def patched(self) -> Generator[None, None, None]:
        with patch("dns.query.udp", self.udp), patch("dns.query.tcp", self.tcp):
            yield


def _a(*addresses: str, tc: bool = False) -> Reply:
    def build(query: dns.message.Message) -> dns.message.Message:
        reply = dns.message.make_response(query)
        if addresses:
            reply.answer.append(
                dns.rrset.from_text(query.question[0].name, 60, "IN", "A", *addresses)
            )
        if tc:
            reply.flags |= dns.flags.TC
        return reply

    return build


def _rcode(rcode: dns.rcode.Rcode) -> Reply:
    def build(query: dns.message.Message) -> dns.message.Message:
        reply = dns.message.make_response(query)
        reply.set_rcode(rcode)
        return reply

    return build


@pytest.fixture
def marks() -> Iterator[list[socket.SocketKind]]:
    seen: list[socket.SocketKind] = []
    with patch.object(server_lookup, "apply_so_mark", lambda s: seen.append(s.type)):
        yield seen


def test_the_first_a_record_comes_back_over_marked_udp(
    marks: list[socket.SocketKind],
) -> None:
    resolver = _Resolver(udp=[_a("203.0.113.7", "203.0.113.8")])
    with resolver.patched():
        assert server_lookup.lookup_a(NAME, ["192.0.2.53"]) == "203.0.113.7"
    # The trailing dot: no search domain is added, only the name leaves.
    assert resolver.asked == [("udp", "192.0.2.53", "vpn.example.org.")]
    assert marks == [socket.SOCK_DGRAM]
    assert resolver.timeouts[0] <= 3.0


def test_a_cut_short_answer_is_asked_again_over_marked_tcp() -> None:
    # One list for both calls, so the order shows: the TCP socket is marked
    # before DSM connects it, so the SYN carries the mark (the start-up
    # table drops an unmarked one).
    steps: list[tuple[str, Any]] = []
    resolver = _Resolver(udp=[_a(tc=True)], tcp=[_a("203.0.113.7")])
    with (
        resolver.patched(),
        patch.object(
            server_lookup, "apply_so_mark", lambda s: steps.append(("mark", s.type))
        ),
        patch.object(
            socket.socket, "connect", lambda _s, addr: steps.append(("connect", addr))
        ),
    ):
        assert server_lookup.lookup_a(NAME, ["192.0.2.53"]) == "203.0.113.7"
    assert [proto for proto, _, _ in resolver.asked] == ["udp", "tcp"]
    assert steps == [
        ("mark", socket.SOCK_DGRAM),
        ("mark", socket.SOCK_STREAM),
        ("connect", ("192.0.2.53", 53)),
    ]


def test_a_resolver_that_closes_the_tcp_retry_is_skipped(
    marks: list[socket.SocketKind],
) -> None:
    # dnspython raises the builtin EOFError, not an OSError, when the far end
    # closes the TCP connection. Plain DNS has no protection, so anyone on
    # the path can send TC and then close: that must not crash DSM.
    resolver = _Resolver(udp=[_a(tc=True), _a("203.0.113.7")], tcp=[EOFError("EOF")])
    with (
        resolver.patched(),
        patch.object(socket.socket, "connect", lambda _s, _addr: None),
    ):
        found = server_lookup.lookup_a(NAME, ["192.0.2.53", "192.0.2.54"])
    assert found == "203.0.113.7"
    assert [(proto, server) for proto, server, _ in resolver.asked] == [
        ("udp", "192.0.2.53"),
        ("tcp", "192.0.2.53"),
        ("udp", "192.0.2.54"),
    ]


def test_the_tcp_retry_gets_only_the_time_left(marks: list[socket.SocketKind]) -> None:
    clock = [100.0]

    def slow(query: dns.message.Message) -> dns.message.Message:
        clock[0] += 2.5  # the cut-short UDP answer took 2.5 s of the 3 s
        return _a(tc=True)(query)

    resolver = _Resolver(udp=[slow], tcp=[_a("203.0.113.7")])
    with (
        resolver.patched(),
        patch.object(server_lookup.time, "monotonic", lambda: clock[0]),
        patch.object(socket.socket, "connect", lambda _s, _addr: None),
    ):
        assert server_lookup.lookup_a(NAME, ["192.0.2.53"]) == "203.0.113.7"
    assert resolver.timeouts == pytest.approx([3.0, 0.5])


def test_a_resolver_that_does_not_answer_is_skipped(
    marks: list[socket.SocketKind],
) -> None:
    resolver = _Resolver(udp=[dns.exception.Timeout(), _a("203.0.113.7")])
    with resolver.patched():
        assert (
            server_lookup.lookup_a(NAME, ["192.0.2.53", "192.0.2.54"]) == "203.0.113.7"
        )
    assert [server for _, server, _ in resolver.asked] == ["192.0.2.53", "192.0.2.54"]


def test_a_cname_is_followed_to_its_a_record(marks: list[socket.SocketKind]) -> None:
    def build(query: dns.message.Message) -> dns.message.Message:
        reply = dns.message.make_response(query)
        name = query.question[0].name
        reply.answer.append(
            dns.rrset.from_text(name, 60, "IN", "CNAME", "home.example.net.")
        )
        reply.answer.append(
            dns.rrset.from_text("home.example.net.", 60, "IN", "A", "203.0.113.7")
        )
        return reply

    with _Resolver(udp=[build]).patched():
        assert server_lookup.lookup_a(NAME, ["192.0.2.53"]) == "203.0.113.7"


def test_no_address_anywhere_is_an_oserror_that_names_no_server(
    marks: list[socket.SocketKind],
) -> None:
    resolver = _Resolver(udp=[_rcode(dns.rcode.NXDOMAIN), _rcode(dns.rcode.SERVFAIL)])
    with resolver.patched(), pytest.raises(OSError) as err:
        server_lookup.lookup_a(NAME, ["192.0.2.53", "192.0.2.54"])
    assert str(err.value) == "no address (asked 2 nameservers, last: SERVFAIL)"


def test_a_mark_the_host_refuses_is_an_oserror() -> None:
    def refuse(_sock: object) -> None:
        raise PermissionError(1, "Operation not permitted")

    resolver = _Resolver(udp=[])
    with (
        patch.object(server_lookup, "apply_so_mark", refuse),
        resolver.patched(),
        pytest.raises(OSError, match="last: PermissionError"),
    ):
        server_lookup.lookup_a(NAME, ["192.0.2.53"])
    assert resolver.asked == []


def test_nothing_is_asked_once_the_time_is_up(marks: list[socket.SocketKind]) -> None:
    resolver = _Resolver(udp=[])
    with (
        patch.object(server_lookup, "LOOKUP_TIMEOUT_S", 0.0),
        resolver.patched(),
        pytest.raises(OSError, match="out of time"),
    ):
        server_lookup.lookup_a(NAME, ["192.0.2.53"])
    assert resolver.asked == []
