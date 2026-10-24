"""The client's start-up kill switch (R1, fix 1, re-decisions 1, 2, 5).

Only DSM's own marked packets reach the server, and only replies to them
come back. While DSM looks a name up, its own query (uid 0, marked) may
reach the resolvers it chose; while a date holds the start, the time
daemon may reach its NTP servers. The full kill switch also wants the mark
on the server lines. Template text only, no nft; the NTP finder runs with
pwd and timedatectl faked.
"""

from __future__ import annotations

import re
from unittest.mock import MagicMock, patch

import pytest

from dsm.net import ntp_opening
from dsm.net.nftables import NFTablesManager, PreHandshakeKillSwitch
from dsm.net.ntp_opening import NtpOpening, time_daemon_opening
from tests.test_nft_icmp_gating import _chains
from tests.test_rp_filter_strict import _chain_lines, _table_body

PORT = 51820
SERVER = "203.0.113.5"
NTP = NtpOpening(uid=991, servers=("192.0.2.123", "192.0.2.124"))

_HEAD_OUT = ["type filter hook output priority 0; policy drop;", 'oif "lo" accept']
_TAIL_OUT = [
    "udp dport 67 udp sport 68 accept",
    'oif != "lo" meta nfproto ipv6 counter drop',
    "counter drop",
]
_HEAD_IN = ["type filter hook input priority 0; policy drop;", 'iif "lo" accept']
_TAIL_IN = [
    "udp sport 67 udp dport 68 accept",
    "ct state established,related meta mark 0x1 accept",
    'iif != "lo" meta nfproto ipv6 counter drop',
    "icmp type destination-unreachable icmp code frag-needed accept",
    "counter drop",
]
_SERVER_OUT = (
    f"meta mark 0x1 meta skuid 0 ip daddr {SERVER} meta l4proto {{ tcp, udp }} "
    f"th dport {PORT} ct mark set meta mark accept"
)
_SERVER_IN = (
    f"ip saddr {SERVER} meta l4proto {{ tcp, udp }} th sport {PORT} "
    "ct state established ct mark 0x1 accept"
)
_LOOKUP_OUT = (
    "meta mark 0x1 meta skuid 0 ip daddr 192.0.2.53 meta l4proto { tcp, udp } "
    "th dport 53 ct mark set meta mark accept"
)
_LOOKUP_IN = (
    "ip saddr 192.0.2.53 meta l4proto { tcp, udp } th sport 53 "
    "ct state established ct mark 0x1 accept"
)
_NTP_OUT = "meta skuid 991 ip daddr { 192.0.2.123, 192.0.2.124 } udp dport 123 accept"
_NTP_IN = (
    "ip saddr { 192.0.2.123, 192.0.2.124 } udp sport 123 ct state established accept"
)


def test_with_an_address_only_marked_sockets_reach_the_server() -> None:
    chains = _chains(PreHandshakeKillSwitch(SERVER, PORT)._render())
    assert chains["output"] == [*_HEAD_OUT, _SERVER_OUT, *_TAIL_OUT]
    # A packet that only claims the server's address and port, to any local
    # port, has no conntrack entry with DSM's mark: dropped.
    assert chains["input"] == [*_HEAD_IN, _SERVER_IN, *_TAIL_IN]


def test_before_the_lookup_only_loopback_and_dhcp_pass() -> None:
    chains = _chains(PreHandshakeKillSwitch(None, PORT)._render())
    assert chains["output"] == [*_HEAD_OUT, *_TAIL_OUT]
    assert chains["input"] == [*_HEAD_IN, *_TAIL_IN]


def test_during_the_lookup_only_dsms_query_to_its_resolvers_passes() -> None:
    chains = _chains(
        PreHandshakeKillSwitch([], PORT, resolvers=["192.0.2.53"])._render()
    )
    assert chains["output"] == [*_HEAD_OUT, _LOOKUP_OUT, *_TAIL_OUT]
    assert chains["input"] == [*_HEAD_IN, _LOOKUP_IN, *_TAIL_IN]


def test_while_a_date_holds_the_start_the_time_daemon_may_sync() -> None:
    chains = _chains(PreHandshakeKillSwitch(SERVER, PORT, ntp=NTP)._render())
    assert chains["output"] == [*_HEAD_OUT, _SERVER_OUT, _NTP_OUT, *_TAIL_OUT]
    assert chains["input"] == [*_HEAD_IN, _SERVER_IN, _NTP_IN, *_TAIL_IN]


def test_two_server_addresses_share_one_rule() -> None:
    rules = PreHandshakeKillSwitch([SERVER, "198.51.100.7"], PORT)._render()
    assert f"ip daddr {{ {SERVER}, 198.51.100.7 }} meta l4proto" in rules
    assert f"ip saddr {{ {SERVER}, 198.51.100.7 }} meta l4proto" in rules


@pytest.mark.parametrize(
    "table",
    [
        PreHandshakeKillSwitch(None, PORT),
        PreHandshakeKillSwitch(SERVER, PORT),
        PreHandshakeKillSwitch([SERVER, "198.51.100.7"], PORT, ntp=NTP),
        PreHandshakeKillSwitch(None, PORT, resolvers=["192.0.2.53", "192.0.2.54"]),
        PreHandshakeKillSwitch("2001:db8::5", PORT),
    ],
)
def test_no_placeholder_or_tag_is_left(table: PreHandshakeKillSwitch) -> None:
    assert re.search(r"\{[A-Z_]+\}", table._render()) is None


def test_the_openings_are_ipv4_only() -> None:
    with pytest.raises(ValueError):
        PreHandshakeKillSwitch(None, PORT, resolvers=["2001:db8::53"])
    with pytest.raises(ValueError):
        PreHandshakeKillSwitch(SERVER, PORT, ntp=NtpOpening(991, ("2001:db8::7b",)))
    with pytest.raises(ValueError):
        PreHandshakeKillSwitch([SERVER, "2001:db8::5"], PORT)


def test_every_form_replaces_every_client_table() -> None:
    rules = PreHandshakeKillSwitch(None, PORT, resolvers=["192.0.2.53"])._ruleset()
    for name in PreHandshakeKillSwitch.CLIENT_TABLES:
        assert f"add table inet {name}\ndelete table inet {name}\n" in rules


def test_the_full_kill_switch_takes_only_marked_server_traffic() -> None:
    body = _table_body(
        NFTablesManager(SERVER, PORT, "mtun0")._render(), "dsm_killswitch"
    )
    out = _chain_lines(body, "output")
    inp = _chain_lines(body, "input")
    for proto in ("udp", "tcp"):
        assert (
            f"meta mark 0x1 meta skuid 0 ip daddr {SERVER} {proto} dport {PORT} accept"
            in out
        )
    # No accept line for packets that claim the server's address as source.
    assert not any(line.startswith(f"ip saddr {SERVER}") for line in out)
    assert f"ip saddr {SERVER} udp sport {PORT} meta mark 0x1 accept" in inp
    assert f"ip saddr {SERVER} tcp sport {PORT} meta mark 0x1 accept" in inp
    assert not any(line.startswith(f"ip daddr {SERVER}") for line in out)
    assert f"ip saddr {SERVER} udp sport {PORT} accept" not in inp


def _timesync(stdout: str) -> MagicMock:
    return MagicMock(stdout=stdout)


def test_the_time_daemon_gets_its_ipv4_servers() -> None:
    user = MagicMock(pw_uid=991)
    listing = (
        "192.0.2.123\n\n0.debian.pool.ntp.org 192.0.2.124 2001:db8::7b 192.0.2.123\n"
    )
    with (
        patch.object(ntp_opening.pwd, "getpwnam", return_value=user),
        patch.object(ntp_opening.subprocess, "run", return_value=_timesync(listing)),
    ):
        assert time_daemon_opening() == NtpOpening(991, ("192.0.2.123", "192.0.2.124"))


def test_pool_names_only_give_no_opening() -> None:
    with (
        patch.object(ntp_opening.pwd, "getpwnam", return_value=MagicMock(pw_uid=991)),
        patch.object(
            ntp_opening.subprocess,
            "run",
            return_value=_timesync("\n\n0.debian.pool.ntp.org\n"),
        ),
    ):
        assert time_daemon_opening() is None


def test_no_timesyncd_gives_no_opening() -> None:
    with patch.object(ntp_opening.pwd, "getpwnam", side_effect=KeyError("no user")):
        assert time_daemon_opening() is None
    with (
        patch.object(ntp_opening.pwd, "getpwnam", return_value=MagicMock(pw_uid=991)),
        patch.object(ntp_opening.subprocess, "run", side_effect=FileNotFoundError),
    ):
        assert time_daemon_opening() is None
