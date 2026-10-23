"""The server's NAT table keeps clients apart (multi-client spec §3.2,
§3.3): a forward chain drops anything the kernel would forward from the TUN
back into it, and each client's flows carry its CN's tag. ``nft`` is faked;
the ruleset text is checked.
"""

from __future__ import annotations

import hashlib
import subprocess
from typing import Any
from unittest.mock import patch

import pytest

from dsm.net import forwarding, nftables
from dsm.net.forwarding import MasqueradeManager

A = ("10.8.0.2", "dsm-a-client")
B = ("10.8.0.3", "dsm-b-client")


class _Nft:
    """Records each nft call and the ruleset it loads."""

    def __init__(self) -> None:
        self.argv: list[list[str]] = []
        self.rulesets: list[str] = []

    def __call__(
        self, argv: list[str], **kwargs: Any
    ) -> subprocess.CompletedProcess[bytes]:
        self.argv.append(list(argv))
        if "input" in kwargs:
            self.rulesets.append(kwargs["input"].decode())
        return subprocess.CompletedProcess(argv, 0, b"", b"")


def _apply(clients: dict[str, str] | None = None) -> _Nft:
    nft = _Nft()
    with patch.object(nftables.subprocess, "run", nft):
        MasqueradeManager("mtun0", clients=clients).apply()
    return nft


def _tag(cn: str) -> str:
    raw = int.from_bytes(hashlib.sha256(cn.encode()).digest()[:4], "big") | 1
    return f"{raw:#010x}"


def test_the_forward_chain_drops_tun_to_tun_traffic_with_a_counter() -> None:
    nft = _apply()
    assert nft.argv == [["nft", "-f", "-"]]
    (ruleset,) = nft.rulesets
    assert "type filter hook forward priority 0; policy accept;" in ruleset
    assert 'iifname "mtun0" oifname "mtun0" counter drop' in ruleset
    assert 'iifname "mtun0" oifname != "mtun0" masquerade' in ruleset
    assert "ct mark" not in ruleset  # no clients, no tags


def test_each_client_gets_a_tag_rule_and_a_drop_rule_in_the_same_load() -> None:
    nft = _apply(dict([A, B]))
    assert nft.argv == [["nft", "-f", "-"]]
    (ruleset,) = nft.rulesets
    for address, cn in (A, B):
        assert (
            f'iifname "mtun0" ct state new ip saddr {address} ct mark set {_tag(cn)}'
            in ruleset
        )
        assert (
            f'oifname "mtun0" ip daddr {address} ct mark != {_tag(cn)} counter drop'
            in ruleset
        )
    assert ruleset.count("ct mark set") == 2


def test_a_tag_is_the_cns_hash_with_the_low_bit_set() -> None:
    tags = {forwarding._flow_tag(cn) for cn in ("", "a", "b", "dsm-a-client")}
    assert len(tags) == 4
    assert all(tag & 1 for tag in tags)  # never 0, the mark of untagged flows
    assert f"{forwarding._flow_tag('dsm-a-client'):#010x}" == _tag("dsm-a-client")


def test_a_table_left_by_a_crashed_run_is_replaced_not_merged() -> None:
    (ruleset,) = _apply(dict([A])).rulesets
    assert ruleset.splitlines()[:2] == [
        "add table inet dsm_server_nat",
        "delete table inet dsm_server_nat",
    ]


@pytest.mark.parametrize("address", ["10.8.0.2; flush ruleset", "fd00::2", "10.8.0"])
def test_a_client_address_that_is_not_ipv4_is_refused(address: str) -> None:
    with pytest.raises(ValueError):
        MasqueradeManager("mtun0", clients={address: "dsm-a-client"})


def test_a_tunnel_source_from_outside_the_tun_is_dropped() -> None:
    (ruleset,) = _apply().rulesets
    assert "type filter hook prerouting priority -150; policy accept;" in ruleset
    assert (
        'iifname != "mtun0" iifname != "lo" ip saddr 10.8.0.0/24 counter drop'
        in ruleset
    )


def test_only_tracked_traffic_is_forwarded_into_the_tun() -> None:
    (ruleset,) = _apply(dict([A])).rulesets
    rule = 'oifname "mtun0" ct state invalid,untracked counter drop'
    assert rule in ruleset
    assert ruleset.index(rule) < ruleset.index("ct mark set")


def test_applied_says_whether_the_table_is_loaded() -> None:
    # The server stops when the load failed (roadmap item 1.8); apply()
    # itself never raises (tests/test_forwarding.py pins that).
    nat = MasqueradeManager("mtun0", clients=dict([A]))
    assert not nat.applied
    with patch.object(nftables.subprocess, "run", _Nft()):
        nat.apply()
        assert nat.applied
        nat.remove()
    assert not nat.applied
    with patch.object(nftables.subprocess, "run", side_effect=FileNotFoundError("nft")):
        nat.apply()  # logs a WARNING
    assert not nat.applied
