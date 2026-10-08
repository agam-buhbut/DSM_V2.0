"""The pre-handshake kill switch replaces every client table in one commit.

At start this removes a kill switch a crashed run left, and after a session
it swaps the full kill switch back, each time in the same ``nft -f``
transaction as the new table, so the host is never without one. Only
``subprocess.run`` (the nft call) is faked.
"""

from __future__ import annotations

import subprocess
from unittest.mock import patch

from dsm.net import nftables
from dsm.net.nftables import NFTablesManager, PreHandshakeKillSwitch

V4_IP = "203.0.113.7"
PORT = 51820

_REPLACE = (
    "add table inet dsm_killswitch_pre\n"
    "delete table inet dsm_killswitch_pre\n"
    "add table inet dsm_killswitch\n"
    "delete table inet dsm_killswitch\n"
    "add table inet dsm_dns_leak\n"
    "delete table inet dsm_dns_leak\n"
)


class _Nft:
    """Stands in for ``subprocess.run``: records each argv and its input."""

    def __init__(self) -> None:
        self.calls: list[tuple[list[str], str]] = []

    def __call__(
        self, args: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        raw = kwargs.get("input")
        text = raw.decode() if isinstance(raw, bytes) else ""
        self.calls.append((list(args), text))
        return subprocess.CompletedProcess(args, 0, stdout=b"", stderr=b"")


def test_apply_replaces_every_client_table_in_the_same_commit() -> None:
    nft = _Nft()
    pre = PreHandshakeKillSwitch(V4_IP, PORT)
    with patch.object(nftables.subprocess, "run", nft):
        pre.apply()

    assert len(nft.calls) == 1
    argv, rules = nft.calls[0]
    assert argv == ["nft", "-f", "-"]
    assert rules == _REPLACE + pre._render()


def test_the_server_tables_are_left_alone() -> None:
    rules = PreHandshakeKillSwitch(V4_IP, PORT)._ruleset()
    assert "dsm_server_ratelimit" not in rules
    assert "dsm_server_nat" not in rules


def test_a_swap_back_after_a_session_is_one_commit() -> None:
    nft = _Nft()
    pre = PreHandshakeKillSwitch(V4_IP, PORT)
    with patch.object(nftables.subprocess, "run", nft):
        pre.apply()
        NFTablesManager(V4_IP, PORT).apply()
        pre.apply()  # the session ended: back to the pre-handshake table

    # Three loads, each one `nft -f -`; never a separate delete in between.
    assert [argv for argv, _ in nft.calls] == [["nft", "-f", "-"]] * 3
    swap = nft.calls[2][1]
    new_table = swap.index("table inet dsm_killswitch_pre {")
    assert swap.index("delete table inet dsm_killswitch\n") < new_table
    assert swap.index("delete table inet dsm_dns_leak\n") < new_table


def test_remove_after_a_swap_back_deletes_the_pre_table() -> None:
    nft = _Nft()
    pre = PreHandshakeKillSwitch(V4_IP, PORT)
    with patch.object(nftables.subprocess, "run", nft):
        pre.apply()
        pre.apply()
        pre.remove()

    assert nft.calls[-1][0] == ["nft", "delete", "table", "inet", "dsm_killswitch_pre"]
