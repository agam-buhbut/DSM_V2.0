"""The client keeps local-network routes out of the tunnel.

Without a `table main suppress_prefixlength 0` rule ahead of the
not-fwmark rule, a host with strict rp_filter drops ARP requests from its
own network (their source "should" come through the tunnel), so neighbours
lose this host whenever their ARP entry expires. Found in a live test.
"""

from __future__ import annotations

from unittest.mock import patch

from dsm.net import cleanup, tunnel
from dsm.net.tunnel import LAN_RULE_ARGS, TunDevice


def _configure_cmds(*, server_mode: bool) -> list[list[str]]:
    seen: list[list[str]] = []

    def fake_run_commands(cmds: list[list[str]], *, strict: bool = True) -> None:
        seen.extend(cmds)

    with (
        patch.object(tunnel, "_run_commands", side_effect=fake_run_commands),
        patch.object(TunDevice, "_capture_ipv6_state", return_value={}),
        patch.object(TunDevice, "_save_ipv6_state"),
        patch.object(tunnel.subprocess, "run"),
    ):
        TunDevice(name="mtun0").configure(local_ip="10.8.0.2", server_mode=server_mode)
    return seen


def test_client_adds_the_lan_rule_before_the_tunnel_rule() -> None:
    cmds = _configure_cmds(server_mode=False)
    assert ["ip", "rule", "add", *LAN_RULE_ARGS] in cmds
    # Lower priority number = checked first.
    assert LAN_RULE_ARGS[-2:] == ["priority", "9"]
    tunnel_rule = next(c for c in cmds if c[:4] == ["ip", "rule", "add", "not"])
    assert tunnel_rule[tunnel_rule.index("priority") + 1] == "10"


def test_lan_rule_only_hides_the_default_route() -> None:
    assert LAN_RULE_ARGS[:4] == ["table", "main", "suppress_prefixlength", "0"]


def test_server_adds_no_lan_rule() -> None:
    cmds = _configure_cmds(server_mode=True)
    assert all(c[:3] != ["ip", "rule", "add"] for c in cmds)


def test_deconfigure_and_crash_cleanup_remove_the_lan_rule() -> None:
    seen: list[list[str]] = []

    def fake_run_commands(cmds: list[list[str]], *, strict: bool = True) -> None:
        seen.extend(cmds)

    with patch.object(tunnel, "_run_commands", side_effect=fake_run_commands):
        TunDevice(name="mtun0").deconfigure()
    assert ["ip", "rule", "del", *LAN_RULE_ARGS] in seen

    best: list[list[str]] = []
    with (
        patch.object(cleanup, "_best_effort", side_effect=best.append),
        patch.object(cleanup, "_restore_resolv_conf"),
        patch.object(cleanup, "_restore_src_valid_mark"),
    ):
        cleanup.cleanup_host_state()
    assert ["ip", "rule", "del", *LAN_RULE_ARGS] in best
