"""Kill-switch ICMP gating.

Verifies that every ICMP accept rule in the rendered kill-switch templates
is gated to the TUN interface so real-IP ICMP cannot escape the WAN.

Regression: unqualified
    meta l4proto icmp limit rate 2/second accept
lines allowed ping traffic to bypass the kill switch at 2 pps, leaking
the client's real IP to a passive WAN observer.

No mocking needed — these tests exercise the template text only.
"""

from __future__ import annotations

from dsm.net.nftables import NFTablesManager, PreHandshakeKillSwitch

_SERVER_IP = "203.0.113.5"
_PORT = 51820
_TUN = "mtun0"


# --------------------------------------------------------------------------- #
# No unqualified ICMP accept in the full kill switch
# --------------------------------------------------------------------------- #


def test_no_unqualified_icmp_accept_full_killswitch() -> None:
    """Every line with 'l4proto icmp' and 'accept' must also carry oif/iif TUN.

    The kill switch must not allow any ICMP to leave/enter the WAN interface.
    Loopback ICMP is already covered by 'oif "lo" accept' / 'iif "lo" accept'.
    """
    rules = NFTablesManager(_SERVER_IP, _PORT, _TUN)._render()
    for line in rules.splitlines():
        s = line.strip()
        if "l4proto icmp" in s and s.endswith("accept"):
            assert (
                f'oif "{_TUN}"' in s or f'iif "{_TUN}"' in s
            ), f"unqualified ICMP accept: {s}"


def test_no_unqualified_icmp_accept_full_killswitch_icmpv6() -> None:
    """Same gate check applied to icmpv6 rules (output chain only)."""
    rules = NFTablesManager(_SERVER_IP, _PORT, _TUN)._render()
    for line in rules.splitlines():
        s = line.strip()
        if "l4proto icmpv6" in s and s.endswith("accept"):
            assert (
                f'oif "{_TUN}"' in s or f'iif "{_TUN}"' in s
            ), f"unqualified ICMPv6 accept: {s}"


def test_pre_handshake_has_no_icmp_accept() -> None:
    """Pre-handshake ruleset must have zero 'l4proto icmp … accept' lines.

    There is no TUN device during the handshake window so there's nowhere to
    gate ICMP to — delete the lines entirely so off-link ICMP falls through
    to 'counter drop'. Loopback ICMP works via 'oif "lo" accept'.
    """
    rules = PreHandshakeKillSwitch(_SERVER_IP, _PORT)._render()
    assert not any(
        "l4proto icmp" in line and line.strip().endswith("accept")
        for line in rules.splitlines()
    ), "pre-handshake ruleset must not contain any 'l4proto icmp … accept' rule"


# --------------------------------------------------------------------------- #
# Sanity: kill switch still has its core structure after the edit
# --------------------------------------------------------------------------- #


def test_full_killswitch_still_has_tun_accept() -> None:
    """Editing ICMP rules must not accidentally remove the TUN accept rules."""
    rules = NFTablesManager(_SERVER_IP, _PORT, _TUN)._render()
    assert f'oif "{_TUN}" accept' in rules, "output TUN accept rule missing"
    assert f'iif "{_TUN}" accept' in rules, "input TUN accept rule missing"


def test_full_killswitch_still_has_server_ip_accept() -> None:
    """Server-IP accept rules must survive the edit."""
    rules = NFTablesManager(_SERVER_IP, _PORT, _TUN)._render()
    assert _SERVER_IP in rules, "server IP missing from rendered ruleset"


def test_full_killswitch_policy_drop_on_all_chains() -> None:
    """All three hooked chains must retain 'policy drop' (fail-closed posture)."""
    rules = NFTablesManager(_SERVER_IP, _PORT, _TUN)._render()
    # Isolate the kill-switch table body (exclude dsm_dns_leak whose policy is accept)
    start = rules.index("table inet dsm_killswitch")
    end = rules.find("table inet dsm_dns_leak", start)
    body = rules[start:] if end == -1 else rules[start:end]
    count = body.count("policy drop")
    assert count == 3, f"expected 3 'policy drop' in kill-switch chains, found {count}"


def test_pre_handshake_policy_drop_on_all_chains() -> None:
    """Pre-handshake: all three hooked chains must retain 'policy drop'."""
    rules = PreHandshakeKillSwitch(_SERVER_IP, _PORT)._render()
    assert rules.count("policy drop") == 3


def test_icmp_redirect_drop_still_present() -> None:
    """'icmp type redirect counter drop' must be untouched."""
    rules = NFTablesManager(_SERVER_IP, _PORT, _TUN)._render()
    assert (
        "icmp type redirect counter drop" in rules
    ), "ICMP redirect drop rule removed — must stay"


def test_full_killswitch_gated_icmp_lines_present() -> None:
    """After the fix, gated ICMP lines must appear in the rendered output."""
    rules = NFTablesManager(_SERVER_IP, _PORT, _TUN)._render()
    assert (
        f'oif "{_TUN}" meta l4proto icmp limit rate 2/second accept' in rules
    ), "gated IPv4 ICMP output rule not found"
    assert (
        f'oif "{_TUN}" meta l4proto icmpv6 limit rate 2/second accept' in rules
    ), "gated ICMPv6 output rule not found"
    assert (
        f'iif "{_TUN}" meta l4proto icmp limit rate 2/second accept' in rules
    ), "gated IPv4 ICMP input rule not found"
