"""The server keeps a client's plain DNS off its uplink (finding #13). The
NAT table sends plain DNS (UDP and TCP port 53) to the server's own DNS proxy
and drops any other port-53 traffic before it can be forwarded. ``nft`` is
faked, and the ruleset text is checked.
"""

from __future__ import annotations

import re

from tests.test_forwarding_isolation import A, _apply, _chains


def test_plain_dns_to_any_resolver_goes_to_the_servers_proxy() -> None:
    (ruleset,) = _apply(dict([A])).rulesets
    # TCP is redirected too: nothing listens on TCP there, so a client gets
    # a fast reset, and port-53 traffic aimed at a server-local address other
    # than 10.8.0.1 is caught (a forward rule would never see it).
    assert _chains(ruleset).get("dns_redirect") == (
        "    chain dns_redirect {\n"
        "        type nat hook prerouting priority -100; policy accept;\n"
        '        iifname "mtun0" ip daddr != 10.8.0.1 udp dport 53 '
        "counter dnat ip to 10.8.0.1:53\n"
        '        iifname "mtun0" ip daddr != 10.8.0.1 tcp dport 53 '
        "counter dnat ip to 10.8.0.1:53\n"
        "    }\n"
    )


def test_port_53_traffic_from_the_tun_is_never_forwarded() -> None:
    (ruleset,) = _apply(dict([A])).rulesets
    forward = _chains(ruleset)["forward"]
    rule = 'iifname "mtun0" meta l4proto { tcp, udp } th dport 53 counter drop'
    assert rule in forward
    assert forward.index(rule) < forward.index("ct mark set")
    # Owner decision: DoT and DoQ (853) are encrypted, like DoH on 443, and
    # stay open through the tunnel (SECURITY.md, "DNS blocklist bypass").
    # A word match, so a flow tag such as 0x1853abcd cannot trip it.
    assert re.search(r"\b853\b", ruleset) is None
