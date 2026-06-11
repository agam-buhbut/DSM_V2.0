"""Shared on-the-wire address constants.

These literals are part of the client/server protocol contract:
  * the server binds its TUN to ``SERVER_TUN_IP`` and the local DNS proxy
    listens on ``SERVER_TUN_IP:53``;
  * the client's resolv.conf points at the same address.

Changing this value affects deployment guides and any pre-existing
nftables/captive-portal configuration that references the address, so
single-source-of-truth them here.
"""

from __future__ import annotations

# The server's address inside the tunnel. Also the DNS-proxy bind IP.
# Clients write this into /etc/resolv.conf as `nameserver SERVER_TUN_IP`.
SERVER_TUN_IP: str = "10.8.0.1"

# Prefix length for the in-tunnel /24 network.
# Consumers: dns_proxy.LocalDNSProxy (source-filter net) and
# tunnel.TunDevice.configure (netmask default).
TUN_PREFIX_LEN: int = 24
