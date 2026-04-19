"""Shared fwmark-application helper for VPN transport sockets.

Marks the socket with SO_MARK so nftables/ip-rule can exempt VPN
outer-frame traffic from the TUN routing table — otherwise the
server→resolver or peer packets would try to egress back through the
tunnel and deadlock.
"""

from __future__ import annotations

import socket

# Must match FWMARK in tunnel.py.
SO_MARK_VALUE = 0x1


def apply_so_mark(sock: socket.socket | None) -> None:
    """Set SO_MARK on ``sock`` if non-None. Silently no-op otherwise."""
    if sock is None:
        return
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, SO_MARK_VALUE)
