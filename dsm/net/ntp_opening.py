"""The NTP opening in the client's start-up kill switch (re-decision 2).

While a date problem holds a start (a CRL past its next update with a
clock that is not synchronized, a cert outside its dates), the clock may be
what is wrong. The kill switch drops NTP outside the tunnel, so the clock
could never heal. So the start-up table lets systemd-timesyncd's own user
reach the NTP servers its config or DHCP names by IPv4 address, and only
while such a date problem holds the start. A pool name cannot be looked up
through the block, so it gets no opening; chrony and ntpd get none either
(deploy/GUIDE.md §0f).
"""

from __future__ import annotations

import ipaddress
import pwd
import subprocess
from dataclasses import dataclass

_TIMESYNC_USER = "systemd-timesync"
_MAX_SERVERS = 8


@dataclass(frozen=True)
class NtpOpening:
    """The time daemon's uid and the IPv4 NTP servers it may reach."""

    uid: int
    servers: tuple[str, ...]


def time_daemon_opening() -> NtpOpening | None:
    """systemd-timesyncd's uid and its NTP servers given as IPv4 addresses.

    None when there is no such user, ``timedatectl`` fails, or every server
    is a name. Best effort; never raises.
    """
    try:
        uid = pwd.getpwnam(_TIMESYNC_USER).pw_uid
    except KeyError:
        return None
    try:
        out = subprocess.run(
            [
                "timedatectl",
                "show-timesync",
                "--property=SystemNTPServers",
                "--property=LinkNTPServers",
                "--property=FallbackNTPServers",
                "--value",
            ],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    servers: list[str] = []
    for word in out.stdout.split():
        try:
            address = ipaddress.ip_address(word)
        except ValueError:
            continue  # a name: it cannot be looked up through the block
        if address.version == 4 and word not in servers:
            servers.append(word)
    if not servers:
        return None
    return NtpOpening(uid=uid, servers=tuple(servers[:_MAX_SERVERS]))
