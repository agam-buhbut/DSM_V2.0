"""A TUN MTU below 1280 must not stop DSM at TUN set-up.

Linux removes a device's IPv6 (and its ``net.ipv6.conf.<dev>`` knobs) while
its MTU is below 1280, the IPv6 minimum. ``configure()`` used to turn IPv6 on
for the TUN at every MTU, so with ``mtu`` 576-1279 that sysctl failed and
the client exited right after the handshake with the start-up kill switch
still up. The fake ``subprocess.run`` below follows that kernel rule.
"""

from __future__ import annotations

import subprocess
import unittest
from typing import Any
from unittest.mock import patch

from dsm.net import tunnel
from dsm.net.tunnel import TunDevice

_TUN = "mtun0"
_TUN_IPV6_ON = ["sysctl", "-w", f"net.ipv6.conf.{_TUN}.disable_ipv6=0"]
_ALL_IPV6_OFF = ["sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"]


class _Kernel:
    """``subprocess.run`` stand-in that keeps the TUN's MTU and, like Linux,
    has no ``net.ipv6.conf.<tun>`` knob while that MTU is below 1280."""

    def __init__(self) -> None:
        self.mtu = 1500  # a new TUN starts at 1500
        self.calls: list[list[str]] = []

    def run(self, cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        self.calls.append(cmd)
        if cmd[:3] == ["ip", "link", "set"] and cmd[4:5] == ["mtu"]:
            self.mtu = int(cmd[5])
        no_knob = cmd[:2] == ["sysctl", "-w"] and cmd[2].startswith(
            f"net.ipv6.conf.{_TUN}."
        )
        if no_knob and self.mtu < 1280 and kwargs.get("check"):
            raise subprocess.CalledProcessError(
                255, cmd, stderr=b"sysctl: cannot stat ...: No such file or directory"
            )
        return subprocess.CompletedProcess(cmd, 0, b"", b"")


class TestConfigureBelowIpv6MinimumMtu(unittest.TestCase):
    def test_configure_works_at_every_allowed_mtu(self) -> None:
        for mtu in (576, 1000, 1279, 1280, 1360, 1500):
            for server_mode in (False, True):
                with self.subTest(mtu=mtu, server_mode=server_mode):
                    kernel = _Kernel()
                    with (
                        patch.object(tunnel.subprocess, "run", kernel.run),
                        patch.object(TunDevice, "_capture_ipv6_state", return_value={}),
                        patch.object(TunDevice, "_save_ipv6_state"),
                    ):
                        TunDevice(_TUN).configure(
                            local_ip="10.8.0.2", mtu=mtu, server_mode=server_mode
                        )
                    self.assertEqual(kernel.mtu, mtu)
                    # IPv6 stays off on every other interface at every MTU.
                    self.assertIn(_ALL_IPV6_OFF, kernel.calls)
                    # The TUN gets IPv6 only where the kernel keeps it.
                    self.assertEqual(_TUN_IPV6_ON in kernel.calls, mtu >= 1280)


if __name__ == "__main__":
    unittest.main()
