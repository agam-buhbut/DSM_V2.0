"""Phase 1.3: server-mode configure() must NOT add the client full-tunnel
policy route (table 100 default) or the not-fwmark ip rule, which would
loop forwarded traffic back into the TUN.
"""

from __future__ import annotations

import unittest
from unittest.mock import patch

from dsm.net import tunnel
from dsm.net.tunnel import TunDevice


class ServerModeConfigure(unittest.TestCase):
    def _captured_cmds(self, **configure_kwargs: object) -> list[list[str]]:
        seen: list[list[str]] = []

        def fake_run_commands(cmds: list[list[str]], *, strict: bool = True) -> None:
            seen.extend(cmds)

        with (
            patch.object(tunnel, "_run_commands", side_effect=fake_run_commands),
            patch.object(TunDevice, "_capture_ipv6_state", return_value={}),
            patch.object(TunDevice, "_save_ipv6_state"),
            patch.object(tunnel.subprocess, "run"),  # the ip-rule del probe
        ):
            tun = TunDevice(name="mtun0")
            tun.configure(local_ip="10.8.0.1", **configure_kwargs)  # type: ignore[arg-type]
        return seen

    def test_server_mode_omits_table100_default_route(self) -> None:
        cmds = self._captured_cmds(server_mode=True)
        for cmd in cmds:
            self.assertNotIn("100", cmd, f"server mode must not touch table 100: {cmd}")
        # And no `ip rule add ... not fwmark` should have been emitted.
        self.assertFalse(
            any(cmd[:3] == ["ip", "rule", "add"] for cmd in cmds),
            "server mode must not add the not-fwmark ip rule",
        )

    def test_client_mode_still_adds_table100_route(self) -> None:
        cmds = self._captured_cmds(server_mode=False)
        self.assertTrue(
            any(
                cmd[:4] == ["ip", "route", "replace", "default"] and "100" in cmd
                for cmd in cmds
            ),
            "client mode must keep the table-100 default route",
        )
        self.assertTrue(
            any(cmd[:3] == ["ip", "rule", "add"] for cmd in cmds),
            "client mode must add the not-fwmark ip rule",
        )


if __name__ == "__main__":
    unittest.main()
