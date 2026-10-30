"""#12: the server's rate-limit meters must forget idle sources.

Each meter slot has a 10 s timeout, so a full meter empties again once a
flood stops (before, it stayed full and new clients were dropped until DSM
restarted). Loopback skips the meters, because a local program can send
from any 127/8 address and fill them. The kernel tests load the real
ruleset in a throwaway user+net namespace; they are skipped where nft or
unprivileged namespaces are missing.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import unittest

from dsm.net.nftables import ServerRateLimitManager

PORT = 51820
_TABLE = "dsm_server_ratelimit"
_NFT = shutil.which(
    "nft", path=os.pathsep.join([os.environ.get("PATH", ""), "/usr/sbin", "/sbin"])
)
_UNSHARE = shutil.which("unshare")
_KEY_RE = r"\{ ip6? saddr timeout 10s limit rate 5/second burst 10 packets \} accept$"
# What a killed f0261f2 server leaves behind: a meter with no timeout.
_STALE = f"""table inet {_TABLE} {{
    chain input {{
        type filter hook input priority -100; policy accept;
        udp dport {PORT} ct state new meter dsm_ratelimit_v4 size 65535 \\
            {{ ip saddr limit rate 5/second burst 10 packets }} accept
    }}
}}
"""
# $1 is nft; each later argument is one ruleset, loaded in turn.
_LOAD_AND_LIST = (
    'nft=$1; shift; for r in "$@"; do printf "%s\\n" "$r" | "$nft" -f - || exit 1;'
    f' done; "$nft" -t list table inet {_TABLE}'
)


def _rules() -> list[str]:
    """The rendered ruleset, one rule per line, without comments."""
    text = ServerRateLimitManager(PORT)._render().replace("\\\n", " ")
    lines = (" ".join(line.split()) for line in text.splitlines())
    return [line for line in lines if line and not line.startswith("#")]


def _in_namespace(script: str, *args: str) -> subprocess.CompletedProcess[str]:
    assert _NFT and _UNSHARE  # the kernel tests skip without them
    return subprocess.run(
        [_UNSHARE, "-rn", "sh", "-c", script, "sh", _NFT, *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )


class MeterTemplateTest(unittest.TestCase):
    def test_every_meter_slot_has_a_timeout(self) -> None:
        meters = [rule for rule in _rules() if " meter " in rule]
        self.assertEqual(len(meters), 4)
        self.assertEqual([rule for rule in meters if not re.search(_KEY_RE, rule)], [])

    def test_loopback_skips_the_meters(self) -> None:
        rules = _rules()
        first_meter = next(i for i, rule in enumerate(rules) if " meter " in rule)
        self.assertIn('iif "lo" accept', rules[:first_meter])

    def test_load_replaces_a_table_left_behind(self) -> None:
        self.assertEqual(
            _rules()[:2], [f"add table inet {_TABLE}", f"delete table inet {_TABLE}"]
        )


@unittest.skipUnless(_NFT and _UNSHARE, "nft or unshare absent")
class MeterKernelTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        probe = _in_namespace('"$1" list ruleset')
        if probe.returncode != 0:
            raise unittest.SkipTest(f"no nft in a user+net namespace: {probe.stderr}")

    def _assert_fixed_table(self, proc: subprocess.CompletedProcess[str]) -> None:
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.count("flags dynamic,timeout"), 4)
        self.assertEqual(proc.stdout.count("@dsm_ratelimit"), 4)
        self.assertEqual(
            proc.stdout.count("saddr timeout 10s limit rate 5/second burst 10 packets"),
            4,
        )
        loopback = proc.stdout.find('iif "lo" accept')
        self.assertGreaterEqual(loopback, 0)
        self.assertLess(loopback, proc.stdout.index("@dsm_ratelimit_v4"))

    def test_kernel_loads_meters_that_expire(self) -> None:
        rendered = ServerRateLimitManager(PORT)._render()
        self._assert_fixed_table(_in_namespace(_LOAD_AND_LIST, rendered))

    def test_kernel_replaces_a_table_a_killed_run_left(self) -> None:
        rendered = ServerRateLimitManager(PORT)._render()
        self._assert_fixed_table(_in_namespace(_LOAD_AND_LIST, _STALE, rendered))


if __name__ == "__main__":
    unittest.main()
