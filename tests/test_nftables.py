"""DSM-006 — fail-closed leak-control surface of dsm.net.nftables.

Covers template rendering, address-family selection, the fail-closed
default-drop posture of the kill-switch chains, input validation, and the
fatal/non-fatal ``nft -f`` contract. The only thing mocked is the I/O
boundary: ``dsm.net.nftables.subprocess.run`` (the single place the module
shells out to ``nft``). The real templates under ``nftables/`` are loaded
unmodified.
"""

from __future__ import annotations

import re
import subprocess
import unittest
from unittest.mock import patch

from dsm.net import nftables
from dsm.net.nftables import (
    NFTablesManager,
    PreHandshakeKillSwitch,
    ServerRateLimitManager,
    _apply_ruleset,
)

V4_IP = "203.0.113.7"
V6_IP = "2001:db8::1"
PORT = 51820

# The four substitution tokens. nftables set/meter syntax uses bare ``{``/``}``
# legitimately (e.g. ``chain output {`` and ``{ ip saddr limit rate ... }``),
# so "no placeholder left" must match the named tokens, not every brace.
_PLACEHOLDER_RE = re.compile(r"\{SERVER_IP\}|\{SERVER_PORT\}|\{TUN_NAME\}|\{IP_PROTO\}")


class _FakeRun:
    """Stand-in for ``subprocess.run`` that records calls and can fail.

    ``side_effects`` is consumed one entry per call: an exception instance
    is raised, anything else is returned. When exhausted, returns a benign
    success object (rc=0). Each call's ``input=`` kwarg is captured.
    """

    def __init__(self, side_effects: list[object] | None = None) -> None:
        self._side_effects = list(side_effects or [])
        self.calls: list[dict[str, object]] = []
        self.inputs: list[str] = []

    def __call__(self, *args: object, **kwargs: object) -> object:
        self.calls.append({"args": args, "kwargs": kwargs})
        raw = kwargs.get("input")
        if isinstance(raw, (bytes, bytearray)):
            self.inputs.append(bytes(raw).decode())
        elif isinstance(raw, str):
            self.inputs.append(raw)
        else:
            self.inputs.append("")
        if self._side_effects:
            effect = self._side_effects.pop(0)
            if isinstance(effect, BaseException):
                raise effect
            return effect
        return subprocess.CompletedProcess(
            args=args, returncode=0, stdout=b"", stderr=b""
        )


def _called_process_error(stderr: bytes) -> subprocess.CalledProcessError:
    return subprocess.CalledProcessError(returncode=1, cmd=["nft"], stderr=stderr)


# --------------------------------------------------------------------------- #
# Rendering / substitution
# --------------------------------------------------------------------------- #
class RenderSubstitutionTest(unittest.TestCase):
    def test_prehandshake_substitutes_all_placeholders(self) -> None:
        rendered = PreHandshakeKillSwitch(V4_IP, PORT)._render()
        self.assertIn(V4_IP, rendered)
        self.assertIn(str(PORT), rendered)
        # No named {...} placeholder token survives (bare braces are valid
        # nft set/chain syntax and are expected to remain).
        self.assertIsNone(_PLACEHOLDER_RE.search(rendered))

    def test_full_manager_substitutes_all_placeholders(self) -> None:
        rendered = NFTablesManager(V4_IP, PORT, tun_name="mtun0")._render()
        self.assertIn(V4_IP, rendered)
        self.assertIn(str(PORT), rendered)
        self.assertIn("mtun0", rendered)
        self.assertIsNone(_PLACEHOLDER_RE.search(rendered))

    def test_rate_limit_substitutes_only_server_port(self) -> None:
        # server.conf only carries {SERVER_PORT}; SERVER_IP/TUN_NAME tokens
        # are absent by design, so we assert the port is filled in and the
        # one placeholder it has is gone — not a blanket no-brace check.
        rendered = ServerRateLimitManager(PORT)._render()
        self.assertIn(str(PORT), rendered)
        self.assertNotIn("{SERVER_PORT}", rendered)

    def test_address_family_v4_renders_ip_matcher(self) -> None:
        rendered = NFTablesManager(V4_IP, PORT)._render()
        # IPv4 server -> "ip daddr <v4>"; the ip6 matcher must not appear
        # against the server address.
        self.assertIn(f"ip daddr {V4_IP}", rendered)
        self.assertNotIn(f"ip6 daddr {V4_IP}", rendered)

    def test_address_family_v6_renders_ip6_matcher(self) -> None:
        rendered = NFTablesManager(V6_IP, PORT)._render()
        self.assertIn(f"ip6 daddr {V6_IP}", rendered)
        # The literal "ip daddr <v6>" (IPv4 matcher) must not be emitted.
        self.assertNotIn(f"ip daddr {V6_IP}", rendered)

    def test_prehandshake_address_family_v6(self) -> None:
        rendered = PreHandshakeKillSwitch(V6_IP, PORT)._render()
        self.assertIn("ip6", rendered)
        self.assertIn(V6_IP, rendered)


# --------------------------------------------------------------------------- #
# Fail-closed default-drop posture
# --------------------------------------------------------------------------- #
class FailClosedPolicyTest(unittest.TestCase):
    def _killswitch_chains(self, rendered: str) -> str:
        """Return only the dsm_killswitch[/_pre] table body.

        The dsm_dns_leak table (policy accept by design) is excluded so we
        assert policy drop strictly on the kill-switch chains.
        """
        start = rendered.index("table inet dsm_killswitch")
        end = rendered.find("table inet dsm_dns_leak", start)
        return rendered[start:] if end == -1 else rendered[start:end]

    def test_full_killswitch_chains_default_drop(self) -> None:
        body = self._killswitch_chains(NFTablesManager(V4_IP, PORT)._render())
        for chain in ("chain output", "chain input", "chain forward"):
            self.assertIn(chain, body)
        # Three hooked chains, each fail-closed.
        self.assertEqual(body.count("policy drop"), 3)

    def test_prehandshake_chains_default_drop(self) -> None:
        body = PreHandshakeKillSwitch(V4_IP, PORT)._render()
        for chain in ("chain output", "chain input", "chain forward"):
            self.assertIn(chain, body)
        self.assertEqual(body.count("policy drop"), 3)


# --------------------------------------------------------------------------- #
# Input validation
# --------------------------------------------------------------------------- #
class InputValidationTest(unittest.TestCase):
    def test_tun_name_injection_rejected(self) -> None:
        for bad in ("mtun0; drop", "a" * 16, "bad name", ""):
            with self.subTest(tun_name=bad):
                with self.assertRaises(ValueError):
                    # tun_name is validated in _render(), not __init__.
                    NFTablesManager(V4_IP, PORT, tun_name=bad)._render()

    def test_valid_tun_name_accepted(self) -> None:
        # Does not raise; renders the name verbatim.
        rendered = NFTablesManager(V4_IP, PORT, tun_name="mtun0")._render()
        self.assertIn('"mtun0"', rendered)

    def test_prehandshake_rejects_bad_server_ip(self) -> None:
        with self.assertRaises(ValueError):
            PreHandshakeKillSwitch("not-an-ip", PORT)

    def test_prehandshake_rejects_out_of_range_port(self) -> None:
        for bad_port in (0, 65536, -1):
            with self.subTest(port=bad_port):
                with self.assertRaises(ValueError):
                    PreHandshakeKillSwitch(V4_IP, bad_port)

    def test_rate_limit_rejects_out_of_range_port(self) -> None:
        for bad_port in (0, 65536):
            with self.subTest(port=bad_port):
                with self.assertRaises(ValueError):
                    ServerRateLimitManager(bad_port)


# --------------------------------------------------------------------------- #
# _apply_ruleset fatal / non-fatal contract (no real nft)
# --------------------------------------------------------------------------- #
class ApplyRulesetContractTest(unittest.TestCase):
    def test_called_process_error_fatal_raises_with_stderr(self) -> None:
        fake = _FakeRun([_called_process_error(b"syntax error near line 3")])
        with patch.object(nftables.subprocess, "run", fake):
            with self.assertRaises(RuntimeError) as ctx:
                _apply_ruleset("ruleset", fatal=True, log_label="ks")
        self.assertIn("syntax error near line 3", str(ctx.exception))

    def test_called_process_error_nonfatal_returns_false_and_logs(self) -> None:
        fake = _FakeRun([_called_process_error(b"boom")])
        with patch.object(nftables.subprocess, "run", fake):
            with self.assertLogs(nftables.log, level="WARNING") as cm:
                result = _apply_ruleset("ruleset", fatal=False, log_label="ks")
        self.assertFalse(result)
        self.assertTrue(any("boom" in m for m in cm.output))

    def test_file_not_found_fatal_reraises(self) -> None:
        fake = _FakeRun([FileNotFoundError("nft")])
        with patch.object(nftables.subprocess, "run", fake):
            with self.assertRaises(FileNotFoundError):
                _apply_ruleset("ruleset", fatal=True, log_label="ks")

    def test_file_not_found_nonfatal_returns_false(self) -> None:
        fake = _FakeRun([FileNotFoundError("nft")])
        with patch.object(nftables.subprocess, "run", fake):
            with self.assertLogs(nftables.log, level="WARNING"):
                result = _apply_ruleset("ruleset", fatal=False, log_label="ks")
        self.assertFalse(result)

    def test_success_returns_true(self) -> None:
        fake = _FakeRun()  # default success
        with patch.object(nftables.subprocess, "run", fake):
            self.assertTrue(_apply_ruleset("ruleset", fatal=True, log_label="ks"))
        self.assertEqual(len(fake.calls), 1)


# --------------------------------------------------------------------------- #
# Per-manager fatal-ness (fail-closed posture)
# --------------------------------------------------------------------------- #
class ManagerFatalnessTest(unittest.TestCase):
    def test_prehandshake_apply_raises_on_nft_failure(self) -> None:
        fake = _FakeRun([_called_process_error(b"nope")])
        with patch.object(nftables.subprocess, "run", fake):
            with self.assertRaises(RuntimeError):
                PreHandshakeKillSwitch(V4_IP, PORT).apply()

    def test_full_manager_apply_raises_on_nft_failure(self) -> None:
        # Both the delete-prefixed attempt AND the fallback fail -> the
        # kill switch must stay fatal and propagate.
        fake = _FakeRun(
            [_called_process_error(b"first"), _called_process_error(b"second")]
        )
        with patch.object(nftables.subprocess, "run", fake):
            with self.assertRaises(RuntimeError):
                NFTablesManager(V4_IP, PORT).apply()

    def test_rate_limit_apply_raises_on_nft_failure(self) -> None:
        # Fail closed: handshake rate-limiting is mandatory, so a failed
        # install raises (the server aborts startup) rather than serving
        # without flood protection. Mirrors the kill-switch fatal path above.
        fake = _FakeRun([_called_process_error(b"meh")])
        mgr = ServerRateLimitManager(PORT)
        with patch.object(nftables.subprocess, "run", fake):
            with self.assertRaises(RuntimeError):
                mgr.apply()
        self.assertFalse(mgr._applied)


# --------------------------------------------------------------------------- #
# Atomic pre->full upgrade transaction
# --------------------------------------------------------------------------- #
class AtomicUpgradeTest(unittest.TestCase):
    _DELETE_LINE = f"delete table inet {PreHandshakeKillSwitch.TABLE_NAME}"

    def test_successful_apply_input_starts_with_delete_table(self) -> None:
        # A successful first nft call means the whole upgrade ships as one
        # transaction whose ruleset begins by tearing down the pre table.
        fake = _FakeRun()  # first (and only) call succeeds
        with patch.object(nftables.subprocess, "run", fake):
            NFTablesManager(V4_IP, PORT).apply()
        self.assertEqual(len(fake.inputs), 1)
        self.assertTrue(fake.inputs[0].startswith(self._DELETE_LINE))

    def test_fallback_input_has_no_delete_table_line(self) -> None:
        # First attempt (with delete prefix) raises -> documented retry
        # WITHOUT the delete-table line. Second attempt succeeds.
        fake = _FakeRun([_called_process_error(b"no such table"), None])
        with patch.object(nftables.subprocess, "run", fake):
            NFTablesManager(V4_IP, PORT).apply()  # must not raise on fallback
        self.assertEqual(len(fake.inputs), 2)
        self.assertTrue(fake.inputs[0].startswith(self._DELETE_LINE))
        self.assertNotIn(self._DELETE_LINE, fake.inputs[1])


if __name__ == "__main__":
    unittest.main()
