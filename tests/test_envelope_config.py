"""Envelope config knobs — defaults, range validators, type checks."""

from __future__ import annotations

import unittest
from typing import Any

from dsm.core.config import Config


def _base(**overrides: Any) -> dict[str, Any]:
    """Minimal valid client config fixture (mirrors test_config.py convention)."""
    defaults: dict[str, Any] = {
        "mode": "client",
        "server_ip": "10.0.0.1",
        "server_port": 51820,
        "listen_port": 51821,
        "key_file": "/tmp/test.key",
        "cert_file": "/tmp/test.crt",
        "ca_root_file": "/tmp/test-ca.pem",
        "attest_key_file": "/tmp/test-attest.key",
        "expected_server_cn": "dsm-test-server",
        "transport": "udp",
    }
    defaults.update(overrides)
    return defaults


class TestEnvelopeDefaults(unittest.TestCase):
    """All envelope fields have the documented defaults when unset."""

    def setUp(self) -> None:
        self.c = Config(**_base())

    def test_latency_budget_ms_default(self) -> None:
        self.assertEqual(self.c.envelope_latency_budget_ms, 1000)

    def test_rise_per_s_default(self) -> None:
        self.assertAlmostEqual(self.c.envelope_rise_per_s, 2.0)

    def test_fall_half_life_s_default(self) -> None:
        self.assertAlmostEqual(self.c.envelope_fall_half_life_s, 4.0)

    def test_ceiling_pps_default(self) -> None:
        self.assertEqual(self.c.envelope_ceiling_pps, 600)

    def test_idle_floor_min_pps_default(self) -> None:
        self.assertAlmostEqual(self.c.envelope_idle_floor_min_pps, 0.5)

    def test_idle_floor_max_pps_default(self) -> None:
        self.assertAlmostEqual(self.c.envelope_idle_floor_max_pps, 2.0)


class TestEnvelopeValidValues(unittest.TestCase):
    """Valid non-default values are accepted."""

    def test_full_envelope_config_loads(self) -> None:
        c = Config(
            **_base(
                envelope_latency_budget_ms=500,
                envelope_rise_per_s=3.0,
                envelope_fall_half_life_s=8.0,
                envelope_ceiling_pps=1000,
                envelope_idle_floor_min_pps=1.0,
                envelope_idle_floor_max_pps=5.0,
            )
        )
        self.assertEqual(c.envelope_latency_budget_ms, 500)
        self.assertAlmostEqual(c.envelope_rise_per_s, 3.0)
        self.assertAlmostEqual(c.envelope_fall_half_life_s, 8.0)
        self.assertEqual(c.envelope_ceiling_pps, 1000)
        self.assertAlmostEqual(c.envelope_idle_floor_min_pps, 1.0)
        self.assertAlmostEqual(c.envelope_idle_floor_max_pps, 5.0)

    def test_equal_floor_min_max_accepted(self) -> None:
        # min == max is a degenerate (non-random) floor — valid per the spec.
        c = Config(
            **_base(
                envelope_idle_floor_min_pps=1.0,
                envelope_idle_floor_max_pps=1.0,
            )
        )
        self.assertAlmostEqual(c.envelope_idle_floor_min_pps, 1.0)
        self.assertAlmostEqual(c.envelope_idle_floor_max_pps, 1.0)

    def test_boundary_latency_budget_min(self) -> None:
        c = Config(**_base(envelope_latency_budget_ms=10))
        self.assertEqual(c.envelope_latency_budget_ms, 10)

    def test_boundary_latency_budget_max(self) -> None:
        c = Config(**_base(envelope_latency_budget_ms=5000))
        self.assertEqual(c.envelope_latency_budget_ms, 5000)

    def test_boundary_rise_just_above_one(self) -> None:
        c = Config(**_base(envelope_rise_per_s=1.01))
        self.assertGreater(c.envelope_rise_per_s, 1.0)

    def test_boundary_fall_half_life_max(self) -> None:
        c = Config(**_base(envelope_fall_half_life_s=60.0))
        self.assertAlmostEqual(c.envelope_fall_half_life_s, 60.0)

    def test_boundary_ceiling_equals_floor_max(self) -> None:
        # ceiling == idle_floor_max is the minimum valid ceiling.
        c = Config(
            **_base(
                envelope_idle_floor_min_pps=1.0,
                envelope_idle_floor_max_pps=5.0,
                envelope_ceiling_pps=5,
            )
        )
        self.assertEqual(c.envelope_ceiling_pps, 5)


class TestEnvelopeRangeValidation(unittest.TestCase):
    """Out-of-range values raise ValueError naming the offending field."""

    def _raises(self, field: str, **overrides: Any) -> str:
        with self.assertRaises(ValueError) as cm:
            Config(**_base(**overrides))
        msg = str(cm.exception)
        self.assertIn(field, msg, f"error message should name field {field!r}")
        return msg

    def test_latency_budget_ms_zero_rejected(self) -> None:
        msg = self._raises(
            "envelope_latency_budget_ms",
            envelope_latency_budget_ms=0,
        )
        self.assertIn("envelope_latency_budget_ms", msg)

    def test_latency_budget_ms_negative_rejected(self) -> None:
        self._raises("envelope_latency_budget_ms", envelope_latency_budget_ms=-1)

    def test_latency_budget_ms_below_minimum_rejected(self) -> None:
        # Minimum is 10; 9 is below it.
        self._raises("envelope_latency_budget_ms", envelope_latency_budget_ms=9)

    def test_latency_budget_ms_above_maximum_rejected(self) -> None:
        self._raises("envelope_latency_budget_ms", envelope_latency_budget_ms=5001)

    def test_rise_per_s_at_one_rejected(self) -> None:
        # Exactly 1.0 would mean the envelope cannot rise — rejected (must be > 1.0).
        msg = self._raises("envelope_rise_per_s", envelope_rise_per_s=1.0)
        self.assertIn("envelope_rise_per_s", msg)

    def test_rise_per_s_below_one_rejected(self) -> None:
        self._raises("envelope_rise_per_s", envelope_rise_per_s=0.5)

    def test_rise_per_s_above_max_rejected(self) -> None:
        self._raises("envelope_rise_per_s", envelope_rise_per_s=100.01)

    def test_fall_half_life_s_zero_rejected(self) -> None:
        msg = self._raises("envelope_fall_half_life_s", envelope_fall_half_life_s=0.0)
        self.assertIn("envelope_fall_half_life_s", msg)

    def test_fall_half_life_s_negative_rejected(self) -> None:
        self._raises("envelope_fall_half_life_s", envelope_fall_half_life_s=-1.0)

    def test_fall_half_life_s_above_max_rejected(self) -> None:
        self._raises("envelope_fall_half_life_s", envelope_fall_half_life_s=61.0)

    def test_ceiling_pps_below_floor_max_rejected(self) -> None:
        # floor_max=5.0 but ceiling=4: ceiling < floor_max → rejected.
        msg = self._raises(
            "envelope_ceiling_pps",
            envelope_idle_floor_min_pps=1.0,
            envelope_idle_floor_max_pps=5.0,
            envelope_ceiling_pps=4,
        )
        self.assertIn("envelope_ceiling_pps", msg)

    def test_ceiling_pps_above_max_rejected(self) -> None:
        self._raises("envelope_ceiling_pps", envelope_ceiling_pps=100001)

    def test_idle_floor_min_zero_rejected(self) -> None:
        msg = self._raises(
            "envelope_idle_floor_min_pps",
            envelope_idle_floor_min_pps=0.0,
        )
        self.assertIn("envelope_idle_floor_min_pps", msg)

    def test_idle_floor_min_negative_rejected(self) -> None:
        self._raises("envelope_idle_floor_min_pps", envelope_idle_floor_min_pps=-0.1)

    def test_idle_floor_max_below_min_rejected(self) -> None:
        # min=3.0, max=1.0 → min > max → rejected.
        msg = self._raises(
            "envelope_idle_floor_min_pps",
            envelope_idle_floor_min_pps=3.0,
            envelope_idle_floor_max_pps=1.0,
        )
        # Either field name is acceptable — the validator reports both.
        self.assertTrue(
            "envelope_idle_floor_min_pps" in msg or "envelope_idle_floor_max_pps" in msg
        )

    def test_idle_floor_max_above_max_rejected(self) -> None:
        self._raises(
            "envelope_idle_floor_max_pps",
            envelope_idle_floor_min_pps=500.0,
            envelope_idle_floor_max_pps=1001.0,
        )


class TestEnvelopeTypeChecks(unittest.TestCase):
    """Wrong types (string for a numeric field) raise readable ValueError
    from _validate_types — not a cryptic TypeError from a comparison."""

    def _raises_named(self, field: str, **overrides: Any) -> str:
        with self.assertRaises(ValueError) as cm:
            Config(**_base(**overrides))
        msg = str(cm.exception)
        self.assertIn(field, msg, f"error must name field {field!r}")
        return msg

    def test_string_latency_budget_ms_raises_valueerror(self) -> None:
        msg = self._raises_named(
            "envelope_latency_budget_ms",
            envelope_latency_budget_ms="250",  # type: ignore[arg-type]
        )
        self.assertIn("integer", msg)

    def test_string_ceiling_pps_raises_valueerror(self) -> None:
        msg = self._raises_named(
            "envelope_ceiling_pps",
            envelope_ceiling_pps="600",  # type: ignore[arg-type]
        )
        self.assertIn("integer", msg)

    def test_string_rise_per_s_raises_valueerror(self) -> None:
        msg = self._raises_named(
            "envelope_rise_per_s",
            envelope_rise_per_s="2.0",  # type: ignore[arg-type]
        )
        self.assertIn("number", msg)

    def test_string_fall_half_life_raises_valueerror(self) -> None:
        msg = self._raises_named(
            "envelope_fall_half_life_s",
            envelope_fall_half_life_s="4.0",  # type: ignore[arg-type]
        )
        self.assertIn("number", msg)

    def test_string_floor_min_raises_valueerror(self) -> None:
        msg = self._raises_named(
            "envelope_idle_floor_min_pps",
            envelope_idle_floor_min_pps="0.5",  # type: ignore[arg-type]
        )
        self.assertIn("number", msg)

    def test_string_floor_max_raises_valueerror(self) -> None:
        msg = self._raises_named(
            "envelope_idle_floor_max_pps",
            envelope_idle_floor_max_pps="2.0",  # type: ignore[arg-type]
        )
        self.assertIn("number", msg)

    def test_bool_ceiling_pps_rejected(self) -> None:
        # bool is a subclass of int — must be rejected.
        self._raises_named(
            "envelope_ceiling_pps",
            envelope_ceiling_pps=True,  # type: ignore[arg-type]
        )

    def test_bool_latency_budget_ms_rejected(self) -> None:
        self._raises_named(
            "envelope_latency_budget_ms",
            envelope_latency_budget_ms=False,  # type: ignore[arg-type]
        )


if __name__ == "__main__":
    unittest.main()
