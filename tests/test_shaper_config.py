"""Tier shaper config keys: defaults, rules, type checks, the clear startup
error for the removed ``envelope_*`` keys, and the path into the shaper."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from dsm.core.config import SHAPER_KEYS, Config, ConfigError, load
from dsm.traffic.shaper import TrafficShaper

_CLIENT_TOML = """\
mode = "client"
server_ip = "10.0.0.1"
server_port = 51820
listen_port = 51821
key_file = "/tmp/test.key"
cert_file = "/tmp/test.crt"
ca_root_file = "/tmp/test-ca.pem"
attest_key_file = "/tmp/test-attest.key"
expected_server_cn = "dsm-test-server"
transport = "udp"
"""


def _base(**overrides: Any) -> dict[str, Any]:
    """Minimal valid client config (mirrors test_config.py)."""
    values: dict[str, Any] = {
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
    values.update(overrides)
    return values


def _load(tmp_path: Path, extra: str) -> Config:
    path = tmp_path / "config.toml"
    path.write_text(_CLIENT_TOML + extra)
    os.chmod(path, 0o600)
    return load(path)


def test_defaults() -> None:
    c = Config(**_base())
    assert c.shaper_tiers_pps == [10.0, 50.0, 200.0, 800.0]
    assert c.shaper_latency_budget_ms == 500
    assert c.shaper_decoy_interval_s == 7200
    assert c.shaper_linger_s == [300.0, 1800.0]


@pytest.mark.parametrize(
    "overrides",
    [
        # The 1 packet/s and 10 ms edges get a partner value that meets the
        # first-tier rule (above 4.25 / budget-in-seconds packets/s).
        {"shaper_tiers_pps": [1, 5000], "shaper_latency_budget_ms": 5000},
        {
            "shaper_tiers_pps": [1, 2, 3, 4, 5, 6, 7, 8],
            "shaper_latency_budget_ms": 5000,
        },
        {"shaper_tiers_pps": [10.5, 50.25]},
        {"shaper_latency_budget_ms": 10, "shaper_tiers_pps": [430, 5000]},
        {"shaper_latency_budget_ms": 5000},
        {"shaper_decoy_interval_s": 0},
        {"shaper_decoy_interval_s": 300},
        {"shaper_decoy_interval_s": 86400},
        {"shaper_linger_s": [0, 0]},
        {"shaper_linger_s": [7200, 7200]},
        {"shaper_linger_s": [0.5, 1]},
    ],
)
def test_valid_values_are_accepted(overrides: dict[str, Any]) -> None:
    Config(**_base(**overrides))


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("shaper_tiers_pps", [10]),
        ("shaper_tiers_pps", [1, 2, 3, 4, 5, 6, 7, 8, 9]),
        ("shaper_tiers_pps", [10, 10]),
        ("shaper_tiers_pps", [50, 10]),
        ("shaper_tiers_pps", [0.5, 10]),
        ("shaper_tiers_pps", [10, 5001]),
        ("shaper_tiers_pps", [10, float("nan")]),
        ("shaper_latency_budget_ms", 9),
        ("shaper_latency_budget_ms", 5001),
        ("shaper_decoy_interval_s", 299),
        ("shaper_decoy_interval_s", 86401),
        ("shaper_decoy_interval_s", -1),
        ("shaper_decoy_interval_s", float("inf")),
        ("shaper_linger_s", [0, 10]),
        ("shaper_linger_s", [10, 5]),
        ("shaper_linger_s", [10, 7201]),
        ("shaper_linger_s", [-1, 10]),
        ("shaper_linger_s", [300]),
        ("shaper_linger_s", [300, 600, 900]),
    ],
)
def test_out_of_range_values_name_the_key(key: str, value: Any) -> None:
    with pytest.raises(ValueError, match=key):
        Config(**_base(**{key: value}))


@pytest.mark.parametrize(
    ("tier0", "budget_ms"),
    [
        (8.6, 500),  # just above 8.5 packets/s
        (430, 10),  # just above 425
        (1, 5000),  # above 0.85
        (10, 500),  # the defaults
    ],
)
def test_a_first_tier_fast_enough_for_the_budget_is_accepted(
    tier0: float, budget_ms: int
) -> None:
    c = Config(
        **_base(shaper_tiers_pps=[tier0, 5000], shaper_latency_budget_ms=budget_ms)
    )
    # The Rust core agrees: it builds a shaper from the same values.
    TrafficShaper.from_config(c)


@pytest.mark.parametrize(
    ("tier0", "budget_ms", "minimum"),
    [
        (8.4, 500, "8.5"),  # just below
        (8.5, 500, "8.5"),  # at the limit: the rate must be above it
        (420, 10, "425"),
        (10, 400, "10.625"),  # the default first tier needs at least 425 ms
    ],
)
def test_a_first_tier_too_slow_for_the_budget_is_refused(
    tier0: float, budget_ms: int, minimum: str
) -> None:
    with pytest.raises(ValueError) as caught:
        Config(
            **_base(shaper_tiers_pps=[tier0, 5000], shaper_latency_budget_ms=budget_ms)
        )
    message = str(caught.value)
    assert f"shaper_tiers_pps[0] must be above {minimum} packets/s" in message
    assert f"shaper_latency_budget_ms is {budget_ms}" in message
    # The Rust core refuses the same values.
    with pytest.raises(ValueError):
        TrafficShaper(tiers_pps=[tier0, 5000], latency_budget_ms=budget_ms)


@pytest.mark.parametrize(
    ("key", "value", "kind"),
    [
        ("shaper_latency_budget_ms", "500", "integer"),
        ("shaper_latency_budget_ms", True, "integer"),
        ("shaper_latency_budget_ms", 500.0, "integer"),
        ("shaper_decoy_interval_s", "7200", "number"),
        ("shaper_decoy_interval_s", False, "number"),
        ("shaper_tiers_pps", "10, 50", "list"),
        ("shaper_tiers_pps", 10, "list"),
        ("shaper_tiers_pps", [10, "50"], "number"),
        ("shaper_tiers_pps", [10, True], "number"),
        ("shaper_linger_s", 300, "list"),
    ],
)
def test_wrong_types_raise_a_readable_value_error(
    key: str, value: Any, kind: str
) -> None:
    with pytest.raises(ValueError, match=key) as caught:
        Config(**_base(**{key: value}))
    assert kind in str(caught.value)


# TOML integers can have any size, but a float cannot hold one this big.
_HUGE = 10**400


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("shaper_tiers_pps", [10, _HUGE]),
        ("shaper_tiers_pps", [-_HUGE, 10]),
        ("shaper_linger_s", [300, _HUGE]),
    ],
)
def test_a_huge_integer_raises_a_value_error_naming_the_key(
    key: str, value: list[int]
) -> None:
    with pytest.raises(ValueError, match=key):
        Config(**_base(**{key: value}))


def test_a_huge_integer_in_the_file_stops_startup_without_a_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from dsm.__main__ import _load_config_or_exit

    path = tmp_path / "config.toml"
    path.write_text(_CLIENT_TOML + f"shaper_tiers_pps = [10, {'9' * 400}]\n")
    os.chmod(path, 0o600)
    with pytest.raises(SystemExit) as caught:
        _load_config_or_exit(path)
    assert caught.value.code == 2
    err = capsys.readouterr().err
    assert err.startswith("config: shaper_tiers_pps")
    assert "Traceback" not in err


def test_load_reads_the_new_keys(tmp_path: Path) -> None:
    c = _load(
        tmp_path,
        "shaper_tiers_pps = [20, 100, 400]\n"
        "shaper_latency_budget_ms = 250\n"
        "shaper_decoy_interval_s = 0\n"
        "shaper_linger_s = [0, 0]\n",
    )
    assert c.shaper_tiers_pps == [20, 100, 400]
    assert c.shaper_latency_budget_ms == 250
    assert c.shaper_decoy_interval_s == 0
    assert c.shaper_linger_s == [0, 0]


def test_an_envelope_key_stops_startup_with_a_clear_message(tmp_path: Path) -> None:
    with pytest.raises(ConfigError) as caught:
        _load(tmp_path, "envelope_latency_budget_ms = 1000\n")
    message = str(caught.value)
    assert "envelope_latency_budget_ms" in message
    for key in SHAPER_KEYS:
        assert key in message


def test_every_envelope_key_is_named(tmp_path: Path) -> None:
    with pytest.raises(ConfigError) as caught:
        _load(
            tmp_path,
            "envelope_rise_per_s = 2.0\nenvelope_ceiling_pps = 600\n",
        )
    message = str(caught.value)
    assert "envelope_ceiling_pps" in message
    assert "envelope_rise_per_s" in message


@pytest.mark.parametrize("key", ["jitter_ms_min", "jitter_ms_max"])
def test_a_jitter_key_stops_startup_with_a_clear_message(
    tmp_path: Path, key: str
) -> None:
    with pytest.raises(ConfigError) as caught:
        _load(tmp_path, f"{key} = 1\n")
    message = str(caught.value)
    assert key in message
    assert "no longer exist" in message


def test_from_config_hands_the_keys_to_the_shaper() -> None:
    c = Config(
        **_base(
            shaper_tiers_pps=[100, 400],
            shaper_decoy_interval_s=0,
            shaper_linger_s=[0, 0],
            padding_min=256,
            padding_max=1024,
        )
    )
    shaper = TrafficShaper.from_config(c, clock=lambda: 1000.0)
    assert shaper._active_classes == (256, 384, 512, 640, 768, 896, 1024)
    # The idle rate sits in the first tier's band (100 x 0.8-1.2 packets/s),
    # which shows the configured tiers reached the core.
    sent = 0
    now = 1000.0
    while now < 1010.0:
        slots, now = shaper.poll(now, 0, 0.0, 0)
        sent += slots
    assert 80 * 10 * 0.95 <= sent <= 120 * 10 * 1.05
