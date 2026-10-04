"""A setting that sits under [dns_provider_pins] is refused.

In TOML every key after a ``[dns_provider_pins]`` header belongs to that table,
and ``dsm init`` writes the table last. A setting appended after it used to land
in the table and be silently ignored. Config validation now refuses any pin
entry whose key is not a provider listed in ``dns_providers``.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from dsm.__main__ import _load_config_or_exit
from dsm.core.config import Config, load

_PROVIDER = "https://1.1.1.1/dns-query"
_OTHER_PROVIDER = "https://9.9.9.9/dns-query"
_PIN = "a" * 64

# The top-level keys `dsm init server` writes (it ends with dns_providers, the
# pins table, and the first pin).
_TOP = """\
mode = "server"
server_ip = "0.0.0.0"
server_port = 51820
listen_port = 51820
key_file = "/tmp/test.key"
cert_file = "/tmp/test.crt"
ca_root_file = "/tmp/test-ca.pem"
attest_key_file = "/tmp/test-attest.key"
allowed_cns_file = "/tmp/test-allowed-cns.txt"
transport = "udp"
"""
_PROVIDERS = f'dns_providers = ["{_PROVIDER}"]\n'
_PINS = f'[dns_provider_pins]\n"{_PROVIDER}" = ["{_PIN}"]\n'
_SETTING = "shaper_tiers_pps = [20, 100]\n"


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "config.toml"
    path.write_text(text)
    os.chmod(path, 0o600)
    return path


def _server(**overrides: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "mode": "server",
        "server_ip": "0.0.0.0",
        "server_port": 51820,
        "listen_port": 51820,
        "key_file": "/tmp/test.key",
        "cert_file": "/tmp/test.crt",
        "ca_root_file": "/tmp/test-ca.pem",
        "attest_key_file": "/tmp/test-attest.key",
        "allowed_cns_file": "/tmp/test-allowed-cns.txt",
        "dns_providers": [_PROVIDER],
        "dns_provider_pins": {_PROVIDER: [_PIN]},
    }
    values.update(overrides)
    return values


def test_setting_under_the_pins_table_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path, _TOP + _PROVIDERS + _PINS + _SETTING)

    with pytest.raises(ValueError) as excinfo:
        load(path)

    assert str(excinfo.value) == (
        "dns_provider_pins has entries that are not in dns_providers: "
        "'shaper_tiers_pps'. If any of them is a setting, move it above the "
        "[dns_provider_pins] section; otherwise add the provider to "
        "dns_providers or remove the pin (names must match exactly)."
    )


def test_every_setting_under_the_pins_table_is_named(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        _TOP + _PROVIDERS + _PINS + 'log_level = "debug"\nmtu = 1380\n',
    )

    with pytest.raises(ValueError) as excinfo:
        load(path)

    assert "'log_level', 'mtu'" in str(excinfo.value)


def test_the_same_setting_above_the_pins_table_is_applied(tmp_path: Path) -> None:
    path = _write(tmp_path, _TOP + _SETTING + _PROVIDERS + _PINS)

    config = load(path)

    assert config.shaper_tiers_pps == [20.0, 100.0]
    assert config.dns_provider_pins == {_PROVIDER: [_PIN]}


def test_dns_providers_under_the_pins_table_is_named_not_reported_missing(
    tmp_path: Path,
) -> None:
    path = _write(tmp_path, _TOP + _PINS + _PROVIDERS)

    with pytest.raises(ValueError) as excinfo:
        load(path)

    message = str(excinfo.value)
    assert "'dns_providers'" in message
    assert "server mode requires" not in message


def test_the_refusal_reaches_the_user_as_a_config_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = _write(tmp_path, _TOP + _PROVIDERS + _PINS + _SETTING)

    with pytest.raises(SystemExit) as excinfo:
        _load_config_or_exit(path)

    assert excinfo.value.code == 2
    err = capsys.readouterr().err
    assert err.startswith("config: dns_provider_pins has entries that are not in ")
    assert "Traceback" not in err


def test_a_pin_for_every_listed_provider_is_accepted() -> None:
    config = Config(
        **_server(
            dns_providers=[_PROVIDER, _OTHER_PROVIDER],
            dns_provider_pins={_PROVIDER: [_PIN], _OTHER_PROVIDER: [_PIN, "b" * 64]},
        )
    )

    assert set(config.dns_provider_pins) == {_PROVIDER, _OTHER_PROVIDER}


def test_a_spare_pin_is_refused_with_a_hint_for_a_pin() -> None:
    pins = {_PROVIDER: [_PIN], _OTHER_PROVIDER: [_PIN]}

    with pytest.raises(ValueError) as excinfo:
        Config(**_server(dns_provider_pins=pins))

    message = str(excinfo.value)
    assert f"'{_OTHER_PROVIDER}'" in message
    assert "add the provider to dns_providers or remove the pin" in message
    assert "names must match exactly" in message


def test_a_mistyped_pin_name_is_named_not_reported_as_a_missing_pin() -> None:
    # The provider has no pin under its own name, and the mistyped entry is
    # not a provider. The message names the entry and says how to fix it.
    pins = {_PROVIDER + "/": [_PIN]}

    with pytest.raises(ValueError) as excinfo:
        Config(**_server(dns_provider_pins=pins))

    message = str(excinfo.value)
    assert f"'{_PROVIDER}/'" in message
    assert "names must match exactly" in message
    assert "requires dns_provider_pins entry" not in message


def test_pins_without_any_listed_provider_are_refused_in_client_mode() -> None:
    client: dict[str, Any] = {
        "mode": "client",
        "server_ip": "10.0.0.1",
        "server_port": 51820,
        "listen_port": 0,
        "key_file": "/tmp/test.key",
        "cert_file": "/tmp/test.crt",
        "ca_root_file": "/tmp/test-ca.pem",
        "attest_key_file": "/tmp/test-attest.key",
        "expected_server_cn": "dsm-test-server",
        "dns_provider_pins": {"log_level": ["debug"]},
    }

    with pytest.raises(ValueError, match="'log_level'"):
        Config(**client)
