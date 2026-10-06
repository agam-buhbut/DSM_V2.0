"""Wrong types for ``dns_providers`` and pin values are clear config errors.

A string where a list belongs used to be read letter by letter, which gave
confusing errors about single characters.
"""

from __future__ import annotations

from typing import Any

import pytest

from dsm.core.config import Config

_PROVIDER = "https://1.1.1.1/dns-query"
_PIN = "a" * 64


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


@pytest.mark.parametrize("value", [_PROVIDER, 7, [_PROVIDER, 7]])
def test_dns_providers_must_be_a_list_of_strings(value: Any) -> None:
    with pytest.raises(ValueError, match="dns_providers must be a list of strings"):
        Config(**_server(dns_providers=value))


@pytest.mark.parametrize("value", [_PIN, 7, [_PIN, 7]])
def test_pin_value_must_be_a_list_of_strings(value: Any) -> None:
    with pytest.raises(
        ValueError,
        match=r"dns_provider_pins\['https://1.1.1.1/dns-query'\] must be a list",
    ):
        Config(**_server(dns_provider_pins={_PROVIDER: value}))


def test_good_values_still_load() -> None:
    config = Config(**_server())
    assert config.dns_provider_pins == {_PROVIDER: [_PIN]}
