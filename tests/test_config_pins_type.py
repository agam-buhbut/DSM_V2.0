"""``dns_provider_pins`` that is not a table is a clear config error.

Written as a plain key (``dns_provider_pins = "..."`` or ``= [...]``) instead
of a ``[dns_provider_pins]`` section, the value used to crash server startup
with a raw ``AttributeError`` (or, for a non-empty string, name each letter
as a stray pin). Config validation now names the key and the wrong type.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from dsm.__main__ import _load_config_or_exit
from dsm.core.config import Config, load

_PROVIDER = "https://1.1.1.1/dns-query"
_PIN = "a" * 64

_TOP = f"""\
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
dns_providers = ["{_PROVIDER}"]
"""


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


@pytest.mark.parametrize(
    ("value", "type_name"),
    [
        ("", "str"),
        (_PIN, "str"),
        ([], "list"),
        ([_PIN], "list"),
        (7, "int"),
    ],
)
def test_a_value_that_is_not_a_table_names_the_key(
    value: object, type_name: str
) -> None:
    with pytest.raises(ValueError) as excinfo:
        Config(**_server(dns_provider_pins=value))

    assert str(excinfo.value) == (
        "dns_provider_pins must be a table (a [dns_provider_pins] section), "
        f"got {type_name}"
    )


def test_a_wrong_type_is_refused_in_client_mode_too() -> None:
    client = _server(
        mode="client",
        server_ip="10.0.0.1",
        listen_port=0,
        expected_server_cn="dsm-test-server",
        allowed_cns_file=None,
        dns_providers=[],
        dns_provider_pins="",
    )

    with pytest.raises(ValueError, match="dns_provider_pins must be a table"):
        Config(**client)


def test_a_toml_string_reaches_the_user_as_one_config_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = _write(tmp_path, _TOP + f'dns_provider_pins = "{_PIN}"\n')

    with pytest.raises(SystemExit) as excinfo:
        _load_config_or_exit(path)

    assert excinfo.value.code == 2
    err = capsys.readouterr().err
    assert err == (
        "config: dns_provider_pins must be a table (a [dns_provider_pins] "
        "section), got str\n"
    )


def test_a_toml_list_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path, _TOP + f'dns_provider_pins = ["{_PIN}"]\n')

    with pytest.raises(ValueError, match="got list"):
        load(path)


def test_a_toml_section_still_loads(tmp_path: Path) -> None:
    path = _write(tmp_path, _TOP + f'[dns_provider_pins]\n"{_PROVIDER}" = ["{_PIN}"]\n')

    config = load(path)

    assert config.dns_provider_pins == {_PROVIDER: [_PIN]}
