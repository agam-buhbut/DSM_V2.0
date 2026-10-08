"""The dns_blocklist switch: on by default, a TOML boolean only."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from dsm.core.config import Config, load

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


def test_on_by_default() -> None:
    assert Config(**_base()).dns_blocklist is True


@pytest.mark.parametrize(("text", "want"), [("true", True), ("false", False)])
def test_true_and_false_load(tmp_path: Path, text: str, want: bool) -> None:
    assert _load(tmp_path, f"dns_blocklist = {text}\n").dns_blocklist is want


@pytest.mark.parametrize("text", ['"false"', "0", "1"])
def test_anything_but_a_boolean_stops_startup(tmp_path: Path, text: str) -> None:
    with pytest.raises(ValueError, match="dns_blocklist must be true or false"):
        _load(tmp_path, f"dns_blocklist = {text}\n")


def test_the_example_config_documents_the_key_above_the_pins_table() -> None:
    example = (
        Path(__file__).resolve().parent.parent / "config.example.toml"
    ).read_text()
    assert "# dns_blocklist = true" in example
    assert example.index("# dns_blocklist = true") < example.index(
        "# [dns_provider_pins]"
    )
