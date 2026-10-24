"""Config messages a user can act on (QA Minor 5, Minor 15, Nit 3)."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from dsm.core.config import ConfigError, load
from tests.test_client_fail_closed import _config

_GOOD = (
    'mode = "client"\nserver_ip = "10.0.0.1"\nserver_port = 51820\n'
    'listen_port = 0\nkey_file = "/tmp/k"\ncert_file = "/tmp/c"\n'
    'ca_root_file = "/tmp/ca"\nattest_key_file = "/tmp/a"\n'
    'expected_server_cn = "dsm-x-server"\n'
)


def _write(tmp_path: Path, text: str, mode: int = 0o600) -> Path:
    path = tmp_path / "config.toml"
    path.write_text(text)
    path.chmod(mode)
    return path


def test_a_mistyped_key_names_the_nearest_setting(tmp_path: Path) -> None:
    with pytest.raises(ConfigError) as err:
        load(_write(tmp_path, _GOOD + 'trasport = "tcp"\n'))
    assert str(err.value) == (
        "unknown setting 'trasport' (did you mean 'transport'?); "
        "see config.example.toml"
    )


def test_several_unknown_keys_are_named_together(tmp_path: Path) -> None:
    with pytest.raises(ConfigError) as err:
        load(_write(tmp_path, _GOOD + 'trasport = "tcp"\nzzzz = 1\n'))
    assert str(err.value).startswith(
        "unknown settings 'trasport' (did you mean 'transport'?), 'zzzz'"
    )


def test_the_permission_error_says_chmod_once(tmp_path: Path) -> None:
    path = _write(tmp_path, _GOOD, mode=0o644)
    with pytest.raises(ConfigError) as err:
        load(path)
    text = str(err.value)
    assert text.lower().count("chmod 600") == 1
    assert ".." not in text


def test_the_mtu_warning_says_1360(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING, logger="dsm")
    _config(mtu=1500)
    (line,) = [r.getMessage() for r in caplog.records if "mtu=1500" in r.getMessage()]
    assert "Use 1360, the default" in line
    assert "1380" not in line


def test_a_config_owned_by_someone_else_has_no_double_dot(tmp_path: Path) -> None:
    # QA Nit 3's ".." came from this text, and a chmod cannot fix an owner.
    path = _write(tmp_path, _GOOD)
    with (
        patch("dsm.core.path_security.os.getuid", return_value=os.getuid() + 1),
        pytest.raises(ConfigError) as err,
    ):
        load(path)
    text = str(err.value)
    assert ".." not in text
    assert "chmod" not in text.lower()
    assert text.endswith("Refusing to trust a file owned by another user.")
