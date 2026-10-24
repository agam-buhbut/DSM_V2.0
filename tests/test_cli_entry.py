"""The dsm command line (QA M4, M5, M10, Minors 3, 4, 6, Nits 1, 5).

main() runs with sys.argv patched; the daemons, the cleanup and the
passphrase reads are faked, so nothing touches the host and no terminal is
read. Config files live in tmp_path.
"""

from __future__ import annotations

import contextlib
import re
from collections.abc import Generator
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

import dsm.__main__ as entry

_CLIENT_TOML = (
    'mode = "client"\nserver_ip = "10.0.0.1"\nserver_port = 51820\n'
    "listen_port = 0\n"
    'key_file = "{dir}/identity.key"\ncert_file = "{dir}/device.crt"\n'
    'ca_root_file = "{dir}/ca.pem"\nattest_key_file = "{dir}/attest.key"\n'
    'expected_server_cn = "dsm-x-server"\n'
)


@pytest.fixture
def client_config(tmp_path: Path) -> Path:
    path = tmp_path / "config.toml"
    path.write_text(_CLIENT_TOML.format(dir=tmp_path))
    path.chmod(0o600)
    return path


def _run(argv: list[str], *, euid: int = 1000) -> int | str | None:
    with (
        patch.object(entry.sys, "argv", ["dsm", *argv]),
        patch.object(entry.os, "geteuid", return_value=euid),
        pytest.raises(SystemExit) as err,
    ):
        entry.main()
    return err.value.code


def test_a_daemon_start_without_root_says_use_sudo(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with patch.object(entry, "_load_config_or_exit") as load:
        assert _run(["--mode", "client"]) == 1
    assert capsys.readouterr().err == "dsm: DSM must run as root: use sudo\n"
    load.assert_not_called()


def test_cleanup_without_root_says_use_sudo(capsys: pytest.CaptureFixture[str]) -> None:
    with patch("dsm.net.cleanup.cleanup_host_state") as cleanup:
        assert _run(["cleanup"]) == 1
    assert capsys.readouterr().err == "dsm: dsm cleanup must run as root: use sudo\n"
    cleanup.assert_not_called()


def test_ctrl_c_is_one_word_not_a_traceback(capsys: pytest.CaptureFixture[str]) -> None:
    with (
        patch.object(entry, "_main", side_effect=KeyboardInterrupt),
        pytest.raises(SystemExit) as err,
    ):
        entry.main()
    assert err.value.code == 130
    assert capsys.readouterr().err == "aborted\n"


def test_init_help_is_inits_own_help(capsys: pytest.CaptureFixture[str]) -> None:
    assert _run(["init", "--help"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("usage: dsm init")
    assert "--install-unit" in out


def test_version_names_the_wire_version(capsys: pytest.CaptureFixture[str]) -> None:
    with patch.object(entry.sys, "argv", ["dsm", "--version"]):
        entry.main()  # prints and returns: no daemon, no root needed
    assert re.fullmatch(r"dsm \S+ \(wire v\d+\)\n", capsys.readouterr().out)


def test_the_help_says_what_the_passphrase_file_holds(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert _run(["--help"]) == 0
    out = capsys.readouterr().out
    assert "KEY=VALUE" in out
    assert "§9g" in out


def test_a_mode_the_config_does_not_fit_is_one_config_line(
    client_config: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as err:
        entry._load_config_or_exit(client_config, mode="server")
    assert err.value.code == 2
    text = capsys.readouterr().err
    assert text.startswith("config: listen_port must be 1-65535 in server mode")
    assert text.rstrip().endswith("(with --mode server)")


def test_enroll_refuses_a_cn_with_a_space(
    client_config: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as err:
        entry._run_enroll(
            client_config,
            csr_out=tmp_path / "x.csr",
            import_cert=None,
            cn="my laptop",
            role="client",
            passphrase_fd=None,
            passphrase_env_file=None,
        )
    assert err.value.code == 2
    assert "enroll: --cn must be one word" in capsys.readouterr().err
    assert not (tmp_path / "identity.key").exists()


def test_enroll_asks_for_a_new_passphrase_twice(
    client_config: Path, tmp_path: Path
) -> None:
    seen: dict[str, Any] = {}

    def stop(**kwargs: Any) -> bytearray:
        seen.update(kwargs)
        raise ValueError("stop here")

    with (
        patch("dsm.core.passphrase.read_passphrase", stop),
        patch("dsm.crypto.tpm_preflight.preflight_tpm"),
        pytest.raises(SystemExit),
    ):
        entry._run_enroll(
            client_config,
            csr_out=tmp_path / "x.csr",
            import_cert=None,
            cn=None,
            role="client",
            passphrase_fd=None,
            passphrase_env_file=None,
        )
    assert seen["confirm"] is True


def test_enroll_import_checks_the_cert_against_the_mode(
    client_config: Path, tmp_path: Path
) -> None:
    @contextlib.contextmanager
    def unlocked(*_a: object, **_k: object) -> Generator[None, None, None]:
        yield

    leaf = MagicMock(subject_cn="dsm-x-client", serial_number=7)
    with (
        patch("dsm.crypto._stores.loaded_stores_cli", unlocked),
        patch("dsm.crypto.enroll.import_signed_cert", return_value=leaf) as imp,
    ):
        entry._run_enroll(
            client_config,
            csr_out=None,
            import_cert=tmp_path / "signed.pem",
            cn=None,
            role=None,
            passphrase_fd=None,
            passphrase_env_file=None,
        )
    assert imp.call_args.kwargs["role"] == "client"


def test_show_pubkey_with_an_empty_passphrase_is_one_line(
    client_config: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    empty = tmp_path / "pp"
    empty.write_bytes(b"")
    empty.chmod(0o600)
    with pytest.raises(SystemExit) as err:
        entry._run_show_pubkey(
            client_config, passphrase_fd=None, passphrase_env_file=str(empty)
        )
    assert err.value.code == 2
    assert capsys.readouterr().err.startswith(
        "show-pubkey: passphrase must not be empty"
    )


def test_main_hands_mode_to_the_config_check(
    client_config: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # QA Minor 4(b): main() applied --mode after the load, a traceback.
    assert _run(["--mode", "server", "--config", str(client_config)], euid=0) == 2
    assert capsys.readouterr().err.rstrip().endswith("(with --mode server)")
