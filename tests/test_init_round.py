"""dsm init, as a new user meets it (QA B2, M1, M6, M7, Minors 3, 13, 16,
Nit 2). The enrollment, the TPM check, the store unlock and the cert import
are faked, as in tests/test_init.py; files live in tmp_path."""

from __future__ import annotations

import contextlib
from collections.abc import Generator
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

from dsm import init as dsm_init
from dsm.core.config import load as config_load
from dsm.crypto.enroll import EnrollError
from tests.test_init import _fake_enrollment, _server_flags


@pytest.fixture
def cfg_dir(tmp_path: Path) -> Path:
    (tmp_path / "dsm_ca_root.pem").write_bytes(b"-----BEGIN CERTIFICATE-----\n")
    passphrase = tmp_path / "pass"
    passphrase.write_bytes(b"hunter2hunter2\n")
    passphrase.chmod(0o600)
    return tmp_path


@contextlib.contextmanager
def _enrolls() -> Generator[mock.MagicMock, None, None]:
    with (
        mock.patch.object(dsm_init, "preflight_tpm"),
        mock.patch.object(
            dsm_init, "generate_enrollment", return_value=_fake_enrollment()
        ) as gen,
    ):
        yield gen


def _set(flags: list[str], name: str, value: str) -> list[str]:
    out = list(flags)
    out[out.index(name) + 1] = value
    return out


def _without(flags: list[str], name: str) -> list[str]:
    i = flags.index(name)
    return flags[:i] + flags[i + 2 :]


def test_init_on_an_enrolled_host_leaves_its_config_as_it_was(cfg_dir: Path) -> None:
    config = cfg_dir / "config.toml"
    config.write_text("# my hand edits\n")
    (cfg_dir / "identity.key").write_bytes(b"old key")
    with _enrolls() as gen, pytest.raises(SystemExit) as err:
        dsm_init.main(_server_flags(cfg_dir))
    assert err.value.code == 2
    assert config.read_text() == "# my hand edits\n"
    gen.assert_not_called()


def test_a_failed_enrollment_writes_no_config(cfg_dir: Path) -> None:
    def refuse(**_k: object) -> None:
        raise EnrollError("the TPM said no")

    with (
        mock.patch.object(dsm_init, "preflight_tpm"),
        mock.patch.object(dsm_init, "generate_enrollment", side_effect=refuse),
        pytest.raises(SystemExit),
    ):
        dsm_init.main(_server_flags(cfg_dir))
    assert not (cfg_dir / "config.toml").exists()
    assert not (cfg_dir / "config.toml.new").exists()


def test_a_config_that_does_not_check_out_writes_no_file(cfg_dir: Path) -> None:
    # A DoH provider given by name, not by IP address, is refused.
    flags = _set(
        _server_flags(cfg_dir), "--dns-provider", "https://dns.example/dns-query"
    )
    with _enrolls(), pytest.raises(SystemExit) as err:
        dsm_init.main(flags)
    assert err.value.code == 2
    assert not (cfg_dir / "config.toml").exists()
    assert not (cfg_dir / "config.toml.new").exists()


def _usb_ca(tmp_path: Path) -> Path:
    usb = tmp_path / "usb"
    usb.mkdir()
    ca = usb / "dsm_ca_root.pem"
    ca.write_bytes(b"-----BEGIN CERTIFICATE-----\nfrom the stick\n")
    ca.chmod(0o664)  # as `openssl req` leaves it
    return ca


def test_the_ca_root_is_copied_into_the_install_dir(
    cfg_dir: Path, tmp_path: Path
) -> None:
    ca = _usb_ca(tmp_path)
    inst = tmp_path / "inst"
    flags = _set(_server_flags(inst), "--ca-root", str(ca))
    flags = _set(flags, "--passphrase-env-file", str(cfg_dir / "pass"))
    with _enrolls():
        assert dsm_init.main(flags) == 0
    copied = inst / "dsm_ca_root.pem"
    assert copied.read_bytes() == ca.read_bytes()
    assert copied.stat().st_mode & 0o777 == 0o600
    assert config_load(inst / "config.toml").ca_root_file == str(copied)


def test_a_relative_ca_root_works(
    cfg_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ca = _usb_ca(tmp_path)
    monkeypatch.chdir(ca.parent)
    inst = tmp_path / "inst"
    flags = _set(_server_flags(inst), "--ca-root", ca.name)
    flags = _set(flags, "--passphrase-env-file", str(cfg_dir / "pass"))
    with _enrolls():
        assert dsm_init.main(flags) == 0
    assert config_load(inst / "config.toml").ca_root_file == str(
        inst / "dsm_ca_root.pem"
    )


@pytest.mark.parametrize("soft", [True, False])
def test_a_soft_build_writes_allow_soft_attest(cfg_dir: Path, soft: bool) -> None:
    with _enrolls(), mock.patch.object(dsm_init, "_backend_is_soft", return_value=soft):
        assert dsm_init.main(_server_flags(cfg_dir)) == 0
    assert config_load(cfg_dir / "config.toml").allow_soft_attest is soft


def test_a_server_needs_no_server_ip(cfg_dir: Path) -> None:
    with _enrolls():
        assert dsm_init.main(_without(_server_flags(cfg_dir), "--server-ip")) == 0
    assert config_load(cfg_dir / "config.toml").server_ip == "0.0.0.0"


def test_a_client_still_needs_its_server_ip(
    cfg_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    flags = _server_flags(cfg_dir)
    flags[0] = "client"
    flags = _without(
        _without(_without(flags, "--server-ip"), "--dns-provider"), "--dns-pin"
    )
    flags += ["--expected-server-cn", "dsm-x-server"]
    with _enrolls(), pytest.raises(SystemExit):
        dsm_init.main(flags)
    assert "--server-ip" in capsys.readouterr().err


def test_the_resume_hint_keeps_a_custom_install_dir(
    cfg_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with _enrolls():
        dsm_init.main(_server_flags(cfg_dir))
    assert f"--install-dir {cfg_dir}" in capsys.readouterr().out


def test_resume_without_state_says_what_to_run_first(
    cfg_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    argv = ["server", "--resume", "--install-dir", str(cfg_dir), "--signed-cert", "x"]
    with pytest.raises(SystemExit):
        dsm_init.main(argv)
    assert "run `dsm init server` without --resume first" in capsys.readouterr().err


def _resume(
    cfg_dir: Path, *, unit: bool = False, unit_at_resume: bool = False
) -> mock.MagicMock:
    flags = _server_flags(cfg_dir) + (["--install-unit"] if unit else [])
    with _enrolls():
        assert dsm_init.main(flags) == 0
    signed = cfg_dir / "signed.crt"
    signed.write_bytes(b"-----BEGIN CERTIFICATE-----\n")

    @contextlib.contextmanager
    def unlocked(
        *_a: object, on_unlocked: Any = None, **_k: object
    ) -> Generator[None, None, None]:
        if on_unlocked is not None:
            on_unlocked(bytearray(b"hunter2hunter2"))
        yield

    with (
        mock.patch.object(dsm_init, "loaded_stores_cli", unlocked),
        mock.patch.object(dsm_init, "import_signed_cert") as imp,
    ):
        argv = [
            "server",
            "--resume",
            "--install-dir",
            str(cfg_dir),
            "--signed-cert",
            str(signed),
            "--passphrase-env-file",
            str(cfg_dir / "pass"),
        ]
        if unit_at_resume:
            argv.append("--install-unit")
        assert dsm_init.main(argv) == 0
    return imp


def test_resume_lists_what_is_left_instead_of_done(
    cfg_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _resume(cfg_dir)
    out = capsys.readouterr().out
    assert "Done." not in out
    assert "Still to do before you start DSM:" in out
    assert str(cfg_dir / "dsm_ca.crl") in out
    assert str(cfg_dir / "allowed_cns.txt") in out
    assert f"sudo dsm --config {cfg_dir / 'config.toml'}" in out


def test_resume_checks_the_cert_against_the_role(cfg_dir: Path) -> None:
    assert _resume(cfg_dir).call_args.kwargs["role"] == "server"


@pytest.fixture
def cred(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "etc-dsm" / "passphrase"
    monkeypatch.setattr(dsm_init, "_CRED_FILE", path)
    # No unit source here: init prints the manual steps instead. No test
    # reads the host's own /etc/systemd/system.
    monkeypatch.setattr(dsm_init, "_DEPLOY_DIR", tmp_path / "no-deploy")
    (tmp_path / "units").mkdir()
    monkeypatch.setattr(dsm_init, "_SYSTEMD_DIR", tmp_path / "units")
    return path


def test_resume_with_the_unit_writes_the_proven_passphrase(
    cfg_dir: Path, cred: Path
) -> None:
    _resume(cfg_dir, unit=True)
    assert cred.read_bytes() == b"hunter2hunter2"
    assert cred.stat().st_mode & 0o777 == 0o600
    assert cred.parent.stat().st_mode & 0o777 == 0o700


def test_resume_keeps_a_passphrase_file_that_holds_one(
    cfg_dir: Path, cred: Path
) -> None:
    cred.parent.mkdir(mode=0o700)
    cred.write_bytes(b"already here")
    cred.chmod(0o600)
    _resume(cfg_dir, unit=True)
    assert cred.read_bytes() == b"already here"


def test_every_init_option_has_help() -> None:
    for action in dsm_init._build_parser()._actions:
        assert action.help, action.dest


def test_install_unit_given_only_at_resume_counts(
    cfg_dir: Path, cred: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _resume(cfg_dir, unit_at_resume=True)
    assert cred.read_bytes() == b"hunter2hunter2"
    assert "sudo systemctl start dsm" in capsys.readouterr().out


def test_a_unit_install_sh_put_in_place_is_not_called_missing(
    cfg_dir: Path, cred: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "units" / "dsm.service").write_text("server unit\n")
    _resume(cfg_dir, unit=True)
    captured = capsys.readouterr()
    assert "dsm.service is already installed" in captured.out
    assert "not found at the expected location" not in captured.err
    assert "enable --now" not in captured.out + captured.err


def test_the_server_unit_is_enabled_not_started(
    cfg_dir: Path, cred: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # QA M2: the server starts only once its allowlist has a client CN.
    _resume(cfg_dir, unit=True)  # no unit file anywhere: the manual steps
    captured = capsys.readouterr()
    assert "sudo systemctl enable dsm" in captured.err
    assert "enable --now" not in captured.out + captured.err
    assert "release tarball" not in captured.err


def test_resume_closes_a_passphrase_file_others_can_read(
    cfg_dir: Path, cred: Path
) -> None:
    cred.parent.mkdir()
    cred.parent.chmod(0o755)
    cred.write_bytes(b"already here")
    cred.chmod(0o644)
    _resume(cfg_dir, unit=True)
    assert cred.read_bytes() == b"already here"
    assert cred.stat().st_mode & 0o777 == 0o600
    assert cred.parent.stat().st_mode & 0o777 == 0o700


def test_init_asks_for_the_new_passphrase_twice(cfg_dir: Path) -> None:
    # QA M10. The other tests pass --passphrase-env-file, where confirm does
    # nothing, so the call itself is checked.
    seen: dict[str, Any] = {}

    def stop(**kwargs: Any) -> bytearray:
        seen.update(kwargs)
        raise ValueError("stop here")

    with (
        _enrolls() as gen,
        mock.patch.object(dsm_init, "read_passphrase", stop),
        pytest.raises(SystemExit),
    ):
        dsm_init.main(_server_flags(cfg_dir))
    assert seen["confirm"] is True
    gen.assert_not_called()
    assert not (cfg_dir / "config.toml").exists()
