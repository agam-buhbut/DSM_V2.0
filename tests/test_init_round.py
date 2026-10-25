"""dsm init, as a new user meets it (QA B2, M1, M6, M7, Minors 3, 13, 16,
Nit 2). The enrollment, the TPM check, the store unlock and the cert import
are faked, as in tests/test_init.py; files live in tmp_path."""

from __future__ import annotations

import contextlib
import errno
import hashlib
import os
from collections.abc import Generator
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

from dsm import init as dsm_init
from dsm.core import passphrase
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


def _fail_the_write(monkeypatch: pytest.MonkeyPatch) -> None:
    real = os.write

    def write(fd: int, data: Any) -> int:
        if bytes(data).startswith(b"hunter2"):
            raise OSError(errno.ENOSPC, "No space left on device")
        return real(fd, data)

    monkeypatch.setattr(os, "write", write)


def test_a_failed_write_leaves_no_passphrase_file(
    cfg_dir: Path,
    cred: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _fail_the_write(monkeypatch)
    _resume(cfg_dir, unit=True)
    captured = capsys.readouterr()
    assert not cred.exists()
    assert "put the passphrase there by hand" in captured.err
    assert "Ready." not in captured.out
    assert f"Put the key passphrase in {cred}" in captured.out


def test_a_hard_linked_passphrase_file_is_refused(
    cfg_dir: Path, cred: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cred.parent.mkdir(mode=0o700)
    other = cred.parent / "other"
    other.write_bytes(b"")
    os.link(other, cred)
    _resume(cfg_dir, unit=True)
    assert "more than one name" in capsys.readouterr().err
    assert other.read_bytes() == b""
    assert cred.read_bytes() == b""


def test_a_kept_hard_linked_file_is_warned_about(
    cfg_dir: Path, cred: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cred.parent.mkdir(mode=0o700)
    other = cred.parent / "other"
    other.write_bytes(b"already here")
    other.chmod(0o600)
    os.link(other, cred)
    _resume(cfg_dir, unit=True)
    captured = capsys.readouterr()
    assert "more than one name" in captured.out + captured.err
    assert cred.read_bytes() == b"already here"


def test_a_symlinked_passphrase_file_is_named_and_not_followed(
    cfg_dir: Path, cred: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cred.parent.mkdir(mode=0o700)
    target = tmp_path / "target"
    target.write_bytes(b"already here")
    target.chmod(0o644)
    cred.symlink_to(target)
    _resume(cfg_dir, unit=True)
    captured = capsys.readouterr()
    assert f"{cred} is a symlink; init did not check or change" in (
        captured.out + captured.err
    )
    assert target.read_bytes() == b"already here"
    assert target.stat().st_mode & 0o777 == 0o644


def test_a_dangling_symlink_is_not_written_through(
    cfg_dir: Path, cred: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cred.parent.mkdir(mode=0o700)
    target = tmp_path / "nowhere"
    cred.symlink_to(target)
    _resume(cfg_dir, unit=True)
    assert "is a symlink" in capsys.readouterr().err
    assert not target.exists()


def test_o_nofollow_stops_a_link_made_after_the_check(
    cfg_dir: Path,
    cred: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cred.parent.mkdir(mode=0o700)
    target = tmp_path / "target"
    target.write_bytes(b"")
    cred.symlink_to(target)
    monkeypatch.setattr(Path, "is_symlink", lambda _self: False)
    _resume(cfg_dir, unit=True)
    assert target.read_bytes() == b""
    assert "is a symlink" in capsys.readouterr().err


def test_an_empty_loose_passphrase_file_ends_0600_with_the_passphrase(
    cfg_dir: Path, cred: Path
) -> None:
    cred.parent.mkdir(mode=0o700)
    cred.write_bytes(b"")
    cred.chmod(0o644)
    _resume(cfg_dir, unit=True)
    assert cred.read_bytes() == b"hunter2hunter2"
    assert cred.stat().st_mode & 0o777 == 0o600


def test_a_ca_root_already_in_place_ends_0600(cfg_dir: Path) -> None:
    ca = cfg_dir / "dsm_ca_root.pem"
    ca.chmod(0o644)
    with _enrolls():
        assert dsm_init.main(_server_flags(cfg_dir)) == 0
    assert ca.stat().st_mode & 0o777 == 0o600


def test_the_proven_passphrase_is_wiped(
    cfg_dir: Path, cred: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[bytes] = []
    real = dsm_init.wipe_passphrase

    def record(buf: bytearray) -> None:
        seen.append(bytes(buf))
        real(buf)

    monkeypatch.setattr(dsm_init, "wipe_passphrase", record)
    _resume(cfg_dir, unit=True)
    # Once for the new passphrase, once for the one that unlocked the keys.
    assert seen.count(b"hunter2hunter2") == 2


def test_a_soft_build_says_so_in_the_config_file(cfg_dir: Path) -> None:
    with _enrolls(), mock.patch.object(dsm_init, "_backend_is_soft", return_value=True):
        assert dsm_init.main(_server_flags(cfg_dir)) == 0
    assert "# Evaluation build" in (cfg_dir / "config.toml").read_text()


def test_an_attest_key_alone_also_means_enrolled(cfg_dir: Path) -> None:
    (cfg_dir / "attest.key").write_bytes(b"old key")
    with _enrolls() as gen, pytest.raises(SystemExit) as err:
        dsm_init.main(_server_flags(cfg_dir))
    assert err.value.code == 2
    assert not (cfg_dir / "config.toml").exists()
    gen.assert_not_called()


def test_a_missing_ca_root_flag_is_named(
    cfg_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with _enrolls(), pytest.raises(SystemExit):
        dsm_init.main(_without(_server_flags(cfg_dir), "--ca-root"))
    assert "--ca-root" in capsys.readouterr().err


def _config_of(cfg_dir: Path, role: str = "server") -> Any:
    flags = _server_flags(cfg_dir)
    if role == "client":
        flags = _without(_without(flags, "--dns-provider"), "--dns-pin")
        flags[0] = "client"
        flags += ["--expected-server-cn", "dsm-x-server"]
    with _enrolls():
        assert dsm_init.main(flags) == 0
    return config_load(cfg_dir / "config.toml")


def test_a_client_is_told_to_wait_for_the_server(
    cfg_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cfg = _config_of(cfg_dir, "client")
    capsys.readouterr()
    dsm_init._print_next_steps("client", cfg, cfg_dir / "config.toml", False)
    out = capsys.readouterr().out
    assert "Still to do before you start DSM:" in out
    assert "Wait until the server's allowlist has this client's CN" in out


def _ready_server(cfg_dir: Path, cred: Path) -> Any:
    cfg = _config_of(cfg_dir)
    Path(cfg.crl_file).write_bytes(b"crl")
    Path(cfg.allowed_cns_file).write_text("# none\ndsm-x-client\n")
    cred.parent.mkdir()
    cred.write_bytes(b"x")
    return cfg


def test_a_server_with_nothing_left_is_ready(
    cfg_dir: Path, cred: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cfg = _ready_server(cfg_dir, cred)
    (tmp_path / "units" / "dsm.service").write_text("unit\n")
    capsys.readouterr()
    dsm_init._print_next_steps("server", cfg, cfg_dir / "config.toml", True)
    out = capsys.readouterr().out
    assert "Ready. Start it: sudo systemctl start dsm" in out
    assert "Still to do" not in out


def test_a_missing_unit_is_never_ready(
    cfg_dir: Path, cred: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cfg = _ready_server(cfg_dir, cred)
    capsys.readouterr()
    dsm_init._print_next_steps("server", cfg, cfg_dir / "config.toml", True)
    out = capsys.readouterr().out
    assert "Ready." not in out
    assert "Copy deploy/dsm.service to /etc/systemd/system/" in out
    assert "sudo systemctl daemon-reload && sudo systemctl enable dsm" in out


def test_the_list_asks_for_a_missing_passphrase(
    cfg_dir: Path, cred: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cfg = _config_of(cfg_dir)
    capsys.readouterr()
    dsm_init._print_next_steps("server", cfg, cfg_dir / "config.toml", True)
    assert f"Put the key passphrase in {cred}" in capsys.readouterr().out


def test_the_resume_hint_quotes_a_path_with_a_space(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    inst = tmp_path / "my dir"
    inst.mkdir()
    (inst / "dsm_ca_root.pem").write_bytes(b"-----BEGIN CERTIFICATE-----\n")
    (inst / "pass").write_bytes(b"hunter2hunter2\n")
    (inst / "pass").chmod(0o600)
    with _enrolls():
        assert dsm_init.main(_server_flags(inst)) == 0
    assert f"--install-dir '{inst}'" in capsys.readouterr().out


def test_force_with_two_different_answers_keeps_the_old_keys(
    cfg_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # A typo in the second answer must leave the old enrollment in place, so
    # "nothing was changed" is true.
    monkeypatch.delenv("DSM_PASSPHRASE_FILE", raising=False)
    monkeypatch.delenv("DSM_PASSPHRASE", raising=False)
    for name in ("identity.key", "attest.key", ".dsm-init-state.json"):
        (cfg_dir / name).write_bytes(b"old")
    stdin = mock.MagicMock()
    stdin.isatty.return_value = True
    tty = mock.MagicMock(
        side_effect=[bytearray(b"one secret"), bytearray(b"one secrte")]
    )
    flags = _without(_server_flags(cfg_dir), "--passphrase-env-file") + ["--force"]
    with (
        _enrolls() as gen,
        mock.patch.object(passphrase, "_read_from_tty", tty),
        mock.patch.object(passphrase.sys, "stdin", stdin),
        pytest.raises(SystemExit) as err,
    ):
        dsm_init.main(flags)
    assert err.value.code == 2
    gen.assert_not_called()
    for name in ("identity.key", "attest.key", ".dsm-init-state.json"):
        assert (cfg_dir / name).read_bytes() == b"old", name
    stderr = capsys.readouterr().err
    assert "the two passphrases do not match; nothing was changed" in stderr
    assert "removing existing enrollment keys" not in stderr


def _enrolled_under_ca_a(cfg_dir: Path) -> dict[str, bytes]:
    """An install dir init enrolled under the fixture's CA, with its keys.
    Returns the bytes of each file a failed --force run must keep."""
    with _enrolls():
        assert dsm_init.main(_server_flags(cfg_dir)) == 0
    for name in ("identity.key", "attest.key"):
        (cfg_dir / name).write_bytes(b"old")
    kept = (
        "dsm_ca_root.pem",
        "config.toml",
        "identity.key",
        "attest.key",
        ".dsm-init-state.json",
    )
    return {name: (cfg_dir / name).read_bytes() for name in kept}


@pytest.mark.parametrize(
    "how",
    ["two different answers", "an empty passphrase file", "a config that fails"],
)
def test_a_failed_force_run_keeps_the_old_ca_copy(
    cfg_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, how: str
) -> None:
    # The kept config pins the old CA, so the kept copy must still be it.
    before = _enrolled_under_ca_a(cfg_dir)
    flags = _set(_server_flags(cfg_dir), "--ca-root", str(_usb_ca(tmp_path)))
    flags.append("--force")
    if how == "two different answers":
        flags = _without(flags, "--passphrase-env-file")
    elif how == "an empty passphrase file":
        empty = tmp_path / "empty"
        empty.write_bytes(b"")
        empty.chmod(0o600)
        flags = _set(flags, "--passphrase-env-file", str(empty))
    else:
        flags = _set(flags, "--dns-provider", "https://dns.example/dns-query")
    monkeypatch.delenv("DSM_PASSPHRASE_FILE", raising=False)
    monkeypatch.delenv("DSM_PASSPHRASE", raising=False)
    stdin = mock.MagicMock()
    stdin.isatty.return_value = True
    tty = mock.MagicMock(
        side_effect=[bytearray(b"one secret"), bytearray(b"one secrte")]
    )
    with (
        _enrolls() as gen,
        mock.patch.object(passphrase, "_read_from_tty", tty),
        mock.patch.object(passphrase.sys, "stdin", stdin),
        pytest.raises(SystemExit) as err,
    ):
        dsm_init.main(flags)
    assert err.value.code == 2
    gen.assert_not_called()
    for name, data in before.items():
        assert (cfg_dir / name).read_bytes() == data, name
    copy = (cfg_dir / "dsm_ca_root.pem").read_bytes()
    pin = config_load(cfg_dir / "config.toml").ca_root_sha256
    assert pin == hashlib.sha256(copy).hexdigest()
    assert not list(cfg_dir.glob("*.new"))


def test_a_good_force_run_copies_the_new_ca_and_pins_it(
    cfg_dir: Path, tmp_path: Path
) -> None:
    _enrolled_under_ca_a(cfg_dir)
    ca = _usb_ca(tmp_path)
    flags = _set(_server_flags(cfg_dir), "--ca-root", str(ca)) + ["--force"]
    with _enrolls():
        assert dsm_init.main(flags) == 0
    copy = cfg_dir / "dsm_ca_root.pem"
    assert copy.read_bytes() == ca.read_bytes()
    assert copy.stat().st_mode & 0o777 == 0o600
    cfg = config_load(cfg_dir / "config.toml")
    assert cfg.ca_root_file == str(copy)
    assert cfg.ca_root_sha256 == hashlib.sha256(ca.read_bytes()).hexdigest()
