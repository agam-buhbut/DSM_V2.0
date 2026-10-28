"""What the QA re-run found (QA2): the laptop pass's Major, Minors and Nits,
and the lab box's N1-N5. Enrollment, the TPM check and the store unlock are
faked as in tests/test_init.py; certs come from tests/cert_helpers.py; files
live in tmp_path. Nothing here needs root or touches the host."""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import datetime
import logging
import os
import shutil
import subprocess
from collections.abc import Generator
from pathlib import Path
from typing import Any
from unittest import mock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

import dsm.__main__ as entry
from dsm import init as dsm_init
from dsm.core import config as dsm_config
from dsm.core import passphrase
from dsm.core.config import ConfigError, load
from dsm.core.log import RepeatLog
from dsm.core.passphrase import PassphraseError, read_passphrase
from dsm.crypto._stores import load_daemon_stores, loaded_stores_cli
from dsm.crypto.attest_store import AttestStore
from dsm.crypto.auth_loader import AuthMaterialsError, load_cert_materials
from dsm.crypto.cert_allowlist import CNAllowlist
from dsm.crypto.enroll import EnrollError, generate_enrollment, import_signed_cert
from dsm.crypto.handshake import CertRevokedError, client_handshake, server_handshake
from dsm.crypto.keystore import KeyStore
from dsm.net import dns as dsm_dns
from dsm.net.dns import DNSResolver
from dsm.net.nftables import PreHandshakeKillSwitch
from dsm.server import run_server
from tests.cert_helpers import (
    CLIENT_AUTH_OID,
    SERVER_AUTH_OID,
    IssuingCA,
    make_enrolled_device,
    make_leaf_cert,
    make_test_ca,
    public_spki_der_from_priv,
)
from tests.test_client_fail_closed import _config as _client_config
from tests.test_client_start_block import _Start
from tests.test_handshake_integration import _build_crl_with_revoked
from tests.test_init import _fake_enrollment, _server_flags
from tests.test_server_dns_fatal import _base_patches, _run_until, _server_config
from tests.test_units_and_release import _FAKE_CURL, _RECORDER, INSTALL, RELEASE, _sums


@contextlib.contextmanager
def _enrolls() -> Generator[mock.MagicMock, None, None]:
    with (
        mock.patch.object(dsm_init, "preflight_tpm"),
        mock.patch.object(
            dsm_init, "generate_enrollment", return_value=_fake_enrollment()
        ) as gen,
    ):
        yield gen


@contextlib.contextmanager
def _unlocked(
    *_a: object, on_unlocked: Any = None, **_k: object
) -> Generator[None, None, None]:
    if on_unlocked is not None:
        on_unlocked(bytearray(b"hunter2hunter2"))
    yield


def _set(flags: list[str], name: str, value: str) -> list[str]:
    out = list(flags)
    out[out.index(name) + 1] = value
    return out


def _passphrase_file(tmp_path: Path) -> Path:
    path = tmp_path / "pass"
    path.write_bytes(b"hunter2hunter2\n")
    path.chmod(0o600)
    return path


def _crl_pem(ca: IssuingCA) -> bytes:
    now = datetime.datetime.now(datetime.UTC)
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca.certificate.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=30))
        .sign(ca.private_key, hashes.SHA384())
    )
    return crl.public_bytes(Encoding.PEM)


def _leaf_pem(ca: IssuingCA) -> bytes:
    spki = public_spki_der_from_priv(ec.generate_private_key(ec.SECP256R1()))
    leaf = make_leaf_cert(
        ca,
        subject_cn="dsm-aabbccddeeff-client",
        leaf_public_spki_der=spki,
        noise_static_pub=b"\x01" * 32,
    )
    return leaf.public_bytes(Encoding.PEM)


# --- Major 1: a CA root that is not a CA certificate --------------------------

_NO_PEM = "no PEM certificate in it"


@pytest.mark.parametrize(
    ("kind", "reason"),
    [
        ("the CRL", _NO_PEM),
        ("a passphrase file", _NO_PEM),
        ("a leaf cert", "CA root must have basicConstraints CA:TRUE"),
    ],
)
def test_init_refuses_a_ca_root_that_is_not_a_ca_cert_before_writing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], kind: str, reason: str
) -> None:
    ca = make_test_ca()
    stick = tmp_path / "stick"
    stick.mkdir()
    bad = stick / "wrong.pem"
    if kind == "the CRL":
        bad.write_bytes(_crl_pem(ca))
    elif kind == "a passphrase file":
        bad.write_bytes(b"hunter2hunter2\n")
    else:
        bad.write_bytes(_leaf_pem(ca))
    inst = tmp_path / "inst"
    flags = _set(_server_flags(inst), "--ca-root", str(bad))
    flags = _set(flags, "--passphrase-env-file", str(_passphrase_file(tmp_path)))

    with _enrolls() as gen, pytest.raises(SystemExit) as err:
        dsm_init.main(flags)

    assert err.value.code == 2
    refusals = [
        line
        for line in capsys.readouterr().err.splitlines()
        if line.startswith("dsm init: --ca-root")
    ]
    assert refusals == [
        f"dsm init: --ca-root {bad} is not a CA certificate (PEM): {reason}"
    ]
    gen.assert_not_called()
    assert not inst.exists() or not list(inst.iterdir())


def _enrolled_install_dir(tmp_path: Path) -> tuple[Path, Path]:
    """An install dir after a good phase A, and a cert that parses."""
    ca = make_test_ca()
    ca_file = tmp_path / "dsm_ca_root.pem"
    ca_file.write_bytes(ca.pem)
    inst = tmp_path / "inst"
    flags = _set(_server_flags(inst), "--ca-root", str(ca_file))
    flags = _set(flags, "--passphrase-env-file", str(_passphrase_file(tmp_path)))
    with _enrolls():
        assert dsm_init.main(flags) == 0
    signed = tmp_path / "signed.pem"
    signed.write_bytes(_leaf_pem(ca))
    return inst, signed


def test_resume_with_a_bad_ca_copy_is_one_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    inst, signed = _enrolled_install_dir(tmp_path)
    copy = inst / "dsm_ca_root.pem"
    copy.write_bytes(b"not a certificate\n")
    capsys.readouterr()
    argv = [
        "server",
        "--resume",
        "--install-dir",
        str(inst),
        "--signed-cert",
        str(signed),
        "--passphrase-env-file",
        str(tmp_path / "pass"),
    ]

    with (
        mock.patch.object(dsm_init, "loaded_stores_cli", _unlocked),
        pytest.raises(SystemExit) as err,
    ):
        dsm_init.main(argv)

    assert err.value.code == 2
    assert capsys.readouterr().err.splitlines() == [
        f"dsm init: the CA root {copy} is not a CA certificate (PEM): {_NO_PEM}"
    ]
    assert (inst / ".dsm-init-state.json").exists()


def test_enroll_import_with_a_bad_ca_copy_is_one_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    ca = make_test_ca()
    bad_ca = tmp_path / "ca.pem"
    bad_ca.write_bytes(_crl_pem(ca))
    config = tmp_path / "config.toml"
    config.write_text(
        'mode = "client"\nserver_ip = "10.0.0.1"\nserver_port = 51820\n'
        "listen_port = 0\n"
        f'key_file = "{tmp_path}/identity.key"\n'
        f'cert_file = "{tmp_path}/device.crt"\n'
        f'ca_root_file = "{bad_ca}"\n'
        f'attest_key_file = "{tmp_path}/attest.key"\n'
        'expected_server_cn = "dsm-x-server"\n'
    )
    config.chmod(0o600)
    signed = tmp_path / "signed.pem"
    signed.write_bytes(_leaf_pem(ca))

    with (
        mock.patch("dsm.crypto._stores.loaded_stores_cli", _unlocked),
        pytest.raises(SystemExit) as err,
    ):
        entry._run_enroll(
            config,
            csr_out=None,
            import_cert=signed,
            cn=None,
            role=None,
            passphrase_fd=None,
            passphrase_env_file=None,
        )

    assert err.value.code == 2
    assert capsys.readouterr().err.splitlines() == [
        f"enroll: the CA root {bad_ca} is not a CA certificate (PEM): {_NO_PEM}"
    ]
    assert not (tmp_path / "device.crt").exists()


# --- Minor 1: --install-unit without root --------------------------------------

_NEED_ROOT = "dsm init: --install-unit must run as root: use sudo\n"


def _ca_file(tmp_path: Path) -> Path:
    path = tmp_path / "dsm_ca_root.pem"
    path.write_bytes(make_test_ca().pem)
    return path


def _phase_a_flags(tmp_path: Path, inst: Path) -> list[str]:
    flags = _set(_server_flags(inst), "--ca-root", str(_ca_file(tmp_path)))
    return _set(flags, "--passphrase-env-file", str(_passphrase_file(tmp_path)))


def test_install_unit_without_root_stops_before_anything_is_written(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    inst = tmp_path / "inst"
    monkeypatch.setattr(dsm_init, "_is_root", lambda: False)

    with _enrolls() as gen, pytest.raises(SystemExit) as err:
        dsm_init.main([*_phase_a_flags(tmp_path, inst), "--install-unit"])

    assert err.value.code == 1
    assert capsys.readouterr().err == _NEED_ROOT
    gen.assert_not_called()
    assert not inst.exists()


@pytest.mark.parametrize("given_at", ["the first step", "--resume"])
def test_resume_with_the_unit_without_root_stops_before_the_import(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    given_at: str,
) -> None:
    cred = tmp_path / "etc-dsm" / "passphrase"
    monkeypatch.setattr(dsm_init, "_CRED_FILE", cred)
    inst = tmp_path / "inst"
    first = _phase_a_flags(tmp_path, inst)
    if given_at == "the first step":
        first.append("--install-unit")
    monkeypatch.setattr(dsm_init, "_is_root", lambda: True)
    with _enrolls():
        assert dsm_init.main(first) == 0
    capsys.readouterr()
    signed = tmp_path / "signed.pem"
    signed.write_bytes(b"-----BEGIN CERTIFICATE-----\n")
    argv = [
        "server",
        "--resume",
        "--install-dir",
        str(inst),
        "--signed-cert",
        str(signed),
        "--passphrase-env-file",
        str(tmp_path / "pass"),
    ]
    if given_at == "--resume":
        argv.append("--install-unit")
    monkeypatch.setattr(dsm_init, "_is_root", lambda: False)

    with (
        mock.patch.object(dsm_init, "loaded_stores_cli", _unlocked),
        mock.patch.object(dsm_init, "import_signed_cert") as imp,
        pytest.raises(SystemExit) as err,
    ):
        dsm_init.main(argv)

    assert err.value.code == 1
    assert capsys.readouterr().err == _NEED_ROOT
    imp.assert_not_called()
    assert (inst / ".dsm-init-state.json").exists()
    assert not cred.exists()


def test_a_unit_copy_that_fails_is_one_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    deploy = tmp_path / "deploy"
    deploy.mkdir()
    (deploy / "dsm.service").write_text("server unit\n")
    monkeypatch.setattr(dsm_init, "_DEPLOY_DIR", deploy)
    monkeypatch.setattr(dsm_init, "_SYSTEMD_DIR", tmp_path / "no-such-dir")
    monkeypatch.setattr(dsm_init, "_CRED_FILE", tmp_path / "etc-dsm" / "passphrase")
    run = mock.MagicMock()
    monkeypatch.setattr(dsm_init.subprocess, "run", run)

    with pytest.raises(SystemExit) as err:
        dsm_init._install_unit("server")

    assert err.value.code == 1
    dst = tmp_path / "no-such-dir" / "dsm.service"
    assert capsys.readouterr().err == (
        f"dsm init: could not install {dst}: No such file or directory\n"
    )
    run.assert_not_called()


# --- Minor 4: a root-owned config without sudo ----------------------------------

_GOOD_CLIENT = (
    'mode = "client"\nserver_ip = "10.0.0.1"\nserver_port = 51820\n'
    'listen_port = 0\nkey_file = "/tmp/k"\ncert_file = "/tmp/c"\n'
    'ca_root_file = "/tmp/ca"\nattest_key_file = "/tmp/a"\n'
    'expected_server_cn = "dsm-x-server"\n'
)


def _write_config(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "config.toml"
    path.write_text(text)
    path.chmod(0o600)
    return path


def _looks_owned_by(monkeypatch: pytest.MonkeyPatch, path: Path, uid: int) -> None:
    """Path.stat (and so Path.lstat) reports ``uid`` as the owner of ``path``;
    the user running the test is uid 1000, not root."""
    _fake_owner(monkeypatch, path, uid)
    monkeypatch.setattr("dsm.core.path_security.os.getuid", lambda: 1000)
    monkeypatch.setattr(dsm_config.os, "geteuid", lambda: 1000)


def _fake_owner(monkeypatch: pytest.MonkeyPatch, path: Path, uid: int) -> None:
    """Path.stat (and so Path.lstat) reports ``uid`` as the owner of ``path``."""
    real = Path.stat

    def stat(self: Path, *args: Any, **kwargs: Any) -> os.stat_result:
        st = real(self, *args, **kwargs)
        if self != path:
            return st
        fields = list(st[:10])
        fields[4] = uid
        return os.stat_result(fields)

    monkeypatch.setattr(Path, "stat", stat)


def test_a_root_owned_config_without_sudo_says_use_sudo(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_config(tmp_path, _GOOD_CLIENT)
    _looks_owned_by(monkeypatch, path, 0)

    with pytest.raises(SystemExit) as err:
        entry._run_show_pubkey(path, passphrase_fd=None, passphrase_env_file=None)

    assert err.value.code == 2
    assert capsys.readouterr().err == (
        f"config: {path} belongs to root: run it with sudo\n"
    )


def test_a_config_of_another_user_keeps_the_owner_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_config(tmp_path, _GOOD_CLIENT)
    _looks_owned_by(monkeypatch, path, 4242)

    with pytest.raises(ConfigError) as err:
        load(path)

    assert str(err.value) == (
        "refusing to load config with insecure permissions: "
        f"{path} owned by uid 4242, expected 1000. Refusing to trust a file "
        "owned by another user."
    )


# --- Minor 2: a missing setting -------------------------------------------------

_REQUIRED = [
    "mode",
    "server_ip",
    "server_port",
    "listen_port",
    "key_file",
    "cert_file",
    "ca_root_file",
    "attest_key_file",
]


def _without_key(text: str, key: str) -> str:
    return "".join(
        line + "\n" for line in text.splitlines() if not line.startswith(f"{key} =")
    )


@pytest.mark.parametrize("key", _REQUIRED)
def test_every_missing_required_setting_is_named(tmp_path: Path, key: str) -> None:
    path = _write_config(tmp_path, _without_key(_GOOD_CLIENT, key))

    with pytest.raises(ConfigError) as err:
        load(path)

    assert str(err.value) == f"missing setting '{key}'"


def test_the_required_settings_come_from_the_config_class() -> None:
    from dataclasses import MISSING, fields

    from dsm.core.config import Config

    required = [
        f.name
        for f in fields(Config)
        if f.default is MISSING and f.default_factory is MISSING
    ]
    assert required == _REQUIRED


def test_a_server_without_server_ip_is_told_any_address_will_do(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    server = (
        'mode = "server"\nserver_port = 51820\nlisten_port = 51820\n'
        'key_file = "/tmp/k"\ncert_file = "/tmp/c"\nca_root_file = "/tmp/ca"\n'
        'attest_key_file = "/tmp/a"\nallowed_cns_file = "/tmp/allowed"\n'
    )
    path = _write_config(tmp_path, server)

    with pytest.raises(SystemExit) as err:
        entry._load_config_or_exit(path)

    assert err.value.code == 2
    assert capsys.readouterr().err == (
        "config: missing setting 'server_ip'; a server does not use it: any "
        "IPv4 address, for example 0.0.0.0\n"
    )


# --- Nit 7: no passphrase source and no terminal --------------------------------

_NO_SOURCE = (
    "no passphrase source was given and there is no terminal to ask on (use "
    "--passphrase-env-file, or run it in a terminal)"
)


def _stdin_without_terminal(data: bytes) -> mock.MagicMock:
    stdin = mock.MagicMock()
    stdin.isatty.return_value = False
    stdin.buffer.readline.return_value = data
    return stdin


@pytest.fixture
def _no_env_passphrase(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DSM_PASSPHRASE", raising=False)
    monkeypatch.delenv("DSM_PASSPHRASE_FILE", raising=False)


@pytest.mark.usefixtures("_no_env_passphrase")
def test_no_source_and_no_terminal_says_so(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with (
        mock.patch.object(passphrase.sys, "stdin", _stdin_without_terminal(b"")),
        pytest.raises(SystemExit) as err,
    ):
        with loaded_stores_cli(
            mock.MagicMock(),
            mock.MagicMock(),
            key_file_label="identity.key",
            attest_key_file_label="attest.key",
        ):
            pass

    assert err.value.code == 2
    assert capsys.readouterr().err == f"cannot unlock the keys: {_NO_SOURCE}\n"


@pytest.mark.usefixtures("_no_env_passphrase")
def test_a_piped_empty_line_is_still_an_empty_passphrase() -> None:
    with (
        mock.patch.object(passphrase.sys, "stdin", _stdin_without_terminal(b"\n")),
        pytest.raises(PassphraseError) as err,
    ):
        read_passphrase()
    assert str(err.value) == "passphrase must not be empty"


# --- Nit 3: unlock errors without Python class names ---------------------------


@pytest.mark.parametrize("store", ["identity", "attest key"])
def test_unlock_errors_name_no_python_class(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], store: str
) -> None:
    keystore = mock.MagicMock()
    attest = mock.MagicMock()
    failing = keystore if store == "identity" else attest
    failing.load_with_passphrase.side_effect = RuntimeError(
        "decryption failed: wrong passphrase or corrupted data"
    )
    label = "/opt/mtun/identity.key" if store == "identity" else "/opt/mtun/attest.key"

    with pytest.raises(SystemExit) as err:
        with loaded_stores_cli(
            keystore,
            attest,
            passphrase_env_file=str(_passphrase_file(tmp_path)),
            key_file_label="/opt/mtun/identity.key",
            attest_key_file_label="/opt/mtun/attest.key",
        ):
            pass

    assert err.value.code == 2
    assert capsys.readouterr().err == (
        f"failed to unlock {store} at {label}: decryption failed: wrong "
        "passphrase or corrupted data\n"
    )


@pytest.mark.parametrize("store", [KeyStore, AttestStore])
def test_a_missing_key_names_the_real_enroll_command(
    tmp_path: Path, store: type[KeyStore] | type[AttestStore]
) -> None:
    with pytest.raises(RuntimeError) as err:
        store(str(tmp_path / "missing.key")).load_with_passphrase(bytearray(b"x"))
    assert str(err.value).endswith(
        "; run `sudo dsm enroll --csr-out <csr file>` to make one "
        "(deploy/GUIDE.md §3b)"
    )


# --- also seen: enroll's texts -------------------------------------------------


def test_enroll_ends_with_the_whole_import_command(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = _write_config(tmp_path, _GOOD_CLIENT)
    with (
        mock.patch(
            "dsm.core.passphrase.read_passphrase",
            return_value=bytearray(b"hunter2hunter2"),
        ),
        mock.patch(
            "dsm.crypto.enroll.generate_enrollment", return_value=_fake_enrollment()
        ),
        mock.patch("dsm.crypto.tpm_preflight.preflight_tpm"),
    ):
        entry._run_enroll(
            config,
            csr_out=tmp_path / "x.csr",
            import_cert=None,
            cn=None,
            role="client",
            passphrase_fd=None,
            passphrase_env_file=None,
        )
    assert (
        f"then run `sudo dsm --config {config} enroll --import <signed.crt>`."
        in capsys.readouterr().out
    )


@pytest.mark.parametrize(
    ("which", "path"),
    [("identity", "/opt/mtun/identity.key"), ("attest", "/opt/mtun/attest.key")],
)
def test_enroll_on_an_enrolled_host_names_the_three_files(
    which: str, path: str
) -> None:
    keystore = mock.MagicMock(path="/opt/mtun/identity.key")
    attest = mock.MagicMock(path="/opt/mtun/attest.key")
    keystore.exists.return_value = which == "identity"
    attest.exists.return_value = True

    with pytest.raises(EnrollError) as err:
        generate_enrollment(
            keystore=keystore, attest_store=attest, passphrase=b"x", role="client"
        )

    assert str(err.value) == (
        f"{which} key already exists at {path}: this host is already enrolled. "
        "To enroll it again, first remove identity.key, attest.key and "
        "device.crt by hand (deploy/GUIDE.md §7c)"
    )


def test_a_cert_made_for_another_device_says_so_plainly(tmp_path: Path) -> None:
    ca = make_test_ca()
    ca_file = tmp_path / "ca.pem"
    ca_file.write_bytes(ca.pem)
    signed = tmp_path / "signed.pem"
    signed.write_bytes(_leaf_pem(ca))  # binds b"\x01" * 32
    keystore = mock.MagicMock()
    keystore.identity.public_key = b"\x02" * 32

    with pytest.raises(EnrollError) as err:
        import_signed_cert(
            cert_input_path=signed,
            cert_output_path=tmp_path / "device.crt",
            ca_root_path=ca_file,
            keystore=keystore,
            attest_store=mock.MagicMock(),
        )

    assert str(err.value) == (
        "this certificate was made for another device: its key does not "
        "match this host's identity key"
    )
    assert not (tmp_path / "device.crt").exists()


# --- commit 3: init's next steps ----------------------------------------------

_CONSOLE = (
    "(at the console, not over SSH: DSM blocks all traffic before it asks for "
    "the passphrase)"
)


def _client_flags(tmp_path: Path, inst: Path) -> list[str]:
    flags = _phase_a_flags(tmp_path, inst)
    flags[0] = "client"
    for name in ("--dns-provider", "--dns-pin"):
        i = flags.index(name)
        flags = flags[:i] + flags[i + 2 :]
    return [*flags, "--expected-server-cn", "dsm-x-server"]


def _resume_argv(role: str, inst: Path, tmp_path: Path) -> list[str]:
    signed = tmp_path / "signed.pem"
    signed.write_bytes(b"-----BEGIN CERTIFICATE-----\n")
    return [
        role,
        "--resume",
        "--install-dir",
        str(inst),
        "--signed-cert",
        str(signed),
        "--passphrase-env-file",
        str(tmp_path / "pass"),
    ]


def _resume_out(
    role: str, tmp_path: Path, capsys: pytest.CaptureFixture[str], *, unit: bool
) -> str:
    inst = tmp_path / "inst"
    first = (
        _client_flags(tmp_path, inst)
        if role == "client"
        else _phase_a_flags(tmp_path, inst)
    )
    with _enrolls():
        assert dsm_init.main(first + (["--install-unit"] if unit else [])) == 0
    capsys.readouterr()
    with (
        mock.patch.object(dsm_init, "loaded_stores_cli", _unlocked),
        mock.patch.object(dsm_init, "import_signed_cert"),
    ):
        assert dsm_init.main(_resume_argv(role, inst, tmp_path)) == 0
    return capsys.readouterr().out


def test_a_client_started_by_hand_is_told_to_use_the_console(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = _resume_out("client", tmp_path, capsys, unit=False)
    config = tmp_path / "inst" / "config.toml"
    assert f"Then start it: sudo dsm --config {config} {_CONSOLE}" in out


def test_a_server_started_by_hand_gets_no_console_note(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = _resume_out("server", tmp_path, capsys, unit=False)
    assert f"sudo dsm --config {tmp_path / 'inst' / 'config.toml'}" in out
    assert "at the console" not in out


def test_a_client_unit_resume_gives_the_start_line_once(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    deploy = tmp_path / "deploy"
    deploy.mkdir()
    (deploy / "dsm-client.service").write_text("client unit\n")
    (tmp_path / "units").mkdir()
    monkeypatch.setattr(dsm_init, "_DEPLOY_DIR", deploy)
    monkeypatch.setattr(dsm_init, "_SYSTEMD_DIR", tmp_path / "units")
    monkeypatch.setattr(dsm_init, "_CRED_FILE", tmp_path / "etc-dsm" / "passphrase")
    monkeypatch.setattr(dsm_init, "_is_root", lambda: True)
    monkeypatch.setattr(dsm_init.subprocess, "run", mock.MagicMock())

    out = _resume_out("client", tmp_path, capsys, unit=True)

    assert out.count("sudo systemctl start dsm-client") == 1
    assert "Then start it: sudo systemctl start dsm-client" in out
    assert "Installed dsm-client.service" in out


@pytest.mark.parametrize("crl", ["there", "missing", "unreadable"])
def test_the_crl_line_comes_only_without_a_readable_crl(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], crl: str
) -> None:
    if crl == "unreadable" and os.geteuid() == 0:
        pytest.skip("root can read any file")
    inst = tmp_path / "inst"
    inst.mkdir(mode=0o700)
    if crl != "missing":
        (inst / "dsm_ca.crl").write_bytes(_crl_pem(make_test_ca()))
        (inst / "dsm_ca.crl").chmod(0o000 if crl == "unreadable" else 0o600)

    with _enrolls():
        assert dsm_init.main(_phase_a_flags(tmp_path, inst)) == 0

    said = "the daemon will NOT start until a current CRL" in capsys.readouterr().err
    assert said is (crl != "there")


def test_the_install_unit_help_says_what_it_does() -> None:
    (action,) = [
        a for a in dsm_init._build_parser()._actions if a.dest == "install_unit"
    ]
    assert action.help == (
        "write /etc/dsm/passphrase and install the systemd unit (from an "
        "installed wheel it only says how to copy it)"
    )


# --- commit 4: server messages --------------------------------------------------


class _Allowlist:
    def __init__(self, names: list[str]) -> None:
        self.order = tuple(names)

    def __len__(self) -> int:
        return len(self.order)


@pytest.mark.parametrize(
    ("names", "line"),
    [
        (["dsm-a-client"], "CN allowlist loaded (1 entry)"),
        (["dsm-a-client", "dsm-b-client"], "CN allowlist loaded (2 entries)"),
    ],
)
async def test_the_allowlist_line_counts_entry_or_entries(
    caplog: pytest.LogCaptureFixture, names: list[str], line: str
) -> None:
    caplog.set_level(logging.INFO, logger="dsm.server")
    captured: dict[str, Any] = {}
    with (
        _base_patches(captured),
        mock.patch("dsm.server.CNAllowlist.from_file", return_value=_Allowlist(names)),
    ):
        assert await _run_until(_server_config(), captured) == 0
    assert line in [r.getMessage() for r in caplog.records]


@pytest.mark.parametrize(
    ("mtu", "warned"), [(1360, False), (1361, True), (1400, True), (1500, True)]
)
def test_the_mtu_warning_starts_above_1360(
    caplog: pytest.LogCaptureFixture, mtu: int, warned: bool
) -> None:
    caplog.set_level(logging.WARNING, logger="dsm")
    _client_config(mtu=mtu)
    lines = [r.getMessage() for r in caplog.records if f"mtu={mtu}" in r.getMessage()]
    expected = (
        f"configured tun mtu={mtu} is above 1360. Use 1360, the default: above "
        "it every full-size packet is split in two."
    )
    assert lines == ([expected] if warned else [])


# --- commit 6: install.sh and release.yml (N1, N2, N3) --------------------------

_TPM_WHEEL = "dsm-0.1.0-cp311-abi3-manylinux_2_35_x86_64.whl"
_SOFT = "dsm-0.1.0+soft-cp311-abi3-manylinux_2_35_x86_64.whl"
_DEPS = [
    "cffi-2.0.0-cp311-cp311-manylinux2014_x86_64.manylinux_2_17_x86_64.whl",
    "cffi-2.0.0-cp313-cp313-manylinux2014_x86_64.manylinux_2_17_x86_64.whl",
    "dnspython-2.8.0-py3-none-any.whl",
]


def _verify_command() -> str:
    start = INSTALL.index("minisign -V ")
    return INSTALL[start : INSTALL.index("\n", INSTALL.index("|| die", start))]


def test_install_sh_gives_minisign_the_key_itself_not_a_key_file() -> None:
    assert _verify_command() == (
        'minisign -V -P "$MINISIGN_PUBKEY" -m "$WORK/SHA256SUMS" \\\n'
        '  || die "minisign verification FAILED — refusing to continue"'
    )
    assert "pubkey.pub" not in INSTALL


@pytest.mark.skipif(
    shutil.which("minisign") is None,
    reason="needs the real minisign; the release check on the box covers it",
)
@pytest.mark.parametrize("case", ["good", "changed list", "wrong key"])
def test_the_verify_command_with_the_real_minisign(tmp_path: Path, case: str) -> None:
    keys = {}
    for name in ("release", "other"):
        subprocess.run(
            [
                "minisign",
                "-G",
                "-W",
                "-p",
                str(tmp_path / f"{name}.pub"),
                "-s",
                str(tmp_path / f"{name}.key"),
            ],
            check=True,
            capture_output=True,
            timeout=30,
        )
        keys[name] = (tmp_path / f"{name}.pub").read_text().splitlines()[-1]
    work = tmp_path / "work"
    work.mkdir()
    sums = work / "SHA256SUMS"
    sums.write_text(f"{'0' * 64}  {_TPM_WHEEL}\n")
    subprocess.run(
        ["minisign", "-S", "-s", str(tmp_path / "release.key"), "-m", str(sums)],
        check=True,
        capture_output=True,
        timeout=30,
    )
    if case == "changed list":
        sums.write_text(f"{'1' * 64}  {_TPM_WHEEL}\n")
    key = keys["other" if case == "wrong key" else "release"]
    script = 'die() { echo "install.sh: $*" >&2; exit 1; }\n' + _verify_command()

    done = subprocess.run(
        ["/bin/sh", "-c", script],
        env={**os.environ, "WORK": str(work), "MINISIGN_PUBKEY": key},
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    if case == "good":
        assert done.returncode == 0, done.stderr
        assert "Signature and comment signature verified" in done.stdout
    else:
        assert done.returncode == 1
        assert "minisign verification FAILED" in done.stderr


def _fake_release(tmp_path: Path, served: list[str]) -> tuple[Path, Path, Path]:
    fakebin = tmp_path / "fakebin"
    fakebin.mkdir()
    for name, body in (
        ("curl", _FAKE_CURL),
        ("minisign", "#!/bin/sh\nexit 0\n"),
        ("id", "#!/bin/sh\necho 0\n"),
        ("uname", "#!/bin/sh\necho x86_64\n"),
        ("apt-get", "#!/bin/sh\nexit 1\n"),  # the first step past the gate
        ("install", _RECORDER),
        ("pip", _RECORDER),
        ("python3", _RECORDER),
        ("systemctl", _RECORDER),
    ):
        (fakebin / name).write_text(body)
        (fakebin / name).chmod(0o755)
    tpm = tmp_path / "tpmrm0"
    tpm.write_text("")
    script = tmp_path / "install.sh"
    script.write_text(INSTALL.replace("/dev/tpmrm0", str(tpm)))
    release = tmp_path / "served"
    release.mkdir()
    for name in served:
        (release / name).parent.mkdir(parents=True, exist_ok=True)
        (release / name).write_text(f"content of {name}\n")
    _sums(release, served)
    (release / "SHA256SUMS.minisig").write_text("sig\n")
    logs = tmp_path / "logs"
    logs.mkdir()
    return script, release, logs


def _run_install_sh(
    tmp_path: Path, served: list[str], *args: str
) -> tuple[subprocess.CompletedProcess[str], list[str], str]:
    script, release, logs = _fake_release(tmp_path, served)
    (tmp_path / "tmp").mkdir()
    done = subprocess.run(
        ["/bin/sh", str(script), *args],
        env={
            "PATH": f"{tmp_path / 'fakebin'}:{os.environ['PATH']}",
            "TMPDIR": str(tmp_path / "tmp"),
            "SERVED": str(release),
            "CURL_FAIL": "",
            "FAKE_LOG_DIR": str(logs),
            "DSM_RELEASE_BASE_URL": "https://example.invalid/rel",
        },
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    fetched = (logs / "curl.log").read_text().split()
    calls = (logs / "calls.log").read_text() if (logs / "calls.log").exists() else ""
    return done, fetched, calls


@pytest.mark.parametrize(
    ("args", "wanted", "other"),
    [((), _TPM_WHEEL, _SOFT), (("--eval",), _SOFT, _TPM_WHEEL)],
)
def test_install_sh_picks_the_manylinux_dsm_wheel_maturin_makes(
    tmp_path: Path, args: tuple[str, ...], wanted: str, other: str
) -> None:
    done, fetched, _ = _run_install_sh(tmp_path, [_TPM_WHEEL, _SOFT, *_DEPS], *args)
    assert "apt-get update failed" in done.stderr  # past the verified gate
    assert f"{wanted}: OK" in done.stdout
    assert wanted in fetched
    assert other not in fetched
    assert all(dep in fetched for dep in _DEPS)


@pytest.mark.parametrize(
    "served",
    [
        # Two production wheels: which one is meant cannot be told.
        [_TPM_WHEEL, "dsm-0.1.0-cp311-abi3-manylinux_2_38_x86_64.whl", _SOFT],
        # The right version and ABI, but not x86_64.
        ["dsm-0.1.0-cp311-abi3-manylinux_2_35_aarch64.whl", _SOFT],
        # Another version only (a rolled-back list).
        ["dsm-0.0.9-cp311-abi3-manylinux_2_35_x86_64.whl", _SOFT],
        # A name with a folder in it.
        ["dsm-0.1.0-cp311-abi3-a/b_x86_64.whl", _SOFT],
        # The right text, but not at the start.
        ["evil-dsm-0.1.0-cp311-abi3-x_x86_64.whl", _SOFT],
        # A backslash, which awk -v would read as an escape.
        ["dsm-0.1.0-cp311-abi3-a\\b_x86_64.whl", _SOFT],
    ],
)
def test_install_sh_wants_exactly_one_matching_dsm_wheel(
    tmp_path: Path, served: list[str]
) -> None:
    done, fetched, calls = _run_install_sh(tmp_path, [*served, *_DEPS])
    assert done.returncode == 1
    assert (
        "signed SHA256SUMS has no single entry for dsm-0.1.0-cp311-abi3-*_x86_64.whl"
        in done.stderr
    )
    assert not [name for name in fetched if name.endswith(".whl")]
    assert calls == ""


def _job(name: str) -> str:
    start = RELEASE.index(f"\n  {name}:\n")
    end = RELEASE.find("\n  ", start + 1)
    while end != -1 and RELEASE[end + 3] == " ":
        end = RELEASE.find("\n  ", end + 1)
    return RELEASE[start : end if end != -1 else len(RELEASE)]


@pytest.mark.parametrize("job", ["build-tpm-wheel", "build-soft-wheel", "build-sdist"])
def test_the_build_jobs_run_on_the_oldest_glibc_runner(job: str) -> None:
    assert "    runs-on: ubuntu-22.04" in _job(job)


def test_the_soft_job_names_its_wheel_plus_soft() -> None:
    soft = _job("build-soft-wheel")
    sed = 'sed -i \'s/^version = "\\([^"+]*\\)"$/version = "\\1+soft"/\' pyproject.toml'
    assert sed in soft
    assert soft.index(sed) < soft.index("maturin build")
    assert 'grep -q \'^version = "[^"]*+soft"$\' pyproject.toml' in soft
    assert "+soft" not in _job("build-tpm-wheel").split("run: |", 1)[1]


def test_the_dependency_wheels_come_for_every_supported_python() -> None:
    publish = _job("sign-and-publish")
    for version in ("311", "312", "313"):
        block = (
            "pip download \\\n"
            "            --require-hashes \\\n"
            "            -r requirements.lock \\\n"
            "            --only-binary=:all: \\\n"
            f"            --python-version {version} \\\n"
            "            --dest dist"
        )
        assert block in publish, version
    assert publish.index("--python-version 313") < publish.index(
        "sha256sum * > SHA256SUMS"
    )


# --- commit 7: a file the unit cannot read (N5) ---------------------------------

_UNIT_HINT = (
    "(the systemd unit runs without CAP_DAC_OVERRIDE: keep DSM's files in "
    "/opt/mtun, owned by root)"
)
_ROOT_SKIP = pytest.mark.skipif(
    os.geteuid() == 0, reason="root can enter any folder, so nothing is closed"
)


@contextlib.contextmanager
def _closed(folder: Path) -> Generator[None, None, None]:
    """``folder`` cannot be entered, as a 0700 home folder of another user is
    for the units (they drop CAP_DAC_OVERRIDE)."""
    folder.chmod(0o000)
    try:
        yield
    finally:
        folder.chmod(0o700)


def _cert_files(tmp_path: Path, closed_one: str) -> tuple[Path, dict[str, str]]:
    home = tmp_path / "home"
    home.mkdir()
    opt = tmp_path / "opt"
    opt.mkdir()
    paths: dict[str, str] = {}
    for name in ("cert_file", "ca_root_file"):
        path = (home if name == closed_one else opt) / name
        path.write_bytes(b"x")
        path.chmod(0o600)
        paths[name] = str(path)
    return home, paths


@_ROOT_SKIP
@pytest.mark.parametrize("closed_one", ["cert_file", "ca_root_file"])
def test_a_cert_file_dsm_cannot_read_is_one_line(
    tmp_path: Path, closed_one: str
) -> None:
    home, paths = _cert_files(tmp_path, closed_one)
    config = _client_config(**paths)

    with _closed(home), pytest.raises(AuthMaterialsError) as err:
        load_cert_materials(config)

    assert str(err.value) == (
        f"cannot read {paths[closed_one]}: Permission denied {_UNIT_HINT}"
    )


@_ROOT_SKIP
async def test_the_server_stops_with_one_line_for_a_cert_it_cannot_read(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.ERROR, logger="dsm")
    home, paths = _cert_files(tmp_path, "cert_file")
    config = dataclasses.replace(_server_config(), **paths)
    captured: dict[str, Any] = {}

    with (
        _base_patches(captured),
        mock.patch("dsm.server.load_cert_materials", load_cert_materials),
        _closed(home),
    ):
        rc = await asyncio.wait_for(run_server(config), 5.0)

    assert rc == 1
    assert [r.getMessage() for r in caplog.records] == [
        "cert auth materials missing or invalid: cannot read "
        f"{paths['cert_file']}: Permission denied {_UNIT_HINT}"
    ]
    assert "host" not in captured  # nothing on the host was set up


@_ROOT_SKIP
def test_a_key_dsm_cannot_read_is_one_line(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.ERROR, logger="dsm")
    home = tmp_path / "home"
    home.mkdir()
    key = home / "identity.key"
    key.write_bytes(b"x")
    key.chmod(0o600)
    passphrase_file = _passphrase_file(tmp_path)

    with _closed(home):
        ok = load_daemon_stores(
            KeyStore(str(key)),
            AttestStore(str(tmp_path / "attest.key")),
            passphrase_env_file=str(passphrase_file),
        )

    assert ok is False
    assert [r.getMessage() for r in caplog.records] == [
        f"identity store: cannot read {key}: Permission denied {_UNIT_HINT}"
    ]


# --- follow-up: dsm init without sudo on root's install dir ---------------------


def _sudo_line(what: str, path: Path) -> str:
    return f"dsm init: cannot {what} {path}: Permission denied: run it with sudo"


@_ROOT_SKIP
@pytest.mark.parametrize("closed", ["the folder", "the state file"])
def test_resume_without_sudo_on_roots_install_dir_says_use_sudo(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    closed: str,
) -> None:
    inst = tmp_path / "inst"
    with _enrolls():
        assert dsm_init.main(_phase_a_flags(tmp_path, inst)) == 0
    capsys.readouterr()
    state = inst / ".dsm-init-state.json"
    monkeypatch.setattr(dsm_init, "_is_root", lambda: False)
    shut = inst if closed == "the folder" else state

    shut.chmod(0o000)
    try:
        with pytest.raises(SystemExit) as err:
            dsm_init.main(_resume_argv("server", inst, tmp_path))
    finally:
        shut.chmod(0o700 if closed == "the folder" else 0o600)

    assert err.value.code == 1
    assert capsys.readouterr().err == _sudo_line("read", state) + "\n"


def test_init_without_sudo_on_a_root_owned_install_dir_says_use_sudo(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    inst = tmp_path / "inst"
    inst.mkdir(mode=0o700)
    flags = _phase_a_flags(tmp_path, inst)
    _looks_owned_by(monkeypatch, inst, 0)
    monkeypatch.setattr(dsm_init, "_is_root", lambda: False)

    with _enrolls() as gen, pytest.raises(SystemExit) as err:
        dsm_init.main(flags)

    assert err.value.code == 1
    assert capsys.readouterr().err.splitlines()[-1] == (
        f"dsm init: {inst} belongs to root: run it with sudo"
    )
    gen.assert_not_called()
    assert not list(inst.iterdir())


def test_init_on_another_users_install_dir_keeps_the_owner_text(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    inst = tmp_path / "inst"
    inst.mkdir(mode=0o700)
    flags = _phase_a_flags(tmp_path, inst)
    _looks_owned_by(monkeypatch, inst, 4242)
    monkeypatch.setattr(dsm_init, "_is_root", lambda: False)

    with _enrolls(), pytest.raises(SystemExit) as err:
        dsm_init.main(flags)

    assert err.value.code == 2
    assert "is owned by uid 4242" in capsys.readouterr().err.splitlines()[-1]


@_ROOT_SKIP
def test_init_without_sudo_that_cannot_make_the_install_dir_says_use_sudo(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = tmp_path / "opt"
    parent.mkdir()
    inst = parent / "mtun"
    flags = _phase_a_flags(tmp_path, inst)
    monkeypatch.setattr(dsm_init, "_is_root", lambda: False)

    parent.chmod(0o500)
    try:
        with _enrolls() as gen, pytest.raises(SystemExit) as err:
            dsm_init.main(flags)
    finally:
        parent.chmod(0o700)

    assert err.value.code == 1
    assert capsys.readouterr().err.splitlines()[-1] == _sudo_line("create", inst)
    gen.assert_not_called()


# --- follow-up 2, commit A ------------------------------------------------------


def _resume_with(inst: Path, signed: Path, tmp_path: Path) -> list[str]:
    return [
        "server",
        "--resume",
        "--install-dir",
        str(inst),
        "--signed-cert",
        str(signed),
        "--passphrase-env-file",
        str(tmp_path / "pass"),
    ]


def test_root_on_a_root_owned_install_dir_goes_on(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    inst = tmp_path / "inst"
    inst.mkdir(mode=0o700)
    flags = _phase_a_flags(tmp_path, inst)
    _fake_owner(monkeypatch, inst, 0)
    monkeypatch.setattr(dsm_init.os, "geteuid", lambda: 0)  # so _is_root() is True

    with _enrolls():
        assert dsm_init.main(flags) == 0

    assert "belongs to root" not in capsys.readouterr().err
    assert (inst / "config.toml").is_file()


def test_root_with_a_root_owned_loose_config_keeps_the_chmod_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_config(tmp_path, _GOOD_CLIENT)
    path.chmod(0o644)
    _fake_owner(monkeypatch, path, 0)
    monkeypatch.setattr("dsm.core.path_security.os.getuid", lambda: 0)
    monkeypatch.setattr(dsm_config.os, "geteuid", lambda: 0)

    with pytest.raises(ConfigError) as err:
        load(path)

    assert str(err.value) == (
        f"refusing to load config with insecure permissions: {path} has "
        f"group/world permissions (mode=644). Run: chmod 600 {path}"
    )


def _ca_pem_with_dates(not_before: datetime.datetime, days: int) -> bytes:
    """A P-384 CA root, as make_test_ca makes one, valid from ``not_before``
    for ``days`` days."""
    priv = ec.generate_private_key(ec.SECP384R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Dated CA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_before + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key=priv, algorithm=hashes.SHA384())
    )
    return cert.public_bytes(Encoding.PEM)


_NOW = datetime.datetime.now(datetime.UTC)
_DATED = {
    "expired": (_NOW - datetime.timedelta(days=800), 365, "CA root expired"),
    "not yet valid": (_NOW + datetime.timedelta(days=30), 365, "CA root not yet valid"),
}


@pytest.mark.parametrize("dates", list(_DATED))
def test_init_says_a_ca_root_outside_its_dates_is_a_date_problem(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], dates: str
) -> None:
    not_before, days, reason = _DATED[dates]
    ca = tmp_path / "dated.pem"
    ca.write_bytes(_ca_pem_with_dates(not_before, days))
    inst = tmp_path / "inst"
    flags = _set(_phase_a_flags(tmp_path, inst), "--ca-root", str(ca))

    with _enrolls() as gen, pytest.raises(SystemExit) as err:
        dsm_init.main(flags)

    assert err.value.code == 2
    line = capsys.readouterr().err.splitlines()[-1]
    assert line.startswith(f"dsm init: --ca-root {ca} is outside its dates: {reason} (")
    assert line.endswith(") (check this host's clock)")
    gen.assert_not_called()


def test_resume_says_a_ca_copy_outside_its_dates_is_a_date_problem(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    inst, signed = _enrolled_install_dir(tmp_path)
    copy = inst / "dsm_ca_root.pem"
    not_before, days, reason = _DATED["expired"]
    copy.write_bytes(_ca_pem_with_dates(not_before, days))
    capsys.readouterr()

    with (
        mock.patch.object(dsm_init, "loaded_stores_cli", _unlocked),
        pytest.raises(SystemExit) as err,
    ):
        dsm_init.main(_resume_with(inst, signed, tmp_path))

    assert err.value.code == 2
    (line,) = capsys.readouterr().err.splitlines()
    assert line.startswith(
        f"dsm init: the CA root {copy} is outside its dates: {reason}"
    )
    assert line.endswith(") (check this host's clock)")


class _RealLoadStart(_Start):
    """The client start harness, with the real cert-file loader."""

    def _load(self, config: object, **kwargs: Any) -> Any:
        self.events.append("materials")
        return load_cert_materials(config, **kwargs)  # type: ignore[arg-type]


@_ROOT_SKIP
@pytest.mark.parametrize(
    ("stop_keeps_block", "events"),
    [
        (False, ["block 10.0.0.1", "materials", "unblock 10.0.0.1"]),
        (True, ["block 10.0.0.1", "materials"]),
    ],
)
async def test_a_client_with_a_cert_it_cannot_read_follows_the_start_rules(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    stop_keeps_block: bool,
    events: list[str],
) -> None:
    # By hand a setup error takes the block down (owner ruling Q1); under
    # dsm-client.service (--stop-keeps-block) it stays.
    caplog.set_level(logging.ERROR, logger="dsm")
    home, paths = _cert_files(tmp_path, "cert_file")
    start = _RealLoadStart(tmp_path / "server-endpoint.json")

    with _closed(home):
        rc = await start.run(stop_keeps_block=stop_keeps_block, **paths)

    assert rc == 1
    assert start.events == events
    assert (
        "cert auth materials missing or invalid: cannot read "
        f"{paths['cert_file']}: Permission denied {_UNIT_HINT}"
    ) in [r.getMessage() for r in caplog.records]


def test_resume_with_a_config_that_does_not_load_is_one_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    inst, signed = _enrolled_install_dir(tmp_path)
    config = inst / "config.toml"
    config.write_text(_without_key(config.read_text(), "mode"))
    capsys.readouterr()
    argv = _resume_with(inst, signed, tmp_path)

    with pytest.raises(SystemExit) as err:
        dsm_init.main(argv)

    assert err.value.code == 2
    assert capsys.readouterr().err == "dsm init: config: missing setting 'mode'\n"


@_ROOT_SKIP
def test_resume_with_a_ca_copy_it_cannot_read_is_one_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    inst, signed = _enrolled_install_dir(tmp_path)
    copy = inst / "dsm_ca_root.pem"
    capsys.readouterr()
    argv = _resume_with(inst, signed, tmp_path)

    copy.chmod(0o000)
    try:
        with (
            mock.patch.object(dsm_init, "loaded_stores_cli", _unlocked),
            pytest.raises(SystemExit) as err,
        ):
            dsm_init.main(argv)
    finally:
        copy.chmod(0o600)

    assert err.value.code == 2
    assert capsys.readouterr().err == (
        f"dsm init: cannot read {copy}: Permission denied\n"
    )


@pytest.mark.parametrize("signed_cert", ["missing", "unreadable"])
def test_enroll_import_of_a_cert_it_cannot_read_is_one_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], signed_cert: str
) -> None:
    if signed_cert == "unreadable" and os.geteuid() == 0:
        pytest.skip("root can read any file")
    ca = make_test_ca()
    ca_file = tmp_path / "ca.pem"
    ca_file.write_bytes(ca.pem)
    text = _GOOD_CLIENT.replace('"/tmp/ca"', f'"{ca_file}"')
    config = _write_config(tmp_path, text)
    signed = tmp_path / "signed.pem"
    if signed_cert == "unreadable":
        signed.write_bytes(_leaf_pem(ca))
        signed.chmod(0o000)
    expected = (
        f"enroll: cert input not found: {signed}\n"
        if signed_cert == "missing"
        else f"enroll: cannot read {signed}: Permission denied\n"
    )

    with (
        mock.patch("dsm.crypto._stores.loaded_stores_cli", _unlocked),
        pytest.raises(SystemExit) as err,
    ):
        entry._run_enroll(
            config,
            csr_out=None,
            import_cert=signed,
            cn=None,
            role=None,
            passphrase_fd=None,
            passphrase_env_file=None,
        )

    assert err.value.code == 2
    assert capsys.readouterr().err == expected


@pytest.mark.parametrize(
    ("missing", "text"),
    [
        (
            "cert_file",
            "cert_file missing at {path}; enroll this host with `sudo dsm init` "
            "or `sudo dsm enroll --csr-out <csr file>` (deploy/GUIDE.md §3)",
        ),
        (
            "ca_root_file",
            "ca_root_file missing at {path}; copy the pinned CA root cert into "
            "place per deploy/GUIDE.md §2f",
        ),
    ],
)
def test_a_missing_cert_file_names_the_real_step(
    tmp_path: Path, missing: str, text: str
) -> None:
    paths = {}
    for name in ("cert_file", "ca_root_file"):
        path = tmp_path / name
        if name != missing:
            path.write_bytes(b"x")
            path.chmod(0o600)
        paths[name] = str(path)

    with pytest.raises(AuthMaterialsError) as err:
        load_cert_materials(_client_config(**paths))

    assert str(err.value) == text.format(path=paths[missing])


# --- follow-up 2, commit B: release.yml ------------------------------------------


def test_the_tpm_job_installs_patchelf_for_maturins_repair() -> None:
    # maturin's repair step vendors libtss2 and needs patchelf (GUIDE §0b);
    # the soft wheel links nothing to vendor.
    assert "sudo apt-get install -y libtss2-dev libtss2-tcti-device0 patchelf" in (
        _job("build-tpm-wheel")
    )


def test_sign_and_publish_runs_on_the_oldest_glibc_runner_too() -> None:
    # Its pip downloads pick each wheel's platform tag from the runner's glibc.
    assert "    runs-on: ubuntu-22.04" in _job("sign-and-publish")


def _check_wheels_script() -> str:
    publish = _job("sign-and-publish")
    start = publish.index("      - name: Check the DSM wheels\n")
    body = publish[publish.index("        run: |\n", start) :].splitlines()[1:]
    lines: list[str] = []
    for line in body:
        if line and not line.startswith(" " * 10):
            break
        lines.append(line[10:])
    return "\n".join(lines) + "\n"


@pytest.mark.parametrize(
    ("wheels", "ok"),
    [
        ([_TPM_WHEEL, _SOFT], True),
        ([_TPM_WHEEL, "dsm-0.1.0-cp311-abi3-manylinux_2_38_x86_64.whl", _SOFT], False),
        ([_TPM_WHEEL], False),
        ([_SOFT], False),
        ([_TPM_WHEEL, _SOFT, "dsm-0.1.0+soft-cp311-abi3-linux_x86_64.whl"], False),
    ],
)
def test_the_release_stops_unless_dist_has_one_dsm_wheel_of_each_kind(
    tmp_path: Path, wheels: list[str], ok: bool
) -> None:
    publish = _job("sign-and-publish")
    assert publish.index("name: Check the DSM wheels") < publish.index(
        "sha256sum * > SHA256SUMS"
    )
    (tmp_path / "install.sh").write_text('DSM_VERSION="0.1.0"\n')
    dist = tmp_path / "dist"
    dist.mkdir()
    for name in [*wheels, *_DEPS]:
        (dist / name).write_text("wheel\n")

    done = subprocess.run(
        ["/bin/bash", "-e", "-c", _check_wheels_script()],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    assert (done.returncode == 0) is ok, done.stdout + done.stderr


# --- follow-up 2, commit C: server and client lines (N-b1, N-b2, N-b3) ----------

_PROVIDER = "https://10.0.0.53/dns-query"


def _failing_resolver(monkeypatch: pytest.MonkeyPatch) -> DNSResolver:
    resolver = DNSResolver([_PROVIDER], {_PROVIDER: ["aa" * 32]})

    async def fail(*_a: object) -> Any:
        raise OSError("timed out")

    monkeypatch.setattr(resolver, "_resolve_doh", fail)
    return resolver


async def test_a_dns_upstream_outage_is_one_line_per_10_s_not_one_per_query(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = [100.0]
    monkeypatch.setattr(
        dsm_dns,
        "_all_failed_log",
        RepeatLog(dsm_dns.log, logging.ERROR, clock=lambda: now[0]),
        raising=False,
    )
    caplog.set_level(logging.ERROR, logger="dsm.net.dns")
    resolver = _failing_resolver(monkeypatch)

    for i in range(50):
        await resolver.resolve_detailed(f"n{i}.example")
    now[0] += 11
    await resolver.resolve_detailed("late.example")

    lines = [r.getMessage() for r in caplog.records]
    assert len(lines) == 2, lines
    assert lines[0].startswith("all DNS providers failed for qname-tag=")
    assert lines[1].endswith(" (49 more in the last 11 s)")


@pytest.mark.parametrize(
    ("serial", "text"), [(4096, "1000"), (4097, "1001"), (0xABC, "0ABC")]
)
def test_a_serial_is_written_as_openssl_writes_it(serial: int, text: str) -> None:
    from dsm.crypto.cert import serial_hex  # new in this commit

    assert serial_hex(serial) == text


def test_enroll_import_prints_the_serial_in_hex(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = _write_config(tmp_path, _GOOD_CLIENT)
    leaf = mock.MagicMock(subject_cn="dsm-x-client", serial_number=4097)
    with (
        mock.patch("dsm.crypto._stores.loaded_stores_cli", _unlocked),
        mock.patch("dsm.crypto.enroll.import_signed_cert", return_value=leaf),
    ):
        entry._run_enroll(
            config,
            csr_out=None,
            import_cert=tmp_path / "signed.pem",
            cn=None,
            role=None,
            passphrase_fd=None,
            passphrase_env_file=None,
        )
    assert "  serial = 1001 (hex)\n" in capsys.readouterr().out


@pytest.mark.parametrize("revoked", ["server", "client"])
async def test_a_revoked_cert_line_gives_its_serial_in_hex(revoked: str) -> None:
    from dsm.net.transport.udp import UDPTransport

    ca = make_test_ca()
    client = make_enrolled_device(ca, subject_cn="dsm-hex-client", eku=CLIENT_AUTH_OID)
    server = make_enrolled_device(ca, subject_cn="dsm-hex-server", eku=SERVER_AUTH_OID)
    device = server if revoked == "server" else client
    crl = _build_crl_with_revoked(ca, [device.cert.serial_number])
    with mock.patch("dsm.net.transport.udp.apply_so_mark", lambda _sock: None):
        server_t = UDPTransport()
        port = await server_t.bind("127.0.0.1", 0)
        client_t = UDPTransport()
        await client_t.bind("127.0.0.1", 0)
        tasks: list[asyncio.Future[Any]] = [
            asyncio.ensure_future(
                client_handshake(
                    client_t,
                    client.identity,
                    ("127.0.0.1", port),
                    attest_key=client.attest_key,
                    cert_der=client.cert_der,
                    ca_root=ca.certificate,
                    expected_server_cn="dsm-hex-server",
                    crl=crl,
                )
            ),
            asyncio.ensure_future(
                server_handshake(
                    server_t,
                    server.identity,
                    attest_key=server.attest_key,
                    cert_der=server.cert_der,
                    ca_root=ca.certificate,
                    cn_allowlist=CNAllowlist(cns=frozenset({"dsm-hex-client"})),
                    crl=crl,
                )
            ),
        ]
        try:
            # The side that checks the revoked cert fails at once; the other
            # would wait for its timeout, so it is cancelled.
            done, pending = await asyncio.wait(
                tasks, timeout=30.0, return_when=asyncio.FIRST_EXCEPTION
            )
            for task in pending:
                task.cancel()
            for task in pending:
                with contextlib.suppress(asyncio.CancelledError):
                    await task
        finally:
            await client_t.aclose()
            await server_t.aclose()
    results = [task.exception() for task in done]

    revoked_lines = [str(r) for r in results if isinstance(r, CertRevokedError)]
    hex_serial = f"{device.cert.serial_number:X}"
    hex_serial = "0" * (len(hex_serial) % 2) + hex_serial
    assert revoked_lines == [f"{revoked} cert serial {hex_serial} (hex) is revoked"]


def test_the_pre_handshake_table_itself_logs_at_debug(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger="dsm.net.nftables")
    with mock.patch("dsm.net.nftables.subprocess.run"):
        PreHandshakeKillSwitch("10.0.0.1", 51820, resolvers=["192.0.2.53"]).apply()
    levels = [
        r.levelno
        for r in caplog.records
        if r.getMessage() == "pre-handshake kill switch applied"
    ]
    assert levels == [logging.DEBUG]


async def test_a_start_with_a_lookup_says_the_kill_switch_is_up_once(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="dsm")
    start = _Start(tmp_path / "server-endpoint.json")
    start.open_lookup = True

    assert await start.run(server_ip="vpn.example.org") == 1

    # The table, then port 53 opened for the lookup, then closed.
    blocks = [e for e in start.events if e.startswith("block ")]
    assert blocks[:3] == ["block none", "block none +dns", "block 10.0.0.1"]
    applied = [
        r
        for r in caplog.records
        if r.getMessage() == "pre-handshake kill switch applied"
    ]
    assert [r.levelno for r in applied] == [logging.INFO]
