"""What the QA re-run found (QA2): the laptop pass's Major, Minors and Nits,
and the lab box's N1-N5. Enrollment, the TPM check and the store unlock are
faked as in tests/test_init.py; certs come from tests/cert_helpers.py; files
live in tmp_path. Nothing here needs root or touches the host."""

from __future__ import annotations

import contextlib
import datetime
import os
from collections.abc import Generator
from pathlib import Path
from typing import Any
from unittest import mock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding

import dsm.__main__ as entry
from dsm import init as dsm_init
from dsm.core import config as dsm_config
from dsm.core import passphrase
from dsm.core.config import ConfigError, load
from dsm.core.passphrase import PassphraseError, read_passphrase
from dsm.crypto._stores import loaded_stores_cli
from dsm.crypto.attest_store import AttestStore
from dsm.crypto.enroll import EnrollError, generate_enrollment, import_signed_cert
from dsm.crypto.keystore import KeyStore
from tests.cert_helpers import (
    IssuingCA,
    make_leaf_cert,
    make_test_ca,
    public_spki_der_from_priv,
)
from tests.test_init import _fake_enrollment, _server_flags


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
    real = Path.stat

    def stat(self: Path, *args: Any, **kwargs: Any) -> os.stat_result:
        st = real(self, *args, **kwargs)
        if self != path:
            return st
        fields = list(st[:10])
        fields[4] = uid
        return os.stat_result(fields)

    monkeypatch.setattr(Path, "stat", stat)
    monkeypatch.setattr("dsm.core.path_security.os.getuid", lambda: 1000)
    monkeypatch.setattr(dsm_config.os, "geteuid", lambda: 1000)


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
