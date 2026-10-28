"""What the QA re-run found (QA2): the laptop pass's Major, Minors and Nits,
and the lab box's N1-N5. Enrollment, the TPM check and the store unlock are
faked as in tests/test_init.py; certs come from tests/cert_helpers.py; files
live in tmp_path. Nothing here needs root or touches the host."""

from __future__ import annotations

import contextlib
import datetime
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
