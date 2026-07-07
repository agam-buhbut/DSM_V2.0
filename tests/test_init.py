"""Tests for the `dsm init` wizard (dsm/init.py).

The wizard is a thin orchestrator. These tests assert it SEQUENCES the
already-audited callables correctly and writes the right files — they do not
re-test enroll/import/config internals (those have their own suites). Mocks
sit only at the I/O boundary: generate_enrollment, import_signed_cert,
preflight_tpm, loaded_stores_cli, and subprocess. No real keys, no real TPM.
"""

from __future__ import annotations

import contextlib
import json
from pathlib import Path
from unittest import mock

import pytest

from dsm import init as dsm_init
from dsm.core.config import load as config_load
from dsm.crypto.enroll import EnrollError, EnrollmentResult


def _server_flags(cfg_dir: Path) -> list[str]:
    return [
        "server",
        "--server-ip",
        "203.0.113.1",
        "--server-port",
        "51820",
        "--install-dir",
        str(cfg_dir),
        "--ca-root",
        str(cfg_dir / "dsm_ca_root.pem"),
        "--dns-provider",
        "https://1.1.1.1/dns-query",
        "--dns-pin",
        "ab" * 32,
        "--passphrase-env-file",
        str(cfg_dir / "pass"),
    ]


@pytest.fixture
def cfg_dir(tmp_path: Path) -> Path:
    (tmp_path / "dsm_ca_root.pem").write_bytes(b"-----BEGIN CERTIFICATE-----\n")
    p = tmp_path / "pass"
    p.write_bytes(b"hunter2hunter2\n")
    p.chmod(0o600)
    return tmp_path


def _fake_enrollment() -> EnrollmentResult:
    return EnrollmentResult(
        cn="dsm-aabbccddeeff-server",
        noise_static_pub=b"\x00" * 32,
        attest_spki_der=b"\x00" * 91,
        csr_der=b"DERCSR",
    )


def test_phase_a_writes_loadable_config_and_state(cfg_dir: Path) -> None:
    with (
        mock.patch.object(dsm_init, "preflight_tpm"),
        mock.patch.object(
            dsm_init, "generate_enrollment", return_value=_fake_enrollment()
        ) as gen,
    ):
        rc = dsm_init.main(_server_flags(cfg_dir))

    assert rc == 0
    # Config was written AND is loadable by the real validator.
    config_path = cfg_dir / "config.toml"
    assert config_path.is_file()
    assert oct(config_path.stat().st_mode)[-3:] == "600"
    cfg = config_load(config_path)
    assert cfg.mode == "server"
    assert cfg.server_ip == "203.0.113.1"
    assert cfg.ca_root_sha256 is not None and len(cfg.ca_root_sha256) == 64
    # generate_enrollment was called once with role=server, cn auto (None).
    assert gen.call_count == 1
    assert gen.call_args.kwargs["role"] == "server"
    assert gen.call_args.kwargs["cn"] is None
    # CSR written; state file written with NO secret and phase csr_emitted.
    assert (cfg_dir / "server.csr").read_bytes() == b"DERCSR"
    state = json.loads((cfg_dir / ".dsm-init-state.json").read_text())
    assert state["phase"] == "csr_emitted"
    assert state["role"] == "server"
    blob = (cfg_dir / ".dsm-init-state.json").read_text()
    assert "hunter2" not in blob  # passphrase never persisted
    assert oct((cfg_dir / ".dsm-init-state.json").stat().st_mode)[-3:] == "600"


def test_resume_imports_cert_and_clears_state(cfg_dir: Path) -> None:
    # First run Phase A to lay down config + state.
    with (
        mock.patch.object(dsm_init, "preflight_tpm"),
        mock.patch.object(
            dsm_init, "generate_enrollment", return_value=_fake_enrollment()
        ),
    ):
        assert dsm_init.main(_server_flags(cfg_dir)) == 0

    signed = cfg_dir / "signed.crt"
    signed.write_bytes(b"-----BEGIN CERTIFICATE-----\n")

    @contextlib.contextmanager
    def _fake_stores(*_a, **_k):
        yield

    with (
        mock.patch.object(dsm_init, "loaded_stores_cli", _fake_stores),
        mock.patch.object(dsm_init, "import_signed_cert") as imp,
    ):
        rc = dsm_init.main(
            [
                "server",
                "--resume",
                "--install-dir",
                str(cfg_dir),
                "--signed-cert",
                str(signed),
                "--passphrase-env-file",
                str(cfg_dir / "pass"),
            ]
        )

    assert rc == 0
    assert imp.call_count == 1
    assert imp.call_args.kwargs["cert_input_path"] == signed
    # Allowlist created (server), state file cleared.
    assert (cfg_dir / "allowed_cns.txt").is_file()
    assert not (cfg_dir / ".dsm-init-state.json").exists()


def test_precondition_no_tun_exits_2(cfg_dir: Path) -> None:
    with mock.patch.object(dsm_init, "_tun_present", return_value=False):
        with pytest.raises(SystemExit) as ei:
            dsm_init.main(_server_flags(cfg_dir))
    assert ei.value.code == 2


def test_existing_key_without_force_exits_2(cfg_dir: Path) -> None:
    def _raise(**_k):
        raise EnrollError("identity key already exists at /x; remove by hand")

    with (
        mock.patch.object(dsm_init, "preflight_tpm"),
        mock.patch.object(dsm_init, "generate_enrollment", side_effect=_raise),
    ):
        with pytest.raises(SystemExit) as ei:
            dsm_init.main(_server_flags(cfg_dir))
    assert ei.value.code == 2


def test_client_uses_expected_server_cn(cfg_dir: Path) -> None:
    flags = [
        "client",
        "--server-ip",
        "203.0.113.1",
        "--server-port",
        "51820",
        "--install-dir",
        str(cfg_dir),
        "--ca-root",
        str(cfg_dir / "dsm_ca_root.pem"),
        "--expected-server-cn",
        "dsm-1234abcd-server",
        "--passphrase-env-file",
        str(cfg_dir / "pass"),
    ]
    with (
        mock.patch.object(dsm_init, "preflight_tpm"),
        mock.patch.object(
            dsm_init, "generate_enrollment", return_value=_fake_enrollment()
        ) as gen,
    ):
        assert dsm_init.main(flags) == 0
    cfg = config_load(cfg_dir / "config.toml")
    assert cfg.mode == "client"
    assert cfg.expected_server_cn == "dsm-1234abcd-server"
    assert gen.call_args.kwargs["role"] == "client"


def test_empty_passphrase_rejected_cleanly(cfg_dir: Path) -> None:
    # An empty passphrase source: read_passphrase fails closed with a
    # ValueError; the wizard must surface it as a clean exit(2), never a
    # raw traceback, and must not reach generate_enrollment.
    empty = cfg_dir / "pass"
    empty.write_bytes(b"")
    empty.chmod(0o600)
    with (
        mock.patch.object(dsm_init, "preflight_tpm"),
        mock.patch.object(dsm_init, "generate_enrollment") as gen,
    ):
        with pytest.raises(SystemExit) as ei:
            dsm_init.main(_server_flags(cfg_dir))
    assert ei.value.code == 2
    assert gen.call_count == 0


def test_render_config_escapes_toml_injection(cfg_dir: Path) -> None:
    # A malicious --dns-provider must not break out of the TOML string to
    # inject a config key (e.g. flip allow_soft_attest). All dynamic values
    # are rendered with json.dumps; the rendered config must parse with the
    # payload as a single inert string and no injected key.
    import argparse
    import tomllib

    ca = cfg_dir / "dsm_ca_root.pem"
    ca.write_bytes(b"-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n")
    payload = 'https://x/dns-query"]\nallow_soft_attest = true\ndns_providers = ["y'
    args = argparse.Namespace(
        server_ip="10.0.0.1",
        server_port=51820,
        ca_root=str(ca),
        dns_provider=payload,
        dns_pin="ab" * 32,
        expected_server_cn="cn",
    )
    text = dsm_init._render_config("server", args, cfg_dir)  # noqa: SLF001
    parsed = tomllib.loads(text)
    assert "allow_soft_attest" not in parsed
    assert parsed["dns_providers"] == [payload]


def test_render_config_is_fail_closed_crl(cfg_dir: Path) -> None:
    # The wizard must emit crl_strict=true AND a concrete crl_file, so the
    # generated config is self-consistent (fail-closed on a missing CRL with a
    # clear message) instead of silently skipping revocation.
    import argparse
    import tomllib

    ca = cfg_dir / "dsm_ca_root.pem"
    ca.write_bytes(b"-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n")
    args = argparse.Namespace(
        server_ip="10.0.0.1",
        server_port=51820,
        ca_root=str(ca),
        dns_provider="https://1.1.1.1/dns-query",
        dns_pin="ab" * 32,
        expected_server_cn="cn",
    )
    parsed = tomllib.loads(
        dsm_init._render_config("server", args, cfg_dir)  # noqa: SLF001
    )
    assert parsed["crl_strict"] is True
    assert parsed["crl_file"] == str(cfg_dir / "dsm_ca.crl")


def test_force_restart_removes_keys_then_reenrolls(cfg_dir: Path) -> None:
    # First run lays down state + (mocked) enrollment. Stale key files stand in
    # for the residue generate_enrollment would refuse to clobber.
    with (
        mock.patch.object(dsm_init, "preflight_tpm"),
        mock.patch.object(
            dsm_init, "generate_enrollment", return_value=_fake_enrollment()
        ),
    ):
        assert dsm_init.main(_server_flags(cfg_dir)) == 0
    (cfg_dir / "identity.key").write_bytes(b"stale")
    (cfg_dir / "attest.key").write_bytes(b"stale")
    assert (cfg_dir / ".dsm-init-state.json").exists()

    # Without --force the state guard blocks re-init.
    with pytest.raises(SystemExit) as ei:
        dsm_init.main(_server_flags(cfg_dir))
    assert ei.value.code == 2

    # --force clears the key files + state so generate_enrollment runs again.
    with (
        mock.patch.object(dsm_init, "preflight_tpm"),
        mock.patch.object(
            dsm_init, "generate_enrollment", return_value=_fake_enrollment()
        ) as gen,
    ):
        rc = dsm_init.main(_server_flags(cfg_dir) + ["--force"])
    assert rc == 0
    # generate_enrollment re-ran (it is mocked, so it does not recreate the
    # key files) — the point is the stale keys it would have refused to clobber
    # are gone, unblocking the restart.
    assert gen.call_count == 1
    assert not (cfg_dir / "identity.key").exists()
    assert not (cfg_dir / "attest.key").exists()


def test_force_unlink_failure_is_nonfatal(cfg_dir: Path) -> None:
    # A failed unlink of a TPM-related key must be reported, not crash --force.
    with (
        mock.patch.object(dsm_init, "preflight_tpm"),
        mock.patch.object(
            dsm_init, "generate_enrollment", return_value=_fake_enrollment()
        ),
    ):
        assert dsm_init.main(_server_flags(cfg_dir)) == 0

    with (
        mock.patch.object(dsm_init, "preflight_tpm"),
        mock.patch.object(
            dsm_init, "generate_enrollment", return_value=_fake_enrollment()
        ) as gen,
        mock.patch.object(dsm_init.Path, "unlink", side_effect=OSError("EPERM")),
    ):
        rc = dsm_init.main(_server_flags(cfg_dir) + ["--force"])
    assert rc == 0
    assert gen.call_count == 1
