"""`dsm init` quickstart wizard — a thin orchestrator over the audited
enroll / import / config / preflight paths. ADDS NO new crypto or key code:
it sequences existing callables, renders config.toml, manages a small
no-secret state file for the air-gapped CA round trip, and (optionally)
installs the systemd unit.
"""

from __future__ import annotations

import argparse
import grp
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import NoReturn

from dsm.core.config import ConfigError
from dsm.core.config import load as config_load
from dsm.core.passphrase import read_passphrase, wipe_passphrase
from dsm.crypto._stores import loaded_stores_cli
from dsm.crypto.attest_store import AttestStore
from dsm.crypto.enroll import (
    EnrollError,
    generate_enrollment,
    import_signed_cert,
)
from dsm.crypto.keystore import KeyStore
from dsm.crypto.tpm_preflight import TpmPreflightError, preflight_tpm

_STATE_NAME = ".dsm-init-state.json"
_STATE_SCHEMA = 1


def _fail(msg: str) -> NoReturn:
    print(f"dsm init: {msg}", file=sys.stderr)
    sys.exit(2)


def _tun_present() -> bool:
    return Path("/dev/net/tun").exists()


def _nft_present() -> bool:
    return shutil.which("nft") is not None


def _backend_is_soft() -> bool:
    import tuncore

    return bool(getattr(tuncore, "ATTEST_BACKEND_IS_SOFTWARE", True))


def _supplementary_group_names() -> set[str]:
    return {grp.getgrgid(g).gr_name for g in os.getgroups()}


def _check_preconditions(tcti: str | None) -> None:
    # Hard precondition: a missing /dev/net/tun cannot be worked around — the
    # daemon needs it to attach the TUN device, so refuse the whole run.
    if not _tun_present():
        _fail("/dev/net/tun missing — load the tun module: modprobe tun")
    # Soft preconditions: a non-root / non-tss invocation or a missing nft(8)
    # is fine to *provision* (write config, enroll, emit CSR) — those touch
    # only the install dir. They only bite when the daemon later runs, so warn
    # loudly here instead of blocking enrollment on a workstation/CI box.
    if os.geteuid() != 0 and "tss" not in _supplementary_group_names():
        print(
            "dsm init: warning: not running as root and not in the 'tss' group; "
            "config + enrollment proceed, but `systemctl start dsm` will need "
            "root (and, on the TPM build, 'tss' for /dev/tpmrm0 access).",
            file=sys.stderr,
        )
    if not _nft_present():
        print(
            "dsm init: warning: nft(8) not found on PATH — install nftables "
            "before starting the daemon (the kill-switch needs it).",
            file=sys.stderr,
        )
    if _backend_is_soft():
        print(
            "warning: evaluation build — soft attest backend, not "
            "hardware-bound. Do not deploy in production.",
            file=sys.stderr,
        )
        return
    try:
        preflight_tpm(tcti)
    except TpmPreflightError as e:
        _fail(str(e))


def _render_config(role: str, args: argparse.Namespace, install_dir: Path) -> str:
    """Render config.toml text from config.example.toml-shaped fields."""
    ca_root = Path(args.ca_root)
    if not ca_root.is_file():
        _fail(f"ca-root not found: {ca_root}")
    ca_sha = hashlib.sha256(ca_root.read_bytes()).hexdigest()
    print(f"ca_root_sha256 = {ca_sha}", file=sys.stderr)
    crl_file = install_dir / "dsm_ca.crl"
    print(
        f"dsm init: crl_strict is on (fail-closed); the daemon will NOT start "
        f"until you place a current CRL at {crl_file} — see deploy/GUIDE.md §7e.",
        file=sys.stderr,
    )
    # Every dynamic/operator-supplied value is rendered with json.dumps so it
    # cannot break out of the TOML string and inject config keys (e.g. a
    # --dns-provider or --expected-server-cn containing a quote/newline that
    # flips a security knob like allow_soft_attest). JSON string escaping is a
    # valid subset of TOML basic-string escaping. config_load re-validates after.
    lines = [
        f"mode = {json.dumps(role)}",
        f"server_ip = {json.dumps(args.server_ip)}",
        f"server_port = {args.server_port}",
        f"listen_port = {0 if role == 'client' else args.server_port}",
        f"key_file = {json.dumps(str(install_dir / 'identity.key'))}",
        f"cert_file = {json.dumps(str(install_dir / 'device.crt'))}",
        f"ca_root_file = {json.dumps(str(ca_root))}",
        f"ca_root_sha256 = {json.dumps(ca_sha)}",
        f"attest_key_file = {json.dumps(str(install_dir / 'attest.key'))}",
        # Fail-closed by default: crl_strict=true with a configured crl_file
        # makes the daemon refuse to start on a MISSING/stale CRL with a clear
        # message, rather than silently skipping revocation. The operator must
        # place a current CRL at crl_file before starting (deploy/GUIDE.md §7e).
        "crl_strict = true",
        f"crl_file = {json.dumps(str(crl_file))}",
        'transport = "udp"',
    ]
    if role == "client":
        lines.append(f"expected_server_cn = {json.dumps(args.expected_server_cn)}")
    else:
        lines.append(
            f"allowed_cns_file = {json.dumps(str(install_dir / 'allowed_cns.txt'))}"
        )
        lines.append(f"dns_providers = [{json.dumps(args.dns_provider)}]")
        lines.append("[dns_provider_pins]")
        lines.append(f"{json.dumps(args.dns_provider)} = [{json.dumps(args.dns_pin)}]")
    return "\n".join(lines) + "\n"


def _write_state(
    install_dir: Path,
    role: str,
    args: argparse.Namespace,
    csr_path: Path,
    cn: str,
) -> None:
    state = {
        "schema": _STATE_SCHEMA,
        "role": role,
        "phase": "csr_emitted",
        "config_path": str(install_dir / "config.toml"),
        "csr_path": str(csr_path),
        "cn": cn,
        "ca_root_file": str(Path(args.ca_root)),
        "install_unit": bool(getattr(args, "install_unit", False)),
    }
    path = install_dir / _STATE_NAME
    path.write_text(json.dumps(state, indent=2), encoding="utf-8")
    path.chmod(0o600)


def _require_server_args(role: str, args: argparse.Namespace) -> None:
    missing: list[str] = []
    if not args.server_ip:
        missing.append("--server-ip")
    if args.server_port is None:
        missing.append("--server-port")
    if not args.ca_root:
        missing.append("--ca-root")
    if role == "client":
        if not args.expected_server_cn:
            missing.append("--expected-server-cn")
    else:
        if not args.dns_provider:
            missing.append("--dns-provider")
        if not args.dns_pin:
            missing.append("--dns-pin")
    if missing:
        _fail(f"missing required argument(s): {', '.join(missing)}")


def _ensure_secret_dir(install_dir: Path) -> None:
    """Create/harden the install dir to 0o700 (it holds the identity + attest
    keys, the device cert, and the resume-state file).

    ``mkdir(exist_ok=True)`` does not re-chmod an already-existing dir, so we
    follow up with an explicit ``chmod`` — mirroring the secret-dir handling in
    ``dsm.net.tunnel``. To avoid silently weakening a dir owned by someone else
    (e.g. a pre-provisioned ``/opt/mtun`` owned by a service account), we fail
    closed when the dir already exists and is not owner-owned.
    """
    if install_dir.exists():
        try:
            st = install_dir.stat()
        except OSError as e:
            _fail(f"cannot stat install dir {install_dir}: {e}")
        if st.st_uid != os.geteuid():
            _fail(
                f"install dir {install_dir} is owned by uid {st.st_uid}, not "
                f"the current uid {os.geteuid()}; refusing to chmod a dir owned "
                "by another user (provision it yourself at mode 0700)"
            )
    install_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        install_dir.chmod(0o700)
    except OSError as e:
        _fail(f"cannot set 0o700 on install dir {install_dir}: {e}")


def _force_remove_enrollment(install_dir: Path, state_path: Path) -> None:
    """--force restart: clear the prior enrollment so generate_enrollment can
    re-run.

    generate_enrollment refuses to clobber an existing identity/attest key, so
    --force alone (which only bypasses the state guard) can never restart an
    enrollment. Remove those keys and the resume-state file here. Fail-safe:
    these are TPM-related, so a failed unlink is reported and skipped rather
    than crashing mid-teardown.
    """
    print(
        "dsm init: --force: removing existing enrollment keys",
        file=sys.stderr,
    )
    for path in (
        install_dir / "identity.key",
        install_dir / "attest.key",
        state_path,
    ):
        try:
            path.unlink(missing_ok=True)
        except OSError as e:
            print(
                f"dsm init: --force: could not remove {path}: {e}",
                file=sys.stderr,
            )


def _phase_a(role: str, args: argparse.Namespace) -> int:
    _require_server_args(role, args)
    _check_preconditions(getattr(args, "tcti", None))
    install_dir = Path(args.install_dir)
    _ensure_secret_dir(install_dir)

    state_path = install_dir / _STATE_NAME
    if state_path.exists() and not args.force:
        _fail(
            f"init already in progress ({state_path} exists); resume with "
            "`--resume` or re-run with `--force` to restart"
        )
    if args.force:
        _force_remove_enrollment(install_dir, state_path)

    config_path = install_dir / "config.toml"
    config_path.write_text(_render_config(role, args, install_dir), encoding="utf-8")
    config_path.chmod(0o600)
    try:
        config_load(config_path)
    except (ConfigError, ValueError, TypeError) as e:
        _fail(f"generated config did not validate: {e}")

    keystore = KeyStore(str(install_dir / "identity.key"))
    attest_store = AttestStore(str(install_dir / "attest.key"))
    try:
        passphrase = read_passphrase(
            passphrase_fd=getattr(args, "passphrase_fd", None),
            passphrase_env_file=getattr(args, "passphrase_env_file", None),
            prompt="New passphrase (protects the identity key): ",
        )
    except ValueError as e:
        # read_passphrase fails closed on an empty passphrase from any source
        # (it would otherwise enroll an unprotected empty-auth TPM key). Surface
        # it cleanly, mirroring the `dsm enroll` handler — no traceback, exit 2.
        _fail(str(e))
    try:
        try:
            result = generate_enrollment(
                keystore=keystore,
                attest_store=attest_store,
                passphrase=passphrase,
                role=role,
                cn=None,
            )
        except EnrollError as e:
            # generate_enrollment refuses to clobber existing keys; surface its
            # actionable "remove the file by hand" message rather than a trace.
            _fail(str(e))
    finally:
        wipe_passphrase(passphrase)

    csr_path = install_dir / f"{role}.csr"
    csr_path.write_bytes(result.csr_der)
    # A CSR is not secret, but write it 0o600 for consistency with the rest of
    # the install dir (config, state, keys) and to avoid an umask-dependent mode.
    csr_path.chmod(0o600)
    _write_state(install_dir, role, args, csr_path, result.cn)
    print(f"Wrote CSR to {csr_path} (cn={result.cn})")
    print(
        "Walk the CSR to the offline CA (deploy/GUIDE.md §3c), sign it, then "
        "run:\n"
        f"  sudo dsm init {role} --resume --signed-cert <signed.crt>"
    )
    return 0


def _phase_b(role: str, args: argparse.Namespace) -> int:
    install_dir = Path(args.install_dir)
    state_path = install_dir / _STATE_NAME
    if not state_path.is_file():
        _fail(f"no init state at {state_path}; run Phase A first (without --resume)")
    state = json.loads(state_path.read_text(encoding="utf-8"))
    if state.get("schema") != _STATE_SCHEMA:
        _fail(
            f"unrecognized init-state schema {state.get('schema')!r} in "
            f"{state_path} (expected {_STATE_SCHEMA})"
        )
    if state.get("role") != role:
        _fail(
            f"state file role {state.get('role')!r} does not match the "
            f"requested role {role!r}; resume with `dsm init {state.get('role')}`"
        )
    if not args.signed_cert:
        _fail("--signed-cert <path> is required to resume (import the CA cert)")
    cfg = config_load(Path(state["config_path"]))

    keystore = KeyStore(cfg.key_file)
    attest_store = AttestStore(cfg.attest_key_file)
    signed = Path(args.signed_cert)
    with loaded_stores_cli(
        keystore,
        attest_store,
        passphrase_fd=getattr(args, "passphrase_fd", None),
        passphrase_env_file=getattr(args, "passphrase_env_file", None),
        key_file_label=cfg.key_file,
        attest_key_file_label=cfg.attest_key_file,
    ):
        try:
            import_signed_cert(
                cert_input_path=signed,
                cert_output_path=Path(cfg.cert_file),
                ca_root_path=Path(cfg.ca_root_file),
                keystore=keystore,
                attest_store=attest_store,
            )
        except EnrollError as e:
            _fail(str(e))

    if role == "server" and cfg.allowed_cns_file:
        allow = Path(cfg.allowed_cns_file)
        allow.touch(mode=0o600, exist_ok=True)
        print(f"Created empty allowlist {allow}; add the client CN there.")
    else:
        print(
            "Give this CN to the server operator for its allowlist: " f"{state['cn']}"
        )

    if state.get("install_unit"):
        _install_unit()

    state_path.unlink()
    print("Done. Verify with: systemctl status dsm  (deploy/GUIDE.md §6)")
    return 0


def _install_unit() -> None:
    src = Path(__file__).resolve().parent.parent / "deploy" / "dsm.service"
    dst = Path("/etc/systemd/system/dsm.service")
    shutil.copyfile(src, dst)
    Path("/etc/dsm").mkdir(parents=True, exist_ok=True)
    cred = Path("/etc/dsm/passphrase")
    if not cred.exists():
        cred.touch(mode=0o600)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    print("Installed dsm.service. Start with: sudo systemctl enable --now dsm")


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="dsm init")
    p.add_argument("role", choices=["server", "client"])
    p.add_argument("--resume", action="store_true")
    p.add_argument("--force", action="store_true")
    p.add_argument("--install-dir", default="/opt/mtun")
    p.add_argument("--server-ip")
    p.add_argument("--server-port", type=int)
    p.add_argument("--ca-root")
    p.add_argument("--dns-provider")
    p.add_argument("--dns-pin")
    p.add_argument("--expected-server-cn")
    p.add_argument("--signed-cert")
    p.add_argument("--install-unit", action="store_true")
    p.add_argument("--tcti")
    p.add_argument("--passphrase-fd", type=int)
    p.add_argument("--passphrase-env-file")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.resume:
        return _phase_b(args.role, args)
    return _phase_a(args.role, args)
