"""`dsm init` quickstart wizard — a thin orchestrator over the audited
enroll / import / config / preflight paths. ADDS NO new crypto or key code:
it sequences existing callables, renders config.toml, manages a small
no-secret state file for the air-gapped CA round trip, and (optionally)
installs the systemd unit.
"""

from __future__ import annotations

import argparse
import errno
import grp
import hashlib
import json
import os
import shlex
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Literal, NoReturn

from dsm.core.atomic_io import atomic_write
from dsm.core.config import Config, ConfigError
from dsm.core.config import load as config_load
from dsm.core.passphrase import read_passphrase, wipe_passphrase
from dsm.crypto._stores import loaded_stores_cli
from dsm.crypto.attest_store import AttestStore
from dsm.crypto.cert import (
    CertChainError,
    CertError,
    CertExpiredError,
    check_ca_key,
    load_ca_root,
)
from dsm.crypto.enroll import (
    EnrollError,
    ca_root_reason,
    generate_enrollment,
    import_signed_cert,
)
from dsm.crypto.keystore import KeyStore
from dsm.crypto.tpm_preflight import TpmPreflightError, preflight_tpm

_STATE_NAME = ".dsm-init-state.json"
_STATE_SCHEMA = 1

# Where `--install-unit` copies from and to. Module names so tests can point
# them at a temporary folder.
_DEPLOY_DIR = Path(__file__).resolve().parent.parent / "deploy"
_SYSTEMD_DIR = Path("/etc/systemd/system")
_CRED_FILE = Path("/etc/dsm/passphrase")
_DEFAULT_INSTALL_DIR = "/opt/mtun"


def _fail(msg: str) -> NoReturn:
    print(f"dsm init: {msg}", file=sys.stderr)
    sys.exit(2)


def _is_root() -> bool:
    return os.geteuid() == 0


def _need_sudo(what: str, path: Path, e: PermissionError) -> NoReturn:
    """A normal user met a folder or file of root's: say sudo, not chmod
    (QA2). Root gets the same one line without the sudo advice."""
    tail = "" if _is_root() else ": run it with sudo"
    print(f"dsm init: cannot {what} {path}: {e.strerror or e}{tail}", file=sys.stderr)
    sys.exit(1)


def _need_root_for_unit() -> None:
    """--install-unit writes /etc/dsm/passphrase and the unit: refuse a
    normal user at the start, before anything is written (QA2 Minor 1)."""
    if not _is_root():
        print("dsm init: --install-unit must run as root: use sudo", file=sys.stderr)
        sys.exit(1)


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


def _render_config(
    role: str,
    args: argparse.Namespace,
    install_dir: Path,
    *,
    soft: bool = False,
    ca_sha: str | None = None,
) -> str:
    """Render config.toml text from config.example.toml-shaped fields.

    The config names ``install_dir/dsm_ca_root.pem`` and pins ``ca_sha``,
    the sha256 of the CA root that will be copied there. Without it the
    copy must already be there and its sha256 is pinned. With ``soft`` (an
    evaluation build) the config acknowledges the software attest key (QA
    Minor 13).
    """
    ca_root = install_dir / "dsm_ca_root.pem"
    if ca_sha is None:
        if not ca_root.is_file():
            _fail(f"ca-root not found: {ca_root}")
        ca_sha = hashlib.sha256(ca_root.read_bytes()).hexdigest()
    print(f"ca_root_sha256 = {ca_sha}", file=sys.stderr)
    crl_file = install_dir / "dsm_ca.crl"
    # Only when it is not there yet: README item 2 and GUIDE §2f put it
    # there before init (QA2 Nit 1).
    if not (crl_file.is_file() and os.access(crl_file, os.R_OK)):
        print(
            f"dsm init: crl_strict is on (fail-closed); the daemon will NOT start "
            f"until a current CRL is at {crl_file}: copy the CA's CRL there "
            "(deploy/GUIDE.md §2c, §2f).",
            file=sys.stderr,
        )
    # A server does not use server_ip (QA Minor 16), but the config check
    # wants an address there.
    server_ip_line = f"server_ip = {json.dumps(args.server_ip or '0.0.0.0')}"
    if role == "server":
        server_ip_line += "  # not used by a server"
    # Every dynamic/operator-supplied value is rendered with json.dumps so it
    # cannot break out of the TOML string and inject config keys (e.g. a
    # --dns-provider or --expected-server-cn containing a quote/newline that
    # flips a security knob like allow_soft_attest). JSON string escaping is a
    # valid subset of TOML basic-string escaping. config_load re-validates after.
    lines = [
        f"mode = {json.dumps(role)}",
        server_ip_line,
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
        # place a current CRL at crl_file before starting (deploy/GUIDE.md §2f).
        "crl_strict = true",
        f"crl_file = {json.dumps(str(crl_file))}",
        'transport = "udp"',
    ]
    if soft:
        lines += [
            "# Evaluation build: the attest key is a software key, not held in",
            "# a TPM. Never use this host in production.",
            "allow_soft_attest = true",
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


def _read_ca_root(src: Path, install_dir: Path) -> tuple[bytes, bool]:
    """Check the CA root given by --ca-root and read it once. Returns its
    bytes, and True when it is already the install dir's copy. A relative
    ``src`` is taken from the current folder."""
    src = src.absolute()
    try:
        found = src.is_file()
    except PermissionError as e:
        _need_sudo("read", src, e)
    if not found:
        _fail(f"ca-root not found: {src}")
    target = install_dir / "dsm_ca_root.pem"
    in_place = target.exists() and os.path.samefile(src, target)
    try:
        data = src.read_bytes()
        # The daemon's own CA loader, before anything is written: the CRL or
        # the passphrase file given by mistake would otherwise show only
        # after the CA trip (QA2 Major 1). The pin makes it check these bytes.
        ca = load_ca_root(src, expected_sha256=hashlib.sha256(data).digest())
    except PermissionError as e:
        _need_sudo("read", src, e)
    except OSError as e:
        _fail(f"cannot read --ca-root {src}: {e}")
    except CertExpiredError as e:
        # A CA cert, but not valid now: the clock may be the cause.
        _fail(f"--ca-root {src} is outside its dates: {e} (check this host's clock)")
    except (CertError, ValueError) as e:
        _fail(f"--ca-root {src} is not a CA certificate (PEM): {ca_root_reason(e)}")
    try:
        # The rule validate_chain applies at --resume, after the CA trip.
        check_ca_key(ca)
    except CertChainError as e:
        _fail(f"--ca-root {src} is not a P-384 CA certificate: {e}")
    return data, in_place


def _install_ca_root(data: bytes, in_place: bool, install_dir: Path) -> Path:
    """Copy the CA root into the install dir at 0600, as GUIDE §2f does by
    hand, so the config never points at a USB stick or a download folder
    (QA M7)."""
    target = install_dir / "dsm_ca_root.pem"
    if in_place:
        # The folder is init's own (0700), so it may set the mode the
        # daemon wants.
        target.chmod(0o600)
        return target
    atomic_write(target, data, mode=0o600)
    print(f"Copied the CA root to {target} (mode 0600).")
    return target


def _write_state(
    install_dir: Path,
    role: str,
    args: argparse.Namespace,
    csr_path: Path,
    cn: str,
    ca_root: Path,
) -> None:
    state = {
        "schema": _STATE_SCHEMA,
        "role": role,
        "phase": "csr_emitted",
        "config_path": str(install_dir / "config.toml"),
        "csr_path": str(csr_path),
        "cn": cn,
        "ca_root_file": str(ca_root),
        "install_unit": bool(getattr(args, "install_unit", False)),
    }
    path = install_dir / _STATE_NAME
    path.write_text(json.dumps(state, indent=2), encoding="utf-8")
    path.chmod(0o600)


def _require_server_args(role: str, args: argparse.Namespace) -> None:
    missing: list[str] = []
    if role == "client" and not args.server_ip:
        # A server does not use it (QA Minor 16).
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
    try:
        exists = install_dir.exists()
    except PermissionError as e:
        _need_sudo("read", install_dir, e)
    if exists:
        try:
            st = install_dir.stat()
        except OSError as e:
            _fail(f"cannot stat install dir {install_dir}: {e}")
        if st.st_uid == 0 and not _is_root():
            # Sudo, not a chown to this user (as config.load says).
            print(
                f"dsm init: {install_dir} belongs to root: run it with sudo",
                file=sys.stderr,
            )
            sys.exit(1)
        if st.st_uid != os.geteuid():
            _fail(
                f"install dir {install_dir} is owned by uid {st.st_uid}, not "
                f"the current uid {os.geteuid()}; refusing to chmod a dir owned "
                "by another user (provision it yourself at mode 0700)"
            )
    try:
        install_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    except PermissionError as e:
        _need_sudo("create", install_dir, e)
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
    if getattr(args, "install_unit", False):
        _need_root_for_unit()
    _require_server_args(role, args)
    _check_preconditions(getattr(args, "tcti", None))
    install_dir = Path(args.install_dir).absolute()
    _ensure_secret_dir(install_dir)

    state_path = install_dir / _STATE_NAME
    if state_path.exists() and not args.force:
        _fail(
            f"init already in progress ({state_path} exists); resume with "
            "`--resume` or re-run with `--force` to restart"
        )
    if not args.force:
        # Refuse before anything is written, so a re-run on an enrolled host
        # leaves its config as it is (QA M6).
        for key in (install_dir / "identity.key", install_dir / "attest.key"):
            if key.exists():
                _fail(
                    f"{key} already exists: this host is already enrolled, and "
                    "its config.toml was not changed. To enroll it again, "
                    "re-run with --force (it removes the keys)."
                )

    ca_bytes, ca_in_place = _read_ca_root(Path(args.ca_root), install_dir)
    soft = _backend_is_soft()
    if soft:
        print(
            "dsm init: evaluation build: writing allow_soft_attest = true "
            "(never in production).",
            file=sys.stderr,
        )
    config_path = install_dir / "config.toml"
    # Written aside and checked first; it replaces config.toml only once the
    # enrollment worked, so a failure leaves the old config as it was (M6, M7).
    new_config = install_dir / "config.toml.new"
    done = False
    try:
        atomic_write(
            new_config,
            _render_config(
                role,
                args,
                install_dir,
                soft=soft,
                ca_sha=hashlib.sha256(ca_bytes).hexdigest(),
            ).encode("utf-8"),
            mode=0o600,
        )
        try:
            config_load(new_config)
        except (ConfigError, ValueError, TypeError) as e:
            _fail(f"generated config did not validate: {e}")

        keystore = KeyStore(str(install_dir / "identity.key"))
        attest_store = AttestStore(str(install_dir / "attest.key"))
        try:
            passphrase = read_passphrase(
                passphrase_fd=getattr(args, "passphrase_fd", None),
                passphrase_env_file=getattr(args, "passphrase_env_file", None),
                prompt="New passphrase (protects the identity key): ",
                confirm=True,
            )
        except ValueError as e:
            # read_passphrase fails closed on an empty passphrase from any
            # source (it would otherwise enroll an unprotected empty-auth TPM
            # key), and on two answers that differ. Surface it cleanly.
            _fail(str(e))
        try:
            if args.force:
                # Only now: a refusal or a typo above keeps the old keys.
                _force_remove_enrollment(install_dir, state_path)
            try:
                result = generate_enrollment(
                    keystore=keystore,
                    attest_store=attest_store,
                    passphrase=passphrase,
                    role=role,
                    cn=None,
                )
            except EnrollError as e:
                _fail(str(e))
        finally:
            wipe_passphrase(passphrase)
        # Only now: until the enrollment worked, the old config.toml stays,
        # and it pins the old CA copy (final review F1).
        ca_root = _install_ca_root(ca_bytes, ca_in_place, install_dir)
        new_config.replace(config_path)
        done = True
    finally:
        if not done:
            new_config.unlink(missing_ok=True)

    csr_path = install_dir / f"{role}.csr"
    csr_path.write_bytes(result.csr_der)
    # A CSR is not secret, but write it 0o600 for consistency with the rest of
    # the install dir (config, state, keys) and to avoid an umask-dependent mode.
    csr_path.chmod(0o600)
    _write_state(install_dir, role, args, csr_path, result.cn, ca_root)
    print(f"Wrote CSR to {csr_path} (cn={result.cn})")
    resume = f"sudo dsm init {role} --resume --signed-cert <signed.crt>"
    if install_dir != Path(_DEFAULT_INSTALL_DIR):
        resume += f" --install-dir {shlex.quote(str(install_dir))}"
    print(
        "Walk the CSR to the offline CA (deploy/GUIDE.md §3c), sign it, then "
        f"run:\n  {resume}"
    )
    return 0


def _phase_b(role: Literal["client", "server"], args: argparse.Namespace) -> int:
    install_dir = Path(args.install_dir).absolute()
    state_path = install_dir / _STATE_NAME
    try:
        if not state_path.is_file():
            identity = install_dir / "identity.key"
            cert = install_dir / "device.crt"
            if identity.is_file() and cert.is_file():
                # The first step would refuse this host, so do not send the
                # user there (QA2 final check).
                _fail(
                    f"this host looks enrolled already ({identity} and {cert} "
                    "are there): nothing to resume"
                )
            _fail(
                f"no init state at {state_path}: run `dsm init {role}` without "
                "--resume first, with the same --install-dir"
            )
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except PermissionError as e:
        _need_sudo("read", state_path, e)
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
    # --install-unit counts at either step: the README gives it to the first
    # one, and a user may add it to --resume.
    unit = bool(state.get("install_unit")) or bool(getattr(args, "install_unit", False))
    if unit:
        _need_root_for_unit()
    if not args.signed_cert:
        _fail("--signed-cert <path> is required to resume (import the CA cert)")
    config_path = Path(state["config_path"])
    try:
        cfg = config_load(config_path)
    except (ConfigError, ValueError, TypeError, OSError) as e:
        _fail(f"config: {e}")

    keystore = KeyStore(cfg.key_file)
    attest_store = AttestStore(cfg.attest_key_file)
    signed = Path(args.signed_cert)
    # The passphrase that unlocks both stores, kept (wipeable) for the unit's
    # passphrase file, written only once the import worked (QA B2).
    proven = bytearray()
    try:
        with loaded_stores_cli(
            keystore,
            attest_store,
            passphrase_fd=getattr(args, "passphrase_fd", None),
            passphrase_env_file=getattr(args, "passphrase_env_file", None),
            key_file_label=cfg.key_file,
            attest_key_file_label=cfg.attest_key_file,
            on_unlocked=proven.extend if unit else None,
            again=(
                "start again with new keys and a new CSR: sudo dsm init "
                f"{role} --force (with the first step's options)"
            ),
        ):
            try:
                import_signed_cert(
                    cert_input_path=signed,
                    cert_output_path=Path(cfg.cert_file),
                    ca_root_path=Path(cfg.ca_root_file),
                    keystore=keystore,
                    attest_store=attest_store,
                    role=role,
                )
            except EnrollError as e:
                _fail(str(e))

        if role == "server" and cfg.allowed_cns_file:
            allow = Path(cfg.allowed_cns_file)
            allow.touch(mode=0o600, exist_ok=True)
            # The list below says to add the client CNs.
            print(f"Created the allowlist {allow}.")
        else:
            print(
                "Give this CN to the server operator for its allowlist: "
                f"{state['cn']}"
            )

        if unit:
            _write_unit_passphrase(proven)
            _install_unit(role)
    finally:
        wipe_passphrase(proven)

    state_path.unlink()
    _print_next_steps(role, cfg, config_path, unit)
    return 0


def _cred_file_ready() -> bool:
    try:
        return _CRED_FILE.is_file() and _CRED_FILE.stat().st_size > 0
    except OSError:
        # Cannot tell: "not ready" only makes init ask for the file.
        return False


def _close_to_others(path: Path, mode: int) -> None:
    """Set ``path`` to ``mode`` if group or others may use it. Never reads
    the file. A missing path is left for the caller to make; a symlink is
    left alone."""
    try:
        if path.is_symlink() or not path.exists():
            return
        old = path.stat().st_mode & 0o777
        if not old & 0o077:
            return
        path.chmod(mode)
    except OSError as e:
        print(
            f"dsm init: could not set {path} to mode {mode:o}: {e}; run: "
            f"sudo chmod {mode:o} {path}",
            file=sys.stderr,
        )
    else:
        print(f"{path} was open to others (mode {old:o}); it is now {mode:o}.")


def _warn_if_shared(path: Path) -> None:
    """One line if the kept file is owned by someone else or has more than
    one name. Reads no content."""
    try:
        st = path.stat()
    except OSError:
        return
    if st.st_uid != os.geteuid() or st.st_nlink > 1:
        print(
            f"dsm init: {path} is owned by another user or has more than one "
            "name; check who can change it.",
            file=sys.stderr,
        )


def _write_unit_passphrase(passphrase: bytearray) -> None:
    """Give the systemd unit the passphrase that just unlocked the keys.

    The unit reads /etc/dsm/passphrase (LoadCredential=); an empty file
    stops it with every start error, a missing one makes systemd refuse to
    start it (QA B2). A file with something in it is left alone and not
    read: reading it would copy a secret into memory that cannot be wiped.
    A write that fails leaves no file, never a partial one.
    """
    path = _CRED_FILE
    # Under the unit DSM sees only systemd's 0400 copy, so nothing else would
    # notice a passphrase file or folder others can open: close them here.
    _close_to_others(path.parent, 0o700)
    if path.is_symlink():
        print(
            f"{path} is a symlink; init did not check or change the file it "
            "points to: make it mode 0600, owned by root.",
            file=sys.stderr,
        )
        return
    if _cred_file_ready():
        _close_to_others(path, 0o600)
        _warn_if_shared(path)
        print(f"Kept {path}; make sure it holds this passphrase.")
        return
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        # No O_TRUNC: the file is truncated only after the checks below, so a
        # file with another name is never emptied.
        fd = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
        try:
            st = os.fstat(fd)
            if (
                not stat.S_ISREG(st.st_mode)
                or st.st_uid != os.geteuid()
                or st.st_nlink != 1
            ):
                # The list below says to put the passphrase there.
                print(
                    f"dsm init: {path} is not a plain file of yours, or has more "
                    "than one name; not written",
                    file=sys.stderr,
                )
                return
            try:
                os.ftruncate(fd, 0)
                os.fchmod(fd, 0o600)
                with memoryview(passphrase) as view:
                    written = 0
                    while written < len(view):
                        written += os.write(fd, view[written:])
                os.fsync(fd)
            except OSError:
                # The file was missing or empty before, or we made it: remove
                # it so no partial passphrase stays behind.
                path.unlink(missing_ok=True)
                raise
        finally:
            os.close(fd)
    except OSError as e:
        why = "it is a symlink" if e.errno == errno.ELOOP else str(e)
        # The cause only: the list below says to put the passphrase there.
        print(f"dsm init: could not write {path}: {why}", file=sys.stderr)
        return
    print(f"Wrote the key passphrase to {path} (mode 0600) for the systemd unit.")


def _has_names(path: Path) -> bool:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        # Cannot read it: "no names" only makes init ask for them.
        return False
    return any(
        line.strip() and not line.strip().startswith("#") for line in text.splitlines()
    )


def _print_next_steps(role: str, cfg: Config, config_path: Path, unit: bool) -> None:
    """What is left before DSM can start (QA M1), instead of "Done"."""
    steps: list[str] = []
    if cfg.crl_file and not Path(cfg.crl_file).is_file():
        steps.append(
            f"Copy the CA's current CRL to {cfg.crl_file}, mode 0600 "
            "(deploy/GUIDE.md §2f)."
        )
    if role == "server":
        if cfg.allowed_cns_file and not _has_names(Path(cfg.allowed_cns_file)):
            steps.append(
                f"Add each client's CN to {cfg.allowed_cns_file}, one per line "
                "(deploy/GUIDE.md §4)."
            )
    else:
        steps.append(
            "Wait until the server's allowlist has this client's CN "
            "(deploy/GUIDE.md §4): until then this client blocks all traffic, "
            "SSH too."
        )
    if unit and not _cred_file_ready():
        steps.append(f"Put the key passphrase in {_CRED_FILE} (deploy/GUIDE.md §3e).")
    name = _unit_name(role)
    if unit and not (_SYSTEMD_DIR / f"{name}.service").is_file():
        # Where to get it too: a wheel has no deploy/ folder.
        fetch = "--systemd --client" if role == "client" else "--systemd"
        steps.append(
            f"Copy {name}.service to /etc/systemd/system/: it is "
            f"deploy/{name}.service in the DSM source or release (install.sh "
            f"{fetch} puts it there). Then: sudo systemctl daemon-reload && "
            f"sudo systemctl enable {name}"
        )
    if unit:
        start = f"sudo systemctl start {_unit_name(role)}"
    else:
        start = f"sudo dsm --config {config_path}"
        if role == "client":
            # The client's start-up block goes up before it asks for the
            # passphrase, so over SSH nobody can type it (QA2 Minor 3).
            start += (
                " (at the console, not over SSH: DSM blocks all traffic "
                "before it asks for the passphrase)"
            )
    if not steps:
        print(f"Ready. Start it: {start}  (check: deploy/GUIDE.md §6)")
        return
    print("Still to do before you start DSM:")
    for number, step in enumerate(steps, start=1):
        print(f"  {number}. {step}")
    print(f"Then start it: {start}  (check: deploy/GUIDE.md §6)")


def _unit_name(role: str) -> str:
    """The systemd unit for ``role``. A client must never get the server
    unit: it runs DSM as a server."""
    return "dsm-client" if role == "client" else "dsm"


def _install_unit(role: str = "server") -> None:
    """Install the unit, and say only what was done. Each step that is left
    (the passphrase file, copying a unit a wheel lacks, waiting for the
    server, the start) is said once, in _print_next_steps' list (QA2)."""
    name = _unit_name(role)
    src = _DEPLOY_DIR / f"{name}.service"
    dst = _SYSTEMD_DIR / f"{name}.service"
    # Enabled now, started later: a server needs a client CN in its
    # allowlist first, and a client must be known to the server (QA M2).
    if not src.is_file():
        # deploy/ exists only in a source checkout.
        if dst.is_file():
            # install.sh --systemd put it there.
            print(
                f"{name}.service is already installed. Enable it with: "
                f"sudo systemctl enable {name}"
            )
        else:
            print(
                f"{name}.service is not in this install (an installed wheel "
                "has no deploy/ folder): the list below says how to add it."
            )
        return
    try:
        shutil.copyfile(src, dst)
    except OSError as e:
        # The state file stays, so the same --resume can run again.
        print(f"dsm init: could not install {dst}: {e.strerror or e}", file=sys.stderr)
        sys.exit(1)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    print(f"Installed {name}.service. Enable it with: sudo systemctl enable {name}")


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dsm init",
        description=(
            "Set up this host: write config.toml, pin the CA root, make the "
            "keys and a CSR. Then, with --resume, import the cert the CA "
            "signed (deploy/GUIDE.md §3)."
        ),
    )
    p.add_argument("role", choices=["server", "client"], help="what this host is")
    p.add_argument(
        "--resume",
        action="store_true",
        help="second step: import the cert the CA signed (needs --signed-cert)",
    )
    p.add_argument(
        "--force",
        action="store_true",
        help="start again: remove this host's keys and the saved init state",
    )
    p.add_argument(
        "--install-dir",
        default=_DEFAULT_INSTALL_DIR,
        help="folder for the config, keys and certs (default: %(default)s)",
    )
    p.add_argument(
        "--server-ip",
        help=(
            "client: the server's address, a literal IPv4 address or a DDNS "
            "name for a home server on a dynamic IP (looked up at start). A "
            "server does not use it (default there: 0.0.0.0)"
        ),
    )
    p.add_argument("--server-port", type=int, help="the server's port, e.g. 51820")
    p.add_argument(
        "--ca-root",
        help="your CA's root certificate (PEM); init copies it into --install-dir",
    )
    p.add_argument(
        "--dns-provider",
        help="server: a DoH URL whose host is an IP address, e.g. https://1.1.1.1/dns-query",
    )
    p.add_argument(
        "--dns-pin",
        help=(
            "server: the provider's key pin, 64 hex characters "
            "(deploy/GUIDE.md §3a.1)"
        ),
    )
    p.add_argument(
        "--expected-server-cn",
        help="client: the server's CN, as `dsm init server` printed it",
    )
    p.add_argument("--signed-cert", help="with --resume: the cert the CA signed")
    p.add_argument(
        "--install-unit",
        action="store_true",
        help=(
            "write /etc/dsm/passphrase and install the systemd unit (from an "
            "installed wheel it only says how to copy it)"
        ),
    )
    p.add_argument(
        "--tcti", help="the TPM to use, as a TSS2 TCTI string (default /dev/tpmrm0)"
    )
    p.add_argument(
        "--passphrase-fd",
        type=int,
        metavar="N",
        help="read the key passphrase from file descriptor N",
    )
    p.add_argument(
        "--passphrase-env-file",
        metavar="PATH",
        help=(
            "read the key passphrase from the file at PATH (mode 0600; only "
            "the passphrase)"
        ),
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.resume:
        return _phase_b(args.role, args)
    return _phase_a(args.role, args)
