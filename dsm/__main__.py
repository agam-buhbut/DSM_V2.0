"""DSM VPN entry point.

Usage:
    python -m dsm --mode client
    python -m dsm --mode server
    python -m dsm enroll --csr-out PATH [--cn CN] [--role client|server]
    python -m dsm enroll --import CERT_PATH
    python -m dsm show-pubkey
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import tomllib
from dataclasses import replace
from pathlib import Path

from dsm.core import log as dsm_log
from dsm.core import netaudit
from dsm.core.config import Config, ConfigError, load


def _load_config_or_exit(config_path: Path | None) -> Config:
    """Load config, turning every load-time failure into a clean stderr
    message + exit(2) instead of a raw traceback.
    """
    try:
        return load(config_path)
    except ConfigError as e:
        print(f"config: {e}", file=sys.stderr)
        sys.exit(2)
    except tomllib.TOMLDecodeError as e:
        print(f"config: malformed TOML: {e}", file=sys.stderr)
        sys.exit(2)
    except TypeError as e:
        # Unknown / missing key surfaces as "unexpected keyword argument".
        print(f"config: invalid or unknown key: {e}", file=sys.stderr)
        sys.exit(2)
    except ValueError as e:
        print(f"config: {e}", file=sys.stderr)
        sys.exit(2)


def _add_passphrase_args(p: argparse.ArgumentParser) -> None:
    """Non-interactive passphrase sources (stronger than DSM_PASSPHRASE env).

    default=SUPPRESS so a flag placed before the subcommand
    (`dsm --passphrase-fd 3 enroll ...`) is not clobbered by the subparser's
    own default — argparse only writes the attr when the flag is present.
    """
    p.add_argument(
        "--passphrase-fd",
        type=int,
        default=argparse.SUPPRESS,
        help="Read passphrase from file descriptor N (e.g. systemd socket pipe)",
    )
    p.add_argument(
        "--passphrase-env-file",
        type=str,
        default=argparse.SUPPRESS,
        help="Read passphrase from file at PATH (must be 0600)",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="DSM VPN")
    parser.add_argument(
        "--mode",
        choices=["client", "server"],
        help="Override config mode",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Config file path (default: /opt/mtun/config.toml)",
    )
    parser.add_argument(
        "--debug-net",
        action="store_true",
        help="Emit structured JSON events on the dsm.netaudit logger "
        "(handshake/nft/tun/rekey/liveness/shutdown). Overrides "
        "config.debug_net. See deploy/GUIDE.md §9 for capture flow.",
    )
    _add_passphrase_args(parser)

    subparsers = parser.add_subparsers(dest="command", help="Subcommand (optional)")

    enroll_parser = subparsers.add_parser(
        "enroll",
        help="Provision device keys + emit CSR / import signed cert",
    )
    mode = enroll_parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--csr-out",
        type=Path,
        default=None,
        help="Generate identity + attest key and write a CSR to PATH",
    )
    mode.add_argument(
        "--import",
        dest="import_cert",
        type=Path,
        default=None,
        help="Import a CA-signed cert from PATH",
    )
    enroll_parser.add_argument(
        "--cn",
        type=str,
        default=None,
        help="Override the device CN (default derived from Noise static pub)",
    )
    enroll_parser.add_argument(
        "--role",
        choices=["client", "server"],
        default=None,
        help="Role suffix used when --cn is not given (default: from config.mode)",
    )
    _add_passphrase_args(enroll_parser)

    show_parser = subparsers.add_parser(
        "show-pubkey", help="Print the local identity's Noise static pubkey (hex)"
    )
    _add_passphrase_args(show_parser)

    subparsers.add_parser(
        "cleanup",
        help="Remove all dsm host state (nft tables, table-100 route, ip "
        "rule, resolv.conf, sysctls). Idempotent; for ExecStopPost / crash "
        "recovery. Needs no config or passphrase.",
    )

    init_parser = subparsers.add_parser(
        "init",
        help="Quickstart wizard: orchestrate config + CA-pin + enroll + TPM "
        "+ unit install. Use `dsm init server` or `dsm init client`.",
        add_help=False,
    )
    init_parser.add_argument("init_args", nargs=argparse.REMAINDER)

    args = parser.parse_args()

    if args.command == "enroll":
        _run_enroll(
            args.config,
            csr_out=args.csr_out,
            import_cert=args.import_cert,
            cn=args.cn,
            role=args.role,
            passphrase_fd=getattr(args, "passphrase_fd", None),
            passphrase_env_file=getattr(args, "passphrase_env_file", None),
        )
        return

    if args.command == "show-pubkey":
        _run_show_pubkey(
            args.config,
            passphrase_fd=getattr(args, "passphrase_fd", None),
            passphrase_env_file=getattr(args, "passphrase_env_file", None),
        )
        return

    if args.command == "cleanup":
        # Teardown utility: no config load, no store unlock, no passphrase.
        from dsm.net.cleanup import cleanup_host_state

        dsm_log.configure("info")
        cleanup_host_state()
        return

    if args.command == "init":
        from dsm import init as dsm_init

        sys.exit(dsm_init.main(args.init_args))

    config = _load_config_or_exit(args.config)
    if args.mode:
        config = replace(config, mode=args.mode)

    dsm_log.configure(config.log_level)

    # Audit stream: --debug-net CLI flag wins over config.debug_net so
    # an operator can flip it on for one run without editing the file.
    netaudit.configure(args.debug_net or config.debug_net)

    if config.mode == "client":
        from dsm.client import run_client

        sys.exit(
            asyncio.run(
                run_client(
                    config,
                    passphrase_fd=getattr(args, "passphrase_fd", None),
                    passphrase_env_file=getattr(args, "passphrase_env_file", None),
                )
            )
        )
    elif config.mode == "server":
        from dsm.server import run_server

        sys.exit(
            asyncio.run(
                run_server(
                    config,
                    passphrase_fd=getattr(args, "passphrase_fd", None),
                    passphrase_env_file=getattr(args, "passphrase_env_file", None),
                )
            )
        )
    else:
        print(f"mode {config.mode!r} is not supported", file=sys.stderr)
        sys.exit(1)


def _run_enroll(
    config_path: Path | None,
    *,
    csr_out: Path | None,
    import_cert: Path | None,
    cn: str | None,
    role: str | None,
    passphrase_fd: int | None,
    passphrase_env_file: str | None,
) -> None:
    from dsm.core.passphrase import read_passphrase, wipe_passphrase
    from dsm.crypto.attest_store import AttestStore
    from dsm.crypto.enroll import EnrollError, generate_enrollment, import_signed_cert
    from dsm.crypto.keystore import KeyStore

    config = _load_config_or_exit(config_path)
    keystore = KeyStore(config.key_file)
    attest_store = AttestStore(config.attest_key_file)

    # Thread the configured TCTI to the Rust attest backend, which reads it
    # from the environment. setdefault so an explicit TCTI already in the
    # environment (e.g. a test harness pointing at swtpm) still wins. No-op on
    # the soft backend, which ignores the TCTI entirely.
    tcti = getattr(config, "attest_tpm_tcti", None)
    if tcti:
        os.environ.setdefault("TCTI", tcti)

    if csr_out is not None:
        effective_role = role or config.mode
        if effective_role not in ("client", "server"):
            print(
                f"--role must be client or server (got {effective_role!r})",
                file=sys.stderr,
            )
            sys.exit(2)

        # Validate the CSR output path before we persist any keys.
        # generate_enrollment writes identity + attest keys to disk; if the CSR
        # write then fails the operator is stranded with keys on disk and no
        # CSR, and re-running errors "identity key already exists".
        csr_parent = csr_out.parent
        if not csr_parent.is_dir():
            print(
                f"enroll: cannot write CSR to {csr_out}: directory "
                f"{csr_parent} does not exist",
                file=sys.stderr,
            )
            sys.exit(2)
        if not os.access(csr_parent, os.W_OK):
            print(
                f"enroll: cannot write CSR to {csr_out}: directory "
                f"{csr_parent} is not writable",
                file=sys.stderr,
            )
            sys.exit(2)

        # Backend-aware enroll: on the TPM build the attest key is generated
        # inside the TPM (no passphrase protects it), so verify the TPM is
        # reachable before provisioning and word the prompt accurately.
        import tuncore
        from dsm.crypto.tpm_preflight import TpmPreflightError, preflight_tpm

        is_soft = bool(getattr(tuncore, "ATTEST_BACKEND_IS_SOFTWARE", True))
        if not is_soft:
            try:
                preflight_tpm(getattr(config, "attest_tpm_tcti", None))
            except TpmPreflightError as e:
                print(f"enroll: {e}", file=sys.stderr)
                sys.exit(2)

        prompt = (
            "New passphrase (will protect identity + attest key): "
            if is_soft
            else "New passphrase (protects the identity key; attest key is "
            "TPM-resident): "
        )
        try:
            passphrase = read_passphrase(
                passphrase_fd=passphrase_fd,
                passphrase_env_file=passphrase_env_file,
                prompt=prompt,
            )
        except ValueError as e:
            # read_passphrase fails closed on an empty passphrase (would
            # otherwise enroll an unprotected empty-auth TPM key). Surface
            # cleanly rather than as a raw traceback, mirroring the
            # EnrollError / TpmPreflightError handlers above.
            print(f"enroll: {e}", file=sys.stderr)
            sys.exit(2)
        try:
            try:
                result = generate_enrollment(
                    keystore=keystore,
                    attest_store=attest_store,
                    passphrase=passphrase,
                    role=effective_role,
                    cn=cn,
                )
            except EnrollError as e:
                print(f"enroll: {e}", file=sys.stderr)
                sys.exit(2)
        finally:
            wipe_passphrase(passphrase)

        try:
            csr_out.write_bytes(result.csr_der)
            # A CSR is not secret, but write it 0o600 for consistency with the
            # 0o600/0o700 convention used for the cert/key/state files and to
            # avoid an umask-dependent mode.
            csr_out.chmod(0o600)
        except OSError as e:
            # Keys are already persisted by generate_enrollment; the precheck
            # above caught the common cases, but a race (dir removed) or a
            # transient FS error still lands here — report cleanly rather than
            # surfacing a raw traceback.
            print(f"enroll: cannot write CSR to {csr_out}: {e}", file=sys.stderr)
            sys.exit(2)
        print(f"Wrote CSR to {csr_out}")
        print(f"  cn = {result.cn}")
        print(f"  noise_static_pub = {result.noise_static_pub.hex()}")
        print(
            "Walk the CSR via USB to the offline CA per "
            "deploy/GUIDE.md §3c, then run "
            "`dsm enroll --import <signed.crt>`."
        )
        return

    if import_cert is not None:
        # --import binds a CA-signed cert to an *existing* identity
        # provisioned by --csr-out. Auto-generating here would yield
        # a fresh Noise static that doesn't match the cert's
        # noiseStaticBinding extension; better to refuse loudly via
        # loaded_stores_cli (sys.exit on RuntimeError).
        from dsm.crypto._stores import loaded_stores_cli

        with loaded_stores_cli(
            keystore,
            attest_store,
            passphrase_fd=passphrase_fd,
            passphrase_env_file=passphrase_env_file,
            key_file_label=config.key_file,
            attest_key_file_label=config.attest_key_file,
        ):
            try:
                leaf = import_signed_cert(
                    cert_input_path=import_cert,
                    cert_output_path=Path(config.cert_file),
                    ca_root_path=Path(config.ca_root_file),
                    keystore=keystore,
                    attest_store=attest_store,
                )
            except EnrollError as e:
                print(f"enroll: {e}", file=sys.stderr)
                sys.exit(2)

        print(f"Imported cert into {config.cert_file}")
        print(f"  cn = {leaf.subject_cn}")
        print(f"  serial = {leaf.serial_number}")
        print(f"  not_after = {leaf.not_after.isoformat()}")
        return


def _run_show_pubkey(
    config_path: Path | None,
    passphrase_fd: int | None,
    passphrase_env_file: str | None,
) -> None:
    from dsm.core.passphrase import read_passphrase, wipe_passphrase
    from dsm.crypto.keystore import KeyStore

    config = _load_config_or_exit(config_path)
    keystore = KeyStore(config.key_file)
    # show-pubkey is strictly read-only — if no identity has been provisioned,
    # silently auto-generating one would mislead the operator who's trying to
    # *inspect* their existing key. Fail loudly instead.
    passphrase = read_passphrase(
        passphrase_fd=passphrase_fd,
        passphrase_env_file=passphrase_env_file,
    )
    try:
        try:
            keystore.load_with_passphrase(passphrase)
        except (RuntimeError, OSError) as e:
            # Widen to OSError so a key file with insecure perms
            # (InsecureFilePermissionsError, an OSError subclass) produces the
            # clean "show-pubkey: <msg>" + exit 2 instead of a raw traceback —
            # the same UX as the missing-file path. Still excludes
            # ValueError/TypeError programming errors.
            print(f"show-pubkey: {e}", file=sys.stderr)
            sys.exit(2)
    finally:
        wipe_passphrase(passphrase)
    try:
        pub = bytes(keystore.identity.public_key)
        print(pub.hex())
    finally:
        keystore.unload()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        # Ctrl-C at an interactive prompt (e.g. the passphrase tty read in
        # dsm.core.passphrase raises a bare KeyboardInterrupt) or during a
        # running session. Exit cleanly with the conventional 128+SIGINT code
        # instead of dumping a raw traceback.
        print("aborted", file=sys.stderr)
        sys.exit(130)
