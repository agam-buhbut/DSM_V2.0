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
import sys
from dataclasses import replace
from pathlib import Path

from dsm.core import log as dsm_log
from dsm.core.config import load


def _add_passphrase_args(p: argparse.ArgumentParser) -> None:
    """Non-interactive passphrase sources (stronger than DSM_PASSPHRASE env)."""
    p.add_argument(
        "--passphrase-fd", type=int, default=None,
        help="Read passphrase from file descriptor N (e.g. systemd socket pipe)",
    )
    p.add_argument(
        "--passphrase-env-file", type=str, default=None,
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
             "config.debug_net. Used by the two-box runbook for capture.",
    )
    _add_passphrase_args(parser)

    subparsers = parser.add_subparsers(dest="command", help="Subcommand (optional)")

    enroll_parser = subparsers.add_parser(
        "enroll",
        help="Provision device keys + emit CSR / import signed cert",
    )
    mode = enroll_parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--csr-out", type=Path, default=None,
        help="Generate identity + attest key and write a CSR to PATH",
    )
    mode.add_argument(
        "--import", dest="import_cert", type=Path, default=None,
        help="Import a CA-signed cert from PATH",
    )
    enroll_parser.add_argument(
        "--cn", type=str, default=None,
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

    args = parser.parse_args()

    if args.command == "enroll":
        _run_enroll(
            args.config,
            csr_out=args.csr_out,
            import_cert=args.import_cert,
            cn=args.cn,
            role=args.role,
            passphrase_fd=args.passphrase_fd,
            passphrase_env_file=args.passphrase_env_file,
        )
        return

    if args.command == "show-pubkey":
        _run_show_pubkey(
            args.config,
            passphrase_fd=args.passphrase_fd,
            passphrase_env_file=args.passphrase_env_file,
        )
        return

    config = load(args.config)
    if args.mode:
        config = replace(config, mode=args.mode)

    dsm_log.configure(config.log_level)

    # Audit stream: --debug-net CLI flag wins over config.debug_net so
    # an operator can flip it on for one run without editing the file.
    from dsm.core import netaudit
    netaudit.configure(args.debug_net or config.debug_net)

    if config.mode == "client":
        from dsm.client import run_client
        asyncio.run(run_client(
            config,
            passphrase_fd=args.passphrase_fd,
            passphrase_env_file=args.passphrase_env_file,
        ))
    elif config.mode == "server":
        from dsm.server import run_server
        asyncio.run(run_server(
            config,
            passphrase_fd=args.passphrase_fd,
            passphrase_env_file=args.passphrase_env_file,
        ))
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

    config = load(config_path)
    keystore = KeyStore(config.key_file)
    attest_store = AttestStore(config.attest_key_file)

    if csr_out is not None:
        effective_role = role or config.mode
        if effective_role not in ("client", "server"):
            print(
                f"--role must be client or server (got {effective_role!r})",
                file=sys.stderr,
            )
            sys.exit(2)

        passphrase = read_passphrase(
            passphrase_fd=passphrase_fd,
            passphrase_env_file=passphrase_env_file,
            prompt="New passphrase (will protect identity + attest key): ",
        )
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

        csr_out.write_bytes(result.csr_der)
        print(f"Wrote CSR to {csr_out}")
        print(f"  cn = {result.cn}")
        print(f"  noise_static_pub = {result.noise_static_pub.hex()}")
        print(
            "Walk the CSR via USB to the offline CA per "
            "deploy/CA_RUNBOOK.md, then run "
            "`dsm enroll --import <signed.crt>`."
        )
        return

    if import_cert is not None:
        passphrase = read_passphrase(
            passphrase_fd=passphrase_fd,
            passphrase_env_file=passphrase_env_file,
        )
        try:
            try:
                keystore.load_or_generate_with_passphrase(passphrase)
            except Exception as e:
                print(
                    f"failed to unlock identity at {config.key_file}: {e}",
                    file=sys.stderr,
                )
                sys.exit(2)
            try:
                attest_store.load_with_passphrase(passphrase)
            except Exception as e:
                print(
                    f"failed to unlock attest key at {config.attest_key_file}: {e}",
                    file=sys.stderr,
                )
                keystore.unload()
                sys.exit(2)
        finally:
            wipe_passphrase(passphrase)

        try:
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
        finally:
            attest_store.unload()
            keystore.unload()

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
    from dsm.crypto.keystore import KeyStore

    config = load(config_path)
    keystore = KeyStore(config.key_file)
    keystore.load_or_generate(
        passphrase_fd=passphrase_fd,
        passphrase_env_file=passphrase_env_file,
    )
    try:
        pub = bytes(keystore.identity.public_key)
        print(pub.hex())
    finally:
        keystore.unload()


if __name__ == "__main__":
    main()
