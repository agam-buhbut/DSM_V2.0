"""DSM VPN entry point.

Usage:
    python -m dsm --mode client
    python -m dsm --mode server
    python -m dsm reset-trust [--yes]
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
    _add_passphrase_args(parser)

    subparsers = parser.add_subparsers(dest="command", help="Subcommand (optional)")

    reset_parser = subparsers.add_parser(
        "reset-trust", help="Delete known_hosts.json after identity rotation"
    )
    reset_parser.add_argument(
        "--yes", "-y", action="store_true",
        help="Skip interactive confirmation",
    )

    authorize_parser = subparsers.add_parser(
        "authorize",
        help="Add a client public key (hex) to authorized_clients.json",
    )
    authorize_parser.add_argument("pubkey_hex", help="32-byte client public key as hex")
    _add_passphrase_args(authorize_parser)

    show_parser = subparsers.add_parser(
        "show-pubkey", help="Print the local identity's public key (hex)"
    )
    _add_passphrase_args(show_parser)

    args = parser.parse_args()

    if args.command == "reset-trust":
        _run_reset_trust(assume_yes=args.yes)
        return

    if args.command == "authorize":
        _run_authorize(
            args.pubkey_hex,
            args.config,
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


def _run_reset_trust(assume_yes: bool) -> None:
    from dsm.crypto.handshake import DEFAULT_KNOWN_HOSTS_PATH

    path = DEFAULT_KNOWN_HOSTS_PATH
    if not path.exists():
        print(f"{path} does not exist")
        return

    if not assume_yes:
        if not sys.stdin.isatty():
            print(
                f"refusing to delete {path} non-interactively; pass --yes",
                file=sys.stderr,
            )
            sys.exit(2)
        response = input(f"Delete {path}? [y/N] ").strip().lower()
        if response != "y":
            print("Aborted")
            return

    try:
        path.unlink()
        print(f"Deleted {path}")
    except OSError as e:
        print(f"Error deleting {path}: {e}", file=sys.stderr)
        sys.exit(1)


def _load_identity(
    config_path: Path | None,
    passphrase_fd: int | None,
    passphrase_env_file: str | None,
):
    """Shared helper for authorize/show-pubkey subcommands.

    Returns (config, keystore) — caller must keystore.unload() when done.
    """
    from dsm.crypto.keystore import KeyStore

    config = load(config_path)
    keystore = KeyStore(config.key_file)
    keystore.load_or_generate(
        passphrase_fd=passphrase_fd,
        passphrase_env_file=passphrase_env_file,
    )
    return config, keystore


def _run_authorize(
    pubkey_hex: str,
    config_path: Path | None,
    passphrase_fd: int | None,
    passphrase_env_file: str | None,
) -> None:
    from dsm.crypto.authorized_clients import AuthorizedClients

    try:
        pubkey = bytes.fromhex(pubkey_hex)
    except ValueError as e:
        print(f"invalid hex pubkey: {e}", file=sys.stderr)
        sys.exit(2)
    if len(pubkey) != 32:
        print(f"pubkey must be 32 bytes, got {len(pubkey)}", file=sys.stderr)
        sys.exit(2)

    config, keystore = _load_identity(config_path, passphrase_fd, passphrase_env_file)
    try:
        ac = AuthorizedClients(
            config.config_dir / "authorized_clients.json", keystore.identity,
        )
        ac.load()
        ac.add(pubkey)
        ac.save()
        print(f"Authorized client {pubkey.hex()[:16]}… ({len(ac)} total)")
    finally:
        keystore.unload()


def _run_show_pubkey(
    config_path: Path | None,
    passphrase_fd: int | None,
    passphrase_env_file: str | None,
) -> None:
    _config, keystore = _load_identity(config_path, passphrase_fd, passphrase_env_file)
    try:
        pub = bytes(keystore.identity.public_key)
        print(pub.hex())
    finally:
        keystore.unload()


if __name__ == "__main__":
    main()
