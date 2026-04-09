"""DSM VPN entry point.

Usage:
    python -m dsm --mode client
    python -m dsm --mode server
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from dsm.core import log as dsm_log
from dataclasses import replace

from dsm.core.config import load


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
    args = parser.parse_args()

    config = load(args.config)
    if args.mode:
        config = replace(config, mode=args.mode)

    dsm_log.configure(config.log_level)

    mode = config.mode
    if mode == "client":
        from dsm.client import run_client

        asyncio.run(run_client(config))
    elif mode == "server":
        from dsm.server import run_server

        asyncio.run(run_server(config))
    else:
        print(f"mode {mode!r} is not yet implemented", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
