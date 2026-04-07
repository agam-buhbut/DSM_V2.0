"""Logging configuration for DSM."""

from __future__ import annotations

import logging
import sys

_configured = False


def configure(level: str = "warning") -> None:
    """Configure logging. Call once at startup."""
    global _configured
    if _configured:
        return

    numeric = getattr(logging, level.upper(), logging.WARNING)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s %(levelname)s %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    root = logging.getLogger("dsm")
    root.setLevel(numeric)
    root.addHandler(handler)
    _configured = True
