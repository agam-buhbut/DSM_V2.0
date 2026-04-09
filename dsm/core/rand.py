"""CSPRNG utilities for traffic shaping and protocol padding."""

from __future__ import annotations

import os


def csprng_float() -> float:
    """Return a cryptographically secure random float in [0, 1)."""
    return int.from_bytes(os.urandom(4), "big") / (1 << 32)
