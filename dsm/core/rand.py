"""CSPRNG utilities for traffic shaping and protocol padding."""

from __future__ import annotations

import math
import os


def csprng_float() -> float:
    """Return a cryptographically secure random float in [0, 1)."""
    return int.from_bytes(os.urandom(4), "big") / (1 << 32)


def csprng_exponential(lam: float, lo: float, hi: float) -> float:
    """Sample Exp(1/lam) via inverse CDF on a CSPRNG uniform, clamped to [lo, hi]."""
    u = max(1e-10, csprng_float())
    return max(lo, min(-lam * math.log(u), hi))
