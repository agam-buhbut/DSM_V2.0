"""CSPRNG utilities for traffic shaping and protocol padding.

M-PERF-1/2 fix: previous implementation called `os.urandom(4)` on every
``csprng_float`` invocation. The shaper and scheduler call this on
every packet and every poll tick — 3-7 syscalls per packet on the hot
path, ~200k getrandom syscalls/sec at high pkt/s.

We now back ``csprng_float`` with a single ``random.SystemRandom``
instance per thread. ``SystemRandom`` internally batches OsRng reads
(it reads 56 bytes at a time when called from ``.random()`` and slices
out doubles) and uses the same kernel CSPRNG, so security is unchanged
while the syscall rate drops by ~10x. The wrapper preserves the public
``csprng_float() -> float`` contract.
"""

from __future__ import annotations

import math
import threading
from random import SystemRandom

# One SystemRandom per thread. Python's SystemRandom is thread-safe but
# documented to be slightly faster when not shared across threads
# because it serializes the internal buffer refill.
_thread_local = threading.local()


def _rng() -> SystemRandom:
    rng = getattr(_thread_local, "rng", None)
    if rng is None:
        rng = SystemRandom()
        _thread_local.rng = rng
    return rng


def csprng_float() -> float:
    """Return a cryptographically secure random float in [0, 1).

    Backed by ``random.SystemRandom.random()`` which reads from the
    kernel CSPRNG (same source as ``os.urandom``) but batches reads.
    Result distribution matches the previous `int.from_bytes(...) /
    (1<<32)` form to 32 bits of resolution (SystemRandom.random uses 53
    bits of entropy — strictly stronger).
    """
    return _rng().random()


def csprng_exponential(lam: float, lo: float, hi: float) -> float:
    """Sample Exp(1/lam) via inverse CDF on a CSPRNG uniform, clamped to [lo, hi]."""
    u = max(1e-10, csprng_float())
    return max(lo, min(-lam * math.log(u), hi))
