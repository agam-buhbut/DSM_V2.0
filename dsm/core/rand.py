"""CSPRNG utilities for traffic shaping and protocol padding.

``csprng_float`` is backed by a per-thread ``random.SystemRandom``
instance. ``SystemRandom.random()`` reads from the kernel CSPRNG (the
same source as ``os.urandom``) and yields 53 bits of entropy per call.
The wrapper preserves the public ``csprng_float() -> float`` contract.
"""

from __future__ import annotations

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
    kernel CSPRNG (same source as ``os.urandom``) and yields 53 bits of
    entropy per call.
    """
    return _rng().random()
