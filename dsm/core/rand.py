"""CSPRNG utilities for traffic shaping and protocol padding.

``csprng_float`` is backed by a shared ``random.SystemRandom`` instance.
``SystemRandom.random()`` reads from the kernel CSPRNG (the same source as
``os.urandom``) and yields 53 bits of entropy per call. The wrapper
preserves the public ``csprng_float() -> float`` contract.
"""

from __future__ import annotations

from random import SystemRandom

# SystemRandom holds no reusable state — every call reads os.urandom — so a
# single shared instance is thread-safe and there is nothing to serialize.
_rng = SystemRandom()


def csprng_float() -> float:
    """Return a cryptographically secure random float in [0, 1)."""
    return _rng.random()
