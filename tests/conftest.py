"""Pytest session configuration for the DSM test suite.

DSM-022 — make a tuncore-unbuilt LOCAL run loud instead of silently
green.

Many tests gate themselves behind ``@unittest.skipUnless(_HAS_TUNCORE,
...)`` so that contributors without the Rust extension built can still
run the pure-Python suite. The hazard is that those skips are easy to
miss: a CI lane (or a developer) can run the suite, see all-green, and
never notice that the entire crypto-core-backed half was skipped.

This hook splits the two intents:

  * ``DSM_REQUIRE_TUNCORE`` set (truthy) — the caller asserts tuncore
    MUST be importable (e.g. the CI lane that builds it). If the import
    fails, fail the whole session at configure time with a clear message
    rather than reporting a misleading pass.

  * Unset (the default, local-dev) — behave exactly as before (skips are
    allowed), but when tuncore is missing emit ONE warning line so the
    skip is visible in the run summary.

When tuncore IS importable, this hook is a no-op.
"""

from __future__ import annotations

import os

import pytest

_REQUIRE_ENV = "DSM_REQUIRE_TUNCORE"
# Values that mean "off" when the env var is present. Anything else
# (including "1", "true", "yes") is treated as truthy.
_FALSEY = frozenset({"", "0", "false", "no", "off"})


class DsmTuncoreSkipWarning(pytest.PytestWarning):
    """The tuncore-gated portion of the suite is being skipped."""


def _require_tuncore() -> bool:
    value = os.environ.get(_REQUIRE_ENV)
    if value is None:
        return False
    return value.strip().lower() not in _FALSEY


def _tuncore_importable() -> bool:
    try:
        import tuncore  # noqa: F401
    except ImportError:
        return False
    return True


def pytest_configure(config: pytest.Config) -> None:
    if _tuncore_importable():
        return

    if _require_tuncore():
        raise pytest.UsageError(
            f"{_REQUIRE_ENV} is set but the Rust extension 'tuncore' is not "
            "importable. Build it first: run `maturin develop` in "
            "rust/tuncore/. Refusing to run a suite that would silently skip "
            "every tuncore-gated test and report a misleading pass."
        )

    config.issue_config_time_warning(
        DsmTuncoreSkipWarning(
            "tuncore (Rust crypto core) is not built; tuncore-gated tests "
            "will be SKIPPED (not failed). Build it with `maturin develop` "
            f"in rust/tuncore/, or set {_REQUIRE_ENV}=1 to make this a hard "
            "error in CI."
        ),
        stacklevel=2,
    )
