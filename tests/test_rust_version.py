"""The Rust version the build needs is set once, as rust-version in
rust/tuncore/Cargo.toml, and the build docs name that same version (review
#10: the guide said 1.74, but the locked crates need 1.88). Text checks, as
the other install.sh and unit tests do."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CARGO = REPO / "rust" / "tuncore" / "Cargo.toml"
GUIDE = REPO / "deploy" / "GUIDE.md"
CONTRIBUTING = REPO / "CONTRIBUTING.md"


def _rust_version() -> str | None:
    return tomllib.loads(CARGO.read_text())["package"].get("rust-version")


def test_cargo_toml_sets_the_rust_version() -> None:
    # Without it, cargo on an old rustc prints a `--precise` downgrade hint
    # instead of naming the version the locked crates need.
    version = _rust_version()
    assert version is not None
    assert re.fullmatch(r"\d+\.\d+(\.\d+)?", version)


def test_the_build_docs_name_that_version() -> None:
    minimum = _rust_version()
    assert minimum is not None
    guide = GUIDE.read_text()
    toolchain = guide[guide.index("### 0c.") : guide.index("### 0e.")]
    assert f"rustc {minimum} or newer" in toolchain
    assert "Debian 13" in toolchain  # its apt rustc is too old: use rustup
    assert "--precise" in toolchain  # do not downgrade the locked crates
    assert "RUSTSEC-2026-0387" in toolchain
    for stale in ("1.74", "1.82"):
        assert stale not in toolchain, stale
    for line in toolchain.splitlines():
        if line.startswith("$ rustc --version"):
            assert f"# {minimum} or newer" in line, line
    assert f"Rust {minimum} or newer" in CONTRIBUTING.read_text()
