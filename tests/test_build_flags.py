"""The Rust build does not force CPU features (#6).

Forcing +aes, +ssse3, +sse4.1 or +pclmulqdq at build time turns the aes
crate's run-time AES-NI check into an always-on path, so the wheel dies with
SIGILL, and no traceback, on a CPU or VM without them. Without the flags the
crate still uses AES-NI where the CPU has it, and a constant-time software
AES where it does not. Text checks, as the other release tests do.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
# Cargo reads .cargo/config.toml in the folder it runs in and every folder
# above; the builds run in the repo root or the crate's folder.
BUILD_DIRS = (REPO, REPO / "rust", REPO / "rust" / "tuncore")
CPU_WORDS = ("target-feature", "target-cpu")


def _cargo_rustflags(path: Path) -> str:
    config = tomllib.loads(path.read_text(encoding="utf-8"))
    tables = [config.get("build", {}), *config.get("target", {}).values()]
    return " ".join(str(table.get("rustflags", "")) for table in tables)


def test_the_rust_build_does_not_force_cpu_features() -> None:
    for folder in BUILD_DIRS:
        for name in ("config.toml", "config"):
            path = folder / ".cargo" / name
            if path.is_file():
                flags = _cargo_rustflags(path)
                for word in CPU_WORDS:
                    assert word not in flags, f"{path}: {flags}"
    maturin = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    maturin_table = str(maturin["tool"]["maturin"])
    for word in CPU_WORDS:
        assert word not in maturin_table, "pyproject.toml [tool.maturin]"
    # Only the CPU words: a plain `RUSTFLAGS: -D warnings` in CI is fine.
    for workflow in sorted((REPO / ".github" / "workflows").glob("*.yml")):
        text = workflow.read_text(encoding="utf-8")
        for word in CPU_WORDS:
            assert word not in text, f"{workflow.name}: {word}"
