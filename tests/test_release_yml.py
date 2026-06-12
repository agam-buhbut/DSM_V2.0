"""Contract assertions on the tag-triggered Release workflow
(.github/workflows/release.yml).

Locks the load-bearing properties of the release pipeline so a regression can
never silently ship: the `v*` trigger, the minimal `permissions:` block, reuse
of the ci.yml gate suite as a precondition that runs BEFORE any artifact build,
the three supported-distro artifacts (tpm-attest wheel, +soft eval wheel,
sdist), the minisign signing of SHA256SUMS via OWNER-held repo SECRETS (not
invented values), the pre-release flag for 0.x tags, and full SHA-pinning of
every third-party action. Parsed both structurally (PyYAML if present) and by
text so the suite stays useful on a stripped-down dev box.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_YML_PATH = _ROOT / ".github" / "workflows" / "release.yml"
_TEXT = _YML_PATH.read_text(encoding="utf-8")


def _load_yaml() -> dict | None:
    """Load the workflow with PyYAML if available, else None (text-only run)."""
    try:
        import yaml
    except ImportError:
        return None
    return yaml.safe_load(_TEXT)


def test_workflow_exists_and_parses() -> None:
    assert _YML_PATH.is_file()
    assert _TEXT.strip()
    data = _load_yaml()
    if data is None:
        pytest.skip("PyYAML not installed; structural checks via text assertions")
    assert isinstance(data, dict)
    assert "jobs" in data


def test_tag_trigger() -> None:
    assert "tags:" in _TEXT and "'v*'" in _TEXT
    data = _load_yaml()
    if data is None:
        return
    # YAML parses the bare `on:` key as the boolean True.
    on = data.get("on", data.get(True))
    assert on is not None, "release.yml has no `on:` trigger"
    assert on["push"]["tags"] == ["v*"]


def test_minimal_permissions() -> None:
    assert "contents: write" in _TEXT
    data = _load_yaml()
    if data is None:
        return
    perms = data["permissions"]
    # contents:write is the ONLY grant — nothing else (no packages/id-token/etc).
    assert perms == {"contents": "write"}


def test_reuses_ci_gates() -> None:
    assert "uses: ./.github/workflows/ci.yml" in _TEXT
    data = _load_yaml()
    if data is None:
        return
    jobs = data["jobs"]
    assert jobs["gate"]["uses"] == "./.github/workflows/ci.yml"


def test_gates_run_before_artifacts() -> None:
    """Every build/publish job must `needs:` the gate (directly or transitively)
    so the lint/test suite passes BEFORE any artifact is built or published."""
    data = _load_yaml()
    if data is None:
        # Text fallback: each build job declares a needs on gate.
        assert "needs: gate" in _TEXT
        return
    jobs = data["jobs"]

    def _needs(job: str) -> set[str]:
        n = jobs[job].get("needs", [])
        return {n} if isinstance(n, str) else set(n)

    for build_job in ("build-tpm-wheel", "build-soft-wheel", "build-sdist"):
        assert "gate" in _needs(build_job), f"{build_job} does not need the gate"

    # The publisher depends on all three builders (so transitively on the gate).
    assert _needs("sign-and-publish") == {
        "build-tpm-wheel",
        "build-soft-wheel",
        "build-sdist",
    }


def test_builds_three_artifacts() -> None:
    assert "--features tpm-attest" in _TEXT
    assert "--features dev-soft-attest" in _TEXT
    assert "maturin sdist" in _TEXT


def test_signs_checksums_with_minisign() -> None:
    assert "SHA256SUMS" in _TEXT
    assert "sha256sum" in _TEXT
    assert "minisign -S" in _TEXT
    assert "SHA256SUMS.minisig" in _TEXT


def test_minisign_secrets_are_owner_placeholders() -> None:
    """The signing key + its password are OWNER-held repo secrets referenced as
    ${{ secrets.* }} with a TODO(owner) note — never invented literal values."""
    assert "${{ secrets.MINISIGN_SECRET_KEY }}" in _TEXT
    assert "${{ secrets.MINISIGN_KEY_PASSWORD }}" in _TEXT
    assert "TODO(owner)" in _TEXT


def test_prerelease_for_0x_tags() -> None:
    # A v0.* tag must publish as a pre-release.
    assert "prerelease:" in _TEXT
    assert "v0\\." in _TEXT or "^v0\\." in _TEXT


def test_third_party_actions_sha_pinned() -> None:
    """Every external (org/repo@ref) action must be pinned to a 40-hex SHA, not
    a mutable tag/branch. The local reusable workflow (./.github/...) is exempt."""
    refs = re.findall(r"uses:\s*(\S+)", _TEXT)
    assert refs, "no `uses:` action references found"
    external = [r for r in refs if not r.startswith("./")]
    assert external, "expected at least one third-party action"
    for ref in external:
        assert "@" in ref, f"action {ref} has no pinned ref"
        sha = ref.split("@", 1)[1]
        assert re.fullmatch(r"[0-9a-f]{40}", sha), f"action {ref} not SHA-pinned"
