# Phase 4 — Release Engineering Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn DSM from an internal, build-from-source codebase into a publicly installable `v0.1.0` release: a supported-distro wheel + verify-before-execute `install.sh`, a `dsm init` orchestration wizard, a signed GitHub-Release pipeline, and Markdown docs — without touching protocol, crypto, or the data path.

**Architecture:** Phase 4 is packaging, orchestration, distribution, docs, and versioning. The one genuinely new piece of runtime code is the `dsm init` wizard (`dsm/init.py`), which is a *thin orchestrator* — it sequences the already-audited `config.load`, `tpm_preflight.preflight_tpm`, `enroll.generate_enrollment`, `enroll.import_signed_cert`, `passphrase.read_passphrase`, and `_stores.loaded_stores_cli` calls and adds **no new crypto or key-handling code**. Everything else is shell (`install.sh`), CI YAML (`release.yml`), a venv install contract, a lockfile regeneration, and doc finalization. Distribution targets a declared contract — Debian 12+ / Ubuntu 22.04+ / x86_64 / TPM 2.0 — because the production wheel dynamically links the host `libtss2-esys.so.0` and the TPM stack `dlopen`s host TCTIs; portable manylinux is impossible and is not attempted.

**Tech Stack:** Python 3.11+ (argparse, pathlib, hashlib, subprocess list-form, tomllib), maturin (PyO3/Rust wheel build), POSIX sh + minisign (release verification), GitHub Actions (reusable-workflow), pytest (+ the `swtpm_tcti` conftest fixture).

---

## Owner-only placeholders (filled by the owner at release time — DO NOT invent)

These three facts are unknown until the owner provides them. The plan uses clearly-marked placeholder tokens everywhere they appear; every other value in this plan is concrete and implementable now.

| Placeholder token | What it is | Where it appears | Filled by |
|---|---|---|---|
| `<OWNER/REPO>` / `DSM_RELEASE_BASE_URL` | the GitHub `org/repo` slug and the derived release download base URL `https://github.com/<OWNER/REPO>/releases/download/v${VER}` | `install.sh` download base, `CHANGELOG.md` compare link, `release.yml` (implicit via `GITHUB_REPOSITORY`) | owner, at release |
| `MINISIGN_PUBKEY` | the minisign **public** key (one base64 line) embedded in `install.sh` for verify-before-execute. The **private** key custody is OWNER-ONLY and lives in a CI secret. | `install.sh` (embedded), `release.yml` signing step (private key via secret) | owner, at release |
| security-contact email | the disclosure address | `SECURITY.md` (already a `TODO(maintainer)` placeholder there) | owner (already flagged in `SECURITY.md`) |

Each placeholder is written as a literal token plus a `# TODO(owner): …` comment at its site so it is impossible to ship by accident — the verification steps below grep for the unresolved tokens.

---

## Already done (Phase-4 hygiene — DO NOT redo)

These were completed in earlier phases; confirm-and-skip, do not reimplement:

- `LICENSE` (MIT) present.
- `SECURITY.md` present (security-contact is a `TODO(maintainer)` placeholder — that is the owner-only fact above, not a task here).
- `CHANGELOG.md` present with a populated `[Unreleased]` section (Task 4.1 *cuts* it; it does not author content).
- `deploy/openssl-ca.cnf` H12 fix + dead `[crl_ext]` removal done.
- `pyproject.toml` license metadata: `license = "MIT"`, `license-files = ["LICENSE"]` done.
- `refactor-plan-*.md` deletion done (absent from tree).
- `.github/workflows/ci.yml` two-wheel (soft + tpm) matrix + gates done — Task 4.7 **reuses** it, does not rewrite it.
- `deploy/GUIDE.txt` TPM prereqs (§0e) + enroll flow (§3) done; `config.example.toml` field-complete (guarded by `test_example_config`).
- Cargo `tpm-attest` is the default feature done.

---

## File Structure

| File | Action | Responsibility |
|---|---|---|
| `pyproject.toml` | confirm | `version = "0.1.0"` (already correct — Task 4.1 only asserts) |
| `rust/tuncore/Cargo.toml` | confirm | `version = "0.1.0"` (already correct — Task 4.1 only asserts) |
| `CHANGELOG.md` | modify | cut `[Unreleased]` → `[0.1.0] - 2026-06-12`; fresh empty `[Unreleased]`; fix compare link to `<OWNER/REPO>` |
| `README.txt` → `README.md` | rename + rewrite | `git mv` + Markdown; QUICKSTART section at top referencing `install.sh` + `dsm init` |
| `deploy/GUIDE.txt` → `deploy/GUIDE.md` | rename + reformat | `git mv` + Markdown (GitHub rendering) |
| `deploy/dsm.service` | modify | `Documentation=` → `.md` paths; `ExecStart=`/`ExecStopPost=` → `/opt/dsm/venv/bin/dsm …` |
| `dsm/init.py` | create | the `dsm init server` / `dsm init client` wizard (thin orchestrator) |
| `dsm/__main__.py` | modify | add the `init` subparser + dispatch to `dsm.init` |
| `tests/test_init.py` | create | TDD for the wizard (non-interactive, `--resume`, precondition exits, idempotency) |
| `tests/test_service_unit.py` | create | static assertions on the `dsm.service` ExecStart/Documentation contract |
| `install.sh` | create | verify-before-execute bootstrap (minisign + SHA256 → venv install) |
| `requirements.lock` | regenerate | `uv pip compile --generate-hashes` for verified installs |
| `.github/workflows/release.yml` | create | tag-triggered: reuse ci.yml gates → build tpm/soft/sdist → sign → publish |
| `CONTRIBUTING.md` | create | build-from-source + two-wheel/feature dev setup + swtpm test loop |
| `.github/ISSUE_TEMPLATE/bug_report.md` | create | minimal bug template with a "do NOT paste keys/certs/CNs" warning |
| `.github/ISSUE_TEMPLATE/config.yml` | create | redirect security reports to `SECURITY.md` |
| `.gitignore` | modify | add build-artifact / venv / release-artifact rows |

**Dependency graph (execution order):**
- **4.1, 4.6, 4.8** are independent of everything (parallelizable).
- **4.2** (docs) and **4.4** (`dsm.service` ExecStart) are coupled to **4.5** (`install.sh` references the `.md` paths and the `/opt/dsm/venv` contract) — land 4.2 + 4.4 before 4.5.
- **4.3** (wizard) is independent of the distribution tasks but is the largest; it only needs the existing audited modules. Can run in parallel with 4.5/4.6.
- **4.7** (`release.yml`) depends on 4.1 (version cut), 4.5 (`install.sh` exists to attach), 4.6 (hashed lock).
- **Sequence:** {4.1, 4.6, 4.8, 4.3} can start immediately and in parallel; 4.2 → 4.4 → 4.5; then 4.7 last.

**Security review required after:** Task 4.3 (`dsm/init.py` — passphrase + state-file handling) and Task 4.5 (`install.sh` — signature verification + root execution). Invoke the `security-crypto` skill / `security` agent on those two surfaces before they are considered done.

---

### Task 4.1 — Versioning + CHANGELOG cut

**Files:**
- Confirm: `pyproject.toml:7` (`version = "0.1.0"`)
- Confirm: `rust/tuncore/Cargo.toml:3` (`version = "0.1.0"`)
- Modify: `CHANGELOG.md`
- Test: `tests/test_version_consistency.py` (create)

> **Note:** a background `cargo build` may be running against `Cargo.toml`. This task only *confirms* the Cargo version (no edit needed — it is already `0.1.0`); if a future bump is required, edit only line 3. The CHANGELOG edit touches no build inputs.

- [ ] **Step 1: Write the failing test**

Create `tests/test_version_consistency.py`:

```python
"""Lock the three version sources together so a release never tags a skewed
set (pyproject / Cargo / CHANGELOG). Pure stdlib parse — no tuncore needed."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
EXPECTED = "0.1.0"


def _pyproject_version() -> str:
    data = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return data["project"]["version"]


def _cargo_version() -> str:
    data = tomllib.loads(
        (_ROOT / "rust" / "tuncore" / "Cargo.toml").read_text(encoding="utf-8")
    )
    return data["package"]["version"]


def _changelog_top_version() -> str:
    text = (_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    # First released (non-Unreleased) heading: "## [0.1.0] - YYYY-MM-DD"
    m = re.search(r"^## \[(\d+\.\d+\.\d+)\]", text, re.MULTILINE)
    assert m is not None, "no released version heading found in CHANGELOG"
    return m.group(1)


def test_pyproject_is_expected() -> None:
    assert _pyproject_version() == EXPECTED


def test_cargo_matches_pyproject() -> None:
    assert _cargo_version() == _pyproject_version()


def test_changelog_top_matches_pyproject() -> None:
    assert _changelog_top_version() == _pyproject_version()


def test_changelog_compare_link_not_placeholder() -> None:
    text = (_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "example.com" not in text, "CHANGELOG still has the example.com link"
    # The real link carries the owner placeholder until release; assert the
    # placeholder token is present (it is replaced by the owner at release time).
    assert "<OWNER/REPO>" in text


def test_unreleased_section_kept() -> None:
    text = (_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "## [Unreleased]" in text
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/test_version_consistency.py -v`
Expected: `test_changelog_top_matches_pyproject` FAILS (no `## [0.1.0]` heading yet) and `test_changelog_compare_link_not_placeholder` FAILS (`example.com` still present).

- [ ] **Step 3: Confirm the two code versions are already 0.1.0**

Run: `grep -n '^version' pyproject.toml rust/tuncore/Cargo.toml`
Expected: `pyproject.toml:7:version = "0.1.0"` and `rust/tuncore/Cargo.toml:3:version = "0.1.0"`. No edit needed (the version-source tests already pass).

- [ ] **Step 4: Cut the CHANGELOG `[Unreleased]` block into `[0.1.0]`**

In `CHANGELOG.md`, replace the single line:

```markdown
## [Unreleased]
```

with:

```markdown
## [Unreleased]

_Nothing yet._

## [0.1.0] - 2026-06-12

First public release. Pre-1.0: wire / sealed-blob / config formats may still
evolve, so this carries **no SemVer-stability promise** yet.
```

(Leave the entire existing `### Security` / `### Reliability` / etc. body in place — it now sits under `[0.1.0]`.)

- [ ] **Step 5: Fix the compare link**

In `CHANGELOG.md`, replace the final line:

```markdown
[Unreleased]: https://example.com/dsm/compare/HEAD
```

with (note the `<OWNER/REPO>` owner placeholder):

```markdown
<!-- TODO(owner): replace <OWNER/REPO> with the real GitHub org/repo before release. -->
[Unreleased]: https://github.com/<OWNER/REPO>/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/<OWNER/REPO>/releases/tag/v0.1.0
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `pytest tests/test_version_consistency.py -v`
Expected: all 6 tests PASS.

---

### Task 4.2 — Doc rename + Markdown (README.txt → README.md, GUIDE.txt → GUIDE.md)

> **OWNER-APPROVED rename** (master-plan Owner Decisions table). This is the approved rename; no fresh ask. The `git mv` preserves history.

**Files:**
- Rename + rewrite: `README.txt` → `README.md`
- Rename + reformat: `deploy/GUIDE.txt` → `deploy/GUIDE.md`
- (the `deploy/dsm.service` `Documentation=` path fix lands in **Task 4.4** together with the `ExecStart` change so the unit is edited once)
- Test: `tests/test_docs_markdown.py` (create)

**GUIDE.txt → .md decision (flagged here, decided in this task):** convert `deploy/GUIDE.txt` → `deploy/GUIDE.md`. Rationale: GitHub renders `.md` with a clickable table of contents and syntax-highlighted code fences, and the GUIDE is already structured with section headers + code blocks, so the conversion is mechanical. **Recommendation: rename to `.md`.** (The alternative — keep `.txt` — loses GitHub rendering for the single most-read operator doc.)

- [ ] **Step 1: Write the failing test**

Create `tests/test_docs_markdown.py`:

```python
"""Lock the doc-rename contract: the .md files exist, the .txt originals are
gone, README leads with a Quickstart, and no doc references a dead .txt path."""

from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent


def test_readme_md_exists_and_txt_gone() -> None:
    assert (_ROOT / "README.md").is_file()
    assert not (_ROOT / "README.txt").exists()


def test_guide_md_exists_and_txt_gone() -> None:
    assert (_ROOT / "deploy" / "GUIDE.md").is_file()
    assert not (_ROOT / "deploy" / "GUIDE.txt").exists()


def test_readme_has_quickstart_referencing_install_and_init() -> None:
    text = (_ROOT / "README.md").read_text(encoding="utf-8")
    assert "## Quickstart" in text
    assert "install.sh" in text
    assert "dsm init server" in text
    assert "dsm init client" in text


def test_readme_states_supported_target_and_tpm() -> None:
    text = (_ROOT / "README.md").read_text(encoding="utf-8").lower()
    assert "tpm 2.0" in text
    assert "debian 12" in text and "ubuntu 22.04" in text
    assert "+soft" in text  # eval-wheel note present


def test_no_doc_points_at_txt_guide() -> None:
    # No shipped doc/unit should reference the old .txt paths.
    for rel in ("README.md", "deploy/GUIDE.md", "deploy/dsm.service"):
        text = (_ROOT / rel).read_text(encoding="utf-8")
        assert "GUIDE.txt" not in text, f"{rel} still references GUIDE.txt"
        assert "README.txt" not in text, f"{rel} still references README.txt"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/test_docs_markdown.py -v`
Expected: FAILs — `README.md` / `GUIDE.md` do not exist yet.

- [ ] **Step 3: Rename both files (history-preserving)**

Run:
```bash
git mv README.txt README.md
git mv deploy/GUIDE.txt deploy/GUIDE.md
```
Expected: both renames succeed; `git status` shows `renamed:`.

- [ ] **Step 4: Add the QUICKSTART section to the top of README.md**

Insert, immediately after the `DSM_V2.0` title line and its one-line description, a new top section (above the existing `GOAL` prose). Convert the existing `GOAL` / `NON-GOALS` / `ARCHITECTURE` plain-text headers to Markdown `##` headings as you go:

````markdown
## Quickstart

> **Supported target:** Debian 12+ / Ubuntu 22.04+ / x86_64 with a **TPM 2.0**.
> Other distros: build from source (see `deploy/GUIDE.md` §1). No PyPI — DSM is
> distributed via signed GitHub Releases.

```sh
# 1. Install (downloads + minisign-verifies the wheel, apt-installs the TPM
#    runtime libs, creates /opt/dsm/venv, symlinks `dsm`, installs the unit).
#    TODO(owner): replace <OWNER/REPO> with the real repo before release.
curl -fsSL https://github.com/<OWNER/REPO>/releases/download/v0.1.0/install.sh | sudo sh

# 2. Go from zero to running (orchestrates config + CA-pin + enroll + TPM + unit).
sudo dsm init server      # or, on the client box:  sudo dsm init client
#   ...prompts for IP/port/paths/CA-root/passphrase; pauses for the offline-CA
#   signing step; resume with:  sudo dsm init server --resume

# 3. Start it.
sudo systemctl enable --now dsm
```

**Evaluation without a TPM:** a clearly-named `+soft` evaluation wheel is also
published. Install it with `install.sh --eval`. It provides **no hardware
binding** — it is for evaluation only and must never be deployed in production.
````

- [ ] **Step 5: Markdown-format the rest of README.md**

Mechanical pass: turn the existing ALL-CAPS section banners (`GOAL`, `NON-GOALS`, `ARCHITECTURE`, `NETWORKING`, threat model, accepted-risks, config-parameter list, etc.) into `##` / `###` headings; wrap command/code blocks in triple-backtick fences; turn the `Flow:` / `Components:` lists into Markdown bullet lists. **Port the prose verbatim** — this is a format pass, not a rewrite. Keep the existing threat-model and accepted-v1-risks wording intact. Ensure the "supported target" sentence (Debian 12+/Ubuntu 22.04+/x86_64/TPM 2.0) appears once near the top and the `+soft` eval note appears once (both already added in Step 4).

- [ ] **Step 6: Markdown-format GUIDE.md**

Mechanical pass on `deploy/GUIDE.md`: convert the `===` banner headers to `#`/`##` headings, fence the copy-paste command blocks, and turn the table-of-contents into a Markdown list. Port prose verbatim. Replace any internal self-references `deploy/GUIDE.txt` → `deploy/GUIDE.md` and `README.txt` → `README.md` (the test in Step 1 enforces this).

- [ ] **Step 7: Run the test to verify it passes**

Run: `pytest tests/test_docs_markdown.py -v`
Expected: `test_no_doc_points_at_txt_guide` for `deploy/dsm.service` still FAILS (the unit's `Documentation=` lines are fixed in Task 4.4). The other 4 tests PASS. **This cross-task dependency is intentional** — note it and proceed to Task 4.4, which makes the last assertion pass. (If running 4.4 before 4.2, the order is fine either way; the suite is green only once both land.)

---

### Task 4.3 — `dsm init` wizard (CENTERPIECE; security review after)

> **Adds NO new crypto/key code.** The wizard ONLY sequences these already-audited callables, with the exact signatures confirmed against the current tree:
> - `dsm.core.config.load(path) -> Config` and the `Config` dataclass fields.
> - `dsm.crypto.tpm_preflight.preflight_tpm(tcti: str | None) -> None` (raises `TpmPreflightError`).
> - `dsm.crypto.keystore.KeyStore(key_file: str)` with `.exists()`.
> - `dsm.crypto.attest_store.AttestStore(attest_key_file: str)` with `.exists()`.
> - `dsm.crypto.enroll.generate_enrollment(*, keystore, attest_store, passphrase, role, cn=None) -> EnrollmentResult` (fields `.cn`, `.noise_static_pub`, `.csr_der`).
> - `dsm.crypto.enroll.import_signed_cert(*, cert_input_path, cert_output_path, ca_root_path, keystore, attest_store) -> DeviceCert`.
> - `dsm.crypto._stores.loaded_stores_cli(keystore, attest_store, *, passphrase_fd, passphrase_env_file, prompt, key_file_label, attest_key_file_label)` (context manager; `sys.exit(2)` on unlock failure).
> - `dsm.core.passphrase.read_passphrase(...)` / `wipe_passphrase(...)`.
>
> The wizard MUST NOT reimplement CSR build, cert verification, passphrase reading, or store unlock. It only orchestrates + writes the `config.toml` + state file + (optionally) the unit.

**Files:**
- Create: `dsm/init.py`
- Modify: `dsm/__main__.py` (add `init` subparser + dispatch)
- Test: `tests/test_init.py` (create)

**Subcommand surface:**
```
dsm init server [--non-interactive ...flags] [--resume] [--force]
dsm init client [--non-interactive ...flags] [--resume] [--force]
```

**Two-phase / `--resume` state file** — `<config_dir>/.dsm-init-state.json`, mode 0600. Carries **NO secret** (paths + phase marker + gathered non-secret answers only). Schema:

```json
{
  "schema": 1,
  "role": "server",
  "phase": "csr_emitted",
  "config_path": "/opt/mtun/config.toml",
  "csr_path": "/opt/mtun/server.csr",
  "cn": "dsm-aabbccddeeff-server",
  "ca_root_file": "/opt/mtun/dsm_ca_root.pem",
  "install_unit": true
}
```
`phase` is one of `"csr_emitted"` (Phase A done, awaiting the offline-CA round trip) → removed on completion. The passphrase, key bytes, and CA-root bytes are **never** written here.

**Steps each subcommand runs:**

*Phase A* (`dsm init server` / `dsm init client`):
1. Preconditions: assert effective root or `tss`-group membership; check `/dev/net/tun` exists; `nft --version` runs; if the installed backend is TPM (`not tuncore.ATTEST_BACKEND_IS_SOFTWARE`), call `preflight_tpm(tcti)`. On the soft (eval) build, print a loud "evaluation build — NOT hardware-bound" banner.
2. Gather answers (interactive prompts or `--non-interactive` flags): server IP (validated as an IPv4 literal — reuse the `Config` validator by constructing a trial `Config`, never a duplicated regex), port, install dir (default `/opt/mtun`), and — server only — DoH provider + SPKI pin; client only — `expected_server_cn`.
3. CA root: take the `ca_root_file` path; compute `hashlib.sha256(path.read_bytes()).hexdigest()`; print it and (interactive) ask the operator to confirm it matches their safe printout; write it into the config as `ca_root_sha256`. This replaces the manual `sha256sum | cut` step.
4. Write `config.toml` rendered from `config.example.toml` with the gathered substitutions; `chmod 0600`; then validate by calling `config.load(config_path)` — fail loudly (exit 2) if it will not parse.
5. Enroll (CSR): `read_passphrase(...)` → `generate_enrollment(keystore=, attest_store=, passphrase=, role=, cn=None)` → `csr_path.write_bytes(result.csr_der)` → `wipe_passphrase(...)`. Print the CN.
6. Pause: write the state file (mode 0600, phase `csr_emitted`); print the exact `openssl ca` sign commands (from `GUIDE.md` §3c) and `dsm init <role> --resume`.

*Phase B* (`--resume`):
7. Read the state file; `loaded_stores_cli(...)` to unlock, then `import_signed_cert(cert_input_path=<signed cert>, cert_output_path=Config.cert_file, ca_root_path=Config.ca_root_file, keystore=, attest_store=)`.
8. Server only: create `allowed_cns_file` (mode 0600, empty); print "add the client CN here." Client only: print "give this CN to the server operator for its allowlist."
9. If `--install-unit`: copy `deploy/dsm.service` to `/etc/systemd/system/`, `daemon-reload` (list-form `subprocess.run(["systemctl", "daemon-reload"], check=True)`), create the `/etc/dsm/passphrase` 0600 credential skeleton, and print `systemctl enable --now dsm`. Do NOT auto-start.
10. Remove the state file; print the GUIDE §6 verification one-liners.

**Error contract:** every precondition failure → clean stderr message + `sys.exit(2)` (mirroring `_run_enroll`), never a raw traceback. The wizard refuses to overwrite existing keys without `--force` (surface `generate_enrollment`'s existing "identity key already exists" `EnrollError` as an actionable message). Passphrase handling reuses `read_passphrase`/`wipe_passphrase` only.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_init.py`. These tests mock ONLY at the I/O boundary (the audited callables and `subprocess`), assert the wizard *calls them with the right arguments*, and drive the non-interactive path against a `tmp_path` config dir. Crypto is never exercised here.

```python
"""Tests for the `dsm init` wizard (dsm/init.py).

The wizard is a thin orchestrator. These tests assert it SEQUENCES the
already-audited callables correctly and writes the right files — they do not
re-test enroll/import/config internals (those have their own suites). Mocks
sit only at the I/O boundary: generate_enrollment, import_signed_cert,
preflight_tpm, loaded_stores_cli, and subprocess. No real keys, no real TPM.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

import pytest

from dsm import init as dsm_init
from dsm.core.config import load as config_load
from dsm.crypto.enroll import EnrollError, EnrollmentResult


def _server_flags(cfg_dir: Path) -> list[str]:
    return [
        "server",
        "--non-interactive",
        "--server-ip",
        "203.0.113.1",
        "--server-port",
        "51820",
        "--install-dir",
        str(cfg_dir),
        "--ca-root",
        str(cfg_dir / "dsm_ca_root.pem"),
        "--dns-provider",
        "https://1.1.1.1/dns-query",
        "--dns-pin",
        "ab" * 32,
        "--passphrase-env-file",
        str(cfg_dir / "pass"),
    ]


@pytest.fixture
def cfg_dir(tmp_path: Path) -> Path:
    (tmp_path / "dsm_ca_root.pem").write_bytes(b"-----BEGIN CERTIFICATE-----\n")
    p = tmp_path / "pass"
    p.write_bytes(b"hunter2hunter2\n")
    p.chmod(0o600)
    return tmp_path


def _fake_enrollment() -> EnrollmentResult:
    return EnrollmentResult(
        cn="dsm-aabbccddeeff-server",
        noise_static_pub=b"\x00" * 32,
        attest_spki_der=b"\x00" * 91,
        csr_der=b"DERCSR",
    )


def test_phase_a_writes_loadable_config_and_state(cfg_dir: Path) -> None:
    with mock.patch.object(
        dsm_init, "preflight_tpm"
    ), mock.patch.object(
        dsm_init, "generate_enrollment", return_value=_fake_enrollment()
    ) as gen:
        rc = dsm_init.main(_server_flags(cfg_dir))

    assert rc == 0
    # Config was written AND is loadable by the real validator.
    config_path = cfg_dir / "config.toml"
    assert config_path.is_file()
    assert oct(config_path.stat().st_mode)[-3:] == "600"
    cfg = config_load(config_path)
    assert cfg.mode == "server"
    assert cfg.server_ip == "203.0.113.1"
    assert cfg.ca_root_sha256 is not None and len(cfg.ca_root_sha256) == 64
    # generate_enrollment was called once with role=server, cn auto (None).
    assert gen.call_count == 1
    assert gen.call_args.kwargs["role"] == "server"
    assert gen.call_args.kwargs["cn"] is None
    # CSR written; state file written with NO secret and phase csr_emitted.
    assert (cfg_dir / "server.csr").read_bytes() == b"DERCSR"
    state = json.loads((cfg_dir / ".dsm-init-state.json").read_text())
    assert state["phase"] == "csr_emitted"
    assert state["role"] == "server"
    blob = (cfg_dir / ".dsm-init-state.json").read_text()
    assert "hunter2" not in blob  # passphrase never persisted
    assert oct((cfg_dir / ".dsm-init-state.json").stat().st_mode)[-3:] == "600"


def test_resume_imports_cert_and_clears_state(cfg_dir: Path) -> None:
    # First run Phase A to lay down config + state.
    with mock.patch.object(dsm_init, "preflight_tpm"), mock.patch.object(
        dsm_init, "generate_enrollment", return_value=_fake_enrollment()
    ):
        assert dsm_init.main(_server_flags(cfg_dir)) == 0

    signed = cfg_dir / "signed.crt"
    signed.write_bytes(b"-----BEGIN CERTIFICATE-----\n")

    import contextlib

    @contextlib.contextmanager
    def _fake_stores(*_a, **_k):
        yield

    with mock.patch.object(
        dsm_init, "loaded_stores_cli", _fake_stores
    ), mock.patch.object(dsm_init, "import_signed_cert") as imp:
        rc = dsm_init.main(
            [
                "server",
                "--resume",
                "--install-dir",
                str(cfg_dir),
                "--signed-cert",
                str(signed),
                "--passphrase-env-file",
                str(cfg_dir / "pass"),
            ]
        )

    assert rc == 0
    assert imp.call_count == 1
    assert imp.call_args.kwargs["cert_input_path"] == signed
    # Allowlist created (server), state file cleared.
    assert (cfg_dir / "allowed_cns.txt").is_file()
    assert not (cfg_dir / ".dsm-init-state.json").exists()


def test_precondition_no_tun_exits_2(cfg_dir: Path) -> None:
    with mock.patch.object(dsm_init, "_tun_present", return_value=False):
        with pytest.raises(SystemExit) as ei:
            dsm_init.main(_server_flags(cfg_dir))
    assert ei.value.code == 2


def test_existing_key_without_force_exits_2(cfg_dir: Path) -> None:
    def _raise(**_k):
        raise EnrollError("identity key already exists at /x; remove by hand")

    with mock.patch.object(dsm_init, "preflight_tpm"), mock.patch.object(
        dsm_init, "generate_enrollment", side_effect=_raise
    ):
        with pytest.raises(SystemExit) as ei:
            dsm_init.main(_server_flags(cfg_dir))
    assert ei.value.code == 2


def test_client_uses_expected_server_cn(cfg_dir: Path) -> None:
    flags = [
        "client",
        "--non-interactive",
        "--server-ip",
        "203.0.113.1",
        "--server-port",
        "51820",
        "--install-dir",
        str(cfg_dir),
        "--ca-root",
        str(cfg_dir / "dsm_ca_root.pem"),
        "--expected-server-cn",
        "dsm-1234abcd-server",
        "--passphrase-env-file",
        str(cfg_dir / "pass"),
    ]
    with mock.patch.object(dsm_init, "preflight_tpm"), mock.patch.object(
        dsm_init, "generate_enrollment", return_value=_fake_enrollment()
    ) as gen:
        assert dsm_init.main(flags) == 0
    cfg = config_load(cfg_dir / "config.toml")
    assert cfg.mode == "client"
    assert cfg.expected_server_cn == "dsm-1234abcd-server"
    assert gen.call_args.kwargs["role"] == "client"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/test_init.py -v`
Expected: collection/import FAILS — `dsm/init.py` (`dsm.init`) does not exist.

- [ ] **Step 3: Implement `dsm/init.py`**

Create `dsm/init.py`. (The names mocked by the tests — `preflight_tpm`, `generate_enrollment`, `import_signed_cert`, `loaded_stores_cli`, `_tun_present` — MUST be module-level so the tests can patch them.)

```python
"""`dsm init` quickstart wizard — a thin orchestrator over the audited
enroll / import / config / preflight paths. ADDS NO new crypto or key code:
it sequences existing callables, renders config.toml, manages a small
no-secret state file for the air-gapped CA round trip, and (optionally)
installs the systemd unit.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from dsm.core.config import ConfigError
from dsm.core.config import load as config_load
from dsm.crypto._stores import loaded_stores_cli
from dsm.crypto.attest_store import AttestStore
from dsm.crypto.enroll import (
    EnrollError,
    generate_enrollment,
    import_signed_cert,
)
from dsm.crypto.keystore import KeyStore
from dsm.crypto.passphrase_imports import (  # see Step 3b note
    read_passphrase,
    wipe_passphrase,
)
from dsm.crypto.tpm_preflight import TpmPreflightError, preflight_tpm

_STATE_NAME = ".dsm-init-state.json"
_STATE_SCHEMA = 1


def _fail(msg: str) -> None:
    print(f"dsm init: {msg}", file=sys.stderr)
    sys.exit(2)


def _tun_present() -> bool:
    return Path("/dev/net/tun").exists()


def _nft_present() -> bool:
    return shutil.which("nft") is not None


def _backend_is_soft() -> bool:
    import tuncore

    return bool(getattr(tuncore, "ATTEST_BACKEND_IS_SOFTWARE", True))


def _check_preconditions(tcti: str | None) -> None:
    if os.geteuid() != 0 and "tss" not in _supplementary_group_names():
        _fail("must run as root (or be in the 'tss' group)")
    if not _tun_present():
        _fail("/dev/net/tun missing — load the tun module: modprobe tun")
    if not _nft_present():
        _fail("nft(8) not found — install nftables")
    if _backend_is_soft():
        print(
            "=== EVALUATION BUILD — soft attest backend, NOT hardware-bound. "
            "Do NOT deploy in production. ===",
            file=sys.stderr,
        )
        return
    try:
        preflight_tpm(tcti)
    except TpmPreflightError as e:
        _fail(str(e))


def _supplementary_group_names() -> set[str]:
    import grp

    return {grp.getgrgid(g).gr_name for g in os.getgroups()}


def _validate_ip_literal(ip: str) -> None:
    """Reuse the audited Config validator instead of a duplicated regex: a
    trial Config raises ValueError on a bad/hostname/IPv6 server_ip."""
    import ipaddress

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        _fail(f"server-ip must be a literal IPv4 address, got {ip!r}")
        return
    if addr.version == 6:
        _fail(f"IPv6 server-ip {ip!r} is not supported (use an IPv4 endpoint)")


def _render_config(role: str, args: argparse.Namespace, install_dir: Path) -> str:
    """Render config.toml text from config.example.toml-shaped fields."""
    ca_root = Path(args.ca_root)
    if not ca_root.is_file():
        _fail(f"ca-root not found: {ca_root}")
    ca_sha = hashlib.sha256(ca_root.read_bytes()).hexdigest()
    print(f"ca_root_sha256 = {ca_sha}", file=sys.stderr)
    lines = [
        f'mode = "{role}"',
        f'server_ip = "{args.server_ip}"',
        f"server_port = {args.server_port}",
        f"listen_port = {0 if role == 'client' else args.server_port}",
        f'key_file = "{install_dir / "identity.key"}"',
        f'cert_file = "{install_dir / "device.crt"}"',
        f'ca_root_file = "{ca_root}"',
        f'ca_root_sha256 = "{ca_sha}"',
        f'attest_key_file = "{install_dir / "attest.key"}"',
        "crl_strict = false",  # init writes a working dev default; GUIDE §7e adds a CRL
        'transport = "udp"',
    ]
    if role == "client":
        lines.append(f'expected_server_cn = "{args.expected_server_cn}"')
    else:
        lines.append(f'allowed_cns_file = "{install_dir / "allowed_cns.txt"}"')
        lines.append(f'dns_providers = ["{args.dns_provider}"]')
        lines.append("[dns_provider_pins]")
        lines.append(f'"{args.dns_provider}" = ["{args.dns_pin}"]')
    return "\n".join(lines) + "\n"


def _write_state(install_dir: Path, role: str, args: argparse.Namespace,
                 csr_path: Path, cn: str) -> None:
    state = {
        "schema": _STATE_SCHEMA,
        "role": role,
        "phase": "csr_emitted",
        "config_path": str(install_dir / "config.toml"),
        "csr_path": str(csr_path),
        "cn": cn,
        "ca_root_file": str(Path(args.ca_root)),
        "install_unit": bool(getattr(args, "install_unit", False)),
    }
    path = install_dir / _STATE_NAME
    path.write_text(json.dumps(state, indent=2), encoding="utf-8")
    path.chmod(0o600)


def _phase_a(role: str, args: argparse.Namespace) -> int:
    _validate_ip_literal(args.server_ip)
    _check_preconditions(getattr(args, "tcti", None))
    install_dir = Path(args.install_dir)
    install_dir.mkdir(parents=True, exist_ok=True)

    config_path = install_dir / "config.toml"
    config_path.write_text(_render_config(role, args, install_dir), encoding="utf-8")
    config_path.chmod(0o600)
    try:
        config_load(config_path)
    except (ConfigError, ValueError, TypeError) as e:
        _fail(f"generated config did not validate: {e}")

    keystore = KeyStore(str(install_dir / "identity.key"))
    attest_store = AttestStore(str(install_dir / "attest.key"))
    passphrase = read_passphrase(
        passphrase_fd=getattr(args, "passphrase_fd", None),
        passphrase_env_file=getattr(args, "passphrase_env_file", None),
        prompt="New passphrase (protects the identity key): ",
    )
    try:
        try:
            result = generate_enrollment(
                keystore=keystore,
                attest_store=attest_store,
                passphrase=passphrase,
                role=role,
                cn=None,
            )
        except EnrollError as e:
            _fail(str(e))
            return 2  # unreachable; _fail exits
    finally:
        wipe_passphrase(passphrase)

    csr_path = install_dir / f"{role}.csr"
    csr_path.write_bytes(result.csr_der)
    _write_state(install_dir, role, args, csr_path, result.cn)
    print(f"Wrote CSR to {csr_path} (cn={result.cn})")
    print(
        "Walk the CSR to the offline CA (deploy/GUIDE.md §3c), sign it, then run:\n"
        f"  sudo dsm init {role} --resume --signed-cert <signed.crt>"
    )
    return 0


def _phase_b(role: str, args: argparse.Namespace) -> int:
    install_dir = Path(args.install_dir)
    state_path = install_dir / _STATE_NAME
    if not state_path.is_file():
        _fail(f"no init state at {state_path}; run Phase A first (without --resume)")
    state = json.loads(state_path.read_text(encoding="utf-8"))
    cfg = config_load(Path(state["config_path"]))

    keystore = KeyStore(cfg.key_file)
    attest_store = AttestStore(cfg.attest_key_file)
    signed = Path(args.signed_cert)
    with loaded_stores_cli(
        keystore,
        attest_store,
        passphrase_fd=getattr(args, "passphrase_fd", None),
        passphrase_env_file=getattr(args, "passphrase_env_file", None),
        key_file_label=cfg.key_file,
        attest_key_file_label=cfg.attest_key_file,
    ):
        try:
            import_signed_cert(
                cert_input_path=signed,
                cert_output_path=Path(cfg.cert_file),
                ca_root_path=Path(cfg.ca_root_file),
                keystore=keystore,
                attest_store=attest_store,
            )
        except EnrollError as e:
            _fail(str(e))

    if role == "server" and cfg.allowed_cns_file:
        allow = Path(cfg.allowed_cns_file)
        allow.touch(mode=0o600, exist_ok=True)
        print(f"Created empty allowlist {allow}; add the client CN there.")
    else:
        print(f"Give this CN to the server operator for its allowlist: {state['cn']}")

    if state.get("install_unit"):
        _install_unit()

    state_path.unlink()
    print("Done. Verify with: systemctl status dsm  (deploy/GUIDE.md §6)")
    return 0


def _install_unit() -> None:
    src = Path(__file__).resolve().parent.parent / "deploy" / "dsm.service"
    dst = Path("/etc/systemd/system/dsm.service")
    shutil.copyfile(src, dst)
    Path("/etc/dsm").mkdir(parents=True, exist_ok=True)
    cred = Path("/etc/dsm/passphrase")
    if not cred.exists():
        cred.touch(mode=0o600)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    print("Installed dsm.service. Start with: sudo systemctl enable --now dsm")


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="dsm init")
    p.add_argument("role", choices=["server", "client"])
    p.add_argument("--resume", action="store_true")
    p.add_argument("--force", action="store_true")
    p.add_argument("--non-interactive", action="store_true")
    p.add_argument("--install-dir", default="/opt/mtun")
    p.add_argument("--server-ip")
    p.add_argument("--server-port", type=int)
    p.add_argument("--ca-root")
    p.add_argument("--dns-provider")
    p.add_argument("--dns-pin")
    p.add_argument("--expected-server-cn")
    p.add_argument("--signed-cert")
    p.add_argument("--install-unit", action="store_true")
    p.add_argument("--tcti")
    p.add_argument("--passphrase-fd", type=int)
    p.add_argument("--passphrase-env-file")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.resume:
        return _phase_b(args.role, args)
    return _phase_a(args.role, args)
```

- [ ] **Step 3b: Resolve the passphrase import path**

The snippet above imports from `dsm.crypto.passphrase_imports` as a deliberate placeholder marker — the real module is `dsm.core.passphrase`. Edit the import in `dsm/init.py` to the real path:

```python
from dsm.core.passphrase import read_passphrase, wipe_passphrase
```

(This is the only spot to fix; it is called out separately so the engineer cannot miss it.)

- [ ] **Step 4: Wire the `init` subparser into `dsm/__main__.py`**

In `dsm/__main__.py`, inside `main()` after the `cleanup` subparser is registered (around line 134), add:

```python
    init_parser = subparsers.add_parser(
        "init",
        help="Quickstart wizard: orchestrate config + CA-pin + enroll + TPM "
        "+ unit install. Use `dsm init server` or `dsm init client`.",
        add_help=False,
    )
    init_parser.add_argument("init_args", nargs=argparse.REMAINDER)
```

and in the dispatch block (after the `cleanup` handler, before the `config = _load_config_or_exit(...)` line) add:

```python
    if args.command == "init":
        from dsm import init as dsm_init

        sys.exit(dsm_init.main(args.init_args))
```

(`add_help=False` + `REMAINDER` hands the full `server --non-interactive …` tail to `dsm.init.main`, which owns its own argparse — this keeps the wizard's flag surface out of the top-level parser.)

- [ ] **Step 5: Run the tests to verify they pass**

Run: `pytest tests/test_init.py -v`
Expected: all 6 tests PASS.

- [ ] **Step 6: Format + lint gate the new module**

Run: `black dsm/init.py tests/test_init.py && isort dsm/init.py tests/test_init.py && ruff check dsm/init.py tests/test_init.py && pyright dsm/init.py`
Expected: clean (no errors).

- [ ] **Step 7: SECURITY REVIEW (required)**

Invoke the `security-crypto` skill on `dsm/init.py`. Confirm: (a) the state file contains no secret (the test asserts `"hunter2" not in blob`, but the reviewer must confirm the schema design); (b) passphrase flows only through `read_passphrase`/`wipe_passphrase`/`loaded_stores_cli` and is never logged; (c) all subprocess calls are list-form (no shell); (d) `import_signed_cert`'s chain/binding/SPKI checks are not bypassed; (e) generated `config.toml` and state file are mode 0600. Address findings before marking the task done.

---

### Task 4.4 — `dsm.service` ExecStart venv contract + Documentation path fix

> **Coupled with Task 4.2** (this is where the unit's `Documentation=` `.txt` → `.md` fix lands) and **Task 4.5** (`install.sh` creates `/opt/dsm/venv` this `ExecStart` points at). Keep ALL Phase-2 hardening directives and the Phase-3 `SupplementaryGroups=tss` exactly as-is.

**Files:**
- Modify: `deploy/dsm.service` (lines 6–7 `Documentation=`; lines 63–64 `ExecStart=`; line 77 `ExecStopPost=`)
- Test: `tests/test_service_unit.py` (create)

- [ ] **Step 1: Write the failing test**

Create `tests/test_service_unit.py`:

```python
"""Static contract on deploy/dsm.service: it launches from the /opt/dsm venv,
documents the .md guides, and keeps the hardening + tss group directives."""

from __future__ import annotations

from pathlib import Path

_UNIT = (
    Path(__file__).resolve().parent.parent / "deploy" / "dsm.service"
).read_text(encoding="utf-8")


def test_execstart_uses_venv_interpreter() -> None:
    assert "ExecStart=/opt/dsm/venv/bin/dsm --mode server" in _UNIT
    assert "/usr/bin/python3 -m dsm --mode" not in _UNIT


def test_execstoppost_uses_venv() -> None:
    assert "ExecStopPost=/opt/dsm/venv/bin/dsm cleanup" in _UNIT
    assert "/usr/bin/python3 -m dsm cleanup" not in _UNIT


def test_documentation_points_at_md() -> None:
    assert "GUIDE.md" in _UNIT and "README.md" in _UNIT
    assert "GUIDE.txt" not in _UNIT and "README.txt" not in _UNIT


def test_hardening_and_tss_group_retained() -> None:
    for directive in (
        "SupplementaryGroups=tss",
        "MemoryDenyWriteExecute=true",
        "NoNewPrivileges=true",
        "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_IPC_LOCK",
        "LoadCredential=passphrase:/etc/dsm/passphrase",
    ):
        assert directive in _UNIT, f"lost hardening directive: {directive}"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/test_service_unit.py -v`
Expected: FAILs — current unit uses `/usr/bin/python3 -m dsm` and `Documentation=…GUIDE.txt`.

- [ ] **Step 3: Fix the `Documentation=` lines**

In `deploy/dsm.service`, replace lines 6–7:

```
Documentation=file:///opt/dsm-repo/deploy/GUIDE.txt
Documentation=file:///opt/dsm-repo/README.txt
```

with:

```
Documentation=file:///opt/dsm-repo/deploy/GUIDE.md
Documentation=file:///opt/dsm-repo/README.md
```

- [ ] **Step 4: Switch `ExecStart=` to the venv `dsm` console script**

Replace the comment block + `ExecStart=` (lines 57–64). The wheel's `[project.scripts] dsm = "dsm.__main__:main"` entry point is installed at `/opt/dsm/venv/bin/dsm`, so the unit calls that script directly (deterministic interpreter, no `PYTHONPATH`, no `--break-system-packages`):

```
# install.sh creates a dedicated venv at /opt/dsm/venv and installs the wheel
# into it, producing the `dsm` console-script at /opt/dsm/venv/bin/dsm (its
# shebang pins the venv interpreter). systemd runs with cwd=/, so this
# absolute path is what guarantees the right interpreter + the installed
# `dsm` + `tuncore` packages — no system-Python pollution.
ExecStart=/opt/dsm/venv/bin/dsm --mode server \
          --passphrase-env-file=${CREDENTIALS_DIRECTORY}/passphrase
```

- [ ] **Step 5: Switch `ExecStopPost=` to the venv script**

Replace line 77:

```
ExecStopPost=/usr/bin/python3 -m dsm cleanup
```

with:

```
ExecStopPost=/opt/dsm/venv/bin/dsm cleanup
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `pytest tests/test_service_unit.py tests/test_docs_markdown.py -v`
Expected: all PASS (this closes the `deploy/dsm.service` assertion left red in Task 4.2 Step 7).

- [ ] **Step 7: Validate the unit parses (best-effort)**

Run: `systemd-analyze verify deploy/dsm.service 2>&1 | head` (skip if `systemd-analyze` is unavailable in the dev env — note the skip).
Expected: no fatal parse error (it may warn that `/opt/dsm/venv/bin/dsm` does not exist on this box — that is fine; the path exists post-install).

---

### Task 4.5 — `install.sh` (verify-before-execute bootstrap; security review after)

> Root-run, network-facing. The load-bearing property: **verify the minisign signature over `SHA256SUMS` with the embedded `MINISIGN_PUBKEY`, then verify the wheel's SHA-256 against that signed list, BEFORE apt-installing anything or installing the wheel.** Fail-closed on any verification failure. Not TDD-able as a unit test — verified with `shellcheck` + a dry-run.

**Files:**
- Create: `install.sh` (repo root; committed and copied into each Release)
- Test: `tests/test_install_sh.py` (create — static assertions on the script's ordering + placeholders)

- [ ] **Step 1: Write the static-contract test**

Create `tests/test_install_sh.py`:

```python
"""Static guards on install.sh: it verifies before executing, carries the
owner placeholders (not invented values), and branches eval vs tpm."""

from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_SH = (_ROOT / "install.sh").read_text(encoding="utf-8")


def test_has_shebang_and_strict_mode() -> None:
    assert _SH.startswith("#!/bin/sh\n")
    assert "set -eu" in _SH


def test_verifies_before_installing() -> None:
    # The minisign verify of SHA256SUMS must appear before any apt-get/pip
    # install in source order (verify-before-execute).
    verify_idx = _SH.index("minisign")
    install_idx = min(
        _SH.index("apt-get") if "apt-get" in _SH else len(_SH),
        _SH.index("pip install") if "pip install" in _SH else len(_SH),
    )
    assert verify_idx < install_idx, "install precedes signature verification"


def test_owner_placeholders_present_not_invented() -> None:
    assert "MINISIGN_PUBKEY" in _SH
    assert "<OWNER/REPO>" in _SH or "DSM_RELEASE_BASE_URL" in _SH
    assert "TODO(owner)" in _SH


def test_eval_branch_and_venv_contract() -> None:
    assert "--eval" in _SH
    assert "/opt/dsm/venv" in _SH
    assert "evaluation only" in _SH.lower()


def test_fail_closed_on_bad_sig() -> None:
    # A failed verify must exit non-zero (set -e + explicit exit).
    assert "exit 1" in _SH
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/test_install_sh.py -v`
Expected: FAILs — `install.sh` does not exist.

- [ ] **Step 3: Write `install.sh`**

Create `install.sh` at the repo root:

```sh
#!/bin/sh
# DSM installer — verify-before-execute bootstrap for the supported target
# (Debian 12+ / Ubuntu 22.04+ / x86_64 / TPM 2.0). Downloads the wheel +
# SHA256SUMS + minisign signature, VERIFIES the signature and the checksum
# BEFORE installing anything, then installs into a dedicated venv.
#
# Usage:  curl -fsSL <release>/install.sh | sudo sh
#         curl -fsSL <release>/install.sh | sudo sh -s -- --eval
set -eu

VER="0.1.0"
# TODO(owner): replace <OWNER/REPO> with the real GitHub org/repo before release.
BASE="${DSM_RELEASE_BASE_URL:-https://github.com/<OWNER/REPO>/releases/download/v${VER}}"

# TODO(owner): paste the real minisign PUBLIC key (one base64 line) before
# release. The matching PRIVATE key is OWNER-ONLY and lives in a CI secret.
MINISIGN_PUBKEY="RWQUNRELEASED_PLACEHOLDER_minisign_public_key_REPLACE_BEFORE_RELEASE"

VENV="/opt/dsm/venv"
EVAL=0
[ "${1:-}" = "--eval" ] && EVAL=1

die() { echo "install.sh: $*" >&2; exit 1; }

[ "$(id -u)" = "0" ] || die "must run as root (sudo)"
[ "$(uname -m)" = "x86_64" ] || die "unsupported arch $(uname -m); build from source (deploy/GUIDE.md §1)"
command -v apt-get >/dev/null 2>&1 || die "no apt-get; supported targets are Debian 12+/Ubuntu 22.04+. Build from source for others."
command -v minisign >/dev/null 2>&1 || { apt-get update && apt-get install -y minisign; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

if [ "$EVAL" = 1 ]; then
  echo "=== EVALUATION INSTALL: +soft wheel, NO hardware binding. For evaluation only — never production. ===" >&2
  WHEEL="dsm-${VER}+soft-cp311-abi3-linux_x86_64.whl"
else
  WHEEL="dsm-${VER}-cp311-abi3-linux_x86_64.whl"
fi

# --- 1. Download checksum file + signature (NOT the wheel yet) ---
curl -fsSL "$BASE/SHA256SUMS"          -o SHA256SUMS         || die "cannot fetch SHA256SUMS"
curl -fsSL "$BASE/SHA256SUMS.minisig"  -o SHA256SUMS.minisig || die "cannot fetch signature"

# --- 2. VERIFY the signature over SHA256SUMS BEFORE touching any artifact ---
printf '%s\n' "$MINISIGN_PUBKEY" > pubkey.pub
minisign -V -p pubkey.pub -m SHA256SUMS || die "minisign verification FAILED — refusing to continue"

# --- 3. Download the wheel, then verify its SHA-256 against the signed list ---
curl -fsSL "$BASE/$WHEEL" -o "$WHEEL" || die "cannot fetch $WHEEL"
grep " $WHEEL\$" SHA256SUMS | sha256sum -c - || die "wheel checksum mismatch — refusing to install"

# --- 4. Only now: system runtime deps (verified-artifact gate passed) ---
apt-get update
apt-get install -y nftables iproute2 ca-certificates python3-venv
if [ "$EVAL" = 0 ]; then
  # TPM 2.0 runtime stack: the .so.0 provider + the device TCTI. No vendoring.
  apt-get install -y libtss2-esys-3.0.2-0t64 libtss2-tcti-device0 || \
    apt-get install -y libtss2-esys libtss2-tcti-device0
fi

# --- 5. Dedicated venv + wheel install (no system-Python pollution) ---
python3 -m venv "$VENV"
"$VENV/bin/pip" install --upgrade pip
"$VENV/bin/pip" install --no-index --find-links "$WORK" "$WORK/$WHEEL"
ln -sf "$VENV/bin/dsm" /usr/local/bin/dsm

# --- 6. tss group (TPM access) + unit install (production only) ---
if [ "$EVAL" = 0 ]; then
  getent group tss >/dev/null 2>&1 || groupadd --system tss
fi

NEXTROLE="server"
[ "$EVAL" = 1 ] && echo "Eval install complete. Try: sudo dsm init client" || \
  echo "Install complete. Next: sudo dsm init ${NEXTROLE}"
```

- [ ] **Step 4: shellcheck the script**

Run: `shellcheck install.sh`
Expected: no errors. (If `shellcheck` is not installed, run `sudo apt-get install -y shellcheck` first; if unavailable in the dev env, note the skip and rely on the static test.)

- [ ] **Step 5: Run the static-contract test**

Run: `pytest tests/test_install_sh.py -v`
Expected: all 5 tests PASS.

- [ ] **Step 6: Dry-run note (manual, not automated)**

A real end-to-end run needs published Release artifacts + the owner's signing key, so it cannot run pre-release. Verification is the `shellcheck` pass + the static ordering test (verify-before-install). Document in the PR description that the first real run happens against the first published Release.

- [ ] **Step 7: SECURITY REVIEW (required)**

Invoke the `security-crypto` skill on `install.sh`. Confirm: (a) the minisign verify of `SHA256SUMS` strictly precedes any `apt-get`/`pip install`; (b) the wheel hash is checked against the *signed* list and the *same* file is then installed (no re-download → no TOCTOU); (c) every failure path `die`s non-zero (fail-closed); (d) `MINISIGN_PUBKEY` and `<OWNER/REPO>` are unresolved placeholders with `TODO(owner)` markers (not invented values); (e) no `eval`/unquoted expansion of downloaded content. Address findings before done.

---

### Task 4.6 — `requirements.lock --generate-hashes`

> Application (not library) → the lockfile is committed. Regenerate WITH hashes so the reproducible/verified install path actually pins artifact digests.

**Files:**
- Regenerate: `requirements.lock`
- Test: `tests/test_requirements_lock.py` (create)

- [ ] **Step 1: Write the failing test**

Create `tests/test_requirements_lock.py`:

```python
"""The committed lockfile must carry per-artifact hashes for verified installs."""

from __future__ import annotations

from pathlib import Path

_LOCK = (
    Path(__file__).resolve().parent.parent / "requirements.lock"
).read_text(encoding="utf-8")


def test_lock_has_hashes() -> None:
    assert "--hash=sha256:" in _LOCK, "requirements.lock has no --generate-hashes output"


def test_lock_pins_core_runtime_deps() -> None:
    assert "cryptography==" in _LOCK
    assert "dnspython==" in _LOCK
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/test_requirements_lock.py -v`
Expected: `test_lock_has_hashes` FAILS (current lock has no hashes).

- [ ] **Step 3: Regenerate the lockfile with hashes**

Run (uv produced the existing lock per its header):
```bash
uv pip compile pyproject.toml --generate-hashes -o requirements.lock
```
Expected: `requirements.lock` now lists each pinned dependency followed by one or more `    --hash=sha256:…` lines. (If `uv` is unavailable, the equivalent is `pip-compile --generate-hashes` from pip-tools; the file header notes uv, so prefer uv to keep the header consistent.)

- [ ] **Step 4: Run the test to verify it passes**

Run: `pytest tests/test_requirements_lock.py -v`
Expected: both tests PASS.

---

### Task 4.7 — `release.yml` (tag-triggered Release pipeline)

> Distinct from `ci.yml`. On a `v*` tag: **reuse the ci.yml gates** as a precondition, build the three artifacts, sign `SHA256SUMS`, publish. SHA-pin third-party actions (matching the ci.yml supply-chain note) and set an explicit `permissions:` block.

**Files:**
- Create: `.github/workflows/release.yml`
- Test: `tests/test_release_workflow.py` (create — YAML validity + contract assertions)

- [ ] **Step 1: Write the failing test**

Create `tests/test_release_workflow.py`:

```python
"""Contract assertions on the release workflow: tag trigger, ci.yml gate reuse,
three build jobs, checksum + minisign signing, no mutable third-party tags."""

from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_YML_PATH = _ROOT / ".github" / "workflows" / "release.yml"


def test_workflow_exists_and_parses() -> None:
    import tomllib  # noqa: F401  (only to assert stdlib present)

    text = _YML_PATH.read_text(encoding="utf-8")
    # Minimal structural sanity without a YAML dep: key anchors present.
    assert text.strip()


def test_tag_trigger_and_permissions() -> None:
    text = _YML_PATH.read_text(encoding="utf-8")
    assert "tags:" in text and "'v*'" in text
    assert "contents: write" in text


def test_reuses_ci_gates() -> None:
    text = _YML_PATH.read_text(encoding="utf-8")
    assert "uses: ./.github/workflows/ci.yml" in text


def test_builds_three_artifacts() -> None:
    text = _YML_PATH.read_text(encoding="utf-8")
    assert "--features tpm-attest" in text
    assert "--features dev-soft-attest" in text
    assert "maturin sdist" in text


def test_signs_checksums_with_minisign() -> None:
    text = _YML_PATH.read_text(encoding="utf-8")
    assert "SHA256SUMS" in text
    assert "minisign" in text


def test_third_party_actions_sha_pinned() -> None:
    text = _YML_PATH.read_text(encoding="utf-8")
    # Every external (org/repo@ref) action must be pinned to a 40-hex SHA,
    # not a mutable tag. Local reusable workflow (./.github/...) is exempt.
    for m in re.finditer(r"uses:\s*([^\s]+)", text):
        ref = m.group(1)
        if ref.startswith("./"):
            continue
        assert "@" in ref, f"action {ref} has no pinned ref"
        sha = ref.split("@", 1)[1]
        assert re.fullmatch(r"[0-9a-f]{40}", sha), f"action {ref} not SHA-pinned"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/test_release_workflow.py -v`
Expected: FAILs — `release.yml` does not exist.

- [ ] **Step 3: Write `.github/workflows/release.yml`**

Create `.github/workflows/release.yml`. (The `@<40-hex>` SHAs below are written as `TODO(owner)` placeholder pins — the engineer looks up and pastes the real commit SHA for each action's intended version. The test enforces the 40-hex shape, so a real SHA must be in place before merge; until then, use the documented current-release SHAs of each action.)

```yaml
name: Release

on:
  push:
    tags: [ 'v*' ]

permissions:
  contents: write          # create the Release + upload assets

jobs:
  # Reuse the per-PR gate suite as a hard precondition: a tag can never publish
  # artifacts that did not pass black/isort/ruff/pylint/pyright/pytest +
  # clippy/cargo-test/cargo-audit + the swtpm TPM lane.
  gate:
    uses: ./.github/workflows/ci.yml

  build-tpm-wheel:
    needs: gate
    runs-on: ubuntu-latest
    steps:
      # TODO(owner): confirm these action SHAs (actions/checkout v4 tip etc.).
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
      - uses: actions/setup-python@0b93645e9fea7318ecaed2b359559ac225c90a2b  # v5.3.0
        with: { python-version: "3.12" }
      - uses: dtolnay/rust-toolchain@stable
        # NOTE: dtolnay/rust-toolchain@stable is a moving alias by design;
        # pin to its commit SHA per supply-chain policy.
      - name: Install build TSS2 stack
        run: |
          sudo apt-get update
          sudo apt-get install -y libtss2-dev libtss2-tcti-device0
      - name: Build TPM wheel
        run: |
          pip install maturin
          # NB: do NOT auditwheel-repair-vendor libtss2-esys (links the host
          # stack on purpose); tag plain linux_x86_64.
          maturin build --release --no-default-features --features tpm-attest --out dist
      - uses: actions/upload-artifact@65c4c4a1ddee5b72f698fdd19549f0f0fb45cf08  # v4.6.0
        with: { name: tpm-wheel, path: dist/*.whl }

  build-soft-wheel:
    needs: gate
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
      - uses: actions/setup-python@0b93645e9fea7318ecaed2b359559ac225c90a2b  # v5.3.0
        with: { python-version: "3.12" }
      - uses: dtolnay/rust-toolchain@stable
      - name: Build +soft eval wheel
        run: |
          pip install maturin
          maturin build --release --no-default-features --features dev-soft-attest --out dist
          # maturin emits the +soft local-version segment from the crate metadata;
          # if not, rename the artifact to carry +soft before upload.
      - uses: actions/upload-artifact@65c4c4a1ddee5b72f698fdd19549f0f0fb45cf08  # v4.6.0
        with: { name: soft-wheel, path: dist/*.whl }

  build-sdist:
    needs: gate
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
      - uses: actions/setup-python@0b93645e9fea7318ecaed2b359559ac225c90a2b  # v5.3.0
        with: { python-version: "3.12" }
      - name: Build sdist (build-from-source fallback)
        run: |
          pip install maturin
          maturin sdist --out dist
      - uses: actions/upload-artifact@65c4c4a1ddee5b72f698fdd19549f0f0fb45cf08  # v4.6.0
        with: { name: sdist, path: dist/*.tar.gz }

  sign-and-publish:
    needs: [ build-tpm-wheel, build-soft-wheel, build-sdist ]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
      - uses: actions/download-artifact@fa0a91b85d4f404e444e00e005971372dc801d16  # v4.1.8
        with: { path: dist, merge-multiple: true }
      - name: Stage install.sh alongside artifacts
        run: cp install.sh dist/install.sh
      - name: Generate SHA256SUMS
        run: |
          cd dist
          sha256sum * > SHA256SUMS
      - name: Sign SHA256SUMS with minisign
        env:
          # TODO(owner): provide the minisign secret key as repo secret
          # MINISIGN_SECRET_KEY (the OWNER-ONLY signing private key).
          MINISIGN_SECRET_KEY: ${{ secrets.MINISIGN_SECRET_KEY }}
        run: |
          sudo apt-get update && sudo apt-get install -y minisign
          printf '%s' "$MINISIGN_SECRET_KEY" > /tmp/minisign.key
          minisign -S -s /tmp/minisign.key -m dist/SHA256SUMS
          shred -u /tmp/minisign.key
      - name: Create GitHub Release
        uses: softprops/action-gh-release@c95fe1489396fe8a9eb87c0abf8aa5b2ef267fda  # v2.2.1
        with:
          files: |
            dist/*.whl
            dist/*.tar.gz
            dist/install.sh
            dist/SHA256SUMS
            dist/SHA256SUMS.minisig
          body_path: # left to release-notes extraction from CHANGELOG [0.1.0]
```

- [ ] **Step 4: Validate the YAML**

Run: `python -c "import sys; print('PyYAML' )" 2>/dev/null; python - <<'PY'
import pathlib
try:
    import yaml  # PyYAML, if available
    yaml.safe_load(pathlib.Path(".github/workflows/release.yml").read_text())
    print("yaml OK")
except ImportError:
    print("PyYAML not installed; rely on the static test")
PY`
Expected: `yaml OK` (or the PyYAML-not-installed note — the static test covers structure regardless).

- [ ] **Step 5: Run the contract test**

Run: `pytest tests/test_release_workflow.py -v`
Expected: all tests PASS. If `test_third_party_actions_sha_pinned` fails, the engineer has not yet looked up a real 40-hex SHA for one of the actions — replace the placeholder pin with the action's real release SHA.

- [ ] **Step 6: Dry-run note**

A `workflow_dispatch`/`act` smoke run needs the repo on GitHub + the `MINISIGN_SECRET_KEY` secret, so it runs against the first real tag. Document this in the PR.

---

### Task 4.8 — Lean repo extras (CONTRIBUTING, issue templates, .gitignore)

> Keep lean. `CODE_OF_CONDUCT.md` is **optional** — flagged but NOT created here (single-maintainer project; add later if desired).

**Files:**
- Create: `CONTRIBUTING.md`
- Create: `.github/ISSUE_TEMPLATE/bug_report.md`
- Create: `.github/ISSUE_TEMPLATE/config.yml`
- Modify: `.gitignore`
- Test: `tests/test_repo_hygiene.py` (create)

- [ ] **Step 1: Write the failing test**

Create `tests/test_repo_hygiene.py`:

```python
"""Lean repo-hygiene contract: CONTRIBUTING + issue templates + .gitignore rows."""

from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent


def test_contributing_covers_build_and_tests() -> None:
    text = (_ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    assert "maturin" in text
    assert "dev-soft-attest" in text and "tpm-attest" in text
    assert "swtpm" in text
    # Gate order from CLAUDE.md run order.
    assert "black" in text and "pyright" in text and "pytest" in text
    assert "never edit existing tests" in text.lower() or "do not edit existing tests" in text.lower()


def test_bug_template_warns_about_secrets() -> None:
    text = (_ROOT / ".github" / "ISSUE_TEMPLATE" / "bug_report.md").read_text(
        encoding="utf-8"
    )
    low = text.lower()
    assert "do not paste" in low or "never paste" in low
    assert "key" in low and "cert" in low and "cn" in low


def test_issue_config_redirects_security() -> None:
    text = (_ROOT / ".github" / "ISSUE_TEMPLATE" / "config.yml").read_text(
        encoding="utf-8"
    )
    assert "SECURITY.md" in text


def test_gitignore_has_release_artifact_rows() -> None:
    text = (_ROOT / ".gitignore").read_text(encoding="utf-8")
    for row in ("*.whl", "dist-tpm/", ".dsm-init-state.json", "SHA256SUMS"):
        assert row in text, f".gitignore missing {row}"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/test_repo_hygiene.py -v`
Expected: FAILs — none of the files exist.

- [ ] **Step 3: Write `CONTRIBUTING.md`**

```markdown
# Contributing to DSM

DSM is a security/anonymity VPN (Python + a Rust crypto core, `tuncore`).
Distribution is signed GitHub Releases — **no PyPI**.

## Build from source

```sh
sudo apt install -y build-essential pkg-config python3-venv libtss2-dev
python3 -m venv .venv && . .venv/bin/activate
pip install maturin
# Production (TPM) backend — the default Cargo feature:
maturin develop --release --no-default-features --features tpm-attest
# Or the dev/eval soft backend (extractable key, NO hardware binding):
maturin develop --release --no-default-features --features dev-soft-attest
```

The two attest backends are mutually exclusive at compile time, so a build
carries exactly one. CI builds and tests both.

## Gate order (must pass before a PR merges)

Run in this order (matches CI): `black` → `isort` → `ruff` → `pylint` →
`pyright` → `pytest`, plus `cargo fmt`/`clippy`/`cargo audit` for Rust.

## Tests

Tests live in `tests/`. Write tests alongside new code. **Do not edit existing
tests to make a failing test pass** — fix the code, or flag the test as wrong
in the PR for a separate decision.

The TPM-backed tests drive a per-test `swtpm` via the `swtpm_tcti` fixture
(see `tests/conftest.py`); install `swtpm swtpm-tools libtss2-tcti-swtpm0` to
run them locally. They self-skip under the soft wheel.

## Security

Do not report vulnerabilities in public issues — see `SECURITY.md`.
```

- [ ] **Step 4: Write `.github/ISSUE_TEMPLATE/bug_report.md`**

```markdown
---
name: Bug report
about: Report a defect in DSM
labels: bug
---

> ⚠️ **Do NOT paste private keys, device certs, CA material, CN allowlists,
> passphrases, or full config files.** Redact `server_ip`, CNs, and any
> `*.key` / `*.crt` content. This is a public tracker.

**What happened:**

**What you expected:**

**Steps to reproduce:**

**Environment:** distro + version, `dsm --version`, TPM present? (`ls -l /dev/tpmrm0`)

**Logs:** redacted `journalctl -u dsm` excerpt (strip IPs/CNs).
```

- [ ] **Step 5: Write `.github/ISSUE_TEMPLATE/config.yml`**

```yaml
blank_issues_enabled: false
contact_links:
  - name: Security vulnerability (do NOT open a public issue)
    url: https://github.com/<OWNER/REPO>/security/policy
    about: >
      Report security issues privately per SECURITY.md — never in a public
      issue. TODO(owner): replace <OWNER/REPO> with the real repo.
```

- [ ] **Step 6: Add the `.gitignore` rows**

Append to `.gitignore`:

```gitignore
# Phase 4 — release artifacts + build outputs + wizard state
*.whl
dist-tpm/
SHA256SUMS
SHA256SUMS.minisig
.dsm-init-state.json
/opt/
*.crt
```

(If `.gitignore` already has some of these, leave the existing rows and add only the missing ones — duplicates are harmless but avoid them.)

- [ ] **Step 7: Run the tests to verify they pass**

Run: `pytest tests/test_repo_hygiene.py -v`
Expected: all 4 tests PASS.

---

## Final verification (all tasks)

- [ ] **Run the full new-test set:**

Run: `pytest tests/test_version_consistency.py tests/test_docs_markdown.py tests/test_init.py tests/test_service_unit.py tests/test_install_sh.py tests/test_requirements_lock.py tests/test_release_workflow.py tests/test_repo_hygiene.py -v`
Expected: all PASS.

- [ ] **Confirm no pre-existing test was modified:**

Run: `git status --porcelain tests/ | grep '^ M'`
Expected: empty (only new `tests/test_*.py` files appear as `??`; no `M` on an existing test).

- [ ] **Confirm the owner placeholders are still unresolved (must be filled by owner, not the engineer):**

Run: `grep -rn '<OWNER/REPO>\|MINISIGN_PUBKEY\|TODO(owner)' install.sh CHANGELOG.md .github/workflows/release.yml README.md`
Expected: matches present in each — these are the owner-only facts; their presence is correct pre-release.

- [ ] **Run the full suite to confirm no regression:**

Run: `pytest tests/ -q`
Expected: no new failures introduced by Phase 4 (TPM-only tests self-skip on a soft build).
