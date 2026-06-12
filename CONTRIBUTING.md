# Contributing to DSM

Thanks for your interest in DSM. This guide covers building from source,
running the test suite (including the software-TPM lane), and the formatting /
lint / type-check gates a change must pass before it can land.

DSM is a Python + Rust project: the pure-Python `dsm/` package is bundled with
the compiled `tuncore` Rust extension into a **single wheel** by
[maturin](https://www.maturin.rs/). There is no PyPI distribution — releases
ship as signed GitHub Release artifacts. For operating a deployed instance, see
[`deploy/GUIDE.md`](deploy/GUIDE.md); this file is about working on the code.

## Supported target

The production wheel dynamically links the host TPM 2.0 stack
(`libtss2-esys.so.0`) and is built for **Debian 12+ / Ubuntu 22.04+ / x86_64
with a TPM 2.0**. A portable manylinux wheel is not possible. Other distros can
build from source, but development and CI target the above.

## Prerequisites

- Python 3.11+ with `python3-venv`.
- A recent Rust toolchain (`rustup` recommended — distro `cargo` is often too
  old for maturin).
- For the **default (TPM) build**: `libtss2-dev` (the tss2-esys headers).
  `tess-esapi-sys` ships pregenerated x86_64 bindings, so no `libclang` /
  `bindgen` is needed.
- For the **software / eval build**: nothing beyond Rust + Python — the
  `dev-soft-attest` feature has no TPM dependency.

## Building from source

DSM ships **two wheel flavors** selected by a Cargo feature. The default Cargo
feature is `tpm-attest`; the dev/eval feature is `dev-soft-attest`. Both import
identically as `dsm` + `tuncore`, but the soft build's attest key is **NOT
hardware-bound** and must never be deployed.

Work inside a virtualenv. Build the extension in place with `maturin develop`:

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install --upgrade pip maturin

# Dev / eval build (no TPM, no libtss2-dev needed) — use this for most work:
maturin develop --no-default-features --features dev-soft-attest

# Production / TPM build (requires libtss2-dev):
maturin develop --no-default-features --features tpm-attest
```

After `maturin develop` succeeds, `import dsm` and `import tuncore` resolve from
the active venv. To produce a redistributable wheel instead of an in-place
install, use `maturin build --release …` (the wheel lands under
`rust/tuncore/target/wheels/`).

## Running the tests

### Python suite

```sh
pytest tests/ -q
```

Tests that need the `tuncore` extension are **skipped** (not failed) if it is
not built, so build it first (see above) for full coverage.

### Software-TPM lane (swtpm)

The TPM-backed tests run against [`swtpm`](https://github.com/stefanberger/swtpm),
a software TPM emulator, so no physical TPM is required. The `swtpm_tcti`
pytest fixture (in `tests/conftest.py`) starts a per-test `swtpm` instance over
loopback TCP and tears it down afterward; tests are **skipped** if `swtpm` /
`swtpm_setup` are not installed.

Install the emulator and the TSS2 stack, then run with the TPM build:

```sh
sudo apt install -y swtpm swtpm-tools libtss2-dev libtss2-tcti-swtpm0

# Build the real backend in an ISOLATED venv so it never clobbers your
# soft-build working venv (CI keeps these lanes strictly separate):
python3 -m venv /tmp/dsm-tpm-venv
/tmp/dsm-tpm-venv/bin/pip install --upgrade pip maturin pytest pytest-asyncio dnspython
/tmp/dsm-tpm-venv/bin/maturin develop --no-default-features --features tpm-attest
/tmp/dsm-tpm-venv/bin/pytest tests/ -q
```

### Rust tests

```sh
# Soft backend (no TSS2 stack needed):
cargo test --manifest-path rust/tuncore/Cargo.toml --release \
    --no-default-features --features dev-soft-attest

# TPM backend against swtpm (needs swtpm + libtss2-dev + libtss2-tcti-swtpm0):
cargo test --manifest-path rust/tuncore/Cargo.toml --release \
    --no-default-features --features tpm-attest \
    --test tpm_swtpm --test dsmt_format -- --test-threads=1
```

`--test-threads=1` keeps the per-test swtpm TCP ports from colliding.

## Toolchain gates

A change must pass the full gate set before it can land. Run them in this order
(this mirrors CI):

**Python** (run order: `black` → `isort` → `ruff` → `pylint` → `pyright` →
`pytest`):

```sh
black --check dsm tests
isort --check-only dsm tests
ruff check dsm tests
pylint dsm
pyright
pytest tests/ -q
```

**Rust** (`rustfmt` → `clippy` (pedantic + `unwrap_used`) → `test`):

```sh
cargo fmt --manifest-path rust/tuncore/Cargo.toml --check
cargo clippy --manifest-path rust/tuncore/Cargo.toml --all-targets \
    --no-default-features --features dev-soft-attest -- \
    -D warnings -W clippy::pedantic -W clippy::unwrap_used
cargo test --manifest-path rust/tuncore/Cargo.toml --release \
    --no-default-features --features dev-soft-attest
```

The `clippy (tpm)` gate (same flags with `--features tpm-attest`) runs in the
TPM lane on a runner with the TSS2 headers.

Install the Python toolchain with the project's dev extra:
`pip install -e '.[dev]'` (or `pip install maturin black isort ruff pylint
pyright pytest pytest-asyncio pip-audit`).

## Reporting bugs and security issues

- **Bugs:** open a GitHub issue using the bug-report template.
- **Security vulnerabilities:** do **not** open a public issue — follow the
  private disclosure process in [`SECURITY.md`](SECURITY.md).

### Never include secrets or PII

DSM is a security tool. When filing issues, opening PRs, or pasting logs, **do
NOT include**:

- Private keys, passphrases, or sealed/wrapped key blobs.
- Config files containing real IPs, certificates, CA roots, or SPKI pins —
  redact them or use placeholder values.
- TPM attestation blobs or device certificates.
- Any personally identifying information.

Redact before you paste. When in doubt, leave it out and describe the shape of
the data instead.
