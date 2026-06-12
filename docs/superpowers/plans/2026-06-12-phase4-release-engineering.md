# DSM V2.0 — Phase 4: Release Engineering (Design + Plan)

> **Status:** Design/plan — NOT implementation. Illustrative snippets only.
> Authored 2026-06-12 against the then-current tree. Feeds a subsequent TDD
> plan (`superpowers:writing-plans` → `superpowers:executing-plans`).
>
> **Scope source:** `docs/superpowers/plans/2026-06-10-production-readiness-master.md`
> §"Phase 4" (items 4.1–4.6) + the Owner Decisions table. Findings referenced
> from `PRODUCTION_REVIEW.md`.
>
> **Owner decisions already locked (do NOT re-litigate):** public MIT release;
> setup "extraordinarily simple"; distribution = **GitHub Releases + install
> script, NO PyPI**; **TPM 2.0 required for v1** (key-residency scope); Claude
> never commits.

---

## 1. Summary — what "v1 public release" means concretely

A stranger with a fresh Debian/Ubuntu box that has a TPM 2.0 lands on the
GitHub Releases page and ends up with a running tunnel **without** building
Rust, hand-resolving system libraries, or reading 1300 lines of GUIDE first.

The intended end-to-end story is two commands plus a passphrase:

```
# 1. Install (system deps + wheel + group + unit), pinned + checksum-verified
$ curl -fsSL https://github.com/<org>/dsm/releases/download/v1.0.0/install.sh \
    | sudo sh

# 2. Go from zero to running (interactive; orchestrates CA-pin, enroll, config, unit)
$ sudo dsm init server      # or: dsm init client
  ...prompts: server IP/port, paths, CA root, passphrase...
  ...runs TPM preflight → enroll (CSR) → [walk to CA] → import → write unit...
$ sudo systemctl enable --now dsm
```

The **hard constraint that shapes everything**: the production wheel both
(a) **dynamically links the system `libtss2-esys`** and (b) **requires real TPM
hardware at runtime**. So `pip install <wheel>` alone is *necessary but not
sufficient* — `install.sh` exists precisely to bridge the system-dependency and
hardware gap that a pure wheel cannot. This is the central tension of "simple
setup for a hardware-dependent VPN," and §6 (Distribution) + §11 (Risks) treat
it as the crux.

Phase 4 does **not** change protocol, crypto, or the data path. It is packaging,
orchestration (`dsm init`), distribution, docs, and versioning. The one genuinely
new piece of *runtime* code is the `dsm init` wizard; everything else is build
config, shell scripting (shipped as release artifacts, not Python deliverables),
CI/CD YAML, and docs.

### What is already done (Phase-4 hygiene) vs remaining

| Item (master plan 4.x) | State | Evidence |
|---|---|---|
| 4.6 LICENSE (MIT) | **DONE** | `LICENSE` present (1073 B, "Copyright (c) 2026 DSM contributors") |
| 4.6 SECURITY.md | **DONE** | `SECURITY.md` present (4351 B) |
| 4.6 CHANGELOG.md | **DONE (Unreleased)** | `CHANGELOG.md` present; needs a `[1.0.0]` cut (§9) |
| 4.6 pyproject license metadata | **DONE** | `license = "MIT"`, `license-files = ["LICENSE"]` |
| 4.6 delete `refactor-plan-*.md` | **DONE** | absent from tree |
| 4.4 `openssl-ca.cnf` H12 fix + dead `[crl_ext]` | **DONE** | `deploy/openssl-ca.cnf` present, 5458 B |
| 4.1 CI two-wheel matrix + gates | **DONE** | `.github/workflows/ci.yml` soft + tpm lanes wired |
| 4.5 GUIDE TPM prereqs + enroll flow | **DONE** | `deploy/GUIDE.txt` §0e / §3 |
| 4.5 `config.example.toml` field-complete | **DONE** | `test_example_config` guard; all fields present |
| — Cargo `tpm-attest` is DEFAULT | **DONE** | `rust/tuncore/Cargo.toml` `default = ["tpm-attest"]` |
| **4.3 `dsm init` wizard** | **REMAINING** | not present in `dsm/__main__.py` |
| **4.2 release pipeline (`release.yml`)** | **REMAINING** | only `ci.yml` exists |
| **4.2 `install.sh`** | **REMAINING** | absent |
| **4.6 README.txt → README.md** | **REMAINING** | still `README.txt` (24757 B) |
| **4.6 GUIDE.txt → GUIDE.md** | **REMAINING** | still `GUIDE.txt`; `.service` Documentation= points at `.txt` |
| **Versioning: pick v1 tag scheme** | **REMAINING** | pyproject + Cargo at `0.1.0`; CHANGELOG `[Unreleased]` |
| **CONTRIBUTING / issue templates / CoC** | **REMAINING (optional)** | none present; §10 recommends a lean subset |
| `requirements.lock --generate-hashes` | **REMAINING (4.1 tail)** | `requirements.lock` has NO hashes |
| `.gitignore` gaps | **PARTIAL** | covers dist/build/target; §10 notes `dist-tpm/`, `*.whl`, `*.crt` |

So Phase 4's remaining surface is: **the wizard, the distribution path
(install.sh + release.yml + the manylinux verdict), the doc rename/finalize,
the version cut, and a lean "credible repo" set.**

---

## 2. Component / artifact map

```
                         GitHub Release  v1.0.0  (tag-triggered)
   ┌──────────────────────────────────────────────────────────────────────┐
   │  install.sh                  ← thin, stable bootstrap; checksum-pinned │
   │  dsm-1.0.0-cp311-abi3-...whl  (TPM/production wheel; links libtss2-esys)│
   │  dsm-1.0.0+soft-...whl        (eval/dev wheel; soft attest, no TPM)     │
   │  SHA256SUMS                   ← checksums of every artifact            │
   │  SHA256SUMS.sig / .minisig    ← signature over the checksum file      │
   │  (optional) source tarball   ← reproducible-build / audit path        │
   └──────────────────────────────────────────────────────────────────────┘
              │ built & attached by
              ▼
   .github/workflows/release.yml  (NEW)   ── reuses gates from ci.yml ──┐
       on: push tags 'v*'                                               │
       jobs: build-tpm-wheel, build-soft-wheel, gate, sign, publish     │
                                                                        │
   .github/workflows/ci.yml       (EXISTS) ── per-PR gates ─────────────┘

   On the operator's box, after install.sh:
   ┌──────────────────────────────────────────────────────────────────────┐
   │  apt: libtss2-esys, libtss2-tcti-device0, nftables, iproute2, ...     │
   │  pipx/venv: the dsm wheel  →  `dsm` on PATH, `python3 -m dsm`          │
   │  group: operator added to `tss`                                       │
   │  unit:  deploy/dsm.service installed (+ Documentation= path fixed)    │
   └──────────────────────────────────────────────────────────────────────┘
              │ operator runs
              ▼
   dsm init {server|client}   (NEW Python subcommand in dsm/__main__.py)
       orchestrates EXISTING code:
         core/config  (write config.toml from example + answers)
         crypto/tpm_preflight.preflight_tpm
         crypto/enroll.generate_enrollment   (CSR)
         [operator walks CSR to offline CA — wizard pauses]
         crypto/enroll.import_signed_cert
         ca_root_sha256 pin compute (hashlib over ca_root_file)
         systemd unit install (copy deploy/dsm.service, fix paths)
```

**Reuse-vs-new at a glance:**

| Layer | New in Phase 4 | Reused (already exists) |
|---|---|---|
| Wizard | `dsm/init.py` + `init` subparser in `__main__.py` | `enroll`, `config.load`, `tpm_preflight`, `import_signed_cert`, `read_passphrase` |
| Distribution | `install.sh`, `release.yml`, signing step | `ci.yml` gate steps, `pyproject` maturin config, `requirements.lock` |
| Docs | `README.md`, `GUIDE.md`, top-level `QUICKSTART.md`(?) | existing prose in `README.txt` / `GUIDE.txt` |
| Version | `[1.0.0]` CHANGELOG cut, bumped versions | CHANGELOG `[Unreleased]` body |
| Repo hygiene | `CONTRIBUTING.md`, issue templates, `.gitignore` rows | — |

---

## 3. Deliverable 1 — `dsm init` quickstart wizard

### 3.1 Problem & constraints

The current zero-to-running path is `deploy/GUIDE.txt` §0–§5: ~12 manual steps
(mkdir, write config TOML by hand, fetch SPKI pin via an openssl pipeline,
compute `ca_root_sha256`, run `enroll --csr-out`, walk to CA, `enroll --import`,
edit allowlist, install unit). Every one is a place a stranger drops out.
`PRODUCTION_REVIEW.md` graded Docs/deploy "C — operator path broken at two
load-bearing points." The owner mandate is *extraordinarily simple*.

Hard constraint the wizard must respect: the **offline-CA round trip is
inherently interactive and air-gapped** (the CA private key never touches a
networked box). `dsm init` therefore *cannot* be fully non-interactive
end-to-end for a fresh device — there is an unavoidable pause where the operator
physically walks a CSR to the CA laptop. The wizard's job is to make everything
*around* that pause trivial and to resume cleanly.

### 3.2 Subcommand surface (recommended)

Split by role (FORK F1 — see §12) with shared internals:

```
dsm init server      # interactive; full hand-holding
dsm init client      # interactive; full hand-holding
dsm init --help

# Non-interactive / automation (every prompt has a flag):
dsm init server --non-interactive \
    --server-ip 203.0.113.1 --server-port 51820 \
    --config-out /opt/mtun/config.toml \
    --ca-root /opt/mtun/dsm_ca_root.pem \
    --dns-provider https://1.1.1.1/dns-query --dns-pin <hex> \
    --install-unit \
    --passphrase-env-file /etc/dsm/passphrase

# Two-phase resume across the CA round trip:
dsm init server          # phase A: writes config, runs TPM preflight + CSR, STOPS
                         #          prints "walk /tmp/...csr to the CA, then:"
dsm init server --resume # phase B: imports the signed cert, finalizes, installs unit
```

A single state file (`/opt/mtun/.dsm-init-state.json`, mode 0600) records which
phase completed so `--resume` knows what to finish. This is the cleanest way to
bridge the air-gap pause without a long-lived process.

### 3.3 Exact steps the wizard runs (server)

Phase A (`dsm init server`):
1. **Preconditions** — assert root (or in `tss` group); check `/dev/net/tun`,
   `nft --version`, `/dev/tpmrm0`. Reuse `crypto/tpm_preflight.preflight_tpm`.
   On the soft (eval) wheel, detect `tuncore.ATTEST_BACKEND_IS_SOFTWARE` and
   print a loud "eval build — not hardware-bound" banner.
2. **Gather answers** — prompt for: server public IP (validate IPv4 literal via
   the same rule `config.py` uses — reject hostnames/IPv6), port, install dir
   (default `/opt/mtun`), DoH provider + SPKI pin (offer to fetch-and-show the
   pin via the GUIDE §3a.1 openssl pipeline for the operator to confirm — do NOT
   auto-trust; print it and ask "is this the pin you expect?").
3. **CA root** — ask for the `dsm_ca_root.pem` path; compute its SHA-256
   (`hashlib`), show it, and ask the operator to confirm it matches the safe
   printout (GUIDE §2c). Write it as `ca_root_sha256`. **This replaces the
   error-prone manual `sha256sum | cut` step.**
4. **Write config** — render `config.toml` from the `config.example.toml`
   template substituting the gathered answers, `chmod 0600`. Validate by calling
   `config.load()` on the result (fail loudly if it won't parse — closes the
   `PRODUCTION_REVIEW` "example ships unusable" class for generated configs too).
5. **Enroll (CSR)** — call the same path as `_run_enroll(csr_out=...)`: TPM
   preflight, provision the in-TPM key, prompt for the enroll passphrase, write
   identity.key + attest.key + the CSR. Print the CN.
6. **Pause** — write the init-state file; print the exact `openssl ca` review +
   sign commands (GUIDE §3c) and "then run `dsm init server --resume`."

Phase B (`dsm init server --resume`):
7. **Import** — call `import_signed_cert` (reuse). Verifies chain + binding +
   SPKI + validity (already implemented).
8. **Allowlist** — create `allowed_cns_file` (mode 0600) empty; print the
   `dsm init client` instruction so the operator knows the client CN goes here.
9. **Unit install** (if `--install-unit`) — copy `deploy/dsm.service` to
   `/etc/systemd/system/`, fix the `Documentation=` path, install the passphrase
   credential file skeleton (`/etc/dsm/passphrase`, 0600), `daemon-reload`, and
   print `systemctl enable --now dsm`. Do **not** auto-start (operator should add
   the client CN first).
10. **Done** — print the verification one-liners (GUIDE §6 subset).

Client (`dsm init client`) mirrors this with `expected_server_cn`,
`listen_port=0`, `auto_mtu=true`/`pmtu_discover=true` defaults, and no allowlist
/ no DNS-provider prompts; phase B finalizes and prints "give this CN to the
server operator for the allowlist."

### 3.4 Reused vs new code

| Step | Reuses | New |
|---|---|---|
| TPM preflight | `dsm/crypto/tpm_preflight.preflight_tpm` | — |
| CSR / key provisioning | `dsm/crypto/enroll.generate_enrollment`, `KeyStore`, `AttestStore`, `read_passphrase`/`wipe_passphrase` | — |
| Cert import | `dsm/crypto/enroll.import_signed_cert` | — |
| Config validation | `dsm/core/config.load` | template-render + substitution logic |
| `ca_root_sha256` | `hashlib.sha256` (stdlib) | the "confirm against safe printout" prompt |
| IP literal validation | the existing `config.py` validator (extract/reuse — do **not** duplicate the regex) | — |
| Unit install | — | copy + path-fix + `daemon-reload` shell-out (list-form subprocess per house style) |
| Orchestration | — | `dsm/init.py` (state machine + prompts) + `init` subparser |

**New module:** `dsm/init.py` (the wizard) and an `init` subparser block in
`dsm/__main__.py`. The wizard is a thin orchestrator: it must call the existing
enroll/import/config functions, **not** reimplement any crypto or cert logic.
Public-API impact: adds a CLI subcommand (additive, no signature change to
existing functions) — but if the IP-literal validator needs extracting from
`config.py` into a shared helper, that touches a module boundary → flag at
implementation time.

### 3.5 Error contract

- Every precondition failure (no TPM, not in `tss` group, no `/dev/net/tun`,
  unwritable config dir) → clean stderr message + `sys.exit(2)`, mirroring the
  existing `_run_enroll` pattern. **Never** a raw traceback.
- The wizard is **idempotent on re-run before phase A completes** (re-prompting
  is safe) but **refuses to overwrite existing keys** without an explicit
  `--force` (reuse `generate_enrollment`'s existing "identity key already
  exists" guard; surface it as an actionable message, not a crash).
- Passphrase handling reuses `read_passphrase`/`wipe_passphrase` — no new secret
  handling code (security boundary: keep all key material inside existing
  audited paths).

---

## 4. Deliverable 2 — Distribution / install (GitHub Releases, no PyPI)

### 4.1 The core technical question (FORK F2): can the TPM wheel be a portable manylinux wheel?

**Verdict: NO — not as a single portable manylinux wheel, because of
`libtss2-esys`. Ship a glibc-Linux wheel built against the oldest supported
TSS2 soname, and have `install.sh` apt-install the matching runtime library.
Provide a source/sdist build path as the fallback for unsupported distros.**

Why (evidence gathered on this host):

- The `tpm-attest` feature links the **system** `tss2-esys` via pkg-config
  (`rust/tuncore/Cargo.toml`, `tss-esapi = "7.7.0"`). The produced `.so` carries
  a `DT_NEEDED` on `libtss2-esys.so.0` (this box: `/usr/lib/x86_64-linux-gnu/
  libtss2-esys.so.0` → `.so.0.0.1`, provided by package `libtss2-esys-3.0.2-0t64`
  at upstream version **4.1.3**).
- **manylinux policy forbids bundling/vendoring this library.** The whole point
  of `auditwheel`/manylinux is that a wheel only depends on a known-stable
  allowlist of system libs (libc, libm, libpthread, libdl, …). `libtss2-esys`
  is **not** on the manylinux allowlist. `auditwheel repair` would try to
  vendor it into the wheel — but vendoring a TPM-access library is wrong: the
  TCTI plumbing must match the host's kernel/TPM and `dlopen()`s sibling TCTI
  `.so`s (`libtss2-tcti-device0`) at runtime. A vendored copy would be brittle
  and is the opposite of "use the host's TPM stack."
- Therefore the wheel must be an **"impure" external-link wheel**: it expects
  `libtss2-esys.so.0` to be *provided by the host*. `auditwheel` will refuse to
  stamp it `manylinux_*` while that external `DT_NEEDED` is unsatisfiable in its
  sandbox. We deliberately **do not** repair-vendor it; instead we tag it as a
  plain `linux_x86_64` wheel (or `manylinux` with `libtss2-esys` explicitly
  excluded from the repair) and make `install.sh` responsible for the system lib.
- **ABI/soname risk (the real fork detail):** the `.so.0` soname is stable
  across the Debian 12 / Ubuntu 22.04+ era (esys 3.x ABI), but Debian's `t64`
  time64 transition repackaged it (`-3.0.2-0t64`) — same soname `.so.0`, new
  package name. A wheel built here links `.so.0`; any target whose
  `libtss2-esys` still exports soname `.so.0` will load it. Targets are
  effectively **glibc x86_64 Linux with TSS2 esys ABI 3.x**. That is a real but
  *bounded* portability surface — it is **not** "any manylinux host."

**Consequence (irreversible-ish):** the production wheel is **not** a
drop-anywhere artifact. The supported target is declared explicitly (e.g.
"Debian 12+, Ubuntu 22.04+, x86_64, TPM 2.0"). `install.sh` apt-installs the
runtime lib; for anything off that list, the documented path is a
**build-from-source on the target** (sdist + maturin + `libtss2-dev`). This is
inherent to a hardware-TPM VPN and must be stated honestly in README (§11).

### 4.2 What ships on a GitHub Release (FORK F4 — soft/eval distribution)

| Artifact | Purpose | Built by |
|---|---|---|
| `dsm-<ver>-<pytag>-linux_x86_64.whl` (TPM) | production install on supported distros | `release.yml` tpm job, against `libtss2-dev` |
| `dsm-<ver>+soft-<pytag>-linux_x86_64.whl` (eval) | try-it-without-a-TPM path | `release.yml` soft job, `--features dev-soft-attest` |
| `dsm-<ver>.tar.gz` (sdist) | build-from-source fallback for unsupported distros / audit | `maturin sdist` |
| `install.sh` | bootstrap (system deps + wheel + group + unit) | committed; copied to the release |
| `SHA256SUMS` + signature | integrity + authenticity | `release.yml` sign step |

The **soft/eval wheel** is the answer to "how do TPM-less people try it": a
clearly-named `+soft` local version segment, an eval-only install path
(`install.sh --eval`) that **skips** the TPM apt packages and group, and a loud
runtime banner (already present: `allow_soft_attest` gate + WARNING). README must
say in one line: *the `+soft` wheel is for evaluation only and provides no
hardware binding — never deploy it.*

### 4.3 `install.sh` design

A thin, stable, auditable POSIX-sh script (the contract that `curl | sudo sh`
runs). Stable because its URL is what people paste; logic lives mostly in `dsm`
itself (`dsm init`) so `install.sh` rarely changes.

Responsibilities:
1. Detect distro/arch; refuse politely if unsupported (point at the
   build-from-source path).
2. **Verify itself & artifacts:** download `SHA256SUMS` + signature, verify the
   signature (see F3), then download the wheel and check its SHA-256 against the
   signed list **before** executing/installing anything.
3. `apt-get install` the runtime system deps: `libtss2-esys` (the `.so.0`
   provider), `libtss2-tcti-device0`, `nftables`, `iproute2`, `ca-certificates`,
   plus `pipx` (or `python3-venv`). Eval mode (`--eval`) skips the TSS2 packages.
4. Install the wheel via the chosen mechanism (FORK F5 below).
5. Create/ensure the `tss` group membership for the service user (skip in eval).
6. Install `deploy/dsm.service` (shipped inside the wheel's data, or fetched),
   `daemon-reload`. Do **not** enable/start — `dsm init` does that.
7. Print the next command: `sudo dsm init server` (or client).

Illustrative skeleton (NOT a deliverable — final script written in the TDD plan):

```sh
#!/bin/sh
set -eu
VER="1.0.0"; BASE="https://github.com/<org>/dsm/releases/download/v${VER}"
EVAL=0; [ "${1:-}" = "--eval" ] && EVAL=1

require_root; detect_distro          # exit nonzero w/ message if unsupported
fetch "$BASE/SHA256SUMS"; fetch "$BASE/SHA256SUMS.minisig"
verify_sig SHA256SUMS SHA256SUMS.minisig   # minisign -Vm (pinned pubkey in script)
WHEEL=$([ "$EVAL" = 1 ] && echo "dsm-${VER}+soft-...whl" || echo "dsm-${VER}-...whl")
fetch "$BASE/$WHEEL"; check_sha "$WHEEL" SHA256SUMS

apt_get_install nftables iproute2 ca-certificates pipx
[ "$EVAL" = 1 ] || apt_get_install libtss2-esys libtss2-tcti-device0
pipx install "./$WHEEL"              # FORK F5: pipx vs venv vs system
[ "$EVAL" = 1 ] || ensure_group tss
install_unit                          # cp + sed Documentation= + daemon-reload
echo "Next: sudo dsm init $( [ "$EVAL" = 1 ] && echo client ) server"
```

### 4.4 Install mechanism (FORK F5): pipx vs dedicated venv vs system package

The GUIDE today installs into **system Python** with `--break-system-packages`
(because the *systemd unit runs `/usr/bin/python3 -m dsm`* and root needs the
import). That is the simplest "it just works under systemd" path but the
**least clean** (pollutes the system interpreter; PEP-668 friction).

| Option | Pros | Cons |
|---|---|---|
| **pipx** | isolated venv, `dsm` on PATH, clean uninstall, idiomatic for CLI apps | the unit's hard-coded `/usr/bin/python3 -m dsm` must change to the pipx venv interpreter (`~/.local/...` or `/opt/pipx/...`); pipx-as-root path quirks |
| **dedicated venv** (`/opt/dsm/venv`) | fully isolated, deterministic interpreter path for the unit (`ExecStart=/opt/dsm/venv/bin/python -m dsm`), no PATH ambiguity | one more thing install.sh manages; not "on PATH" unless symlinked |
| **system Python** (today) | unit works unchanged; matches current GUIDE | PEP-668 `--break-system-packages`; pollutes system; least clean for a public release |

**Recommendation: dedicated venv at `/opt/dsm/venv`,** with `install.sh`
symlinking `/usr/local/bin/dsm → /opt/dsm/venv/bin/dsm` and **updating
`deploy/dsm.service` `ExecStart=` to the venv interpreter.** Rationale: it gives
a *deterministic* interpreter path for systemd (no PATH/`/usr/bin/python3`
coupling, no `--break-system-packages`), isolates dsm's pinned deps from the OS,
and is trivially removable. pipx is a close second but its root/interpreter-path
story under systemd is messier. This is **irreversible-ish**: it sets the public
install contract and the unit's `ExecStart`, so the GUIDE/README and the unit
must be updated together (see §11 irreversibles).

### 4.5 Reused vs new

- **New:** `install.sh`; the `ExecStart=` change in `deploy/dsm.service`; the
  `Documentation=` path fix (→ `.md`, ties to §7).
- **Reused:** the wheel build invocation (`maturin build --release`, with/without
  `--features dev-soft-attest`) exactly as `ci.yml` already does; the apt package
  names already documented in GUIDE §0e/§1.

---

## 5. Deliverable 3 — Release pipeline (`.github/workflows/release.yml`, NEW)

Distinct from `ci.yml` (per-PR gates). Triggered on a version tag.

```yaml
name: Release
on:
  push:
    tags: [ 'v*' ]
permissions:
  contents: write          # create the GitHub Release + upload assets
jobs:
  gate:                    # reuse ci.yml's gates as a precondition
    uses: ./.github/workflows/ci.yml   # call the existing CI as a reusable workflow
  build-tpm-wheel:
    needs: gate
    runs-on: ubuntu-latest
    steps:
      - checkout
      - install libtss2-dev (build) + the TSS2 stack
      - maturin build --release --no-default-features --features tpm-attest --out dist
      # NB: do NOT auditwheel-repair-vendor libtss2-esys (see §4.1); tag linux_x86_64
  build-soft-wheel:
    needs: gate
    runs-on: ubuntu-latest
    steps:
      - maturin build --release --no-default-features --features dev-soft-attest --out dist
      - rename/local-version to +soft
  build-sdist:
    needs: gate
    steps: [ maturin sdist --out dist ]
  sign-and-publish:
    needs: [ build-tpm-wheel, build-soft-wheel, build-sdist ]
    steps:
      - gather dist/* + install.sh
      - sha256sum dist/* install.sh > SHA256SUMS
      - <sign SHA256SUMS>            # FORK F3
      - softprops/action-gh-release  # pinned to SHA; attach all artifacts
```

Design points:
- **Reuse the CI gates as a reusable workflow** (`uses: ./.github/workflows/
  ci.yml`) so a tag can never publish artifacts that didn't pass black/isort/
  ruff/pylint/pyright/pytest + clippy/cargo-test/cargo-audit + the swtpm TPM
  lane. This is the single most important property of the pipeline.
- **SHA-pinned third-party actions** + a `permissions:` block (the master plan
  4.1 already calls for SHA-pinning; do it here too — `PRODUCTION_REVIEW` §6
  flagged "Actions on mutable tags").
- **`requirements.lock --generate-hashes`** is exercised here (and in CI) so the
  reproducible install path is actually tested — closes the
  `PRODUCTION_REVIEW` "lock never exercised / no hashes" medium.
- Artifacts: TPM wheel, soft wheel, sdist, `install.sh`, `SHA256SUMS`,
  signature. Release notes pulled from the `CHANGELOG.md` `[1.0.0]` section.

### 5.1 Signing (FORK F3): sigstore vs minisign vs GPG

| Option | Pros | Cons |
|---|---|---|
| **Sigstore (cosign keyless)** | no key to guard (OIDC + transparency log); modern; CI-native | verifier needs cosign + understanding of keyless; heavier for a "curl \| sh" audience |
| **minisign** | tiny, one static pubkey embeddable in `install.sh`, trivial `-Vm` verify, no keyserver | you must guard one private key; less ecosystem tooling |
| **GPG detached sig** | universally understood; `gpg --verify` | key management/expiry pain; WKD/keyserver friction; heavyweight |

**Recommendation: minisign signature over `SHA256SUMS`, with the public key
embedded in `install.sh`.** Rationale: `install.sh` is the trust root the user
pastes; embedding one short minisign pubkey lets the script verify the checksum
file with a single static dependency, and the per-artifact integrity then chains
off the signed `SHA256SUMS`. Sigstore is the more "modern" answer and is a fine
upgrade later, but it adds verifier complexity that fights "extraordinarily
simple." Whatever is chosen, **sign the checksum file, not each artifact
separately** (one signature, simplest verify).

---

## 6. Deliverable 4 — Docs finalization

### 6.1 README.txt → README.md (FORK F6)

The README was heavily rewritten in Phases 2–3 (threat model, TPM, accepted
risks) and is the public face. It must become real Markdown with:
- A **Quickstart** at the very top: the `curl install.sh | sh` → `dsm init` →
  `systemctl enable --now dsm` three-step (§1), *above* the architecture prose.
- The honest **threat model** + **accepted v1 risks** (already written — port
  verbatim, just Markdown-format).
- The **TPM 2.0 requirement** stated up front (a stranger must know they need a
  TPM before they start).
- The **supported-target statement** (§4.1): "Debian 12+/Ubuntu 22.04+ x86_64
  with TPM 2.0; other distros build from source," and the eval-wheel note.
- Install steps that match the new `install.sh` + venv contract (§4.4), with the
  GUIDE as the deep reference.

This is a **file rename** (hard stop per CLAUDE.md) — but it is **already
owner-approved** in the master-plan Owner Decisions table ("rename
`README.txt`→`README.md` … with proper Markdown formatting"). So F6 is a
*confirmation*, not a fresh ask. Same for `deploy/GUIDE.txt`→`GUIDE.md`.

### 6.2 GUIDE.txt → GUIDE.md + top-level QUICKSTART?

- **GUIDE.txt → GUIDE.md:** owner-approved; convert to Markdown (it is already
  structured with section headers and code blocks). **Coupled change:** the
  `Documentation=` lines in `deploy/dsm.service` point at `GUIDE.txt`/`README.txt`
  — update them in the same change or the unit references dead paths.
- **Top-level QUICKSTART.md:** **Recommend NOT** adding a separate file. With
  `dsm init` + a README Quickstart section, a third doc is redundant surface that
  will drift (the review already flagged doc drift heavily). Keep the quickstart
  *in* README.md. (If the owner wants a one-screen TL;DR, make it the README's
  first section, not a separate file.)

### 6.3 Reused vs new
- **Reused:** all prose content (README.txt, GUIDE.txt) — this is a
  format-and-restructure, not a rewrite.
- **New:** the README Quickstart section; the supported-target statement; the
  `Documentation=` path fix.

---

## 7. Deliverable 5 — Versioning

Current: `pyproject.toml` `version = "0.1.0"`, `rust/tuncore/Cargo.toml`
`version = "0.1.0"`, CHANGELOG `[Unreleased]`.

### 7.1 v0.1.0 vs v1.0.0 for the first public tag (FORK F7)

| Option | Pros | Cons |
|---|---|---|
| **v1.0.0** | matches the owner's "v1 = public release" framing; signals "ready to use" | SemVer 1.0.0 implies a *stable public API/compat commitment*; this is a first public cut of a security tool that will churn |
| **v0.1.0 / v0.x** | honest "early, API/format may change" signal; standard for pre-1.0 software; lets the wire/blob/config formats evolve without a major bump | undercuts the "v1 release" messaging; some users skip 0.x |

**Recommendation: tag the first public release `v0.1.0`** (keep the existing
number; it is already correct). Rationale: SemVer 1.0.0 is a *compatibility
promise* — and this codebase still has explicitly post-v1 items (Android, PCR
policy, IPv6 transport, TLS-fronting) and evolving on-disk formats (the sealed
blob versioning was just added). "v1 public release" is the owner's *milestone*
name, not a mandate to claim SemVer-stable. Ship `v0.1.0` as "first public
release," reserve `v1.0.0` for when the wire/blob/config formats are frozen.
**If the owner prefers the marketing weight of v1.0.0, that is a one-line
decision — but it should be a conscious compatibility commitment, not a default.**

### 7.2 CHANGELOG release process
- Cut the current `[Unreleased]` block into `[0.1.0] - 2026-06-..` (or
  `[1.0.0]`), keep a fresh empty `[Unreleased]` on top.
- Fix the placeholder compare link (`https://example.com/dsm/...` → the real
  repo) — `PRODUCTION_REVIEW` would flag the example.com URL.
- `release.yml` extracts the tagged section as the GitHub Release body.
- Keep version in **three** places in sync (pyproject, Cargo, CHANGELOG) — note
  for the TDD plan: add a release-checklist step or a tiny consistency check.

---

## 8. Deliverable 6 — Credible-public-release extras (keep lean)

| File | Worth it? | Recommendation |
|---|---|---|
| `CONTRIBUTING.md` | **Yes (lean)** | Short: how to build (point at GUIDE §1), the gate order (CLAUDE.md run order), "tests in `tests/`, never edit existing tests to pass," and the no-PyPI/GitHub-Releases model. ~1 screen. |
| `CODE_OF_CONDUCT.md` | **Optional** | A stock Contributor Covenant is low-cost and expected by many; include the short version or skip. Low priority. |
| Issue templates (`.github/ISSUE_TEMPLATE/`) | **Yes (minimal)** | One `bug_report.md` (with a **"do NOT paste keys/certs/CN allowlist"** warning — security-relevant for this project) and one `security` pointer that redirects to `SECURITY.md` (do not collect vuln reports in public issues). |
| PR template | **Optional** | A 4-line checklist (gate ran? tests added? docs updated?). Cheap; nice-to-have. |
| `.gitignore` rows | **Yes** | Add `dist-tpm/`, `*.whl`, `*.crt`, `/opt`-style artifacts, `.dsm-init-state.json`, `SHA256SUMS*`. The review flagged `.gitignore` gaps. |
| Funding / SUPPORT | **Skip** | Out of scope for v1. |

**Explicitly skip** anything heavier (governance docs, multi-maintainer
policies) — the project is single-maintainer and the owner wants lean.

---

## 9. Security lens (Phase 4 surface)

- **Untrusted input entering the system:** `install.sh` downloads remote
  artifacts → mitigated by signature-over-checksums verified *before* any
  install/execute (§4.3, §5.1). The `dsm init` wizard reads operator-typed
  values → validate IP literal, paths, and the SPKI pin format; never `eval` or
  shell-interpolate answers (use list-form subprocess, the house pattern).
- **Auth/authz boundaries:** unchanged — Phase 4 does not touch cert/CRL/allowlist
  logic. The wizard *orchestrates* the existing enroll/import paths; it must not
  bypass `import_signed_cert`'s chain/binding/SPKI checks.
- **Sensitive data crossing boundaries:** the wizard handles the enroll
  passphrase → reuse `read_passphrase`/`wipe_passphrase` only; do not log it,
  do not write it except to the operator-chosen credential file (0600). The
  init-state file must contain **no secrets** (paths + phase marker only).
- **Key material:** `dsm init` provisions the in-TPM attest key via the existing
  `generate_enrollment` — **no new key-handling code.** → `security` agent review
  recommended on the wizard's passphrase/state-file handling and on `install.sh`'s
  signature-verification logic (the two genuinely new trust-bearing surfaces).
- **Blast radius / supply chain:** `install.sh` run as root is a high-value
  target — its embedded signing pubkey and the verify-before-execute ordering are
  load-bearing. Pin third-party GitHub Actions to SHAs in `release.yml`.
- **TOCTOU:** install.sh "verify then install" — verify the wheel hash and then
  install the *same* file (don't re-download between check and install).

`→ security agent review recommended` for: `install.sh` (signature verification
+ root execution) and `dsm/init.py` (passphrase + state-file handling).

---

## 10. Suggested ordered task breakdown (for the subsequent TDD plan)

Ordered so each task is independently testable and later tasks depend on earlier
contracts. (TDD: failing test → minimal code → green; new test files only.)

1. **Versioning + CHANGELOG cut** (4.x, F7) — pick v0.1.0/v1.0.0; sync pyproject
   + Cargo + CHANGELOG; fix the example.com compare link. *Test:* a consistency
   check that the three versions match. Cheapest, unblocks release notes.
2. **Doc rename + Markdown** (4.6, F6) — `README.txt`→`README.md` (+ Quickstart,
   supported-target, TPM-required, eval-wheel note), `GUIDE.txt`→`GUIDE.md`, fix
   `deploy/dsm.service` `Documentation=` paths. *Test:* link-check / the unit's
   Documentation paths resolve; no `.txt` references remain.
3. **`dsm init` wizard** (4.3) — the centerpiece. Subparser + `dsm/init.py`;
   server + client; interactive + `--non-interactive` + `--resume`; reuse
   enroll/import/config/preflight. *Tests:* non-interactive path generates a
   config that `config.load()` accepts; precondition failures exit 2 with
   messages; `--resume` finalizes; idempotency/`--force`. (Pair with a `security`
   review of passphrase/state handling.)
4. **`deploy/dsm.service` ExecStart contract** (F5) — switch to the venv
   interpreter path (or chosen mechanism); keep all hardening directives. *Test:*
   unit parses (`systemd-analyze verify` in CI if available) / a static assertion
   on `ExecStart`.
5. **`install.sh`** (4.2, F2/F4/F5) — distro detect, signature-verify-before-
   install, apt deps, venv install, group, unit install. *Tests:* shellcheck;
   a hermetic dry-run mode that stubs network/apt and asserts the verify-then-
   install ordering and the eval-vs-tpm branch. (Pair with `security` review.)
6. **`requirements.lock --generate-hashes`** (4.1 tail) — regenerate with hashes;
   wire a CI step that installs from it. *Test:* the hashed lock installs in CI.
7. **`release.yml`** (4.2, F3) — reusable-workflow call to ci.yml gates; build
   tpm + soft + sdist; sign checksums; publish. SHA-pin actions; `permissions:`
   block. *Test:* a `workflow_dispatch` dry-run / `act`-style validation; assert
   no mutable action tags.
8. **Repo hygiene extras** (§8) — `CONTRIBUTING.md`, minimal issue templates,
   `.gitignore` rows, optional CoC/PR template. *Test:* presence + the issue
   template "no secrets" warning.

Tasks 1–2 are quick wins; **task 3 (`dsm init`) is the largest and the
"extraordinarily simple" centerpiece** — it should get the most design care and a
security pass. Tasks 5 and 7 carry the distribution-contract irreversibles.

---

## 11. Honest risks

1. **The manylinux/libtss2 crux (highest).** A hardware-TPM VPN *cannot* ship a
   single drop-anywhere wheel (§4.1): the wheel links the host's
   `libtss2-esys.so.0` and the TPM stack `dlopen`s host TCTIs. "Extraordinarily
   simple" therefore means *"simple on the supported distros"* (install.sh +
   apt), not *"pip install anywhere."* If the owner expects pip-anywhere
   portability, that expectation cannot be met — the honest answer is a declared
   supported-target list + a build-from-source fallback. **This must be stated in
   README, not buried.**
2. **ABI drift on `libtss2-esys`.** The soname is `.so.0` across the current
   Debian/Ubuntu era, but the `t64` transition shows packaging churn; a future
   esys major (soname bump) would break the prebuilt wheel on new distros and
   force a rebuild. Mitigate by building the release wheel against the *oldest*
   supported esys and documenting the supported window; the sdist path always
   works.
3. **`install.sh` is root-run remote code.** Its signature-verify-before-execute
   logic and embedded pubkey are the trust root. A bug there is a supply-chain
   compromise. Mitigate: minimal POSIX sh, shellcheck, a security review, verify
   the checksum file's signature before touching any wheel.
4. **`dsm init` cannot remove the air-gap pause.** The offline-CA round trip is
   inherent to the threat model (compromised-server adversary; CA key never
   networked). The wizard makes everything around it trivial but the operator
   still physically walks a CSR. Set expectations: "simple" ≠ "zero manual
   steps" — the CA walk is a *feature* of the security model.
5. **systemd interpreter coupling (F5).** Changing `ExecStart` from
   `/usr/bin/python3` to a venv interpreter must land *with* install.sh and the
   docs, or operators get an import error under systemd. Coupled change; sequence
   tasks 4+5+2 together.
6. **Soft/eval wheel misuse.** A `+soft` wheel deployed in production gives a
   false sense of hardware binding. The runtime WARNING + `allow_soft_attest`
   gate already exist; the release naming (`+soft`), the README one-liner, and
   install.sh's `--eval`-only path must reinforce "evaluation only."
7. **Three-place version skew.** pyproject/Cargo/CHANGELOG can drift; add a
   consistency check (task 1) and a release checklist.

---

## 12. OWNER FORKS (consolidated — decision-ready)

> Present these in one pass. Each has options + a recommendation + rationale.

**F1 — `dsm init` subcommand shape.**
Options: (a) split `dsm init server` / `dsm init client`; (b) one `dsm init`
that prompts for role; (c) a thin scaffolder that only generates config + prints
next commands (no enroll orchestration).
**Recommend (a) split + full orchestration** (it runs enroll/import/config/unit,
not just scaffolds). Rationale: matches "extraordinarily simple"; role-split
keeps each prompt set minimal and unambiguous; the air-gap pause is handled with
`--resume`. (c) is too thin to deliver the owner's centerpiece goal.

**F2 — Distribution / manylinux feasibility (TECHNICAL VERDICT, needs owner
acknowledgement of the contract).**
Verdict: the TPM wheel **cannot** be a portable manylinux wheel — it links the
host `libtss2-esys.so.0`. Ship a `linux_x86_64` wheel + `install.sh` (apt-installs
the runtime lib) for a **declared supported-target list** (Debian 12+/Ubuntu
22.04+/x86_64/TPM 2.0), with an **sdist build-from-source** fallback for everyone
else. **Recommend accept this contract** and state it plainly in README.
(Alternative — vendoring libtss2 into the wheel — is rejected: wrong for a
TPM-access library that must match the host stack.)

**F3 — Release artifact signing.**
Options: sigstore/cosign (keyless), **minisign**, GPG.
**Recommend minisign over `SHA256SUMS`,** pubkey embedded in `install.sh`.
Rationale: smallest verifier footprint for a `curl | sh` audience; one signature,
one static key. Sigstore is a fine later upgrade.

**F4 — How TPM-less users evaluate (soft wheel distribution).**
Options: (a) ship a clearly-named `+soft` eval wheel + `install.sh --eval`;
(b) source-only for eval; (c) no eval path.
**Recommend (a)** with loud "evaluation only, no hardware binding" naming and
docs. Rationale: lets people try DSM without a TPM (adoption) while the runtime
gate + naming prevent accidental production use.

**F5 — Install mechanism / systemd interpreter contract (IRREVERSIBLE-ish).**
Options: pipx, **dedicated venv `/opt/dsm/venv`**, system Python
(`--break-system-packages`, today's GUIDE).
**Recommend dedicated venv** + symlink `dsm` on PATH + change
`deploy/dsm.service` `ExecStart=` to the venv interpreter. Rationale:
deterministic interpreter path for systemd, isolation, clean uninstall, no
PEP-668 friction. This sets the public install contract → confirm consciously.

**F6 — README.txt→README.md and GUIDE.txt→GUIDE.md rename (CONFIRMATION).**
Already owner-approved in the master-plan decisions table. **Recommend proceed**
(Markdown + README Quickstart up top; fix the unit's `Documentation=` paths). No
separate top-level QUICKSTART file (keep it in README to avoid drift).

**F7 — First public tag version (IRREVERSIBLE once tagged/pushed).**
Options: **v0.1.0** (honest pre-1.0; formats may evolve) vs v1.0.0 (SemVer
stability commitment + marketing weight).
**Recommend v0.1.0** for the first public release; reserve v1.0.0 for when
wire/blob/config formats are frozen. If the owner wants v1.0.0's signal, treat it
as a conscious compatibility promise.

### Irreversible decisions flagged
- **F5 (install mechanism + `ExecStart` contract)** — defines how every public
  user installs and how systemd launches dsm; changing it later breaks existing
  installs.
- **F2 (distribution model / supported-target list)** — sets the public "what
  runs DSM" contract; vendoring-vs-system-lib and the manylinux stance are hard
  to walk back once people build tooling around the release artifacts.
- **F7 (first version tag)** — a pushed git tag + GitHub Release is effectively
  permanent; v1.0.0 carries a SemVer compatibility promise.
- **F3 (signing key)** — the signing identity becomes a long-lived trust root
  users pin; rotating it later is disruptive.

---

## 13. Open questions requiring owner input (beyond the forks)

- **Supported-distro list scope:** is "Debian 12+/Ubuntu 22.04+, x86_64" the
  intended v1 target, or must other distros (Fedora/Arch) be first-class at
  launch? (Drives how many wheels/test lanes release.yml needs.)
- **Repo org/URL:** the CHANGELOG compare link and `install.sh` base URL need the
  real `github.com/<org>/dsm` path. (Blocks finalizing both.)
- **Signing key custody:** who holds the minisign (or chosen) private key, and
  where? (Blocks F3 implementation.)
```
