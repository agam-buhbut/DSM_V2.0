#!/bin/sh
# DSM installer — verify-before-execute bootstrap for the supported target
# (Debian 12+ / Ubuntu 22.04+ / x86_64 / TPM 2.0). Downloads the wheel +
# SHA256SUMS + minisign signature, VERIFIES the minisign signature and the
# checksum BEFORE installing anything (apt/pip/venv), then installs into a
# dedicated venv.
#
# Trust model (read before piping to a root shell):
#   * curl | sudo sh is trust-on-first-use: you are trusting THIS script and
#     the TLS chain to the release host the first time. Everything the script
#     then downloads (wheel, checksums) is verified against the embedded
#     minisign public key below — so a compromised release host cannot make
#     us install an unsigned or tampered wheel. The residual TOFU risk is the
#     fetch of this very script; pin it (download, read, then run) if that
#     matters to your threat model.
#   * Rollback: we install exactly DSM_VERSION (below). The wheel filename and
#     its SHA256SUMS line both embed that version, and we refuse to proceed
#     unless the signed checksum list contains a line for THIS version's wheel.
#     A release host can still withhold a NEWER release (a freeze/downgrade-by-
#     omission attack), but cannot substitute a different validly-signed wheel
#     for the version this script pins. Bump DSM_VERSION per release.
#
# Usage:  curl -fsSL <release>/install.sh | sudo sh
#         curl -fsSL <release>/install.sh | sudo sh -s -- --eval
#         curl -fsSL <release>/install.sh | sudo sh -s -- --systemd
#         (flags may be combined and given in any order)
set -eu

# Pinned release this script installs. The wheel name and its signed
# SHA256SUMS entry both embed this; a mismatch aborts (see anti-rollback note).
DSM_VERSION="0.1.0"
# TODO(owner): replace <OWNER/REPO> with the real GitHub org/repo before release.
BASE="${DSM_RELEASE_BASE_URL:-https://github.com/<OWNER/REPO>/releases/download/v${DSM_VERSION}}"

# TODO(owner): paste the real minisign PUBLIC key (one base64 line) before
# release. The matching PRIVATE key is OWNER-ONLY and lives in a CI secret.
MINISIGN_PUBKEY="RWQUNRELEASED_PLACEHOLDER_minisign_public_key_REPLACE_BEFORE_RELEASE"

VENV="/opt/dsm/venv"

die() { echo "install.sh: $*" >&2; exit 1; }

# --- Argument parsing (flags in any order; reject unknown) -------------------
EVAL=0
SYSTEMD=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --eval)    EVAL=1 ;;
    --systemd) SYSTEMD=1 ;;
    -h|--help)
      echo "Usage: install.sh [--eval] [--systemd]" >&2
      exit 0
      ;;
    *) die "unknown argument: $1 (supported: --eval, --systemd, --help)" ;;
  esac
  shift
done

# --- Preconditions -----------------------------------------------------------
[ "$(id -u)" = "0" ] || die "must run as root (sudo)"
[ "$(uname -m)" = "x86_64" ] || die "unsupported arch $(uname -m); build from source (deploy/GUIDE.md §1)"
command -v apt-get >/dev/null 2>&1 || die "no apt-get; supported targets are Debian 12+/Ubuntu 22.04+. Build from source for others."

# Supported-distro warning (warn+continue: Debian 12+ / Ubuntu 22.04+).
# /etc/os-release is sourced in a subshell so its variables (VERSION_ID,
# VERSION, ID, …) cannot leak into and shadow our own state.
if [ -r /etc/os-release ]; then
  _distro_warn="$(
    # shellcheck disable=SC1091
    . /etc/os-release
    case "${ID:-}" in
      debian)
        case "${VERSION_ID:-0}" in
          1[2-9]|[2-9][0-9]) : ;;
          *) echo "WARNING — Debian ${VERSION_ID:-?} is below the supported Debian 12+ baseline; continuing." ;;
        esac
        ;;
      ubuntu)
        _major="${VERSION_ID:-0}"; _major="${_major%%.*}"
        if [ "${_major:-0}" -lt 22 ] 2>/dev/null; then
          echo "WARNING — Ubuntu ${VERSION_ID:-?} is below the supported Ubuntu 22.04+ baseline; continuing."
        fi
        ;;
      *)
        echo "WARNING — ${PRETTY_NAME:-unknown distro} is not a declared supported target (Debian 12+/Ubuntu 22.04+); continuing."
        ;;
    esac
  )"
  [ -n "$_distro_warn" ] && echo "install.sh: $_distro_warn" >&2
fi

# TPM presence gate (production only). --eval skips it (no hardware binding).
if [ "$EVAL" = 0 ] && [ ! -e /dev/tpmrm0 ]; then
  die "/dev/tpmrm0 not found — DSM requires a TPM 2.0 in production. For a no-hardware evaluation, re-run with --eval (NOT for production)."
fi

# --- Install the verifier itself (the ONLY thing done from the distro's
#     trusted apt repo before any downloaded content is verified) -------------
if ! command -v minisign >/dev/null 2>&1; then
  apt-get update || die "apt-get update failed"
  apt-get install -y minisign || die "could not install minisign (the signature verifier); refusing to continue"
fi
command -v minisign >/dev/null 2>&1 || die "minisign still not available after install; refusing to continue"

# --- Private working dir (mktemp; never a predictable /tmp name) -------------
WORK="$(mktemp -d)" || die "could not create a temporary working directory"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK" || die "could not enter working directory"

if [ "$EVAL" = 1 ]; then
  echo "=============================================================" >&2
  echo "=== EVALUATION INSTALL: +soft wheel, NO hardware binding. ===" >&2
  echo "=== For EVALUATION ONLY — never production. No TPM bind.   ===" >&2
  echo "=============================================================" >&2
  WHEEL="dsm-${DSM_VERSION}+soft-cp311-abi3-linux_x86_64.whl"
else
  WHEEL="dsm-${DSM_VERSION}-cp311-abi3-linux_x86_64.whl"
fi

# --- 1. Download checksum file + signature (NOT the wheel yet) ---------------
curl -fsSL --proto '=https' --tlsv1.2 "$BASE/SHA256SUMS" \
  -o "$WORK/SHA256SUMS"          || die "cannot fetch SHA256SUMS"
curl -fsSL --proto '=https' --tlsv1.2 "$BASE/SHA256SUMS.minisig" \
  -o "$WORK/SHA256SUMS.minisig"  || die "cannot fetch signature"

# --- 2. VERIFY the minisign signature over SHA256SUMS BEFORE touching any
#        artifact. The exit code is checked explicitly (|| die); nothing is
#        downstream of a pipe that could swallow a failure. -------------------
printf '%s\n' "$MINISIGN_PUBKEY" > "$WORK/pubkey.pub" \
  || die "could not stage the minisign public key"
minisign -V -p "$WORK/pubkey.pub" -m "$WORK/SHA256SUMS" \
  || die "minisign verification FAILED — refusing to continue"

# --- 3. Anti-rollback / version pin: the signed list MUST contain a line for
#        the EXACT wheel this script installs. We select that line by an exact
#        FIELD match on the filename (awk $2 == name) — not a regex, so the
#        '+' in '+soft' is not treated as a metacharacter and a decoy name
#        cannot match. We extract the hash WITHOUT a pipe into the checker, so
#        a missing entry fails closed rather than feeding empty input to
#        sha256sum (whose empty-input exit is implementation-dependent across
#        coreutils/busybox). awk prints exactly one canonical "<hash>  <name>"
#        line; >1 match (a malformed/duplicated list) is also rejected. -------
EXPECTED_LINE="$(awk -v w="$WHEEL" '$2 == w {n++; line=$1"  "$2} END {if (n==1) print line}' "$WORK/SHA256SUMS")"
[ -n "$EXPECTED_LINE" ] \
  || die "signed SHA256SUMS has no single entry for ${WHEEL} — refusing (wrong/rolled-back release, unsupported variant, or malformed list)"

# --- 4. Download the wheel into the SAME temp dir, then verify the SAME file
#        we downloaded (no re-download between verify and install: no TOCTOU). -
curl -fsSL --proto '=https' --tlsv1.2 "$BASE/$WHEEL" \
  -o "$WORK/$WHEEL" || die "cannot fetch $WHEEL"

# Recompute the hash of the downloaded file and compare to the signed value.
# sha256sum -c reads the "<hash>  <name>" line and the exit code is checked
# explicitly; the comparison file is the verified SHA256SUMS line only.
printf '%s\n' "$EXPECTED_LINE" > "$WORK/expected.sha256" \
  || die "could not stage the expected checksum"
( cd "$WORK" && sha256sum -c "$WORK/expected.sha256" ) \
  || die "wheel checksum mismatch — refusing to install"

# ============================================================================
#  VERIFIED-ARTIFACT GATE PASSED. Only past this line may we run apt/pip/venv.
# ============================================================================

# --- 5. System runtime deps -------------------------------------------------
apt-get update || die "apt-get update failed"
apt-get install -y nftables iproute2 ca-certificates python3-venv \
  || die "could not install base runtime dependencies"
if [ "$EVAL" = 0 ]; then
  # TPM 2.0 runtime stack: the .so.0 provider + the device TCTI. No vendoring.
  apt-get install -y libtss2-esys-3.0.2-0t64 libtss2-tcti-device0 \
    || apt-get install -y libtss2-esys libtss2-tcti-device0 \
    || die "could not install the libtss2 TPM runtime stack"
else
  # Eval allows swtpm for software-TPM testing (still NO hardware binding).
  apt-get install -y swtpm \
    || echo "install.sh: WARNING — swtpm not installed; software-TPM eval may not work." >&2
fi

# --- 6. Dedicated venv + wheel install (no system-Python pollution) ---------
python3 -m venv "$VENV" || die "could not create the venv at $VENV"
"$VENV/bin/pip" install --upgrade pip || die "could not upgrade pip in the venv"
# --no-index + --find-links restricts the install to the verified local wheel
# (and its transitive deps from the same dir); pip never reaches the network.
"$VENV/bin/pip" install --no-index --find-links "$WORK" "$WORK/$WHEEL" \
  || die "wheel install failed"
ln -sf "$VENV/bin/dsm" /usr/local/bin/dsm || die "could not symlink dsm into /usr/local/bin"

# --- 7. tss group (TPM access) + optional unit install (production only) -----
if [ "$EVAL" = 0 ]; then
  getent group tss >/dev/null 2>&1 || groupadd --system tss || die "could not create the tss group"
  echo "Note: the dsm daemon must be in the 'tss' group to reach /dev/tpmrm0." >&2
  echo "      The shipped deploy/dsm.service sets SupplementaryGroups=tss already." >&2
  if [ "$SYSTEMD" = 1 ]; then
    UNIT_SRC=""
    for c in /opt/dsm/deploy/dsm.service ./deploy/dsm.service; do
      [ -f "$c" ] && { UNIT_SRC="$c"; break; }
    done
    if [ -n "$UNIT_SRC" ]; then
      install -m 0644 "$UNIT_SRC" /etc/systemd/system/dsm.service \
        || die "could not install dsm.service"
      systemctl daemon-reload || die "systemctl daemon-reload failed"
      echo "Installed dsm.service. Start with: sudo systemctl enable --now dsm" >&2
    else
      echo "install.sh: WARNING — --systemd requested but deploy/dsm.service not found locally; skipping unit install." >&2
    fi
  fi
elif [ "$SYSTEMD" = 1 ]; then
  echo "install.sh: WARNING — --systemd is ignored in --eval mode (no production unit installed)." >&2
fi

if [ "$EVAL" = 1 ]; then
  echo "Eval install complete (EVALUATION ONLY). Try: sudo dsm init client" >&2
else
  echo "Install complete. Next: sudo dsm init server" >&2
fi
