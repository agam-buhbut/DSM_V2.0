#!/bin/sh
# DSM installer — verify-before-execute bootstrap for the supported target
# (Debian 13+ / Ubuntu 25.04+ / x86_64 / TPM 2.0). Downloads the wheel +
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
#   * --systemd (not with --client) also installs a daily download of a DNS
#     block list for the server (default: StevenBlack/hosts) and runs it
#     once right away. That list is NOT minisign-verified: it comes over
#     HTTPS from the list's own host, so you trust that host for it. dsm
#     only reads it as names to block, never runs it: a bad list can make
#     names fail to resolve (deploy/GUIDE.md §7h).
#
# Usage:  curl -fsSL <release>/install.sh | sudo sh
#         curl -fsSL <release>/install.sh | sudo sh -s -- --eval
#         curl -fsSL <release>/install.sh | sudo sh -s -- --systemd
#         curl -fsSL <release>/install.sh | sudo sh -s -- --systemd --client
#         (flags may be combined and given in any order; --systemd installs
#         the server unit, --systemd --client the client unit)
set -eu

# Pinned release this script installs. The wheel name and its signed
# SHA256SUMS entry both embed this; a mismatch aborts (see anti-rollback note).
DSM_VERSION="0.1.0"
BASE="${DSM_RELEASE_BASE_URL:-https://github.com/agam-buhbut/DSM_V2.0/releases/download/v${DSM_VERSION}}"

# The release signing key's PUBLIC half (minisign key ID DF98FF5321B786A3).
# The matching PRIVATE key is OWNER-ONLY and lives in a CI secret.
MINISIGN_PUBKEY="RWSjhrchU/+Y31PirEAjfoNQ0ktYgR0ovHTLL7CykL22+hSoRfvHgUsi"

VENV="/opt/dsm/venv"

die() { echo "install.sh: $*" >&2; exit 1; }

# Argument parsing: flags in any order; unknown flags are rejected.
EVAL=0
SYSTEMD=0
CLIENT=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --eval)    EVAL=1 ;;
    --systemd) SYSTEMD=1 ;;
    --client)  CLIENT=1 ;;
    -h|--help)
      echo "Usage: install.sh [--eval] [--systemd] [--client]" >&2
      exit 0
      ;;
    *) die "unknown argument: $1 (supported: --eval, --systemd, --client, --help)" ;;
  esac
  shift
done

[ "$(id -u)" = "0" ] || die "must run as root (sudo)"
[ "$(uname -m)" = "x86_64" ] || die "unsupported arch $(uname -m); build from source (deploy/GUIDE.md §1)"
command -v apt-get >/dev/null 2>&1 || die "no apt-get; supported targets are Debian 13+/Ubuntu 25.04+. Build from source for others."

# Supported-distro warning (warn+continue: Debian 13+ / Ubuntu 25.04+; the
# release's wheels are built on Debian 13, and an older glibc may be too old
# for them).
# /etc/os-release is sourced in a subshell so its variables (VERSION_ID,
# VERSION, ID, …) cannot leak into and shadow our own state.
if [ -r /etc/os-release ]; then
  _distro_warn="$(
    # shellcheck disable=SC1091
    . /etc/os-release
    case "${ID:-}" in
      debian)
        case "${VERSION_ID:-0}" in
          1[3-9]|[2-9][0-9]) : ;;
          *) echo "WARNING — Debian ${VERSION_ID:-?} is below the supported Debian 13+ baseline; continuing." ;;
        esac
        ;;
      ubuntu)
        _major="${VERSION_ID:-0}"; _major="${_major%%.*}"
        if [ "${_major:-0}" -lt 25 ] 2>/dev/null; then
          echo "WARNING — Ubuntu ${VERSION_ID:-?} is below the supported Ubuntu 25.04+ baseline; continuing."
        fi
        ;;
      *)
        echo "WARNING — ${PRETTY_NAME:-unknown distro} is not a declared supported target (Debian 13+/Ubuntu 25.04+); continuing."
        ;;
    esac
  )"
  [ -n "$_distro_warn" ] && echo "install.sh: $_distro_warn" >&2
fi

# TPM presence gate (production only). --eval skips it (no hardware binding).
if [ "$EVAL" = 0 ] && [ ! -e /dev/tpmrm0 ]; then
  die "/dev/tpmrm0 not found — DSM requires a TPM 2.0 in production. For a no-hardware evaluation, re-run with --eval (NOT for production)."
fi

# Install the verifier itself — the ONLY thing taken from the distro's trusted
# apt repo before any downloaded content is verified.
if ! command -v minisign >/dev/null 2>&1; then
  apt-get update || die "apt-get update failed"
  apt-get install -y minisign || die "could not install minisign (the signature verifier); refusing to continue"
fi
command -v minisign >/dev/null 2>&1 || die "minisign still not available after install; refusing to continue"

# Private working dir: mktemp, never a predictable /tmp name.
WORK="$(mktemp -d)" || die "could not create a temporary working directory"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK" || die "could not enter working directory"

# The DSM wheel's name up to its platform tag. maturin picks the tag from the
# build host's glibc (manylinux_2_<n>_x86_64), so the name is taken from the
# signed list below.
if [ "$EVAL" = 1 ]; then
  echo "install.sh: EVALUATION INSTALL — soft wheel, no hardware binding." >&2
  echo "install.sh: EVALUATION ONLY — never use this build in production." >&2
  WHEEL_PREFIX="dsm-${DSM_VERSION}+soft-cp311-abi3-"
else
  WHEEL_PREFIX="dsm-${DSM_VERSION}-cp311-abi3-"
fi

# Download checksum file + signature; the wheel is NOT fetched yet.
curl -fsSL --proto '=https' --tlsv1.3 "$BASE/SHA256SUMS" \
  -o "$WORK/SHA256SUMS"          || die "cannot fetch SHA256SUMS"
curl -fsSL --proto '=https' --tlsv1.3 "$BASE/SHA256SUMS.minisig" \
  -o "$WORK/SHA256SUMS.minisig"  || die "cannot fetch signature"

# VERIFY the minisign signature over SHA256SUMS BEFORE touching any artifact.
# The key goes on the command line (-P): minisign reads a key FILE only with
# its "untrusted comment:" line first, and refuses a file that holds just the
# key. The exit code is checked explicitly (|| die); nothing is downstream of
# a pipe that could swallow a failure.
minisign -V -P "$MINISIGN_PUBKEY" -m "$WORK/SHA256SUMS" \
  || die "minisign verification FAILED — refusing to continue"

# Pick the DSM wheel from the signed list: the one entry whose name starts
# with exactly $WHEEL_PREFIX and ends with exactly _x86_64.whl. index() and
# substr() compare plain text, so the '+' in '+soft' is no regex character;
# the production prefix never matches the +soft wheel, nor the other way
# round. A name with a '/' or a '\' is never taken: the first would leave
# $WORK, and awk -v would read the second as an escape in the next step.
# Two entries that match, or none, fail closed.
WHEEL="$(awk -v p="$WHEEL_PREFIX" -v s="_x86_64.whl" 'index($2, p) == 1 && length($2) > length(p) + length(s) && substr($2, length($2) - length(s) + 1) == s && index($2, "/") == 0 && index($2, "\\") == 0 {n++; w=$2} END {if (n == 1) print w}' "$WORK/SHA256SUMS")"
[ -n "$WHEEL" ] \
  || die "signed SHA256SUMS has no single entry for ${WHEEL_PREFIX}*_x86_64.whl — refusing (wrong/rolled-back release, unsupported variant, or malformed list)"

# Anti-rollback / version pin: the signed list MUST contain a line for the
# EXACT wheel this script installs. We select that line by an exact FIELD match
# on the filename (awk $2 == name) — not a regex, so the '+' in '+soft' is not
# treated as a metacharacter and a decoy name cannot match. We extract the hash
# WITHOUT a pipe into the checker, so a missing entry fails closed rather than
# feeding empty input to sha256sum (whose empty-input exit is implementation-
# dependent across coreutils/busybox). awk prints exactly one canonical
# "<hash>  <name>" line; >1 match (a malformed/duplicated list) is rejected.
EXPECTED_LINE="$(awk -v w="$WHEEL" '$2 == w {n++; line=$1"  "$2} END {if (n==1) print line}' "$WORK/SHA256SUMS")"
[ -n "$EXPECTED_LINE" ] \
  || die "signed SHA256SUMS has no single entry for ${WHEEL} — refusing (wrong/rolled-back release, unsupported variant, or malformed list)"

# Download the wheel into the SAME temp dir, then verify the SAME file we
# downloaded (no re-download between verify and install: no TOCTOU).
curl -fsSL --proto '=https' --tlsv1.2 "$BASE/$WHEEL" \
  -o "$WORK/$WHEEL" || die "cannot fetch $WHEEL"

# Recompute the hash of the downloaded file and compare to the signed value.
# sha256sum -c reads the "<hash>  <name>" line and the exit code is checked
# explicitly; the comparison file is the verified SHA256SUMS line only.
printf '%s\n' "$EXPECTED_LINE" > "$WORK/expected.sha256" \
  || die "could not stage the expected checksum"
( cd "$WORK" && sha256sum -c "$WORK/expected.sha256" ) \
  || die "wheel checksum mismatch — refusing to install"

# Dependency wheelhouse: fetch + verify the RUNTIME-dep wheels.
# The venv install below is --no-index, so a fresh venv cannot reach PyPI for
# cryptography/dnspython (+ cffi/pycparser). The release bundles those dep
# wheels next to the DSM wheel and lists EVERY one in this
# already-minisign-VERIFIED SHA256SUMS — the SAME single trust anchor. We
# download each dependency wheel into $WORK and verify it against that signed
# list, reusing the exact-field selection + `sha256sum -c` pattern used for the
# DSM wheel above (fail closed on a missing/duplicated entry or a hash
# mismatch). No new/unsigned dep source is introduced.
#
# Selection: every SHA256SUMS entry whose name ends in `.whl` and does NOT
# start with `dsm-`. That is the third-party dependency set; it excludes BOTH
# DSM variant wheels — the one we want is already fetched and verified above
# ($WHEEL), and the OTHER DSM variant (e.g. the +soft wheel during a production
# install) is a different DSM build, not a dependency, so the installer must
# not pull it. The non-.whl entries (sdist, install.sh, SHA256SUMS*) are
# likewise skipped. The match is an exact awk FIELD test (not a regex), so a
# `+` in a local-version segment is never a metacharacter.
DEP_WHEELS="$(awk '$2 ~ /\.whl$/ && $2 !~ /^dsm-/ {print $2}' "$WORK/SHA256SUMS")"
for dep in $DEP_WHEELS; do
  # Re-select THIS dep's canonical signed line by exact field match; require
  # exactly one (a missing/duplicated entry fails closed, as above).
  dep_line="$(awk -v w="$dep" '$2 == w {n++; line=$1"  "$2} END {if (n==1) print line}' "$WORK/SHA256SUMS")"
  [ -n "$dep_line" ] \
    || die "signed SHA256SUMS has no single entry for dependency wheel ${dep} — refusing"
  curl -fsSL --proto '=https' --tlsv1.2 "$BASE/$dep" \
    -o "$WORK/$dep" || die "cannot fetch dependency wheel $dep"
  printf '%s\n' "$dep_line" > "$WORK/expected.sha256" \
    || die "could not stage the expected checksum for $dep"
  ( cd "$WORK" && sha256sum -c "$WORK/expected.sha256" ) \
    || die "dependency wheel checksum mismatch for $dep — refusing to install"
done

# systemd units: a `curl | sh` install has no deploy/ folder, so with
# --systemd fetch the unit files from the release too, into ./deploy (this
# working dir, where the unit install below looks), each checked against the
# same signed SHA256SUMS before anything is installed. Exact-field selection
# and `sha256sum -c`, as for the wheels above.
if [ "$SYSTEMD" = 1 ] && [ "$EVAL" = 0 ]; then
  if [ "$CLIENT" = 1 ]; then
    UNIT_FILES="dsm-client.service dsm-client-boot-block.service"
  else
    UNIT_FILES="dsm.service dsm-blocklist-update.sh dsm-blocklist-update.service dsm-blocklist-update.timer"
  fi
  mkdir -p "$WORK/deploy" || die "could not create $WORK/deploy"
  for f in $UNIT_FILES; do
    f_line="$(awk -v w="$f" '$2 == w {n++; line=$1"  "$2} END {if (n==1) print line}' "$WORK/SHA256SUMS")"
    [ -n "$f_line" ] \
      || die "signed SHA256SUMS has no single entry for ${f} — refusing"
    curl -fsSL --proto '=https' --tlsv1.2 "$BASE/$f" -o "$WORK/deploy/$f" \
      || die "cannot fetch $f"
    printf '%s\n' "$f_line" > "$WORK/expected.sha256" \
      || die "could not stage the expected checksum for $f"
    ( cd "$WORK/deploy" && sha256sum -c "$WORK/expected.sha256" ) \
      || die "checksum mismatch for $f — refusing to install"
  done
fi

#  VERIFIED-ARTIFACT GATE PASSED. Only past this line may we run apt/pip/venv.

apt-get update || die "apt-get update failed"
apt-get install -y nftables iproute2 ca-certificates python3-venv \
  || die "could not install base runtime dependencies"
if [ "$EVAL" = 0 ]; then
  # TPM 2.0 runtime stack: the .so.0 provider + the device TCTI. No vendoring.
  apt-get install -y libtss2-esys-3.0.2-0t64 libtss2-tcti-device0t64 \
    || die "could not install the libtss2 TPM runtime stack"
else
  # Eval allows swtpm for software-TPM testing (still NO hardware binding).
  apt-get install -y swtpm \
    || echo "install.sh: WARNING — swtpm not installed; software-TPM eval may not work." >&2
fi

# Dedicated venv keeps the wheel out of system Python.
python3 -m venv "$VENV" || die "could not create the venv at $VENV"
# No pip upgrade: it would come from PyPI, outside the signature check. The
# venv's own pip installs the local wheelhouse (checked on 3.13 and 3.14).
# --no-index + --find-links restricts the install to the local wheelhouse: the
# verified DSM wheel PLUS the dependency wheels downloaded and checksum-verified
# above (cryptography/dnspython + cffi/pycparser). pip resolves every
# runtime dep from $WORK and never reaches the network.
"$VENV/bin/pip" install --no-index --find-links "$WORK" "$WORK/$WHEEL" \
  || die "wheel install failed"
ln -sf "$VENV/bin/dsm" /usr/local/bin/dsm || die "could not symlink dsm into /usr/local/bin"

# tss group grants /dev/tpmrm0 access; unit install is production-only.
if [ "$EVAL" = 0 ]; then
  getent group tss >/dev/null 2>&1 || groupadd --system tss || die "could not create the tss group"
  echo "Note: the dsm daemon must be in the 'tss' group to reach /dev/tpmrm0." >&2
  echo "      deploy/dsm.service and deploy/dsm-client.service set SupplementaryGroups=tss already." >&2
  if [ "$SYSTEMD" = 1 ] && [ "$CLIENT" = 0 ]; then
    UNIT_SRC=""
    # ./deploy (in $WORK) holds the copies just checked against the signed
    # SHA256SUMS: they win over an older /opt/dsm/deploy.
    for c in ./deploy/dsm.service /opt/dsm/deploy/dsm.service; do
      [ -f "$c" ] && { UNIT_SRC="$c"; break; }
    done
    if [ -n "$UNIT_SRC" ]; then
      install -m 0644 "$UNIT_SRC" /etc/systemd/system/dsm.service \
        || die "could not install dsm.service"
      # DNS blocklist: the download script, its unit and its daily timer sit
      # next to dsm.service (deploy/GUIDE.md §7h). An older copy of deploy/
      # may not have them; then dsm runs without the daily list download.
      DEPLOY_DIR="$(dirname "$UNIT_SRC")"
      BLOCKLIST=1
      for f in dsm-blocklist-update.sh dsm-blocklist-update.service dsm-blocklist-update.timer; do
        [ -f "$DEPLOY_DIR/$f" ] || BLOCKLIST=0
      done
      if [ "$BLOCKLIST" = 1 ]; then
        install -m 0755 "$DEPLOY_DIR/dsm-blocklist-update.sh" /usr/local/sbin/dsm-blocklist-update \
          || die "could not install dsm-blocklist-update"
        install -m 0644 "$DEPLOY_DIR/dsm-blocklist-update.service" \
          "$DEPLOY_DIR/dsm-blocklist-update.timer" /etc/systemd/system/ \
          || die "could not install the DNS block list timer"
        # The unit can see and write only this folder, so it must exist. Not
        # fatal: daemon-reload below must still run.
        if ! (umask 077; install -d -m 0700 /opt/mtun/dns); then
          echo "install.sh: WARNING — could not create /opt/mtun/dns; the daily list download stays off (deploy/GUIDE.md §7h)." >&2
          BLOCKLIST=0
        fi
      else
        echo "install.sh: WARNING — the DNS block list files are not in $DEPLOY_DIR; skipping the daily list download (deploy/GUIDE.md §7h)." >&2
      fi
      systemctl daemon-reload || die "systemctl daemon-reload failed"
      if [ "$BLOCKLIST" = 1 ]; then
        systemctl enable --now dsm-blocklist-update.timer \
          || die "could not enable dsm-blocklist-update.timer"
        # Download the default list once now, so blocking works from dsm's
        # first start. Through the unit, so this run has the same sandbox as
        # the daily ones (it cannot read DSM's keys or root's ~/.curlrc). Not
        # fatal: the timer tries again every day.
        systemctl start dsm-blocklist-update.service \
          || echo "install.sh: WARNING — could not download the DNS block lists now; the daily timer tries again (journalctl -u dsm-blocklist-update, deploy/GUIDE.md §7h)." >&2
      fi
      echo "Installed dsm.service. Enable it with: sudo systemctl enable dsm. Start it once dsm init is done and its allowlist has a client CN (deploy/GUIDE.md §4, §5)." >&2
      echo "Give --install-unit to the first dsm init command: it writes the file this unit reads at start (deploy/GUIDE.md §3e)." >&2
    else
      echo "install.sh: WARNING — --systemd requested but deploy/dsm.service not found locally; skipping unit install." >&2
    fi
  elif [ "$SYSTEMD" = 1 ] && [ "$CLIENT" = 1 ]; then
    # A client gets only the client unit: never dsm.service (it runs DSM as
    # a server) and never the server's DNS block list download.
    UNIT_SRC=""
    for c in ./deploy/dsm-client.service /opt/dsm/deploy/dsm-client.service; do
      [ -f "$c" ] && { UNIT_SRC="$c"; break; }
    done
    if [ -n "$UNIT_SRC" ]; then
      install -m 0644 "$UNIT_SRC" /etc/systemd/system/dsm-client.service \
        || die "could not install dsm-client.service"
      # The block that holds from boot until DSM starts. The client unit
      # pulls it in, so it is enabled with it.
      install -m 0644 "$(dirname "$UNIT_SRC")/dsm-client-boot-block.service" \
        /etc/systemd/system/dsm-client-boot-block.service \
        || die "could not install dsm-client-boot-block.service"
      systemctl daemon-reload || die "systemctl daemon-reload failed"
      echo "Installed dsm-client.service and dsm-client-boot-block.service. Enable it with: sudo systemctl enable dsm-client" >&2
      echo "Give --install-unit to the first dsm init command: it writes the file this unit reads at start (deploy/GUIDE.md §3e)." >&2
      echo "Start it only after the server has this client's CN (deploy/GUIDE.md §4); until then it blocks all traffic, SSH too. Then: sudo systemctl start dsm-client" >&2
    else
      echo "install.sh: WARNING — --systemd --client requested but deploy/dsm-client.service not found locally; skipping unit install." >&2
    fi
  fi
elif [ "$SYSTEMD" = 1 ]; then
  echo "install.sh: WARNING — --systemd is ignored in --eval mode (no production unit installed)." >&2
fi

if [ "$EVAL" = 1 ]; then
  echo "Eval install complete (EVALUATION ONLY). Try: sudo dsm init client" >&2
elif [ "$CLIENT" = 1 ]; then
  echo "Install complete. Next: sudo dsm init client" >&2
else
  echo "Install complete. Next: sudo dsm init server" >&2
fi
