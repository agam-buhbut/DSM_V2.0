#!/bin/sh
# Download the DNS block lists named in <config dir>/dns/sources.txt into
# <config dir>/dns/block/, for the DSM server's DNS blocklist.
#
# DSM itself never downloads anything. It only reads the files this script
# leaves in block/, and sees changes by itself within 5 minutes, so this
# script never signals dsm (SIGHUP would stop it).
#
# Usage: dsm-blocklist-update [CONFIG_DIR]      (default: /opt/mtun)
# Run once a day by dsm-blocklist-update.timer, and once by install.sh.
set -eu
umask 077

CONFIG_DIR="${1:-/opt/mtun}"
DNS_DIR="$CONFIG_DIR/dns"
BLOCK_DIR="$DNS_DIR/block"
SOURCES="$DNS_DIR/sources.txt"
# The same limit DSM puts on one list file: 64 MiB.
MAX_BYTES=67108864
# The default list (StevenBlack/hosts: ads and malware), written into a new
# sources.txt (deploy/GUIDE.md §7h). The owner can replace it: this is the
# only place the URL is written, so changing this one line is enough.
DEFAULT_SOURCE="https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"

warn() { echo "dsm-blocklist-update: $*" >&2; }
die() { warn "$*"; exit 1; }

# curl before 8.4.0 ignores --max-filesize when the server sends no length.
# So the system also stops any file this script or curl writes at the same
# size (ulimit counts 512-byte blocks): curl is stopped, the download fails,
# the temporary file goes and the list from before stays.
ulimit -f $((MAX_BYTES / 512 + 1)) || die "cannot set the file size limit"

[ "$(id -u)" = "0" ] || die "must run as root: the list files must belong to the uid dsm runs as"
command -v curl >/dev/null 2>&1 || die "curl is not installed"

mkdir -p "$BLOCK_DIR" || die "cannot create $BLOCK_DIR"
chmod 700 "$DNS_DIR" "$BLOCK_DIR" || die "cannot set mode 700 on $DNS_DIR and $BLOCK_DIR"

if [ ! -e "$SOURCES" ] && [ ! -L "$SOURCES" ]; then
  {
    echo "# DNS block lists for DSM: one https:// URL per line."
    echo "# dsm-blocklist-update downloads each one into block/ once a day."
    echo "# Put a # in front of a URL to stop using that list."
    echo "# Default: StevenBlack/hosts, ads and malware (deploy/GUIDE.md 7h)."
    echo "$DEFAULT_SOURCE"
  } >"$SOURCES" || die "cannot write $SOURCES"
fi
if [ ! -f "$SOURCES" ] || [ -L "$SOURCES" ]; then
  die "$SOURCES must be a plain file, not a link"
fi

failed=0
keep=" "
tmp=""
# Never leave a half-written download behind, even if the run is stopped.
trap 'rm -f "$tmp"' EXIT
trap 'exit 1' HUP INT TERM
while IFS= read -r line || [ -n "$line" ]; do
  url=$(printf '%s\n' "$line" | sed -e 's/#.*//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
  [ -n "$url" ] || continue
  case "$url" in
    https://*) ;;
    *)
      warn "skipped a list that does not start with https://: $url"
      failed=1
      continue
      ;;
  esac
  name="fetched-$(printf '%s' "$url" | sha256sum | cut -c1-16).txt"
  keep="$keep$name "
  tmp=$(mktemp "$BLOCK_DIR/.fetch.XXXXXXXX") || die "cannot create a temporary file in $BLOCK_DIR"
  # --globoff: the URL is data; curl must not read [ ] { } in it as a pattern.
  if curl --fail --silent --show-error --location --globoff \
      --proto '=https' --proto-redir '=https' --tlsv1.2 \
      --max-filesize "$MAX_BYTES" --max-time 300 \
      --output "$tmp" "$url" </dev/null \
    && [ "$(wc -c <"$tmp")" -le "$MAX_BYTES" ]; then
    chmod 600 "$tmp"
    mv -f "$tmp" "$BLOCK_DIR/$name"
  else
    rm -f "$tmp"
    warn "could not download $url; the copy from before, if any, stays"
    failed=1
  fi
done <"$SOURCES"

# A list whose URL left sources.txt goes too. Only fetched-*.txt files:
# lists you put in block/ yourself are never touched.
for f in "$BLOCK_DIR"/fetched-*.txt; do
  [ -e "$f" ] || continue
  case "$keep" in
    *" ${f##*/} "*) ;;
    *) rm -f "$f" ;;
  esac
done
exit "$failed"
