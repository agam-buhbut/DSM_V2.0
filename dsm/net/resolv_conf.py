"""Client-side /etc/resolv.conf swap.

On tunnel up we replace the system resolver configuration with a single
``nameserver`` entry pointing at the server's TUN address, so every DNS
query the host generates travels through the tunnel and hits the server's
pinned DoH/DoT proxy. On tunnel down we put the original file (or symlink)
back exactly as we found it.

Without this the kill switch (which blocks port 53 on non-TUN interfaces)
turns every DNS query into a timeout — the host keeps asking its old
resolver and nftables keeps silently dropping it.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from dsm.core.atomic_io import atomic_write

log = logging.getLogger(__name__)

RESOLV_CONF = Path("/etc/resolv.conf")

# Persistent backup of the operator's REAL resolv.conf, written on the first
# apply over a non-dsm file. Survives a crash so a restart that finds the
# dsm-managed file (restore never ran) can still recover the true original.
RESOLV_BACKUP = Path("/var/lib/dsm/resolv.conf.orig")

# Marker that identifies a file WE wrote. If apply() reads this back as the
# "current" file (after a crash), it must NOT treat that as the original.
_DSM_MARKER = b"# Managed by dsm"

# A backup file may hold either the original resolv.conf CONTENTS (a regular
# file was replaced) or — when the original was a symlink (systemd-resolved /
# NetworkManager hosts) — this sentinel line recording the link target so a
# crash-restart or teardown can RECREATE the symlink instead of losing it.
_SYMLINK_SENTINEL = b"# dsm-resolv-symlink -> "


def parse_symlink_backup(data: bytes) -> str | None:
    """Return the symlink target if ``data`` is a symlink-sentinel backup.

    Returns ``None`` when ``data`` is ordinary backed-up file contents.
    """
    if data.startswith(_SYMLINK_SENTINEL):
        return (
            data[len(_SYMLINK_SENTINEL) :].split(b"\n", 1)[0].decode(errors="replace")
        )
    return None


class ResolvConfManager:
    """Own /etc/resolv.conf for the lifetime of the VPN session."""

    def __init__(self, nameserver: str) -> None:
        self._nameserver = nameserver
        self._original_contents: bytes | None = None
        self._original_symlink_target: str | None = None
        self._applied = False

    @staticmethod
    def _load_backup() -> bytes | None:
        try:
            if RESOLV_BACKUP.exists():
                return RESOLV_BACKUP.read_bytes()
        except OSError as e:
            log.warning("could not read resolv.conf backup: %s", e)
        return None

    @staticmethod
    def _save_backup(contents: bytes) -> None:
        # Only write the backup once — never overwrite a good backup with a
        # later (possibly dsm-managed) capture.
        if RESOLV_BACKUP.exists():
            return
        try:
            atomic_write(RESOLV_BACKUP, contents, mode=0o600, mkdir=True)
        except OSError as e:
            log.warning("could not persist resolv.conf backup: %s", e)

    @staticmethod
    def _save_backup_symlink(target: str) -> None:
        # Durably record that the original was a symlink pointing at ``target``
        # so restore can recreate it. Write-once, like _save_backup.
        if RESOLV_BACKUP.exists():
            return
        try:
            atomic_write(
                RESOLV_BACKUP,
                _SYMLINK_SENTINEL + target.encode() + b"\n",
                mode=0o600,
                mkdir=True,
            )
        except OSError as e:
            log.warning("could not persist resolv.conf symlink backup: %s", e)

    def _recover_from_backup(self) -> None:
        """Load the persistent backup into the right in-memory field.

        A backup can hold either a symlink target (sentinel) or ordinary file
        contents; route each to the field remove() acts on.
        """
        data = self._load_backup()
        if data is None:
            return
        target = parse_symlink_backup(data)
        if target is not None:
            self._original_symlink_target = target
        else:
            self._original_contents = data

    def apply(self) -> None:
        """Replace resolv.conf with a single-nameserver file.

        Captures the prior state (symlink target or file contents) so
        teardown can restore exactly what was there. The swap itself
        goes through ``atomic_write`` — a sibling tempfile gets the new
        contents, then ``os.rename`` replaces the destination atomically.
        rename(2) overwrites both regular files AND symlinks in a single
        syscall, so there is no window where /etc/resolv.conf is absent
        between capturing the original and the new file appearing.

        M-NET-1 WARNING: on systems running NetworkManager or systemd-
        resolved, our /etc/resolv.conf swap is fighting against another
        component that ALSO claims the file. systemd-resolved keeps
        listening on 127.0.0.53:53 (with libc resolvers reaching it via
        nsswitch.conf even when /etc/resolv.conf says otherwise) and
        NetworkManager rewrites /etc/resolv.conf on every DHCP renew
        (typically every few hours on consumer networks), restoring its
        own nameserver and locking the user out of DNS until dsm is
        restarted. We log a one-shot warning at apply() so operators
        can disable the conflicting service (`systemctl disable
        systemd-resolved`, `nmcli connection modify ... ipv4.dns-priority
        -1`) before deploying. The kill switch's port-53 block prevents
        leaks either way — this warning is about usability, not security.
        """
        if self._applied:
            return

        # M-NET-1 detection: warn if a known DNS-managing service is
        # running. Detection is best-effort — we don't fail startup.
        for path in ("/run/systemd/resolve/stub-resolv.conf", "/run/NetworkManager"):
            if Path(path).exists():
                log.warning(
                    "detected %s — DNS-managing service may overwrite "
                    "/etc/resolv.conf mid-session (M-NET-1). DSM's kill "
                    "switch will block the resulting plaintext queries; "
                    "to avoid lost DNS, disable the conflicting service.",
                    path,
                )
                break

        if RESOLV_CONF.is_symlink():
            try:
                self._original_symlink_target = os.readlink(RESOLV_CONF)
                # Persist the target durably: a crash before remove() must be
                # able to recreate the symlink, not lose it (B2).
                self._save_backup_symlink(self._original_symlink_target)
            except OSError:
                # Race: symlink was replaced between is_symlink() and
                # readlink. Fall through to the regular-file branch so
                # apply() still completes; the original target (if any)
                # is lost from our perspective but the new state is honored.
                self._original_symlink_target = None
                if RESOLV_CONF.exists():
                    try:
                        self._original_contents = RESOLV_CONF.read_bytes()
                    except OSError:
                        self._original_contents = None
        elif RESOLV_CONF.exists():
            try:
                current: bytes | None = RESOLV_CONF.read_bytes()
            except OSError:
                # File disappeared/errored between exists() and read; treat
                # as "no original to restore" — same as the never-existed
                # branch (remove() will unlink our override). MUST NOT fall
                # into the capture/backup logic with b"": that would both
                # write an empty resolv.conf on restore AND poison the
                # write-once persistent backup with b"", permanently losing
                # the real original on a later crash-restart.
                current = None
            if current is None:
                self._original_contents = None
            elif current.startswith(_DSM_MARKER):
                # Phase 1.5: this is OUR file (a prior run crashed before
                # restore). Do NOT capture it as the original — recover the
                # real original (contents OR symlink target) from the backup.
                self._recover_from_backup()
            else:
                self._original_contents = current
                # First apply over a genuine file: persist it so a later
                # crash can still recover it.
                self._save_backup(current)
        # If the file simply didn't exist, both fields stay None and we
        # remove our override on teardown instead of restoring anything.

        payload = (
            f"# Managed by dsm while the VPN is up — original restored on teardown.\n"
            f"nameserver {self._nameserver}\n"
            f"options edns0 trust-ad\n"
        ).encode()
        # atomic_write: tmpfile -> fchmod -> fsync -> rename. The final
        # rename overwrites any existing file OR symlink at RESOLV_CONF
        # atomically — no transient absence.
        atomic_write(RESOLV_CONF, payload, mode=0o644, mkdir=False)

        self._applied = True
        log.info("resolv.conf -> nameserver %s", self._nameserver)

    def remove(self) -> None:
        """Restore the original resolv.conf (symlink or contents).

        Audit L-AUDIT-3: use atomic rename (or symlinkat + rename) so
        /etc/resolv.conf is never absent during teardown. The previous
        ``unlink → symlink`` sequence opened a microsecond window
        where libc resolvers from co-running processes would hit
        ENOENT. atomic_write already does tmpfile→rename for the
        file path; for the symlink case we create the symlink at a
        temp path then rename it over the target.
        """
        if not self._applied:
            return

        restored = False
        try:
            if (
                self._original_symlink_target is None
                and self._original_contents is None
            ):
                # Phase 1.5: nothing captured in-memory — prefer the persistent
                # backup (a crash-restart manager that found a dsm-managed file).
                self._recover_from_backup()
            if self._original_symlink_target is not None:
                # Symlink restore: create a sibling temp symlink, then
                # rename it over RESOLV_CONF. rename(2) replaces
                # files/symlinks atomically — never an ENOENT window.
                tmp = RESOLV_CONF.with_suffix(RESOLV_CONF.suffix + ".dsm-restore")
                # If a stale temp exists from a previous crash, unlink it.
                try:
                    tmp.unlink()
                except FileNotFoundError:
                    pass
                os.symlink(self._original_symlink_target, tmp)
                os.rename(tmp, RESOLV_CONF)
                restored = True
            elif self._original_contents is not None:
                # atomic_write uses tmpfile → fchmod → fsync → rename;
                # already atomic over both files AND symlinks.
                atomic_write(
                    RESOLV_CONF,
                    self._original_contents,
                    mode=0o644,
                    mkdir=False,
                )
                restored = True
            else:
                # No original to restore — explicitly remove our file.
                # Brief absence here matches the pre-apply state by
                # definition (file didn't exist then either).
                try:
                    RESOLV_CONF.unlink()
                except FileNotFoundError:
                    pass
                restored = True
        except OSError as e:
            log.error("failed to restore resolv.conf: %s", e)
        finally:
            self._applied = False
            # B2: only drop the persistent backup and clear the captured
            # original AFTER a restore actually succeeded. If the restore
            # write raised, keep both so the crash-path cleanup (or a retry)
            # can still recover the true original instead of losing it.
            if restored:
                self._original_contents = None
                self._original_symlink_target = None
                # Phase 1.5: the backup has served its purpose; drop it so the
                # next apply over a genuine file captures a fresh original.
                try:
                    RESOLV_BACKUP.unlink(missing_ok=True)
                except OSError:
                    pass
                log.info("resolv.conf restored")
            else:
                log.error(
                    "resolv.conf restore failed — preserving backup %s",
                    RESOLV_BACKUP,
                )
