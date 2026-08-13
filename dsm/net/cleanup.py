"""Idempotent host-state cleanup for crash / forced-stop recovery.

Run by systemd ``ExecStopPost=`` on BOTH clean and crash stops so a SIGKILL /
OOM that bypasses the in-process AsyncExitStack unwind does not leave the
host with a kill switch up, a dead resolv.conf, a stale table-100 route /
ip rule, or modified sysctls. Every operation is best-effort: a missing
table / rule / file is fine — the goal is to converge on a clean state.

GAP (crash-only restore precision): the in-process teardown restores the
EXACT prior sysctl values it captured (see ``dsm.core.sysctl.SysctlOverride``)
and the EXACT per-interface IPv6 state persisted at apply time
(``/run/dsm/ipv6_state.json``, Task 1.4). When that unwind is bypassed by a
SIGKILL/OOM, those in-memory captures are gone. This module is the COARSE
fallback for that path: it restores ``net.ipv4.ip_forward`` and the global
``disable_ipv6`` knobs to their safe boot defaults (0 / 0) rather than the
operator's true prior values. ``rp_filter`` and the ``send_redirects`` /
``accept_redirects`` knobs are NOT persisted to disk at apply time, so they
cannot be restored here at all — they are left as the daemon set them. This
is acceptable because the safe defaults are exactly what a fresh boot would
have, and the precise restore still happens whenever the clean teardown runs.
"""

from __future__ import annotations

import logging
import subprocess

from dsm.core.atomic_io import atomic_write
from dsm.net.forwarding import MasqueradeManager
from dsm.net.nftables import PreHandshakeKillSwitch
from dsm.net.resolv_conf import (
    DSM_MARKER,
    RESOLV_BACKUP,
    RESOLV_CONF,
    atomic_symlink_restore,
    parse_symlink_backup,
)
from dsm.net.transport._fwmark import SO_MARK_VALUE as FWMARK

log = logging.getLogger(__name__)

# Every inet table dsm can create. The two managers below own their names;
# NFTablesManager (full kill switch) and ServerRateLimitManager use literals.
# Keep in sync if a new table is added.
_DSM_TABLES = (
    PreHandshakeKillSwitch.TABLE_NAME,
    "dsm_killswitch",
    "dsm_dns_leak",
    "dsm_server_ratelimit",
    MasqueradeManager.TABLE,
)


def _best_effort(cmd: list[str]) -> None:
    """Run ``cmd`` swallowing every failure. Idempotency means a missing
    table / rule / binary is a success from cleanup's point of view.
    """
    try:
        subprocess.run(cmd, capture_output=True, timeout=5, check=False)
    except (FileNotFoundError, subprocess.SubprocessError) as e:
        log.debug("cleanup cmd %s: %s", " ".join(cmd), type(e).__name__)


def cleanup_host_state() -> None:
    """Remove every host mutation dsm could have made. Idempotent."""
    # Delete-by-name is stateless; no manager instance needed.
    for table in _DSM_TABLES:
        _best_effort(["nft", "delete", "table", "inet", table])
    # Flush the policy-route table and delete the not-fwmark ip rule.
    # The rule is added with priority 10 by TunDevice.configure; delete by
    # the same selector so we hit exactly that rule and nothing else.
    _best_effort(["ip", "route", "flush", "table", "100"])
    _best_effort(
        [
            "ip",
            "rule",
            "del",
            "not",
            "fwmark",
            str(FWMARK),
            "table",
            "100",
            "priority",
            "10",
        ]
    )
    _restore_resolv_conf()
    # Restore the global IPv6 + forwarding sysctls to safe defaults.
    # Coarse crash-path fallback only — see the module docstring GAP note.
    for key, value in (
        ("net.ipv6.conf.all.disable_ipv6", "0"),
        ("net.ipv6.conf.default.disable_ipv6", "0"),
        ("net.ipv4.ip_forward", "0"),
    ):
        _best_effort(["sysctl", "-w", f"{key}={value}"])
    log.info("dsm host-state cleanup complete")


def _restore_resolv_conf() -> None:
    """Reinstate the operator's resolver config without an in-memory manager.

    Mirrors ``ResolvConfManager.remove``'s persistent-backup branch: if the
    write-once backup from Task 1.5 exists, restore it atomically and drop it;
    otherwise, only remove the file if it is one dsm wrote (identified by the
    marker) so a genuine operator file is never clobbered.
    """
    try:
        if RESOLV_BACKUP.exists():
            data = RESOLV_BACKUP.read_bytes()
            target = parse_symlink_backup(data)
            if target is not None:
                # Original was a symlink (systemd-resolved / NetworkManager):
                # recreate it atomically rather than writing its target text
                # as file contents (B2).
                atomic_symlink_restore(target)
            else:
                atomic_write(RESOLV_CONF, data, mode=0o644, mkdir=False)
            RESOLV_BACKUP.unlink(missing_ok=True)
            log.info("restored resolv.conf from backup")
        elif RESOLV_CONF.exists():
            # No backup: if the live file is dsm-managed, remove it so the
            # host falls back to DHCP / NetworkManager regeneration. A
            # non-dsm file is the operator's own and is left untouched.
            head = RESOLV_CONF.read_bytes()[: len(DSM_MARKER)]
            if head.startswith(DSM_MARKER):
                RESOLV_CONF.unlink(missing_ok=True)
    except OSError as e:
        log.warning("resolv.conf cleanup failed: %s", e)
