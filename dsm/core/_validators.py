"""Compiled regex patterns shared by config + net subsystems.

Two distinct patterns, each load-bearing:

* :data:`DSM_TUN_NAME_RE` — strict. Used to validate ``tun_name`` at
  config load and at every site that interpolates the TUN name into a
  shell/nftables command (`MasqueradeManager`, the nftables template
  renderer, etc.). The character class is intentionally narrow
  (alphanumerics + ``-`` + ``_``) so that even if a future code path
  forgets to validate, attacker-controlled TUN names cannot escape the
  interpolation.
* :data:`LINUX_IFACE_NAME_RE` — broader. Used by
  :mod:`dsm.net.tunnel` when validating interface names loaded from a
  *persisted* IPv6-state file at restart. That file describes interfaces
  the kernel created (so ``.`` and ``\\-`` are legal — virtual /vlan
  separators) and we must accept whatever the kernel will accept. Never
  use this for dsm-issued names.
"""

from __future__ import annotations

import re

# Strict pattern for dsm-issued interface names (config.tun_name).
DSM_TUN_NAME_RE: re.Pattern[str] = re.compile(r"^[a-zA-Z0-9_-]{1,15}$")

# Broader pattern for arbitrary kernel-created interface names parsed
# from persisted state. Allows '.' (vlan separator) and '\-' (literal -
# also already permitted by the strict pattern; included here to keep
# the character class explicit when the historical regex was written).
LINUX_IFACE_NAME_RE: re.Pattern[str] = re.compile(r"^[a-zA-Z0-9_.\-]{1,15}$")
