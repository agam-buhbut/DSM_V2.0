"""Verify the nftables templates ship as package data.

Checks:
  1. All three .conf files are importlib.resources-accessible from
     dsm.net._templates (fails before the templates are moved there).
  2. NFTablesManager / PreHandshakeKillSwitch still render rules
     correctly after the move (regression guard — does not mock anything).
"""

from __future__ import annotations

import importlib.resources as r
import re

from dsm.net.nftables import (
    NFTablesManager,
    PreHandshakeKillSwitch,
    ServerRateLimitManager,
)

_PLACEHOLDER_RE = re.compile(r"\{SERVER_IP\}|\{SERVER_PORT\}|\{TUN_NAME\}|\{IP_PROTO\}")

V4_IP = "198.51.100.1"
PORT = 51820


# --------------------------------------------------------------------------- #
# importlib.resources accessibility — this is the primary gate
# --------------------------------------------------------------------------- #
def test_templates_resolve_from_package() -> None:
    from dsm.net import _templates

    for name in ("nftables.conf", "server.conf", "pre_handshake.conf"):
        txt = (r.files(_templates) / name).read_text(encoding="utf-8")
        assert (
            "table inet" in txt or "chain" in txt
        ), f"{name} does not look like an nftables ruleset"


# --------------------------------------------------------------------------- #
# Render regression after move — no mocking, real template content
# --------------------------------------------------------------------------- #
def test_nftablesmanager_render_still_works_after_move() -> None:
    rendered = NFTablesManager(V4_IP, PORT, tun_name="mtun0")._render()
    assert V4_IP in rendered
    assert str(PORT) in rendered
    assert "mtun0" in rendered
    assert _PLACEHOLDER_RE.search(rendered) is None


def test_prehandshake_render_still_works_after_move() -> None:
    rendered = PreHandshakeKillSwitch(V4_IP, PORT)._render()
    assert V4_IP in rendered
    assert str(PORT) in rendered
    assert _PLACEHOLDER_RE.search(rendered) is None


def test_server_ratelimit_render_still_works_after_move() -> None:
    rendered = ServerRateLimitManager(PORT)._render()
    assert str(PORT) in rendered
    assert "{SERVER_PORT}" not in rendered
