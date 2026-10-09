"""run_server keeps one SourceLimiter for the whole run and hands it to every
accept."""

from __future__ import annotations

from dataclasses import replace
from typing import Any
from unittest.mock import patch

from dsm.net.handshake_gate import SourceLimiter
from dsm.server import _drive_fsm_to_idle, run_server
from tests.test_server_dns_fatal import _base_patches, _server_config


async def _session(*args: Any) -> None:
    _drive_fsm_to_idle(args[1])  # what a finished session leaves


async def test_every_udp_accept_gets_the_same_limiter() -> None:
    seen: list[Any] = []
    captured: dict[str, Any] = {}

    async def _accept(*args: Any, **_k: Any) -> tuple[Any, Any, Any]:
        seen.append(args[7] if len(args) > 7 else None)
        if len(seen) == 1:
            return object(), b"\x01" * 32, args[5]
        args[6].set()  # process_shutdown
        return None, None, args[5]

    with (
        _base_patches(_accept, captured),
        patch("dsm.server._run_one_session", new=_session),
    ):
        rc = await run_server(replace(_server_config(), dns_blocklist=False))

    assert rc == 0
    assert len(seen) == 2
    assert isinstance(seen[0], SourceLimiter)
    assert seen[0] is seen[1]
