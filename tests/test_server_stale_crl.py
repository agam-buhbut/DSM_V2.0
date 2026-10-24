"""A server whose clock is synchronized starts on a stale CRL, with a
WARNING; with a clock that is not, it still refuses (re-decision 4(i), for
both daemons). The loader's side is in test_auth_loader_dates.py."""

from __future__ import annotations

import logging
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from dsm.crypto.auth_loader import AuthMaterialsTimeError
from dsm.server import run_server
from tests.test_server_dns_fatal import (
    _base_patches,
    _FakeMaterials,
    _run_until,
    _server_config,
)


async def test_the_server_asks_the_clock_about_a_stale_crl() -> None:
    captured: dict[str, Any] = {}
    load = MagicMock(return_value=_FakeMaterials())
    with _base_patches(captured), patch("dsm.server.load_cert_materials", load):
        assert await _run_until(_server_config(), captured) == 0
    assert "check_own_dates" not in load.call_args.kwargs
    clock_synced = load.call_args.kwargs["clock_synced"]
    # Only a clear "yes" from timedatectl counts; "no" and "cannot tell"
    # keep today's refusal.
    for answer, synced in ((True, True), (False, False), (None, False)):
        with patch("dsm.server.ntp_synchronized", return_value=answer):
            assert clock_synced() is synced


async def test_a_stale_crl_the_loader_refuses_still_stops_the_server(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.ERROR, logger="dsm")
    stale = AuthMaterialsTimeError(
        "CRL at /opt/mtun/dsm_ca.crl is past its next update "
        "(2026-01-01T00:00:00+00:00). Carry the CA's current CRL here "
        "(deploy/GUIDE.md §7e)"
    )
    captured: dict[str, Any] = {}
    with (
        _base_patches(captured),
        patch("dsm.server.load_cert_materials", side_effect=stale),
    ):
        assert await run_server(_server_config()) == 1
    assert "host" not in captured
    assert [r.getMessage() for r in caplog.records] == [
        f"cert auth materials missing or invalid: {stale}"
    ]
