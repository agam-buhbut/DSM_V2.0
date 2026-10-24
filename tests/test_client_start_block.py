"""The client's start (R1): the kill switch goes up first, before the cert
materials load and the server-name lookup. Mistakes exit 1 and take it down
by hand (owner ruling Q1) but keep it under dsm-client.service
(re-decision 3). A start the clock or the network holds up keeps it and
tries again, 1 s doubling to 30 s, said once. While a date holds the start
the time daemon may sync; while DSM looks a name up, port 53 opens for it.

run_client runs with the host faked, as in tests/test_client_fail_closed.py.
The run ends right after the start, at the passphrase step, which fails (a
wrong or empty passphrase: exit 1). Each kill-switch step is written to
``events`` with the addresses it allows ("none" before a lookup) and its
openings ("+dns", "+ntp"). Waits go through a fake _wait_or_stop that
records them and can stop DSM.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Sequence
from contextlib import ExitStack
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

import dsm.client as client_mod
from dsm.crypto.auth_loader import AuthMaterialsError, AuthMaterialsTimeError
from dsm.net.ntp_opening import NtpOpening
from tests.test_client_fail_closed import _config, _FakeStore, _Materials

NAME = "vpn.example.org"
NTP = NtpOpening(uid=991, servers=("192.0.2.123",))
STALE = AuthMaterialsTimeError("CRL at /opt/mtun/dsm_ca.crl is past its next update")


class _Start:
    def __init__(self, endpoint_file: Path) -> None:
        self.endpoint_file = endpoint_file
        self.events: list[str] = []
        self.waits: list[float] = []
        self.stops: list[asyncio.Event] = []
        # Per materials load, in order: None (it works) or the error it raises.
        self.loads: list[Exception | None] = []
        self.load_kwargs: list[dict[str, Any]] = []
        # Per lookup, in order: the address found, or the error it raises.
        self.lookups: list[str | Exception] = []
        # The lookup opens port 53 first, as the real one does.
        self.open_lookup = False
        self.stop_in_lookup = False
        # The user stops DSM during this wait (1 = the first); None: never.
        self.stop_at_wait: int | None = None
        # A kill-switch apply with this label fails (an nft error).
        self.fail_apply_for: str | None = None
        self.ntp: NtpOpening | None = None
        self.synced: bool | None = True

    def _block(self) -> type:
        start = self

        class _Block:
            def __init__(
                self,
                server_ips: str | Sequence[str] | None,
                _port: int,
                *,
                resolvers: Sequence[str] = (),
                ntp: NtpOpening | None = None,
            ) -> None:
                ips = (
                    [server_ips]
                    if isinstance(server_ips, str)
                    else list(server_ips or ())
                )
                self.label = ",".join(ips) or "none"
                if resolvers:
                    self.label += " +dns"
                if ntp is not None:
                    self.label += " +ntp"

            def apply(self) -> None:
                start.events.append(f"block {self.label}")
                if self.label == start.fail_apply_for:
                    raise RuntimeError("nft: device or resource busy")

            def remove(self) -> None:
                start.events.append(f"unblock {self.label}")

        return _Block

    def _load(self, _config: object, **kwargs: Any) -> _Materials:
        self.events.append("materials")
        self.load_kwargs.append(kwargs)
        error = self.loads.pop(0) if self.loads else None
        if error is not None:
            raise error
        return _Materials()

    async def _lookup(self, _name: str, _port: int, **kwargs: Any) -> str:
        if self.open_lookup:
            kwargs["before_lookup"](["192.0.2.53"])
        self.events.append("lookup")
        if self.stop_in_lookup:
            self.stops[0].set()
            await asyncio.Event().wait()
        found = self.lookups.pop(0) if self.lookups else "10.0.0.1"
        if isinstance(found, Exception):
            raise found
        return found

    async def _wait(self, shutdown: asyncio.Event, delay: float) -> bool:
        self.waits.append(delay)
        self.events.append("wait")
        if self.stop_at_wait == len(self.waits):
            shutdown.set()
            return True
        return False

    def _stores(self, *_a: object, **_k: object) -> bool:
        self.events.append("stores")
        return False  # a wrong or empty passphrase: the run ends here, exit 1

    async def run(self, *, stop_keeps_block: bool = False, **config: Any) -> int:
        patches = [
            patch("tuncore.harden_process"),
            patch("dsm.core.hardening.set_process_nondumpable"),
            patch("dsm.crypto.attest_gate.enforce_attest_backend_policy"),
            patch("dsm.client.setup_signal_handlers", self.stops.append),
            patch("dsm.client.PreHandshakeKillSwitch", self._block()),
            patch("dsm.client.load_cert_materials", self._load),
            patch("dsm.client._wait_or_stop", self._wait),
            patch("dsm.crypto._stores.load_daemon_stores", self._stores),
            patch("dsm.client.KeyStore", _FakeStore),
            patch("dsm.client.AttestStore", _FakeStore),
            patch("dsm.client.time_daemon_opening", lambda: self.ntp),
            patch("dsm.client.ntp_synchronized", lambda: self.synced),
            patch("dsm.client._SERVER_ENDPOINT_FILE", self.endpoint_file),
        ]
        if "server_ip" in config:  # a server name: fake its lookup
            patches.append(patch("dsm.client._resolve_server_endpoint", self._lookup))
        with ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            return await asyncio.wait_for(
                client_mod.run_client(
                    _config(**config), stop_keeps_block=stop_keeps_block
                ),
                timeout=10,
            )


@pytest.fixture
def start(tmp_path: Path) -> _Start:
    return _Start(tmp_path / "server-endpoint.json")


def _errors(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR]


async def test_the_block_goes_up_before_the_cert_materials_load(start: _Start) -> None:
    # Also D1's first row: a passphrase that does not unlock, by hand, exits 1
    # and takes the block down.
    rc = await start.run()
    assert rc == 1
    assert start.events == ["block 10.0.0.1", "materials", "stores", "unblock 10.0.0.1"]
    (kwargs,) = start.load_kwargs
    assert kwargs["check_own_dates"] is True
    assert kwargs["clock_synced"] is client_mod._clock_synced


async def test_a_mistake_in_the_materials_exits_1_and_takes_the_block_down(
    start: _Start, caplog: pytest.LogCaptureFixture
) -> None:
    start.loads = [AuthMaterialsError("ca_root_sha256 is required but not set")]
    caplog.set_level(logging.ERROR, logger="dsm")
    rc = await start.run()
    assert rc == 1
    assert start.events == ["block 10.0.0.1", "materials", "unblock 10.0.0.1"]
    assert start.waits == []
    assert _errors(caplog) == [
        "cert auth materials missing or invalid: ca_root_sha256 is required but not set"
    ]


async def test_under_the_unit_a_mistake_keeps_the_block(
    start: _Start, caplog: pytest.LogCaptureFixture
) -> None:
    start.loads = [AuthMaterialsError("cert_file missing at /opt/mtun/device.crt")]
    caplog.set_level(logging.ERROR, logger="dsm")
    rc = await start.run(stop_keeps_block=True)
    assert rc == 1
    assert start.events == ["block 10.0.0.1", "materials"]
    assert client_mod._KEPT_AFTER_START_ERROR in _errors(caplog)


async def test_under_the_unit_a_passphrase_that_does_not_unlock_keeps_the_block(
    start: _Start, caplog: pytest.LogCaptureFixture
) -> None:
    # D1: an empty /etc/dsm/passphrase under dsm-client.service.
    caplog.set_level(logging.ERROR, logger="dsm")
    rc = await start.run(stop_keeps_block=True)
    assert rc == 1
    assert start.events == ["block 10.0.0.1", "materials", "stores"]
    assert client_mod._KEPT_AFTER_START_ERROR in _errors(caplog)


async def test_a_date_problem_keeps_the_block_opens_ntp_and_backs_off(
    start: _Start, caplog: pytest.LogCaptureFixture
) -> None:
    start.loads = [STALE, STALE, None]
    start.ntp = NTP
    caplog.set_level(logging.ERROR, logger="dsm")
    rc = await start.run()
    assert rc == 1  # the passphrase step after it
    assert start.events == [
        "block 10.0.0.1",
        "materials",
        "block 10.0.0.1 +ntp",
        "wait",
        "materials",
        "wait",
        "materials",
        "block 10.0.0.1",  # NTP closed again, in one commit
        "stores",
        "unblock 10.0.0.1",
    ]
    assert start.waits == [1.0, 2.0]
    held = [m for m in _errors(caplog) if "past its next update" in m]
    assert len(held) == 1  # said once, not on every try
    assert "all traffic stays blocked, and DSM tries again" in held[0]


async def test_with_no_time_daemon_to_open_nothing_more_is_opened(
    start: _Start,
) -> None:
    start.loads = [STALE, None]
    rc = await start.run()
    assert rc == 1
    assert start.events == [
        "block 10.0.0.1",
        "materials",
        "wait",
        "materials",
        "stores",
        "unblock 10.0.0.1",
    ]


async def test_a_clock_that_is_not_synchronized_is_named(
    start: _Start, caplog: pytest.LogCaptureFixture
) -> None:
    start.loads = [STALE, None]
    start.synced = False
    caplog.set_level(logging.ERROR, logger="dsm")
    await start.run()
    held = [m for m in _errors(caplog) if "past its next update" in m]
    assert "the clock is not NTP-synchronized" in held[0]


async def test_a_stop_while_it_waits_takes_the_block_down(start: _Start) -> None:
    start.loads = [AuthMaterialsTimeError("this host's cert ran out on 2026-01-01")]
    start.stop_at_wait = 1
    rc = await start.run()
    assert rc == 0
    assert start.events == ["block 10.0.0.1", "materials", "wait", "unblock 10.0.0.1"]


async def test_with_stop_keeps_block_a_stop_while_it_waits_keeps_it(
    start: _Start, caplog: pytest.LogCaptureFixture
) -> None:
    start.loads = [AuthMaterialsTimeError("this host's cert ran out on 2026-01-01")]
    start.stop_at_wait = 1
    caplog.set_level(logging.INFO, logger="dsm")
    rc = await start.run(stop_keeps_block=True)
    assert rc == 0
    assert start.events == ["block 10.0.0.1", "materials", "wait"]
    assert client_mod._KEPT_ON_STOP in [r.getMessage() for r in caplog.records]


async def test_a_name_is_looked_up_behind_a_block_with_no_server_line(
    start: _Start,
) -> None:
    rc = await start.run(server_ip=NAME)
    assert rc == 1
    assert start.events == [
        "block none",
        "materials",
        "lookup",
        "block 10.0.0.1",
        "stores",
        "unblock 10.0.0.1",
    ]


async def test_port_53_opens_only_while_the_lookup_runs(start: _Start) -> None:
    start.open_lookup = True
    start.lookups = [OSError("no address"), "10.0.0.1"]
    rc = await start.run(server_ip=NAME)
    assert rc == 1
    assert start.events == [
        "block none",
        "materials",
        "block none +dns",
        "lookup",
        "block none",  # closed again for the wait
        "wait",
        "block none +dns",
        "lookup",
        "block 10.0.0.1",  # the server's address only
        "stores",
        "unblock 10.0.0.1",
    ]
    assert start.waits == [1.0]


async def test_a_failed_lookup_is_said_once(
    start: _Start, caplog: pytest.LogCaptureFixture
) -> None:
    start.lookups = [OSError("no address"), OSError("no address"), "10.0.0.1"]
    caplog.set_level(logging.INFO, logger="dsm")
    rc = await start.run(server_ip=NAME)
    assert rc == 1
    assert start.waits == [1.0, 2.0]
    held = [
        r
        for r in caplog.records
        if r.getMessage().startswith("could not look up the server name:")
    ]
    assert [r.levelno for r in held] == [logging.ERROR]
    # Only the line for the address found names the server, as before.
    assert not any(
        NAME in r.getMessage()
        for r in caplog.records
        if not r.getMessage().startswith("resolved server hostname")
    )


async def test_a_failed_lookup_with_a_proven_address_uses_it_at_once(
    start: _Start,
) -> None:
    start.endpoint_file.write_text(json.dumps({"name": NAME, "ip": "10.0.0.9"}))
    start.endpoint_file.chmod(0o600)
    start.lookups = [OSError("no address")]
    rc = await start.run(server_ip=NAME)
    assert rc == 1
    assert start.events == [
        "block none",
        "materials",
        "lookup",
        "block 10.0.0.9",
        "stores",
        "unblock 10.0.0.9",
    ]
    assert start.waits == []


async def test_the_lookup_waits_for_the_materials(start: _Start) -> None:
    # No DNS goes out for a start that cannot go on yet.
    start.loads = [STALE, None]
    rc = await start.run(server_ip=NAME)
    assert rc == 1
    assert start.events == [
        "block none",
        "materials",
        "wait",
        "materials",
        "lookup",
        "block 10.0.0.1",
        "stores",
        "unblock 10.0.0.1",
    ]


async def test_a_stop_during_the_lookup_takes_the_lookup_block_down(
    start: _Start,
) -> None:
    start.stop_in_lookup = True
    rc = await start.run(server_ip=NAME)
    assert rc == 0
    assert start.events == ["block none", "materials", "lookup", "unblock none"]


async def test_a_failed_swap_keeps_the_block_up(
    start: _Start, caplog: pytest.LogCaptureFixture
) -> None:
    start.fail_apply_for = "10.0.0.1"
    caplog.set_level(logging.ERROR, logger="dsm")
    with pytest.raises(RuntimeError, match="busy"):
        await start.run(server_ip=NAME)
    # No "unblock none": the lookup-only table stays up (fail closed).
    assert start.events == ["block none", "materials", "lookup", "block 10.0.0.1"]
    assert client_mod._KEPT_AFTER_ERROR in _errors(caplog)


async def test_a_first_block_nft_refuses_is_one_line_and_exit_1(
    start: _Start, caplog: pytest.LogCaptureFixture
) -> None:
    # QA M4: without root, nft raises RuntimeError; that was a traceback.
    start.fail_apply_for = "10.0.0.1"
    caplog.set_level(logging.ERROR, logger="dsm")
    rc = await start.run()
    assert rc == 1
    assert start.events == ["block 10.0.0.1"]
    (record,) = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert record.getMessage().startswith(
        "pre-handshake kill switch could not be installed: nft: device or resource busy"
    )
    assert record.exc_info is None


def test_the_proven_address_survives_a_reboot() -> None:
    assert client_mod._SERVER_ENDPOINT_FILE == Path("/var/lib/dsm/server-endpoint.json")


async def test_under_the_unit_a_stop_during_the_lookup_closes_port_53(
    start: _Start,
) -> None:
    # The block the unit keeps must not keep the lookup's port-53 line (D7).
    start.open_lookup = True
    start.stop_in_lookup = True
    rc = await start.run(stop_keeps_block=True, server_ip=NAME)
    assert rc == 0
    assert start.events == [
        "block none",
        "materials",
        "block none +dns",
        "lookup",
        "block none",
    ]


async def test_under_the_unit_a_stop_while_ntp_is_open_closes_it(
    start: _Start,
) -> None:
    # Nor the time daemon's NTP line (D8).
    start.loads = [STALE]
    start.ntp = NTP
    start.stop_at_wait = 1
    rc = await start.run(stop_keeps_block=True)
    assert rc == 0
    assert start.events == [
        "block 10.0.0.1",
        "materials",
        "block 10.0.0.1 +ntp",
        "wait",
        "block 10.0.0.1",
    ]


async def test_under_the_unit_a_mistake_after_a_date_wait_closes_ntp(
    start: _Start,
) -> None:
    start.loads = [STALE, AuthMaterialsError("cert_file missing")]
    start.ntp = NTP
    rc = await start.run(stop_keeps_block=True)
    assert rc == 1
    assert start.events == [
        "block 10.0.0.1",
        "materials",
        "block 10.0.0.1 +ntp",
        "wait",
        "materials",
        "block 10.0.0.1",
    ]
