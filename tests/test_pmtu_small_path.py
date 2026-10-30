"""``pmtu_discover = true`` on a path whose MTU is below 1428 bytes.

DF (IP_PMTUDISC_DO) is only safe where DSM can make its packets smaller. The
server cannot, for any client, and nothing can during the handshake: every
handshake frame is 1428 bytes on the wire. With DF there, the first frame
brings back an ICMP "frag needed", the kernel then refuses every resend with
EMSGSIZE, and the tunnel never comes up (box run, finding #14). So the
server never sets DF, and the client sets it only once the handshake is done.

On the client's data path, a datagram the kernel refuses as too big
(EMSGSIZE) never left the host: it must make auto_mtu check the path at once
and must not count as loss on the link for the auto cap.
"""

from __future__ import annotations

import asyncio
import errno
import itertools
import logging
import socket
import unittest
from collections.abc import Coroutine
from contextlib import ExitStack
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import dsm.server as server_mod
from dsm.core.config import Config
from dsm.core.protocol import LinkReport
from dsm.crypto.handshake import HandshakeError
from dsm.net._addresses import SINGLE_CLIENT_TUNNEL
from dsm.net.transport.udp import UDPTransport
from dsm.session import auto_mtu_loop
from dsm.traffic.autocap import AutoCap
from tests.test_client_shaper_start import (
    _FakeKeys,
    _FakeStore,
    _HostChange,
    _Materials,
    _no_send,
)
from tests.test_client_udp_bind import _UdpBindCase as _ClientBindCase
from tests.test_server_udp_bind import _udp_config
from tests.test_server_udp_bind import _UdpBindCase as _ServerBindCase

# <linux/in.h>; CPython's socket module does not export them.
_IP_MTU_DISCOVER = 10
_IP_PMTUDISC_DO = 2


def _df_mode(transport: UDPTransport) -> int:
    """The IP_MTU_DISCOVER mode of the socket ``transport`` sends from."""
    assert transport._transport is not None
    sock = transport._transport.get_extra_info("socket")
    return int(sock.getsockopt(socket.IPPROTO_IP, _IP_MTU_DISCOVER))


def _client_config(**overrides: Any) -> Config:
    fields: dict[str, Any] = {
        "mode": "client",
        "server_ip": "10.0.0.1",
        "server_port": 51820,
        "listen_port": 0,
        "key_file": "/tmp/dsm-test.key",
        "cert_file": "/tmp/dsm-test.crt",
        "ca_root_file": "/tmp/dsm-test-ca.pem",
        "attest_key_file": "/tmp/dsm-test-attest.key",
        "expected_server_cn": "dsm-test-server",
        "transport": "udp",
        "pmtu_discover": True,
    }
    fields.update(overrides)
    return Config(**fields)


def _server_fields(**overrides: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "mode": "server",
        "server_ip": "10.0.0.1",
        "server_port": 51820,
        "listen_port": 51820,
        "key_file": "/tmp/test.key",
        "cert_file": "/tmp/test.crt",
        "ca_root_file": "/tmp/test-ca.pem",
        "attest_key_file": "/tmp/test-attest.key",
        "transport": "udp",
        "dns_providers": ["https://1.1.1.1/dns-query"],
        "dns_provider_pins": {"https://1.1.1.1/dns-query": ["a" * 64]},
        "allowed_cns_file": "/tmp/test-allowed-cns.txt",
    }
    fields.update(overrides)
    return fields


class TestServerNeverSetsDf(_ServerBindCase):
    async def test_pmtu_discover_true_still_binds_without_df(self) -> None:
        config = _udp_config(51820)
        config.pmtu_discover = True
        bind = AsyncMock(return_value=51820)
        with (
            patch.object(server_mod.UDPTransport, "bind", bind),
            patch("dsm.server.setup_signal_handlers", lambda shutdown: shutdown.set()),
        ):
            rc = await asyncio.wait_for(server_mod.run_server(config), 5.0)

        self.assertEqual(rc, 0)
        bind.assert_awaited_once_with(local_port=51820, pmtu_discover=False)


class TestServerConfigWarnings(unittest.TestCase):
    def test_server_pmtu_discover_warns_that_it_is_client_only(self) -> None:
        with self.assertLogs("dsm.core.config", level="WARNING") as logs:
            Config(**_server_fields(pmtu_discover=True))
        self.assertEqual(len(logs.output), 1)
        self.assertIn("pmtu_discover", logs.output[0])
        self.assertIn("client", logs.output[0])

    def test_server_auto_mtu_says_it_is_client_only(self) -> None:
        # Not the client hint "set pmtu_discover=true": that would lead a
        # server operator straight into the bug above.
        with self.assertLogs("dsm.core.config", level="WARNING") as logs:
            Config(**_server_fields(auto_mtu=True))
        self.assertEqual(len(logs.output), 1)
        self.assertIn("auto_mtu", logs.output[0])
        self.assertIn("client", logs.output[0])
        self.assertNotIn("Set pmtu_discover=true", logs.output[0])

    def test_client_pmtu_discover_gives_no_warning(self) -> None:
        with self.assertNoLogs("dsm.core.config", level="WARNING"):
            _client_config(auto_mtu=True)


_DF_WITHOUT_AUTO_MTU = (
    "pmtu_discover = true without auto_mtu = true drops every packet on a path "
    "smaller than 1428 bytes; turn auto_mtu on or pmtu_discover off"
)


def test_pmtu_discover_without_auto_mtu_warns(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # With DF on and nothing to make packets smaller, every full-size packet
    # on a smaller path is refused (EMSGSIZE) once the handshake is done.
    caplog.set_level(logging.WARNING, logger="dsm.core.config")
    _client_config(auto_mtu=False)
    lines = [r.getMessage() for r in caplog.records]
    assert lines.count(_DF_WITHOUT_AUTO_MTU) == 1

    caplog.clear()
    _client_config(auto_mtu=True)
    assert _DF_WITHOUT_AUTO_MTU not in [r.getMessage() for r in caplog.records]


class TestClientHandshakeWithoutDf(_ClientBindCase):
    async def test_the_handshake_runs_without_df(self) -> None:
        seen: list[int] = []

        async def handshake(transport: UDPTransport, *_a: object, **_k: object) -> Any:
            seen.append(_df_mode(transport))
            raise HandshakeError("stop here")

        self.handshake.side_effect = handshake

        async def stop(_shutdown: object, _delay: float) -> bool:
            return True

        with (
            patch("dsm.net.transport.udp.apply_so_mark", lambda sock: None),
            patch("dsm.client._emit_handshake_failure"),
            patch("dsm.client._wait_or_stop", stop),
        ):
            from dsm.client import run_client

            rc = await asyncio.wait_for(run_client(_client_config()), 5.0)

        self.assertEqual(rc, 0)
        self.assertEqual(len(seen), 1)
        self.assertNotEqual(seen[0], _IP_PMTUDISC_DO)


class TestClientDfAfterHandshake(unittest.IsolatedAsyncioTestCase):
    async def test_client_sets_df_once_the_handshake_is_done(self) -> None:
        seen: dict[str, int] = {}
        stops: list[asyncio.Event] = []

        async def handshake(transport: UDPTransport, *_a: object, **_k: object) -> Any:
            seen["handshake"] = _df_mode(transport)
            return _FakeKeys(), b"", b"\x02" * 32, SINGLE_CLIENT_TUNNEL

        async def data_loops(
            _ctx: object,
            transport: UDPTransport,
            *_a: object,
            extra_loops: tuple[Coroutine[Any, Any, None], ...] = (),
            **_k: object,
        ) -> None:
            for loop in extra_loops:
                loop.close()  # never started here
            seen["data"] = _df_mode(transport)
            stops[0].set()  # the user stops DSM

        patches = [
            patch("tuncore.harden_process"),
            patch("dsm.core.hardening.set_process_nondumpable"),
            patch("dsm.crypto.attest_gate.enforce_attest_backend_policy"),
            patch("dsm.client.setup_signal_handlers", stops.append),
            patch("dsm.client.load_cert_materials", return_value=_Materials()),
            patch("dsm.client.verify_cert_matches_identity"),
            patch("dsm.crypto._stores.load_daemon_stores", return_value=True),
            patch("dsm.client.KeyStore", _FakeStore),
            patch("dsm.client.AttestStore", _FakeStore),
            patch("dsm.client.PreHandshakeKillSwitch", _HostChange),
            patch("dsm.client.check_clock_sync", return_value=None),
            patch("dsm.net.transport.udp.apply_so_mark", lambda sock: None),
            patch("dsm.crypto.handshake.client_handshake", handshake),
            patch("dsm.client.TcpTimestampsDisabler", _HostChange),
            patch("dsm.client.SrcValidMarkEnabler", _HostChange),
            patch("dsm.client.TunDevice", _HostChange),
            patch("dsm.client.NFTablesManager", _HostChange),
            patch("dsm.client.ResolvConfManager", _HostChange),
            patch("dsm.client.make_send_fn", return_value=_no_send),
            patch("dsm.session.run_data_loops", data_loops),
        ]
        with ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            from dsm.client import run_client

            rc = await asyncio.wait_for(run_client(_client_config()), timeout=10)

        self.assertEqual(rc, 0)
        self.assertNotEqual(seen["handshake"], _IP_PMTUDISC_DO)
        self.assertEqual(seen["data"], _IP_PMTUDISC_DO)


class TestTooBigIsCounted(unittest.IsolatedAsyncioTestCase):
    async def test_emsgsize_counts_and_other_errors_do_not(self) -> None:
        with patch("dsm.net.transport.udp.apply_so_mark", lambda sock: None):
            t = UDPTransport()
            await t.bind("127.0.0.1", 0, pmtu_discover=True)
            try:
                assert t._transport is not None
                too_big = OSError(errno.EMSGSIZE, "Message too long")
                refused = OSError(errno.ECONNREFUSED, "Connection refused")
                t._transport.get_protocol().error_received(too_big)  # type: ignore[attr-defined]
                t._transport.get_protocol().error_received(refused)  # type: ignore[attr-defined]
                self.assertEqual(t.too_big_drops(), 1)
                await t.rebind_to_fresh_port()
                self.assertEqual(_df_mode(t), _IP_PMTUDISC_DO)
                t._transport.get_protocol().error_received(too_big)  # type: ignore[attr-defined]
                self.assertEqual(t.too_big_drops(), 2)
            finally:
                await t.aclose()


class TestAutoMtuChecksAtOnceOnTooBig(unittest.IsolatedAsyncioTestCase):
    async def test_a_refused_datagram_brings_the_check_forward(self) -> None:
        # The interval is an hour; the refusal must not wait for it.
        config = _client_config(auto_mtu=True, pmtu_check_interval_s=3600.0)
        transport = UDPTransport()
        transport.get_path_mtu = lambda: 1300  # type: ignore[method-assign]
        refusals = itertools.count()  # moves at every look
        transport.too_big_drops = lambda: next(refusals)  # type: ignore[method-assign]
        lowered = asyncio.Event()
        tun = MagicMock()
        tun.set_mtu = MagicMock(side_effect=lambda _mtu: lowered.set())
        ctx = MagicMock()
        ctx.tun = tun
        ctx.shutdown = asyncio.Event()
        with patch("dsm.session.AUTO_MTU_TOO_BIG_POLL_S", 0.01, create=True):
            task = asyncio.create_task(auto_mtu_loop(ctx, transport, config))
            try:
                await asyncio.wait_for(lowered.wait(), timeout=2.0)
            finally:
                ctx.shutdown.set()
                await asyncio.wait_for(task, timeout=2.0)
        tun.set_mtu.assert_called_once()
        ctx.shaper.set_size_class_ceiling.assert_called_once_with(1300 - 28)


class _Shaper:
    def __init__(self) -> None:
        self.caps: list[int] = []

    def set_tier_cap(self, cap: int) -> None:
        self.caps.append(cap)


class TestAutoCapIgnoresTooBig(unittest.TestCase):
    """Loss in a stretch while the kernel refused datagrams as too big is not
    link loss: those packets took a seq but never left this host."""

    @staticmethod
    def _caps_after_two_lossy_seconds(refused_per_second: int) -> list[int]:
        seq, refused = [0], [0]
        shaper = _Shaper()
        auto = AutoCap(
            shaper,
            tiers_pps=(10.0, 50.0, 200.0, 800.0),
            start_tier=3,
            last_seq=lambda: seq[0],
            too_big=lambda: refused[0],
        )
        auto.on_report(LinkReport(highest_seq=0, received=0))
        received = 0
        for _ in range(2):  # two bad seconds in a row at tier 3 cap it
            seq[0] += 800
            received += 640  # 20% missing
            refused[0] += refused_per_second
            auto.on_report(LinkReport(highest_seq=seq[0], received=received))
        return shaper.caps

    def test_refused_packets_do_not_cap_the_shaper(self) -> None:
        self.assertEqual(self._caps_after_two_lossy_seconds(160), [])

    def test_the_same_loss_without_refusals_still_caps(self) -> None:
        self.assertEqual(self._caps_after_two_lossy_seconds(0), [2])


if __name__ == "__main__":
    unittest.main()
