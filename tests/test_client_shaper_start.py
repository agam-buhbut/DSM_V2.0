"""The client builds its tier shaper right before the send loop starts.

A shaper's first slot falls one gap after it is built, and each poll sends
every slot that is already due. A shaper built before the handshake would
find all the slots of the setup time due at the first poll and send them
back to back. This drives ``run_client`` with every host and network
collaborator faked and a handshake that takes 0.9 s on a fake clock: just
under the shaper's 1 s stall reset, which would otherwise hide the burst.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Coroutine
from contextlib import ExitStack
from typing import Any
from unittest.mock import patch

from dsm.core.config import Config
from dsm.traffic.scheduler import SendScheduler
from dsm.traffic.shaper import TrafficShaper

_SETUP_S = 0.9


def _client_config() -> Config:
    return Config(
        mode="client",
        server_ip="10.0.0.1",
        server_port=51820,
        listen_port=0,
        key_file="/tmp/dsm-test.key",
        cert_file="/tmp/dsm-test.crt",
        ca_root_file="/tmp/dsm-test-ca.pem",
        attest_key_file="/tmp/dsm-test-attest.key",
        expected_server_cn="dsm-test-server",
        transport="udp",
    )


class _FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class _HostChange:
    """Stands in for every host-state manager (kill switch, TUN, nftables,
    resolv.conf, TCP timestamps): each call does nothing."""

    def __init__(self, *_a: object, **_k: object) -> None:
        pass

    def apply(self) -> None:
        pass

    def remove(self) -> None:
        pass

    def open(self) -> None:
        pass

    def configure(self, *_a: object, **_k: object) -> None:
        pass

    def close(self) -> None:
        pass


class _Materials:
    cert_der = b""
    ca_root = object()
    crl = None


class _Identity:
    public_key = b"\x01" * 32


class _FakeStore:
    def __init__(self, *_a: object, **_k: object) -> None:
        self.identity = _Identity()
        self.attest_key = object()

    def unload(self) -> None:
        pass


class _FakeTransport:
    async def bind(self, *_a: object, **_k: object) -> int:
        return 0

    def get_path_mtu(self) -> int | None:
        return None

    async def aclose(self) -> None:
        pass


class _FakeKeys:
    epoch = 0


async def _no_send(data: bytes, target_size: int) -> None:
    pass


async def test_the_first_poll_after_a_slow_setup_sends_at_most_one_slot() -> None:
    fake_clock = _FakeClock()
    first_poll: list[int] = []
    polled = asyncio.Event()

    class _ClockedShaper(TrafficShaper):
        @classmethod
        def from_config(
            cls, config: Config, *, clock: Callable[[], float] = time.monotonic
        ) -> TrafficShaper:
            return super().from_config(config, clock=fake_clock)

        def poll(
            self, now: float, queue_len: int, oldest_wait: float, real_sent: int
        ) -> tuple[int, float]:
            slots, next_wake = super().poll(now, queue_len, oldest_wait, real_sent)
            if not polled.is_set():
                first_poll.append(slots)
                polled.set()
            return slots, next_wake

    class _ClockedScheduler(SendScheduler):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, clock=fake_clock, **kwargs)

    async def _slow_handshake(*_a: object, **_k: object) -> tuple[Any, bytes, bytes]:
        fake_clock.now += _SETUP_S
        return _FakeKeys(), b"", b"\x02" * 32

    async def _until_first_poll(
        *_a: object,
        extra_loops: tuple[Coroutine[Any, Any, None], ...] = (),
        **_k: object,
    ) -> None:
        for loop in extra_loops:
            loop.close()  # never started here
        await asyncio.wait_for(polled.wait(), timeout=5)

    patches = [
        patch("tuncore.harden_process"),
        patch("dsm.core.hardening.set_process_nondumpable"),
        patch("dsm.crypto.attest_gate.enforce_attest_backend_policy"),
        patch("dsm.client.setup_signal_handlers"),
        patch("dsm.client.load_cert_materials", return_value=_Materials()),
        patch("dsm.client.verify_cert_matches_identity"),
        patch("dsm.crypto._stores.load_daemon_stores", return_value=True),
        patch("dsm.client.KeyStore", _FakeStore),
        patch("dsm.client.AttestStore", _FakeStore),
        patch("dsm.client.PreHandshakeKillSwitch", _HostChange),
        patch("dsm.client.check_clock_sync", return_value=None),
        patch("dsm.client.UDPTransport", _FakeTransport),
        patch("dsm.crypto.handshake.client_handshake", _slow_handshake),
        patch("dsm.client.TcpTimestampsDisabler", _HostChange),
        patch("dsm.client.TunDevice", _HostChange),
        patch("dsm.client.NFTablesManager", _HostChange),
        patch("dsm.client.ResolvConfManager", _HostChange),
        patch("dsm.client.make_send_fn", return_value=_no_send),
        patch("dsm.client.TrafficShaper", _ClockedShaper),
        patch("dsm.client.SendScheduler", _ClockedScheduler),
        patch("dsm.session.run_data_loops", _until_first_poll),
    ]
    # One ExitStack: a with-statement this long passes Python's limit on
    # nested blocks.
    with ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)
        from dsm.client import run_client

        rc = await asyncio.wait_for(run_client(_client_config()), timeout=10)

    assert rc == 0
    # The idle tier sends 8-12 packets/s with gaps of at most 1.7 / 8 s, so a
    # shaper built before the 0.9 s setup would owe at least 4 slots here.
    assert first_poll and first_poll[0] <= 1
