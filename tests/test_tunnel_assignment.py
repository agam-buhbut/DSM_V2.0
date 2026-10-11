"""The tunnel address in the bootstrap reply (wire v2 spec §7.7, §16.2):
TunnelAssignment's checks, the field on the wire, admit_client choosing it,
and the client setting its TUN and DNS from it. Real handshakes over
loopback UDP (helpers of test_handshake_admit_hook.py); fakes for
run_client. The loopback handshake tests need tuncore.xchacha_open from the
Task 5 wheel (every UDP client handshake tries it on the server's reply), so
on the old wheel they are CI-only; the rest also run there.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterator
from typing import Any
from unittest.mock import patch

import pytest

import tuncore
from dsm.crypto import handshake
from dsm.crypto.handshake import HANDSHAKE_FRAME_SIZE, HandshakeError, VerifiedClient
from dsm.net._addresses import SINGLE_CLIENT_TUNNEL, TunnelAssignment
from tests.test_client_fail_closed import _FakeKeys, _Run
from tests.test_handshake_admit_hook import (
    CLIENT_CN,
    _count_sends,
    _Parties,
    _run,
    _udp_pair,
)

A = ipaddress.IPv4Address
SEVEN = TunnelAssignment(client=A("10.8.0.7"), server=A("10.8.0.1"), prefix_len=24)


@pytest.fixture(autouse=True)
def _no_so_mark() -> Iterator[None]:
    with (
        patch("dsm.net.transport.udp.apply_so_mark", lambda sock: None),
        patch("dsm.net.transport.tcp.apply_so_mark", lambda sock: None),
    ):
        yield


@pytest.fixture
def fast_retries() -> Iterator[None]:
    with (
        patch.object(handshake, "HANDSHAKE_TIMEOUT", 0.2),
        patch.object(handshake, "BACKOFF_BASE", 0.01),
    ):
        yield


def test_it_round_trips_in_9_bytes() -> None:
    other = TunnelAssignment(
        client=A("172.16.5.9"), server=A("172.16.5.1"), prefix_len=20
    )
    # The two ends of the prefix rule are allowed: /16 and /30.
    widest = TunnelAssignment(
        client=A("192.168.7.9"), server=A("192.168.0.1"), prefix_len=16
    )
    narrowest = TunnelAssignment(
        client=A("10.8.0.2"), server=A("10.8.0.1"), prefix_len=30
    )
    for tunnel in (SINGLE_CLIENT_TUNNEL, other, widest, narrowest):
        data = tunnel.to_bytes()
        assert len(data) == TunnelAssignment.SIZE == 9
        assert TunnelAssignment.from_bytes(data) == tunnel


@pytest.mark.parametrize(
    ("client", "server", "prefix"),
    [
        ("10.8.0.2", "10.8.0.1", 15),
        ("10.8.0.2", "10.8.0.1", 31),
        ("8.8.8.8", "10.8.0.1", 24),
        ("10.8.0.2", "8.8.8.8", 24),
        ("10.8.0.2", "172.16.0.1", 24),  # two private ranges
        ("10.8.0.2", "10.9.0.1", 24),  # two networks
        ("10.8.0.0", "10.8.0.1", 24),  # the network address
        ("10.8.0.2", "10.8.0.255", 24),  # the broadcast address
        ("10.8.0.1", "10.8.0.1", 24),  # one address twice
    ],
)
def test_bad_values_are_refused_both_ways(
    client: str, server: str, prefix: int
) -> None:
    with pytest.raises(ValueError):
        TunnelAssignment(client=A(client), server=A(server), prefix_len=prefix)
    with pytest.raises(ValueError):
        TunnelAssignment.from_bytes(
            A(client).packed + A(server).packed + bytes([prefix])
        )


def test_the_field_must_be_9_bytes() -> None:
    data = SINGLE_CLIENT_TUNNEL.to_bytes()
    for bad in (data[:8], data + b"\x00"):
        with pytest.raises(ValueError):
            TunnelAssignment.from_bytes(bad)


async def _handshake(
    p: _Parties, hook: Any = None
) -> tuple[Any, Any, list[bytes], list[bytes]]:
    server_t, client_t, addr = await _udp_pair()
    server_sent: list[bytes] = []
    client_sent: list[bytes] = []
    _count_sends(server_t, server_sent)
    _count_sends(client_t, client_sent)
    try:
        client_res, server_res = await _run(p, server_t, client_t, addr, hook=hook)
    finally:
        await client_t.aclose()
        await server_t.aclose()
    return client_res, server_res, server_sent, client_sent


async def test_the_client_gets_the_default_address_or_the_hooks() -> None:
    p = _Parties()
    client_res, _server_res, _s, _c = await _handshake(p)
    assert client_res[3] == SINGLE_CLIENT_TUNNEL
    seen: list[VerifiedClient] = []

    def hook(client: VerifiedClient) -> TunnelAssignment:
        seen.append(client)
        return SEVEN

    client_res, _server_res, _s, _c = await _handshake(p, hook)
    assert client_res[3] == SEVEN
    assert [c.cn for c in seen] == [CLIENT_CN]


async def test_a_hook_that_refuses_means_no_reply(fast_retries: None) -> None:
    p = _Parties()

    def hook(_client: VerifiedClient) -> TunnelAssignment:
        raise HandshakeError("full")

    client_res, server_res, server_sent, _c = await _handshake(p, hook)
    assert isinstance(server_res, HandshakeError)
    assert isinstance(client_res, HandshakeError)
    # Its usual timeout error, as for a lost reply (spec §7.7).
    assert "timed out" in str(client_res)
    assert len(server_sent) == 1  # msg2 only: no bootstrap reply


async def test_a_bad_field_from_the_server_fails_the_client(fast_retries: None) -> None:
    p = _Parties()
    bad = A("8.8.8.8").packed + A("10.8.0.1").packed + bytes([24])
    real = tuncore.complete_bootstrap
    key_makers: list[bool] = []  # is_initiator of each call

    def _recording(*args: Any, **kwargs: Any) -> Any:
        key_makers.append(bool(kwargs.get("is_initiator")))
        return real(*args, **kwargs)

    with (
        patch.object(handshake, "_tunnel_field", lambda _tunnel: bad),
        patch.object(tuncore, "complete_bootstrap", _recording),
    ):
        client_res, _server_res, _s, _c = await _handshake(p)
    assert isinstance(client_res, HandshakeError)
    assert "server sent a bad tunnel address" in str(client_res)
    assert key_makers == [False]  # the server's keys only: the client made none


async def test_a_bad_hook_value_is_never_sent(fast_retries: None) -> None:
    p = _Parties()
    client_res, server_res, server_sent, _c = await _handshake(
        p, lambda _client: "10.8.0.7"
    )
    assert isinstance(server_res, ValueError)
    assert len(server_sent) == 1
    assert isinstance(client_res, BaseException)


async def test_every_frame_is_1400_bytes_and_the_reply_padding_is_random() -> None:
    p = _Parties()
    tails: list[bytes] = []
    for _ in range(100):
        client_res, _server_res, server_sent, client_sent = await _handshake(p)
        assert not isinstance(client_res, BaseException)
        assert all(len(f) == HANDSHAKE_FRAME_SIZE for f in server_sent + client_sent)
        tails.append(server_sent[-1][57:])
    for offset in range(HANDSHAKE_FRAME_SIZE - 57):
        assert len({t[offset] for t in tails}) > 1, offset


class _CapturingRun(_Run):
    """The fail-closed harness, also keeping what the TUN and resolv.conf got."""

    def __init__(self) -> None:
        super().__init__()
        self.tun_calls: list[dict[str, object]] = []
        self.nameservers: list[object] = []

    def _recorder(self, name: str) -> type:
        base: Any = super()._recorder(name)
        if name == "tun":
            calls = self.tun_calls

            class _Tun(base):
                def configure(self, *args: object, **kwargs: object) -> None:
                    calls.append(dict(kwargs))
                    super().configure(*args, **kwargs)

            return _Tun
        if name == "resolv":
            names = self.nameservers

            class _Resolv(base):
                def __init__(self, *args: object, **kwargs: object) -> None:
                    names.append(kwargs.get("nameserver"))
                    super().__init__(*args, **kwargs)

            return _Resolv
        return base


async def test_run_client_sets_its_tun_and_dns_from_the_handshake() -> None:
    there = TunnelAssignment(client=A("10.9.0.7"), server=A("10.9.0.1"), prefix_len=24)

    async def _handshake_there(
        *_a: object, **_k: object
    ) -> tuple[Any, bytes, bytes, Any]:
        return _FakeKeys(), b"", b"\x02" * 32, there

    run = _CapturingRun()
    run.stop_in_session = [True]
    assert await run.run(handshake=_handshake_there) == 0
    assert [(c["local_ip"], c["netmask"]) for c in run.tun_calls] == [("10.9.0.7", 24)]
    assert run.nameservers == ["10.9.0.1"]
