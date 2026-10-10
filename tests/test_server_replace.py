"""run_server with the in-session accept: a client that comes back takes its
session over.

The in-session accept (SessionWatch) is a scripted stand-in here; its own
tests are in test_handshake_acceptor_in_session.py. Host state is faked and
recorded, so the order of the old session's teardown and the new session's
setup can be checked. No sockets, no root.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Callable, Generator
from dataclasses import replace
from typing import Any
from unittest.mock import MagicMock, patch

from dsm.core.config import Config
from dsm.core.fsm import State
from dsm.crypto.handshake import VerifiedClient
from dsm.net.dns_proxy import DNSProxyPortInUseError
from dsm.net.handshake_acceptor import Winner
from dsm.net.handshake_gate import SourceLimiter
from dsm.net.session_slot import SessionSlot
from dsm.server import run_server
from tests.test_server_dns_fatal import (
    _FakeMaterials,
    _FakeStore,
    _NonEmptyAllowlist,
    _server_config,
)

events: list[str] = []
# (session_keys, transport) handed to each session's data loops, in order.
served: list[tuple[Any, Any]] = []
CLIENT = VerifiedClient(cn="dsm-a-client", noise_static=b"\x01" * 32)
ONE_SESSION = [
    "tun.open",
    "fwd.apply",
    "masq.apply",
    "dns.start",
    "loops",
    "dns.stop",
    "masq.remove",
    "fwd.remove",
    "tun.close",
]


class _Quiet:
    def __init__(self, *_a: Any, **_k: Any) -> None:
        pass

    def apply(self) -> None:
        pass

    def remove(self) -> None:
        pass


class _Fwd(_Quiet):
    def apply(self) -> None:
        events.append("fwd.apply")

    def remove(self) -> None:
        events.append("fwd.remove")


class _Masq(_Quiet):
    fail_next_remove = False

    def apply(self) -> None:
        events.append("masq.apply")

    def remove(self) -> None:
        events.append("masq.remove")
        if _Masq.fail_next_remove:
            _Masq.fail_next_remove = False
            raise RuntimeError("nft: could not remove the MASQUERADE rule (test)")


class _Tun:
    def __init__(self, *_a: Any, **_k: Any) -> None:
        pass

    def open(self) -> None:
        events.append("tun.open")

    def configure(self, *_a: Any, **_k: Any) -> None:
        pass

    def close(self) -> None:
        events.append("tun.close")


class _Resolver:
    def __init__(self, *_a: Any, **_k: Any) -> None:
        pass

    async def close(self) -> None:
        pass


class _Dns:
    """Like LocalDNSProxy: its socket closes one loop step after stop(), and
    a start before that fails as the real bind does."""

    bound = False

    def __init__(self, *_a: Any, **_k: Any) -> None:
        pass

    async def start(self) -> None:
        if _Dns.bound:
            raise DNSProxyPortInUseError("DNS proxy cannot bind 10.8.0.1:53 (test)")
        _Dns.bound = True
        events.append("dns.start")

    def stop(self) -> None:
        events.append("dns.stop")
        asyncio.get_running_loop().call_soon(_Dns.socket_closed)

    @staticmethod
    def socket_closed() -> None:
        _Dns.bound = False


class _Scheduler:
    def __init__(self, *_a: Any, **_k: Any) -> None:
        pass

    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        pass


class _Udp:
    async def bind(self, *_a: Any, **_k: Any) -> int:
        return 51820

    async def aclose(self) -> None:
        pass


class _Conn:
    def __init__(self, name: str) -> None:
        self.name = name

    async def aclose(self) -> None:
        events.append(f"{self.name}.aclose")

    def close(self) -> None:
        events.append(f"{self.name}.close")


class _Listener:
    made: list[_Listener] = []

    def __init__(self) -> None:
        self.connections: asyncio.Queue[Any] = asyncio.Queue()
        _Listener.made.append(self)

    async def start(self, host: str = "0.0.0.0", port: int = 0) -> int:
        del host
        events.append("listener.start")
        return port

    def close(self) -> None:
        events.append("listener.close")


class _Watch:
    """Stands in for SessionWatch. ``plan`` has one entry per session:
    "takeover" (a client takes the session over as soon as it starts) or
    "none". ``after_stop``, when set, runs one loop step after a takeover's
    stop() returned."""

    plan: list[str] = []
    made: list[_Watch] = []
    after_stop: Callable[[], None] | None = None

    def __init__(
        self,
        _config: Any,
        _keystore: Any,
        _attest_store: Any,
        _materials: Any,
        _cn_allowlist: Any,
        limiter: Any,
        slot: Any,
        *,
        udp: Any = None,
        tcp: Any = None,
    ) -> None:
        self.limiter = limiter
        self.slot = slot
        self.udp = udp
        self.tcp = tcp
        self.end_session = asyncio.Event()
        self.offer: Callable[[bytes, tuple[str, int], bool], None] | None = (
            self._offer if udp is not None else None
        )
        self.winner: Winner | None = None
        self.what = _Watch.plan.pop(0)
        _Watch.made.append(self)
        if self.what == "takeover":
            asyncio.get_running_loop().call_soon(self.end_session.set)

    def _offer(self, data: bytes, addr: tuple[str, int], seen: bool) -> None:
        del data, addr, seen

    async def stop(self) -> Winner | None:
        events.append("watch.stop")
        if self.what != "takeover":
            return None
        transport = (
            self.udp if self.udp is not None else _Conn(f"conn{len(_Watch.made) + 1}")
        )
        self.winner = Winner(
            session_keys=object(),  # type: ignore[arg-type]
            client_pub=b"\x02" * 32,
            transport=transport,
        )
        if _Watch.after_stop is not None:
            asyncio.get_running_loop().call_soon(_Watch.after_stop)
        return self.winner


async def _no_send(*_a: Any, **_k: Any) -> None:
    pass


async def _no_accept(*_a: Any) -> Any:
    raise AssertionError("this accept must not run")


def _config(transport: str = "udp") -> Config:
    return replace(_server_config(), dns_blocklist=False, transport=transport)


@contextlib.contextmanager
def _faked(
    captured: dict[str, Any],
    plan: list[str],
    on_session: Callable[[int, Any], None],
    *,
    udp_accept: Any = None,
    tcp_accept: Any = None,
) -> Generator[list[dict[str, Any]], None, None]:
    """Fake every host call of run_server. ``on_session(n, ctx)`` runs when
    session n's data loops start; the loops then wait for the session's
    shutdown event, like the real ones."""
    events.clear()
    served.clear()
    _Dns.bound = False
    _Masq.fail_next_remove = False
    _Watch.plan = list(plan)
    _Watch.made = []
    _Watch.after_stop = None
    _Listener.made = []
    loops_kwargs: list[dict[str, Any]] = []

    async def _loops(
        ctx: Any, transport: Any, keys: Any, _replay: Any, fsm: Any, **kwargs: Any
    ) -> None:
        loops_kwargs.append(kwargs)
        served.append((keys, transport))
        events.append("loops")
        on_session(len(loops_kwargs), ctx)
        await ctx.shutdown.wait()
        fsm.transition(State.TEARDOWN)
        fsm.transition(State.IDLE)

    def _capture(shutdown: asyncio.Event) -> None:
        captured["shutdown"] = shutdown

    patches = [
        patch("tuncore.harden_process"),
        patch("dsm.core.hardening.set_process_nondumpable"),
        patch("dsm.crypto.attest_gate.enforce_attest_backend_policy"),
        patch("dsm.server.load_cert_materials", return_value=_FakeMaterials()),
        patch("dsm.server.verify_cert_matches_identity"),
        patch("dsm.server.CNAllowlist.from_file", return_value=_NonEmptyAllowlist()),
        patch("dsm.crypto._stores.load_daemon_stores", return_value=True),
        patch("dsm.server.KeyStore", _FakeStore),
        patch("dsm.server.AttestStore", _FakeStore),
        patch("dsm.server.ServerRateLimitManager", _Quiet),
        patch("dsm.server.TcpTimestampsDisabler", _Quiet),
        patch("dsm.server.check_clock_sync", return_value=None),
        patch("dsm.server.IPForwardingManager", _Fwd),
        patch("dsm.server.MasqueradeManager", _Masq),
        patch("dsm.server.TunDevice", _Tun),
        patch("dsm.server.DNSResolver", _Resolver),
        patch("dsm.server.LocalDNSProxy", _Dns),
        patch("dsm.server.SendScheduler", _Scheduler),
        patch("dsm.server.TrafficShaper", MagicMock()),
        patch("dsm.server.make_auto_cap", return_value=(None, None)),
        patch("dsm.server.make_send_fn", return_value=_no_send),
        patch("dsm.server.make_addr_send_fn", return_value=_no_send),
        patch("dsm.server.UDPTransport", _Udp),
        patch("dsm.server.TCPListener", _Listener),
        patch("dsm.server.SessionWatch", _Watch),
        patch("dsm.server.setup_signal_handlers", _capture),
        patch("dsm.server._accept_until_winner", new=udp_accept or _no_accept),
        patch("dsm.server._accept_one_session", new=tcp_accept or _no_accept),
        patch("dsm.session.run_data_loops", new=_loops),
    ]
    with contextlib.ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)
        yield loops_kwargs


async def test_udp_a_takeover_ends_the_old_session_before_the_new_one_starts() -> None:
    captured: dict[str, Any] = {}
    accepts: list[tuple[Any, ...]] = []

    async def _accept(*args: Any) -> tuple[Any, bytes, Any]:
        accepts.append(args)
        return object(), b"\x01" * 32, args[5]

    def _on_session(n: int, _ctx: Any) -> None:
        if n == 2:
            captured["shutdown"].set()

    with _faked(
        captured, ["takeover", "none"], _on_session, udp_accept=_accept
    ) as loops:
        rc = await asyncio.wait_for(run_server(_config()), 5.0)

    assert rc == 0, "a DNS port clash here means run_server did not yield"
    assert len(accepts) == 1, "the client that took over needs no new accept"
    assert events == ONE_SESSION + ["watch.stop"] + ONE_SESSION + ["watch.stop"]
    assert _Listener.made == [], "UDP mode opens no TCP port"
    first, second = _Watch.made
    assert first.udp is accepts[0][5]
    assert second.udp is accepts[0][5]
    assert loops[0]["unauthenticated"] is first.offer
    assert loops[1]["unauthenticated"] is second.offer
    # Session 2 runs on the keys the takeover's handshake made.
    assert first.winner is not None
    assert served[1][0] is first.winner.session_keys
    assert served[1][0] is not served[0][0]
    assert served[1][1] is accepts[0][5]


async def test_tcp_one_listener_for_the_run_and_the_old_connection_closes_first() -> (
    None
):
    captured: dict[str, Any] = {}
    accepts: list[tuple[Any, ...]] = []

    async def _accept(*args: Any) -> tuple[Any, bytes, Any]:
        accepts.append(args)
        args[1].transition(State.HANDSHAKING)  # as the real TCP accept does
        return object(), b"\x01" * 32, _Conn("conn1")

    def _on_session(n: int, _ctx: Any) -> None:
        if n == 2:
            captured["shutdown"].set()

    with _faked(
        captured, ["takeover", "none"], _on_session, tcp_accept=_accept
    ) as loops:
        rc = await asyncio.wait_for(run_server(_config("tcp")), 5.0)

    assert rc == 0
    assert len(accepts) == 1
    assert len(_Listener.made) == 1
    listener = _Listener.made[0]
    assert accepts[0][9] is listener
    assert _Watch.made[0].tcp is listener.connections
    assert _Watch.made[1].tcp is listener.connections
    assert events == (
        ["listener.start"]
        + ONE_SESSION
        + ["conn1.aclose", "watch.stop"]
        + ONE_SESSION
        + ["conn2.aclose", "watch.stop", "listener.close"]
    )
    assert loops[0]["unauthenticated"] is None
    winner = _Watch.made[0].winner
    assert winner is not None
    assert served[1] == (winner.session_keys, winner.transport)


async def test_shutdown_during_a_takeover_closes_the_waiting_client() -> None:
    """Review Focus 3: SIGTERM arrives as a client takes the session over."""
    captured: dict[str, Any] = {}

    async def _accept(*args: Any) -> tuple[Any, bytes, Any]:
        args[1].transition(State.HANDSHAKING)
        return object(), b"\x01" * 32, _Conn("conn1")

    def _on_session(_n: int, _ctx: Any) -> None:
        captured["shutdown"].set()

    with _faked(captured, ["takeover"], _on_session, tcp_accept=_accept):
        rc = await asyncio.wait_for(run_server(_config("tcp")), 5.0)

    assert rc == 0
    assert events == (
        ["listener.start"]
        + ONE_SESSION
        + ["conn1.aclose", "watch.stop", "conn2.aclose", "listener.close"]
    )


async def test_a_session_ending_by_itself_clears_the_slot_for_the_next_accept() -> None:
    captured: dict[str, Any] = {}
    accepts: list[tuple[Any, ...]] = []
    holders: list[Any] = []

    async def _accept(*args: Any) -> tuple[Any, Any, Any]:
        accepts.append(args)
        slot: SessionSlot = args[8]
        holders.append(slot.holder)
        if len(accepts) == 2:
            args[6].set()  # process_shutdown
            return None, None, args[5]
        attempt = object()  # as a real winner does: it holds the slot
        slot.admit(attempt, CLIENT, session_live=False)
        slot.confirm(attempt)
        return object(), b"\x01" * 32, args[5]

    def _on_session(_n: int, ctx: Any) -> None:
        ctx.shutdown.set()  # dead peer: the session ends by itself

    with _faked(captured, ["none"], _on_session, udp_accept=_accept):
        rc = await asyncio.wait_for(run_server(_config()), 5.0)

    assert rc == 0
    assert len(accepts) == 2
    assert holders == [None, None]  # cleared once the session ended
    slot = accepts[0][8]
    limiter = accepts[0][7]
    assert isinstance(slot, SessionSlot)
    assert isinstance(limiter, SourceLimiter)
    assert accepts[1][8] is slot and _Watch.made[0].slot is slot
    assert accepts[1][7] is limiter and _Watch.made[0].limiter is limiter


async def test_a_failing_teardown_still_serves_the_client_that_took_over() -> None:
    """Review Focus 1: an nft remove fails while the old session unwinds; the
    client that took over still gets its session and the daemon stays up."""
    captured: dict[str, Any] = {}

    async def _accept(*args: Any) -> tuple[Any, bytes, Any]:
        return object(), b"\x01" * 32, args[5]

    def _on_session(n: int, _ctx: Any) -> None:
        if n == 1:
            _Masq.fail_next_remove = True
        if n == 2:
            captured["shutdown"].set()

    with _faked(captured, ["takeover", "none"], _on_session, udp_accept=_accept):
        rc = await asyncio.wait_for(run_server(_config()), 5.0)

    assert rc == 0
    assert events == ONE_SESSION + ["watch.stop"] + ONE_SESSION + ["watch.stop"]


async def test_a_fatal_dns_clash_closes_the_client_waiting_to_take_over() -> None:
    captured: dict[str, Any] = {}

    async def _accept(*args: Any) -> tuple[Any, bytes, Any]:
        args[1].transition(State.HANDSHAKING)
        return object(), b"\x01" * 32, _Conn("conn1")

    def _on_session(_n: int, _ctx: Any) -> None:
        raise AssertionError("no session may run")

    with _faked(captured, ["takeover"], _on_session, tcp_accept=_accept):
        _Dns.bound = True  # a host resolver holds the DNS port
        rc = await asyncio.wait_for(run_server(_config("tcp")), 5.0)

    assert rc == 1
    assert "loops" not in events
    assert events[-3:] == ["watch.stop", "conn2.aclose", "listener.close"]


async def test_a_client_that_wins_the_idle_accept_as_shutdown_comes_is_not_served() -> (
    None
):
    captured: dict[str, Any] = {}

    async def _accept(*args: Any) -> tuple[Any, bytes, Any]:
        args[1].transition(State.HANDSHAKING)
        captured["shutdown"].set()  # SIGTERM lands as this client wins
        return object(), b"\x01" * 32, _Conn("conn1")

    def _on_session(_n: int, _ctx: Any) -> None:
        raise AssertionError("no session may run")

    with _faked(captured, [], _on_session, tcp_accept=_accept):
        rc = await asyncio.wait_for(run_server(_config("tcp")), 5.0)

    assert rc == 0
    assert _Watch.made == []
    assert events == ["listener.start", "conn1.aclose", "listener.close"]


async def test_shutdown_in_the_step_before_the_next_session_closes_the_winner() -> None:
    """SIGTERM lands in the one loop step between a replaced session and the
    next one: the client that took over is not served, and its connection
    is closed."""
    captured: dict[str, Any] = {}

    async def _accept(*args: Any) -> tuple[Any, bytes, Any]:
        args[1].transition(State.HANDSHAKING)
        return object(), b"\x01" * 32, _Conn("conn1")

    def _on_session(_n: int, _ctx: Any) -> None:
        _Watch.after_stop = captured["shutdown"].set

    with _faked(captured, ["takeover"], _on_session, tcp_accept=_accept):
        rc = await asyncio.wait_for(run_server(_config("tcp")), 5.0)

    assert rc == 0
    assert events == (
        ["listener.start"]
        + ONE_SESSION
        + ["conn1.aclose", "watch.stop", "conn2.aclose", "listener.close"]
    )
