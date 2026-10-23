"""Who a failed or pushed-out start spares (multi-client spec §3.7 E2,
§4.3; owner decisions 2026-10-23): a proved start whose msg3 does not open
bars nothing, and a push-out victim whose msg2 left less than
_REPLY_ALLOWANCE_S ago did not stall. On test_client_acceptor.py's harness:
scripted handshakes, the real session table, limiter and gate, fake clocks.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from dsm.crypto.handshake import BadMsg3Error
from dsm.net.handshake_gate import SourceLimiter
from dsm.net.session_slot import SessionTable
from tests import test_client_acceptor as acc
from tests.test_client_acceptor import (
    A_CN,
    MSG2,
    Addr,
    B,
    _Admit,
    _Demux,
    _gate,
    _msg1,
    _peer_of,
    _send,
    _with_cookie,
)
from tests.test_handshake_acceptor_limits import _Frozen, _spin


class _Hs(acc._Hs):
    """test_client_acceptor's fake, plus two kinds of peer that send msg2
    and never reach the table: one in ``bad_msg3`` then fails as a msg3
    that does not open; one in ``late`` waits for its event before msg2
    (msg2 waiting in the server's TPM queue), then stalls."""

    def __init__(self) -> None:
        super().__init__()
        self.bad_msg3: set[Addr] = set()
        self.late: dict[Addr, asyncio.Event] = {}

    async def __call__(
        self, transport: Any, *a: Any, admit_client: Any, **k: Any
    ) -> tuple[object, bytes]:
        peer = _peer_of(transport)
        if peer not in self.bad_msg3 and peer not in self.late:
            return await super().__call__(transport, *a, admit_client=admit_client, **k)
        self.started.append(peer)
        await transport.recv()
        if peer in self.late:
            await self.late[peer].wait()
        await _send(transport, MSG2, peer)
        if peer in self.bad_msg3:
            raise BadMsg3Error("scripted bad msg3")
        await asyncio.Event().wait()
        raise AssertionError("a late peer stalls until it is cancelled")


@pytest.mark.parametrize(
    ("bad_msg3", "barred"), [(True, False), (False, True)], ids=["bad-msg3", "other"]
)
async def test_a_proved_start_whose_msg3_does_not_open_bars_nothing(
    bad_msg3: bool, barred: bool
) -> None:
    # Owner decision 2026-10-23 (spec §3.7 E2): a spoofed datagram in a real
    # client's attempt reads as a bad msg3, so a bad msg3 may not bar.
    clock = _Frozen()  # the gate's and the limiter's: nothing refills
    gate = _gate(clock)
    gate.load.note_trouble()  # under load: B's msg1 needs a cookie
    limiter = SourceLimiter(clock=clock)
    hs = _Hs()
    (hs.bad_msg3 if bad_msg3 else hs.fail).add(B)
    async with _Demux(hs, SessionTable([A_CN]), limiter=limiter, gate=gate) as run:
        first = _msg1(1)
        run.feed(first, B)
        assert await _spin(lambda: len(run.sent_to(B)) == 1)  # a cookie
        run.feed(_with_cookie(first, run.sent_to(B)[0]), B)  # proved
        assert await _spin(lambda: B in hs.started and not run.workers)
    assert run.sent_to(B)[1:] == [MSG2]  # it got as far as msg3
    assert limiter.try_start(B[0]) is not barred


@pytest.mark.parametrize(
    ("bad_msg3", "barred"), [(True, False), (False, True)], ids=["bad-msg3", "other"]
)
async def test_a_tcp_start_whose_msg3_does_not_open_bars_nothing(
    bad_msg3: bool, barred: bool
) -> None:
    limiter = SourceLimiter(clock=_Frozen())
    hs = _Hs()
    (hs.bad_msg3 if bad_msg3 else hs.fail).add(B)
    async with _Admit(hs, SessionTable([A_CN]), limiter=limiter, gate=_gate()) as run:
        conn = run.connect(B, [_msg1(1)])
        assert await _spin(lambda: conn.closed)
    assert conn.sent == [MSG2]  # it got as far as msg3
    assert limiter.try_start(B[0], shared=False) is not barred


@pytest.mark.parametrize(
    ("msg2_at", "barred"), [(1.0, False), (0.7, True)], ids=["1.0s-ago", "1.3s-ago"]
)
async def test_a_victim_whose_msg2_just_left_is_not_barred(
    msg2_at: float, barred: bool
) -> None:
    # Owner decision 2026-10-23 (spec §4.3, §3.7 E2): B's msg2 waited in the
    # TPM queue. Pushed out at 2.0 s, it is old enough to go, but less than
    # _REPLY_ALLOWANCE_S (1.29 s) after its msg2 left it did not stall.
    clock = _Frozen()  # the gate's and the limiter's: nothing refills
    gate = _gate(clock)
    gate.load.note_trouble()  # under load: every msg1 needs a cookie
    limiter = SourceLimiter(clock=clock)
    other: Addr = ("203.0.113.10", 40010)
    hs = _Hs()
    hs.late[B] = asyncio.Event()
    async with _Demux(
        hs, SessionTable([A_CN]), limiter=limiter, gate=gate, max_inflight=1
    ) as run:
        late = _msg1(1)
        run.feed(late, B)
        assert await _spin(lambda: len(run.sent_to(B)) == 1)  # a cookie
        run.feed(_with_cookie(late, run.sent_to(B)[0]), B)  # proved, starts at 0
        assert await _spin(lambda: B in hs.started)
        run.clock.now = msg2_at  # Step S's clock when msg2 leaves
        hs.late[B].set()
        assert await _spin(lambda: run.sent_to(B)[1:] == [MSG2])
        run.clock.now = 2.0  # B is past _PUSH_OUT_AFTER_S
        first = _msg1(2)
        run.feed(first, other)
        assert await _spin(lambda: len(run.sent_to(other)) == 1)
        run.feed(_with_cookie(first, run.sent_to(other)[0]), other)
        assert await _spin(lambda: len(run.clients) == 1)
    assert run.clients[0].peer == other  # B was pushed out either way
    assert limiter.try_start(B[0]) is not barred


@pytest.mark.parametrize(
    ("msg2_at", "barred"), [(1.0, False), (0.7, True)], ids=["1.0s-ago", "1.3s-ago"]
)
async def test_a_tcp_victim_whose_msg2_just_left_is_not_barred(
    msg2_at: float, barred: bool
) -> None:
    limiter = SourceLimiter(clock=_Frozen())
    other: Addr = ("203.0.113.10", 40010)
    hs = _Hs()
    hs.late[B] = asyncio.Event()
    async with _Admit(
        hs, SessionTable([A_CN]), limiter=limiter, gate=_gate(), max_inflight=1
    ) as run:
        late = run.connect(B, [_msg1(1)])  # accepted at 0
        assert await _spin(lambda: B in hs.started)
        run.clock.now = msg2_at  # Step S's clock when msg2 leaves
        hs.late[B].set()
        assert await _spin(lambda: late.sent == [MSG2])
        run.clock.now = 2.0  # B is past _PUSH_OUT_AFTER_S
        run.connect(other, [_msg1(2)])  # a stranger
        assert await _spin(lambda: late.closed and len(run.clients) == 1)
    assert run.clients[0].peer == other
    assert limiter.try_start(B[0], shared=False) is not barred
