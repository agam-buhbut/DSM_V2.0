"""Carry items of parts A and B of the multi-client work (spec §2.7, §3.7):
tests that pin behaviour earlier tasks left without one, and the guard on a
second ``ClientAcceptor.run()``. Helpers come from the committed acceptor test
files; nothing here edits them."""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest

from dsm.net import handshake_acceptor as hsa
from dsm.net.handshake_gate import SourceLimiter
from dsm.net.session_slot import SessionTable
from tests.test_client_acceptor import (
    A2,
    A_CN,
    MSG2,
    A,
    B,
    _acceptor,
    _Demux,
    _frame,
    _gate,
    _Hs,
    _msg1,
    _with_cookie,
)
from tests.test_handshake_acceptor_limits import _Frozen, _spin, _Transport, _yield


async def test_a_second_run_without_stop_raises() -> None:
    clients: list[hsa.AcceptedClient] = []
    acceptor = _acceptor(SessionTable([A_CN]), clients.append, udp=_Transport())
    runs: list[asyncio.Future[None]] = []
    with patch("dsm.crypto.handshake.server_handshake", new=_Hs()):
        try:
            runs.append(asyncio.ensure_future(acceptor.run()))
            assert await _spin(lambda: acceptor._serving is not None)
            with pytest.raises(RuntimeError, match="stop"):
                await asyncio.wait_for(acceptor.run(), 1.0)
            await acceptor.stop()
            await runs[0]
            # After stop() a new run() serves.
            acceptor.offer(_frame(A), A)
            runs.append(asyncio.ensure_future(acceptor.run()))
            assert await _spin(lambda: len(clients) == 1)
            assert not runs[1].done()  # no late crash
        finally:
            # Cancel rather than await: a run that wrongly served twice
            # leaves a loop that stop() can no longer reach.
            for run in runs:
                run.cancel()
            await asyncio.gather(*runs, return_exceptions=True)
            await asyncio.wait_for(acceptor.stop(), 5.0)


async def test_a_run_called_while_stop_is_draining_raises() -> None:
    hs = _Hs()
    hs.hold[A] = asyncio.Event()
    acceptor = _acceptor(SessionTable([A_CN]), None, udp=_Transport())
    draining = asyncio.Event()
    drain = hsa._cancel_and_drain

    async def _slow_drain(tasks: set[asyncio.Task[None]]) -> None:
        await draining.wait()
        await drain(tasks)

    with patch("dsm.crypto.handshake.server_handshake", new=hs):
        with patch.object(hsa, "_cancel_and_drain", new=_slow_drain):
            first = asyncio.ensure_future(acceptor.run())
            acceptor.offer(_frame(A), A)
            assert await _spin(lambda: hs.admitted == [A])
            stopping = asyncio.ensure_future(acceptor.stop())
            await _yield()  # stop() is now inside its drain
            try:
                with pytest.raises(RuntimeError, match="stop"):
                    await asyncio.wait_for(acceptor.run(), 1.0)
            finally:
                draining.set()
                await asyncio.wait_for(stopping, 5.0)
                first.cancel()
                await asyncio.gather(first, return_exceptions=True)


async def test_a_run_scheduled_before_a_stop_serves_until_the_next_stop() -> None:
    clients: list[hsa.AcceptedClient] = []
    acceptor = _acceptor(SessionTable([A_CN]), clients.append, udp=_Transport())
    with patch("dsm.crypto.handshake.server_handshake", new=_Hs()):
        scheduled = asyncio.ensure_future(acceptor.run())  # has not started
        await acceptor.stop()
        acceptor.offer(_frame(A), A)
        try:
            assert await _spin(lambda: len(clients) == 1)
        finally:
            await acceptor.stop()
            await scheduled


async def test_an_attempt_held_past_admit_gives_its_cn_back_on_a_restart() -> None:
    hs = _Hs()
    hs.hold[A] = asyncio.Event()  # never set: A waits after the table's yes
    clients: list[hsa.AcceptedClient] = []
    acceptor = _acceptor(SessionTable([A_CN]), clients.append, udp=_Transport())
    with patch("dsm.crypto.handshake.server_handshake", new=hs):
        first = asyncio.ensure_future(acceptor.run())
        try:
            acceptor.offer(_frame(A), A)
            assert await _spin(lambda: hs.admitted == [A])
            # What _run_acceptor does after a crash: stop, then run again.
            await acceptor.stop()
        finally:
            first.cancel()
            await asyncio.gather(first, return_exceptions=True)
            await acceptor.stop()
        # The same CN from a new address: refused if A's attempt still held
        # the CN ("another handshake is finishing").
        acceptor.offer(_frame(A2), A2)
        second = asyncio.ensure_future(acceptor.run())
        try:
            assert await _spin(lambda: len(clients) == 1)
        finally:
            await acceptor.stop()
            await second
    assert clients[0].peer == A2
    assert clients[0].client.cn == A_CN


async def test_a_udp_stranger_cut_by_a_stop_costs_nothing() -> None:
    clock = _Frozen()
    gate = _gate(clock)
    gate.load.note_trouble()  # every new msg1 needs a cookie
    limiter = SourceLimiter(clock=clock)
    hs = _Hs()
    hs.stall.add(B)
    async with _Demux(hs, SessionTable([A_CN]), limiter=limiter, gate=gate) as run:
        first = _msg1(1)
        run.feed(first, B)
        assert await _spin(lambda: len(run.sent_to(B)) == 1)
        run.feed(_with_cookie(first, run.sent_to(B)[0]), B)  # proved
        assert await _spin(lambda: run.sent_to(B)[1:] == [MSG2])  # then stalls
    # Leaving the harness cancelled its worker with passed_on None: a stop,
    # not a stall. The twin of the TCP test in test_client_acceptor.py.
    assert limiter.try_start(B[0])
