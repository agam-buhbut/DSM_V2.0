"""The always-on handshake acceptor (spec §2.7): ClientAcceptor, its UDP
demux, TCP admit loop and worker, with the known-address lane's cookie
step, E3 and the failed-start penalty (spec §3.7), and the kept meanings of
the old in-session accept's tests (spec §7 item 2). Handshakes are scripted
fakes; the session table, the limiter and the gate are real; clocks are
fake. No sockets; nothing waits on the wall clock."""

from __future__ import annotations

import asyncio

from dsm.net import handshake_acceptor as hsa

Addr = tuple[str, int]
KNOWN = "198.51.100.7"
STRANGER = "203.0.113.1"


async def _forever() -> None:
    await asyncio.Event().wait()


def _track(
    made: dict[asyncio.Task[None], hsa._Attempt], rec: hsa._Attempt
) -> asyncio.Task[None]:
    """Give ``rec`` a running task of its own, as a real attempt has."""
    task = asyncio.ensure_future(_forever())
    made[task] = rec
    return task


async def _cancel(made: dict[asyncio.Task[None], hsa._Attempt]) -> None:
    for task in made:
        task.cancel()
    await asyncio.gather(*made, return_exceptions=True)


def _never(_task: object) -> bool:
    return False


def _known(ip: str) -> bool:
    return ip == KNOWN


async def test_a_known_start_may_push_out_a_young_stranger() -> None:
    made: dict[asyncio.Task[None], hsa._Attempt] = {}
    young = _track(made, hsa._Attempt(ip=STRANGER, started=0.0, signing=False))
    try:
        assert hsa._choose_push_out(
            made, 0.1, KNOWN, pool_full=True, past_admit=_never, is_known=_known
        ) == (young, hsa._PassedOn.SLOT_ONLY)
        # A stranger's start still waits for the age (spec §4.3).
        assert (
            hsa._choose_push_out(
                made,
                0.1,
                "203.0.113.2",
                pool_full=True,
                past_admit=_never,
                is_known=_known,
            )
            is None
        )
    finally:
        await _cancel(made)


async def test_a_known_start_never_takes_one_signing_or_past_admit() -> None:
    made: dict[asyncio.Task[None], hsa._Attempt] = {}
    _track(made, hsa._Attempt(ip=STRANGER, started=0.0, signing=True))
    admitted = _track(made, hsa._Attempt(ip="203.0.113.2", started=0.0, signing=False))
    try:
        for now in (0.1, 10.0):  # young (E3's any-age path) and old
            assert (
                hsa._choose_push_out(
                    made,
                    now,
                    KNOWN,
                    pool_full=True,
                    past_admit=lambda task: task is admitted,
                    is_known=_known,
                )
                is None
            )
    finally:
        await _cancel(made)


async def test_a_known_address_attempt_still_needs_the_age() -> None:
    made: dict[asyncio.Task[None], hsa._Attempt] = {}
    other = "198.51.100.8"
    _track(made, hsa._Attempt(ip=other, started=0.0, signing=False))

    def known(ip: str) -> bool:
        return ip in (KNOWN, other)

    try:
        for now, pushable in ((1.4, False), (1.5, True)):
            push = hsa._choose_push_out(
                made, now, KNOWN, pool_full=True, past_admit=_never, is_known=known
            )
            assert (push is not None) is pushable
    finally:
        await _cancel(made)


async def test_a_known_start_takes_the_oldest_it_may_push_out() -> None:
    made: dict[asyncio.Task[None], hsa._Attempt] = {}
    _track(made, hsa._Attempt(ip=STRANGER, started=0.5, signing=False))
    oldest = _track(made, hsa._Attempt(ip="203.0.113.2", started=0.2, signing=False))
    try:
        assert hsa._choose_push_out(
            made, 0.6, KNOWN, pool_full=True, past_admit=_never, is_known=_known
        ) == (oldest, hsa._PassedOn.SLOT_ONLY)
    finally:
        await _cancel(made)


async def test_e3_needs_a_full_pool_and_leaves_case_1_alone() -> None:
    made: dict[asyncio.Task[None], hsa._Attempt] = {}
    _track(made, hsa._Attempt(ip=STRANGER, started=0.0, signing=False))
    try:
        # A free slot: nothing is pushed out.
        assert (
            hsa._choose_push_out(
                made, 0.1, KNOWN, pool_full=False, past_admit=_never, is_known=_known
            )
            is None
        )
        # The known address at its own cap: only its own oldest, at the age.
        for _ in range(2):
            _track(made, hsa._Attempt(ip=KNOWN, started=0.0, signing=False))
        assert (
            hsa._choose_push_out(
                made, 0.1, KNOWN, pool_full=True, past_admit=_never, is_known=_known
            )
            is None
        )
    finally:
        await _cancel(made)


def test_a_record_is_not_proved_unless_its_start_says_so() -> None:
    assert not hsa._Attempt(ip=STRANGER, started=0.0, signing=False).proved
    assert hsa._Attempt(ip=STRANGER, started=0.0, signing=False, proved=True).proved
