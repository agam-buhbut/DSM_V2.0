"""The start limits' known-address lane (spec §3.7): an address from which a
CN finished a full, admitted handshake in this run skips the shared start
limits and has its own cookie-reply budget; and the failed-start penalty
(E2). Fake clocks; no event loop, no sockets."""

from __future__ import annotations

import logging

import pytest

from dsm.net import handshake_gate as gate
from dsm.net.handshake_gate import (
    COOKIE_REPLY_BURST,
    GLOBAL_START_BURST,
    IN_SESSION_START_BURST,
    KNOWN_ADDRESSES_PER_CN,
    KNOWN_COOKIE_REPLY_BURST,
    KNOWN_COOKIE_REPLY_RATE,
    PER_SOURCE_BURST,
    PER_SOURCE_INFLIGHT,
    GateKeys,
    HandshakeGate,
    SourceLimiter,
)
from tests.test_handshake_acceptor_limits import _Frozen

KNOWN = "198.51.100.7"
CN = "dsm-a-client"


def _spend_overall(limiter: SourceLimiter) -> None:
    """Use up the overall budget (a frozen clock never refills it)."""
    for i in range(int(GLOBAL_START_BURST)):
        assert limiter.try_start(f"192.0.2.{i}")


def test_the_lane_numbers() -> None:
    assert KNOWN_ADDRESSES_PER_CN == 4
    assert KNOWN_COOKIE_REPLY_RATE == 0.5
    assert KNOWN_COOKIE_REPLY_BURST == 6.0


def test_a_known_address_skips_the_overall_and_newcomer_limits() -> None:
    limiter = SourceLimiter(clock=_Frozen())
    limiter.note_known(KNOWN, CN)
    _spend_overall(limiter)
    assert not limiter.try_start("203.0.113.9", in_session=True)  # a stranger
    assert limiter.try_start(KNOWN, in_session=True)


def test_a_known_address_still_needs_its_per_address_limits() -> None:
    limiter = SourceLimiter(clock=_Frozen())
    limiter.note_known(KNOWN, CN)
    for _ in range(PER_SOURCE_INFLIGHT):
        assert limiter.try_start(KNOWN)
    assert not limiter.try_start(KNOWN)  # its in-flight cap
    for _ in range(PER_SOURCE_INFLIGHT):
        limiter.finish(KNOWN)
    for _ in range(int(PER_SOURCE_BURST) - PER_SOURCE_INFLIGHT):
        assert limiter.try_start(KNOWN)
    assert not limiter.try_start(KNOWN)  # its start rate


def test_a_known_start_spends_no_shared_token() -> None:
    limiter = SourceLimiter(clock=_Frozen())
    limiter.note_known(KNOWN, CN)
    assert limiter.try_start(KNOWN, in_session=True)
    # Every newcomer token and every overall token is still there.
    for i in range(int(IN_SESSION_START_BURST)):
        assert limiter.try_start(f"203.0.113.{i}", in_session=True)
    for i in range(int(GLOBAL_START_BURST - IN_SESSION_START_BURST)):
        assert limiter.try_start(f"192.0.2.{i}")
    assert not limiter.try_start("192.0.2.200")


def test_try_shared_charges_a_stranger_and_not_a_known_address() -> None:
    limiter = SourceLimiter(clock=_Frozen())
    limiter.note_known(KNOWN, CN)
    for i in range(int(GLOBAL_START_BURST)):
        assert limiter.try_shared(f"203.0.113.{i}")
    assert not limiter.try_shared("203.0.113.200")
    assert limiter.try_shared(KNOWN, in_session=True)


def test_a_cn_keeps_its_newest_known_addresses() -> None:
    limiter = SourceLimiter(clock=_Frozen())
    ips = [f"198.51.100.{i}" for i in range(KNOWN_ADDRESSES_PER_CN + 1)]
    for ip in ips:
        limiter.note_known(ip, CN)
    assert not limiter.is_known(ips[0])  # used longest ago: dropped
    assert all(limiter.is_known(ip) for ip in ips[1:])


def test_a_known_address_used_again_becomes_the_newest() -> None:
    limiter = SourceLimiter(clock=_Frozen())
    ips = [f"198.51.100.{i}" for i in range(KNOWN_ADDRESSES_PER_CN)]
    for ip in ips:
        limiter.note_known(ip, CN)
    limiter.note_known(ips[0], CN)  # the device is back on its first network
    limiter.note_known("198.51.100.99", CN)
    assert limiter.is_known(ips[0])
    assert not limiter.is_known(ips[1])


def test_forget_cn_drops_its_addresses() -> None:
    limiter = SourceLimiter(clock=_Frozen())
    limiter.note_known(KNOWN, CN)
    limiter.forget_cn(CN)
    assert not limiter.is_known(KNOWN)
    assert not limiter.take_known_cookie(KNOWN)
    limiter.forget_cn("dsm-never-seen")  # nothing to forget: no error


def test_an_address_known_for_two_cns_stays_until_both_forget_it() -> None:
    limiter = SourceLimiter(clock=_Frozen())
    limiter.note_known(KNOWN, "dsm-a-client")
    limiter.note_known(KNOWN, "dsm-b-client")
    limiter.forget_cn("dsm-a-client")
    assert limiter.is_known(KNOWN)
    limiter.forget_cn("dsm-b-client")
    assert not limiter.is_known(KNOWN)


def test_each_known_address_has_its_own_cookie_budget() -> None:
    clock = _Frozen()
    limiter = SourceLimiter(clock=clock)
    other = "198.51.100.8"
    limiter.note_known(KNOWN, CN)
    limiter.note_known(other, CN)
    for _ in range(int(KNOWN_COOKIE_REPLY_BURST)):
        assert limiter.take_known_cookie(KNOWN)
    assert not limiter.take_known_cookie(KNOWN)  # dry
    assert limiter.take_known_cookie(other)  # its own budget is untouched
    clock.now += 1 / KNOWN_COOKIE_REPLY_RATE
    assert limiter.take_known_cookie(KNOWN)  # one more 2 s later
    assert not limiter.take_known_cookie(KNOWN)
    assert not limiter.take_known_cookie("203.0.113.9")  # a stranger has none


def test_nothing_about_known_addresses_is_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger="dsm")
    limiter = SourceLimiter(clock=_Frozen())
    limiter.note_known(KNOWN, CN)
    _spend_overall(limiter)
    assert limiter.try_start(KNOWN, in_session=True)
    while limiter.take_known_cookie(KNOWN):
        pass
    limiter.forget_cn(CN)
    assert caplog.records == []


def test_a_known_cookie_reply_spends_no_shared_budget() -> None:
    hg = HandshakeGate(
        GateKeys.from_ca_der(bytes.fromhex("3003020101"), "dsm-test-server"),
        clock=_Frozen(),
        wall_clock=lambda: 1_800_000_000.0,
    )
    frame = bytes(gate.FRAME_SIZE)
    # First, while the shared budget is full: these must not spend it.
    for _ in range(3):
        assert hg.cookie_reply(frame, (KNOWN, 1), shared_budget=False) is not None
    for i in range(int(COOKIE_REPLY_BURST)):
        assert hg.cookie_reply(frame, (f"203.0.113.{i}", 1)) is not None
    assert hg.cookie_reply(frame, ("203.0.113.200", 1)) is None  # shared: spent
    assert hg.cookie_reply(frame, (KNOWN, 1), shared_budget=False) is not None
