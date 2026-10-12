"""Step S, slot hardening (spec §4): the gate plumbing, the slot rule, the TCP
first-frame deadline and shared charge, push-out over UDP and TCP, and the
start WARNING. Handshakes are scripted fakes; ages come from Step S's own
injected clock, never the limiter's (re-review I5); nothing waits on the wall
clock. Laptop: run with --noconftest (tests/conftest.py imports dsm.server,
which needs the new tuncore); the run_server tests are box-only.
"""

from __future__ import annotations

import pytest

from dsm.core.config import MAX_INFLIGHT_HANDSHAKES
from dsm.net import handshake_acceptor as hsa
from dsm.net.handshake_gate import (
    GLOBAL_START_BURST,
    GLOBAL_START_RATE,
    IN_SESSION_START_BURST,
    PER_SOURCE_BURST,
    PER_SOURCE_INFLIGHT,
    SourceLimiter,
)
from tests.test_handshake_acceptor_limits import _Frozen


def test_shared_false_charges_only_the_per_address_limits() -> None:
    limiter = SourceLimiter(clock=_Frozen())
    for i in range(int(GLOBAL_START_BURST)):
        assert limiter.try_start(f"203.0.113.{i}")
    assert not limiter.try_start("203.0.113.200")  # the overall limit is spent
    # A TCP connection at accept pays only its address's limits.
    assert limiter.try_start("198.51.100.9", shared=False)


def test_try_shared_charges_the_overall_and_newcomer_limits() -> None:
    limiter = SourceLimiter(clock=_Frozen())
    for i in range(int(IN_SESSION_START_BURST)):
        assert limiter.try_shared(f"198.51.100.{i}", in_session=True)
    assert not limiter.try_shared("198.51.100.50", in_session=True)
    # That refusal spent nothing: the overall tokens the newcomer calls did
    # not use are all still there.
    left = int(GLOBAL_START_BURST) - int(IN_SESSION_START_BURST)
    for i in range(left):
        assert limiter.try_shared(f"198.51.100.{100 + i}")
    assert not limiter.try_shared("198.51.100.200")


def test_an_inherited_share_skips_the_cap_and_adds_nothing() -> None:
    limiter = SourceLimiter(clock=_Frozen())
    ip = "198.51.100.9"
    for _ in range(PER_SOURCE_INFLIGHT):
        assert limiter.try_start(ip)
    assert not limiter.try_start(ip)  # at the in-flight cap
    assert limiter.try_start(ip, inherits_share=True)
    for _ in range(PER_SOURCE_INFLIGHT):
        limiter.finish(ip)
    with pytest.raises(RuntimeError):
        limiter.finish(ip)  # the inherit added no running attempt


def test_an_inherited_share_still_needs_the_address_rate() -> None:
    limiter = SourceLimiter(clock=_Frozen())
    ip = "198.51.100.9"
    for _ in range(PER_SOURCE_INFLIGHT):
        assert limiter.try_start(ip)
    for _ in range(int(PER_SOURCE_BURST) - PER_SOURCE_INFLIGHT):
        assert limiter.try_start(ip, inherits_share=True)
    assert not limiter.try_start(ip, inherits_share=True)  # the rate is spent


def test_a_tcp_inherit_pays_only_its_address() -> None:
    limiter = SourceLimiter(clock=_Frozen())
    ip = "198.51.100.9"
    for _ in range(PER_SOURCE_INFLIGHT):
        assert limiter.try_start(ip, shared=False)
    for i in range(int(GLOBAL_START_BURST)):
        assert limiter.try_shared(f"203.0.113.{i}")  # spend the overall limit
    assert limiter.try_start(ip, shared=False, inherits_share=True)


def test_an_inherit_still_pays_the_overall_limit() -> None:
    limiter = SourceLimiter(clock=_Frozen())
    ip = "198.51.100.9"
    for _ in range(PER_SOURCE_INFLIGHT):
        assert limiter.try_start(ip, shared=False)
    for i in range(int(GLOBAL_START_BURST)):
        assert limiter.try_shared(f"203.0.113.{i}")  # spend the overall limit
    assert not limiter.try_start(ip, inherits_share=True)
    # The refusal spent no address token: the one rate token left is still
    # there for a start that needs only the address.
    assert limiter.try_start(ip, shared=False, inherits_share=True)


def test_an_inherit_takes_one_overall_token() -> None:
    limiter = SourceLimiter(clock=_Frozen())
    ip = "198.51.100.9"
    for _ in range(PER_SOURCE_INFLIGHT):
        assert limiter.try_start(ip, shared=False)
    assert limiter.try_start(ip, inherits_share=True)
    for i in range(int(GLOBAL_START_BURST) - 1):
        assert limiter.try_shared(f"203.0.113.{i}")
    assert not limiter.try_shared("203.0.113.200")


def test_an_in_session_inherit_takes_the_newcomer_token_too() -> None:
    limiter = SourceLimiter(clock=_Frozen())
    ip = "198.51.100.9"
    for _ in range(PER_SOURCE_INFLIGHT):
        assert limiter.try_start(ip, shared=False)
    assert limiter.try_start(ip, in_session=True, inherits_share=True)
    assert not limiter.try_shared("203.0.113.1", in_session=True)
    # The overall limit lost exactly one token to that inherit.
    for i in range(int(GLOBAL_START_BURST) - 1):
        assert limiter.try_shared(f"203.0.113.{10 + i}")
    assert not limiter.try_shared("203.0.113.200")


def test_a_per_address_only_start_ignores_in_session() -> None:
    limiter = SourceLimiter(clock=_Frozen())
    assert limiter.try_start("198.51.100.9", in_session=True, shared=False)
    # Nothing shared was spent: the one newcomer token and every overall
    # token are still there.
    assert limiter.try_shared("203.0.113.1", in_session=True)
    for i in range(int(GLOBAL_START_BURST) - 1):
        assert limiter.try_shared(f"203.0.113.{10 + i}")
    assert not limiter.try_shared("203.0.113.200")


def test_the_step_s_numbers() -> None:
    assert hsa._TCP_FIRST_FRAME_DEADLINE == 3.0
    assert hsa._PUSH_OUT_AFTER_S == 1.5
    assert hsa._SIGNING_ALLOWANCE_S == 0.25
    assert hsa._SERVER_SIGNING_TIME_S == 0.21


def test_slot_rule_conditions_2_and_3_hold_for_the_code_constants() -> None:
    w = hsa._PUSH_OUT_AFTER_S + hsa._SIGNING_ALLOWANCE_S
    # (3) The TPM signs faster than the overall limit lets strangers start.
    assert GLOBAL_START_RATE * hsa._SERVER_SIGNING_TIME_S < 1
    # (2) The deepest queue strangers can build drains inside W, for every
    # slot count the config allows (more slots never deepen it).
    for slots in range(1, MAX_INFLIGHT_HANDSHAKES + 1):
        assert min(slots, GLOBAL_START_BURST) * hsa._SERVER_SIGNING_TIME_S < w


def test_slot_rule_ok_checks_condition_1() -> None:
    assert hsa._slot_rule_ok(8)  # the default meets it: 8 > 4 x 1.75
    assert not hsa._slot_rule_ok(7)  # 7 is not more than 7
    assert not hsa._slot_rule_ok(1)
    assert hsa._slot_rule_ok(16)
