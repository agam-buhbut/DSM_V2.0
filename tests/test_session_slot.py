"""SessionSlot: who holds the server's one session and who may take it over
(step R). A fake clock; no event loop and no sockets."""

from __future__ import annotations

import hashlib
import logging

import pytest

from dsm.crypto.handshake import ClientRefusedError, VerifiedClient
from dsm.net import session_slot as slot_mod
from dsm.net.session_slot import SessionSlot

A = VerifiedClient(cn="dsm-a-client", noise_static=b"\x01" * 32)
A_NEW_KEY = VerifiedClient(cn="dsm-a-client", noise_static=b"\x02" * 32)
B = VerifiedClient(cn="dsm-b-client", noise_static=b"\x03" * 32)


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _hold(slot: SessionSlot, client: VerifiedClient) -> None:
    """``client`` wins an idle accept: it holds the session."""
    attempt = object()
    slot.admit(attempt, client, session_live=False)
    slot.confirm(attempt)


def _take_over(slot: SessionSlot, client: VerifiedClient) -> None:
    attempt = object()
    slot.admit(attempt, client, session_live=True)
    slot.confirm(attempt)


def _lines(caplog: pytest.LogCaptureFixture) -> list[tuple[int, str]]:
    return [
        (r.levelno, r.getMessage())
        for r in caplog.records
        if r.name == "dsm.net.session_slot"
    ]


def test_the_budget_is_three_at_once_then_one_a_minute() -> None:
    assert slot_mod.REPLACE_BURST == 3.0
    assert slot_mod.REPLACE_RATE == 1.0 / 60.0


def test_idle_one_attempt_at_a_time_gets_past_the_check() -> None:
    slot = SessionSlot(clock=_Clock())
    first, second = object(), object()
    slot.admit(first, A, session_live=False)
    with pytest.raises(ClientRefusedError):
        slot.admit(second, B, session_live=False)
    assert slot.admitted is first
    slot.release(first)
    assert slot.admitted is None
    slot.admit(second, B, session_live=False)
    slot.confirm(second)
    assert slot.holder == B
    assert slot.admitted is None
    slot.clear()
    assert slot.holder is None


def test_release_of_an_attempt_that_holds_nothing_changes_nothing() -> None:
    slot = SessionSlot(clock=_Clock())
    first = object()
    slot.admit(first, A, session_live=False)
    slot.release(object())
    assert slot.admitted is first


def test_confirm_needs_a_matching_admit() -> None:
    slot = SessionSlot(clock=_Clock())
    with pytest.raises(RuntimeError):
        slot.confirm(object())
    slot.admit(object(), A, session_live=False)
    with pytest.raises(RuntimeError):
        slot.confirm(object())


def test_the_first_client_is_not_logged_as_a_reconnect(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger="dsm.net.session_slot")
    _hold(SessionSlot(clock=_Clock()), A)
    assert _lines(caplog) == []


def test_in_a_session_the_same_client_takes_over_with_one_info_line(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger="dsm.net.session_slot")
    slot = SessionSlot(clock=_Clock())
    _hold(slot, A)
    attempt = object()
    slot.admit(attempt, A, session_live=True)
    assert _lines(caplog) == []  # nothing until it wins
    slot.confirm(attempt)
    assert _lines(caplog) == [
        (
            logging.INFO,
            "client reconnected (client_cn=dsm-a-client); ending its old session",
        )
    ]
    assert slot.holder == A


def test_in_a_session_another_client_is_refused_with_few_info_lines(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger="dsm.net.session_slot")
    clock = _Clock()
    slot = SessionSlot(clock=clock)
    _hold(slot, A)
    for _ in range(5):
        with pytest.raises(ClientRefusedError):
            slot.admit(object(), B, session_live=True)
    assert _lines(caplog) == [
        (
            logging.INFO,
            "handshake refused: another client is connected (client_cn=dsm-b-client)",
        )
    ]
    assert slot.holder == A
    assert slot.admitted is None
    clock.now += 10.0
    with pytest.raises(ClientRefusedError):
        slot.admit(object(), B, session_live=True)
    assert _lines(caplog)[-1] == (
        logging.INFO,
        "handshake refused: another client is connected (client_cn=dsm-b-client)"
        " (4 more in the last 10 s)",
    )


def test_in_a_session_with_no_known_holder_everyone_is_refused() -> None:
    slot = SessionSlot(clock=_Clock())
    with pytest.raises(ClientRefusedError):
        slot.admit(object(), A, session_live=True)
    assert slot.admitted is None


def test_three_quick_takeovers_then_one_a_minute(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger="dsm.net.session_slot")
    clock = _Clock()
    slot = SessionSlot(clock=clock)
    _hold(slot, A)
    for _ in range(3):
        _take_over(slot, A)
    with pytest.raises(ClientRefusedError):
        slot.admit(object(), A, session_live=True)
    assert _lines(caplog) == [
        (
            logging.WARNING,
            "client_cn=dsm-a-client reconnected too often; keeping its current "
            "session (two devices with one name?)",
        )
    ]
    assert slot.admitted is None
    clock.now += 59.0
    with pytest.raises(ClientRefusedError):
        slot.admit(object(), A, session_live=True)
    clock.now += 1.5  # a token is back a minute after the third takeover
    _take_over(slot, A)
    assert slot.holder == A


def test_each_name_has_its_own_budget() -> None:
    slot = SessionSlot(clock=_Clock())
    _hold(slot, A)
    for _ in range(3):
        _take_over(slot, A)
    slot.clear()  # A's session ended by itself
    _hold(slot, B)  # B connects to the idle server
    for _ in range(3):
        _take_over(slot, B)
    with pytest.raises(ClientRefusedError):
        slot.admit(object(), B, session_live=True)


def test_a_refused_attempt_spends_no_budget() -> None:
    """Only an attempt that gets past every check spends a token."""
    slot = SessionSlot(clock=_Clock())
    _hold(slot, A)
    first = object()
    slot.admit(first, A, session_live=True)  # spends one
    for _ in range(10):
        with pytest.raises(ClientRefusedError):  # another one is finishing
            slot.admit(object(), A, session_live=True)
        with pytest.raises(ClientRefusedError):
            slot.admit(object(), B, session_live=True)
    slot.release(first)  # it failed after all; its token stays spent
    _take_over(slot, A)
    _take_over(slot, A)
    with pytest.raises(ClientRefusedError):
        slot.admit(object(), A, session_live=True)


def test_a_new_device_key_logs_one_warning_with_both_hashes(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="dsm.net.session_slot")
    slot = SessionSlot(clock=_Clock())
    _hold(slot, A)
    _take_over(slot, A_NEW_KEY)
    new = hashlib.sha256(b"\x02" * 32).hexdigest()[:16]
    old = hashlib.sha256(b"\x01" * 32).hexdigest()[:16]
    warnings = [m for level, m in _lines(caplog) if level == logging.WARNING]
    assert warnings == [
        f"client_cn=dsm-a-client reconnected with a different device key "
        f"(noise_static_sha256={new}, was {old}); if this repeats, two devices "
        f"share this name"
    ]
    assert all((b"\x02" * 32).hex() not in m for _, m in _lines(caplog))
    assert slot.holder == A_NEW_KEY


def test_the_same_device_key_logs_no_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger="dsm.net.session_slot")
    slot = SessionSlot(clock=_Clock())
    _hold(slot, A)
    _take_over(slot, A)
    assert _lines(caplog) == []
