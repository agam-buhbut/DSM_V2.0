"""SessionTable (multi-client spec §2.3, §2.4): tunnel addresses by allowlist
order, one SessionSlot per CN, and the live sessions by CN, tunnel address
and hint. A fake clock; no event loop and no sockets."""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import logging
from collections.abc import Sequence

import pytest

from dsm.crypto.handshake import ClientRefusedError, VerifiedClient
from dsm.net.session_slot import SESSION_QUEUE_PACKETS, ServerSession, SessionTable

A = VerifiedClient(cn="dsm-a-client", noise_static=b"\x01" * 32)
A_NEW_KEY = VerifiedClient(cn="dsm-a-client", noise_static=b"\x02" * 32)
B = VerifiedClient(cn="dsm-b-client", noise_static=b"\x03" * 32)
CNS = ("dsm-a-client", "dsm-b-client")
A_TAKEOVER = "client reconnected (client_cn=dsm-a-client); ending its old session"
PEER_A = ("198.51.100.7", 40000)
PEER_A2 = ("198.51.100.7", 40001)
PEER_B = ("203.0.113.9", 51000)


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _table(cns: Sequence[str] = CNS) -> SessionTable:
    return SessionTable(cns, clock=_Clock())


def _confirm(table: SessionTable, client: VerifiedClient) -> None:
    """One attempt of ``client`` passes admit and confirm."""
    attempt = object()
    table.admit(attempt, client)
    table.confirm(attempt)


def _lines(caplog: pytest.LogCaptureFixture) -> list[tuple[int, str]]:
    return [
        (r.levelno, r.getMessage())
        for r in caplog.records
        if r.name == "dsm.net.session_slot"
    ]


class _Secret:
    def __repr__(self) -> str:
        return "SECRET-KEYS"


def _session(
    table: SessionTable,
    client: VerifiedClient,
    number: int = 1,
    peer: tuple[str, int] = PEER_A,
) -> ServerSession:
    tunnel = table.assignment_for(client.cn)
    assert tunnel is not None
    return ServerSession(
        number=number,
        client=client,
        tunnel=tunnel,
        session_keys=_Secret(),  # the table never touches keys
        transport=object(),
        shutdown=asyncio.Event(),
        tun_queue=asyncio.Queue(maxsize=SESSION_QUEUE_PACKETS),
        peer=peer,
    )


def _connect(
    table: SessionTable,
    client: VerifiedClient,
    number: int = 1,
    peer: tuple[str, int] = PEER_A,
) -> ServerSession:
    """``client`` finishes a handshake from ``peer`` and becomes a session."""
    _confirm(table, client)
    session = _session(table, client, number, peer)
    table.add(session)
    return session


def _packed(address: str) -> bytes:
    return ipaddress.IPv4Address(address).packed


def test_the_nth_name_gets_the_nth_address() -> None:
    table = _table(("dsm-c-client", "dsm-a-client", "dsm-b-client"))
    c = table.assignment_for("dsm-c-client")
    a = table.assignment_for("dsm-a-client")
    b = table.assignment_for("dsm-b-client")
    assert c is not None and a is not None and b is not None
    assert [str(t.client) for t in (c, a, b)] == ["10.8.0.2", "10.8.0.3", "10.8.0.4"]
    assert str(a.server) == "10.8.0.1"
    assert a.prefix_len == 24
    assert table.addresses() == {
        "10.8.0.2": "dsm-c-client",
        "10.8.0.3": "dsm-a-client",
        "10.8.0.4": "dsm-b-client",
    }
    assert table.assignment_for("dsm-unknown-client") is None


def test_names_past_the_pool_get_no_address_and_one_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger="dsm.net.session_slot")
    cns = [f"dsm-{i:03d}-client" for i in range(255)]
    table = _table(cns)
    last = table.assignment_for(cns[252])
    assert last is not None
    assert str(last.client) == "10.8.0.254"
    assert table.assignment_for(cns[253]) is None
    assert table.assignment_for(cns[254]) is None
    assert len(table.addresses()) == 253
    assert _lines(caplog) == [
        (
            logging.WARNING,
            "the allowlist has 255 names; only the first 253 get a tunnel address",
        )
    ]


def test_a_full_pool_logs_nothing(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING, logger="dsm.net.session_slot")
    _table([f"dsm-{i:03d}-client" for i in range(253)])
    assert _lines(caplog) == []


def test_a_name_past_the_pool_is_refused_at_its_handshake(
    caplog: pytest.LogCaptureFixture,
) -> None:
    cns = [f"dsm-{i:03d}-client" for i in range(254)]
    table = _table(cns)
    caplog.set_level(logging.WARNING, logger="dsm.net.session_slot")
    caplog.clear()
    late = VerifiedClient(cn=cns[253], noise_static=b"\x04" * 32)
    for _ in range(2):  # the second inside the same 10 s: no second line
        attempt = object()
        with pytest.raises(ClientRefusedError):
            table.admit(attempt, late)
        assert not table.is_admitted(attempt)
    assert _lines(caplog) == [
        (
            logging.WARNING,
            "client_cn=dsm-253-client has no tunnel address (its allowlist line "
            "is past the first 253); refused",
        )
    ]


def test_two_cns_are_admitted_at_once() -> None:
    table = _table()
    first, second = object(), object()
    assert str(table.admit(first, A).client) == "10.8.0.2"
    assert str(table.admit(second, B).client) == "10.8.0.3"
    assert table.is_admitted(first)
    assert table.is_admitted(second)
    assert table.confirm(first) == (A, table.assignment_for("dsm-a-client"))
    assert table.confirm(second) == (B, table.assignment_for("dsm-b-client"))
    assert not table.is_admitted(first)


def test_a_second_attempt_of_one_cn_is_refused() -> None:
    table = _table()
    first, refused = object(), object()
    table.admit(first, A)
    with pytest.raises(ClientRefusedError):
        table.admit(refused, A_NEW_KEY)
    assert not table.is_admitted(refused)
    table.release(refused)  # the worker's finally: the first keeps its mark
    assert table.is_admitted(first)
    table.release(first)
    assert not table.is_admitted(first)
    table.admit(object(), A)  # released: the next one may pass


def test_confirm_needs_a_matching_admit() -> None:
    table = _table()
    with pytest.raises(RuntimeError):
        table.confirm(object())
    attempt = object()
    table.admit(attempt, A)
    table.release(attempt)
    with pytest.raises(RuntimeError):
        table.confirm(attempt)


def test_release_after_confirm_changes_nothing() -> None:
    """The worker's ``finally`` releases its attempt also after it won."""
    table = _table()
    attempt = object()
    table.admit(attempt, A)
    table.confirm(attempt)
    table.release(attempt)
    assert not table.is_admitted(attempt)
    assert table.ever_confirmed


def test_each_cn_has_its_own_takeover_allowance(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Step R's rules, through the table: 3 takeovers at once per CN."""
    caplog.set_level(logging.INFO, logger="dsm.net.session_slot")
    table = _table()
    _confirm(table, A)
    _confirm(table, B)  # another CN while A runs: never refused
    for _ in range(3):
        _confirm(table, A)  # A comes back: a takeover, one token each
    with pytest.raises(ClientRefusedError):
        table.admit(object(), A)
    _confirm(table, B)  # B's allowance is its own
    lines = _lines(caplog)
    assert [m for _, m in lines if m.startswith("client reconnected")] == [
        A_TAKEOVER,
        A_TAKEOVER,
        A_TAKEOVER,
        "client reconnected (client_cn=dsm-b-client); ending its old session",
    ]
    assert (
        logging.WARNING,
        "client_cn=dsm-a-client reconnected too often; keeping its current "
        "session (two devices with one name?)",
    ) in lines


def test_a_takeover_with_a_new_device_key_logs_step_rs_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """confirm keeps step R's lines, texts unchanged (spec §2.4)."""
    caplog.set_level(logging.WARNING, logger="dsm.net.session_slot")
    table = _table()
    _confirm(table, A)
    _confirm(table, A_NEW_KEY)  # A comes back with another device key
    new = hashlib.sha256(b"\x02" * 32).hexdigest()[:16]
    old = hashlib.sha256(b"\x01" * 32).hexdigest()[:16]
    assert _lines(caplog) == [
        (
            logging.WARNING,
            f"client_cn=dsm-a-client reconnected with a different device key "
            f"(noise_static_sha256={new}, was {old}); if this repeats, two devices "
            f"share this name",
        )
    ]


def test_ever_confirmed_turns_on_at_the_first_confirm() -> None:
    table = _table()
    refused, attempt = object(), object()
    table.admit(refused, A)
    table.release(refused)
    assert not table.ever_confirmed
    table.admit(attempt, A)
    assert not table.ever_confirmed
    table.confirm(attempt)
    assert table.ever_confirmed


def test_each_session_queue_holds_one_client_share() -> None:
    assert SESSION_QUEUE_PACKETS == 256


def test_a_session_repr_shows_no_keys_and_no_packets() -> None:
    session = _session(_table(), A)
    session.tun_queue.put_nowait(b"inner-packet")
    assert "SECRET-KEYS" not in repr(session)
    assert "inner-packet" not in repr(session)


def test_add_makes_the_session_findable() -> None:
    table = _table()
    assert not table.any_live
    a = _connect(table, A, peer=PEER_A)
    assert table.any_live
    assert table.sessions() == [a]
    assert table.by_tunnel(_packed("10.8.0.2")) is a
    assert table.by_tunnel(_packed("10.8.0.3")) is None
    assert table.by_peer(PEER_A) is a
    assert table.by_peer(PEER_B) is None


def test_a_takeover_keeps_the_address_and_returns_the_old_session(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="dsm.net.session_slot")
    table = _table()
    old = _connect(table, A, number=1, peer=PEER_A)
    _confirm(table, A)
    new = _session(table, A, number=2, peer=PEER_A2)
    assert table.add(new) is old
    assert new.tunnel == old.tunnel
    assert table.by_tunnel(_packed("10.8.0.2")) is new
    assert table.by_peer(PEER_A) is None  # the old session's hint is gone
    assert table.by_peer(PEER_A2) is new
    assert table.sessions() == [new]
    assert not table.remove(old)  # replaced: it is not the current one
    assert table.sessions() == [new]
    assert table.by_tunnel(_packed("10.8.0.2")) is new
    assert table.by_peer(PEER_A2) is new
    caplog.clear()
    _confirm(table, A)  # the slot still holds A: this is a takeover
    assert [m for _, m in _lines(caplog) if m.startswith("client reconnected")] == [
        A_TAKEOVER
    ]


def test_remove_is_true_only_for_the_current_session_and_clears_its_slot(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="dsm.net.session_slot")
    table = _table()
    a = _connect(table, A)
    assert table.remove(a)
    assert not table.any_live
    assert table.by_tunnel(_packed("10.8.0.2")) is None
    assert table.by_peer(PEER_A) is None
    assert not table.remove(a)  # nothing left to take out
    caplog.clear()
    again = _connect(table, A, number=2)  # cleared: not a takeover
    assert not [m for _, m in _lines(caplog) if m.startswith("client reconnected")]
    assert again.tunnel == a.tunnel  # the same address after its session ended


def test_the_takeover_allowance_outlives_the_session() -> None:
    """The slot is kept for the run (spec §2.4): a session that ends does not
    refill its CN's takeover allowance."""
    table = _table()
    first = _connect(table, A)
    for _ in range(3):
        _confirm(table, A)  # three takeovers spend the allowance
    assert table.remove(first)  # still the current one: the slot is cleared
    _connect(table, A, number=2)  # no session ran: not a takeover, no token
    with pytest.raises(ClientRefusedError):
        table.admit(object(), A)  # the frozen clock refilled nothing


def test_a_bad_assignment_stops_the_table_at_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Checked at start, so no takeover token is spent on it (spec §2.3)."""
    monkeypatch.setattr(
        "dsm.net.session_slot._POOL", (ipaddress.IPv4Address("10.8.0.1"),)
    )
    with pytest.raises(ValueError, match="both have"):
        SessionTable(["dsm-a-client"])


def test_an_attempt_admitted_while_its_cns_session_ends_can_still_win() -> None:
    table = _table()
    old = _connect(table, A)
    back = object()
    table.admit(back, A)  # a takeover: A's session is live
    assert table.remove(old)  # the old session ends by itself first
    assert table.is_admitted(back)
    assert table.confirm(back) == (A, old.tunnel)
    new = _session(table, A, number=2)
    assert table.add(new) is None
    assert table.sessions() == [new]


def test_two_cns_run_at_once() -> None:
    table = _table()
    a = _connect(table, A, number=1, peer=PEER_A)
    b = _connect(table, B, number=2, peer=PEER_B)
    assert table.sessions() == [a, b]
    assert table.by_tunnel(_packed("10.8.0.3")) is b
    assert table.remove(a)
    assert table.sessions() == [b]
    assert table.by_peer(PEER_B) is b


def test_note_peer_moves_a_hint_and_takes_it_from_another_session() -> None:
    table = _table()
    a = _connect(table, A, number=1, peer=PEER_A)
    b = _connect(table, B, number=2, peer=PEER_B)
    table.note_peer(a, PEER_A2)  # a validated PATH_RESPONSE
    assert table.by_peer(PEER_A2) is a
    assert table.by_peer(PEER_A) is None
    table.note_peer(b, PEER_A2)  # that address now belongs to b
    assert table.by_peer(PEER_A2) is b
    assert table.by_peer(PEER_B) is None
    table.note_peer(a, PEER_A)
    assert table.by_peer(PEER_A) is a
    assert table.by_peer(PEER_A2) is b


def test_add_takes_the_hint_from_another_session() -> None:
    """A finished handshake proves its address at least as well as a
    PATH_RESPONSE (spec §2.5)."""
    table = _table()
    a = _connect(table, A, number=1, peer=PEER_A)
    b = _connect(table, B, number=2, peer=PEER_A)  # from a's address
    assert table.by_peer(PEER_A) is b
    assert table.remove(a)
    assert table.by_peer(PEER_A) is b  # a had no hint left to drop


def test_note_peer_does_nothing_for_a_replaced_session() -> None:
    table = _table()
    old = _connect(table, A, number=1, peer=PEER_A)
    _confirm(table, A)
    table.add(_session(table, A, number=2, peer=PEER_A2))
    table.note_peer(old, PEER_B)  # its last PATH_RESPONSE, after the takeover
    assert table.by_peer(PEER_B) is None


def test_abandon_clears_the_slot_so_the_next_attempt_is_no_takeover(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="dsm.net.session_slot")
    table = _table()
    _confirm(table, A)  # confirmed, but on_client failed: no session
    table.abandon("dsm-a-client")
    caplog.clear()
    _confirm(table, A)
    assert not [m for _, m in _lines(caplog) if m.startswith("client reconnected")]


def test_abandon_after_a_failed_takeover_keeps_the_old_session_a_takeover_target(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """OWNER-APPROVAL ITEM A-OA-1: the old session still runs, so the CN's next
    attempt is still a takeover and spends a token."""
    caplog.set_level(logging.INFO, logger="dsm.net.session_slot")
    table = _table()
    old = _connect(table, A)
    _confirm(table, A)  # a takeover passed; then on_client failed
    table.abandon("dsm-a-client")
    assert table.sessions() == [old]
    caplog.clear()
    _confirm(table, A)
    assert [m for _, m in _lines(caplog) if m.startswith("client reconnected")] == [
        A_TAKEOVER
    ]
