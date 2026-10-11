"""The handshake gate (wire v2, spec §7.1-7.5; T10 §3.16 tests 1-8): mac1,
mac2 and cookies, the cookie reply, the load rule and the client's stamps.
Unit tests with injected clocks. Laptop: partly (old wheel and shim). The
shim has no XChaCha, so the cookie-reply tests (cookie binding and lifetime,
reply opening, two replies differing, msg2 and random frames, reply budget,
never raising) need tuncore's xchacha_seal and xchacha_open from the Task 5
wheel and run in CI.
"""

from __future__ import annotations

import logging
import random

import pytest
from cryptography.hazmat.primitives.serialization import Encoding

import tuncore
from dsm.crypto.handshake import HANDSHAKE_FRAME_SIZE
from dsm.net.handshake_gate import (
    BAD_MAC1_LINE,
    COOKIE_REPLY_BURST,
    FRAME_SIZE,
    GateKeyError,
    GateKeys,
    HandshakeGate,
    LoadTracker,
    Msg1Verdict,
    compute_mac1,
    open_cookie_reply,
    stamp_mac2,
    stamp_msg1,
)
from tests.cert_helpers import make_test_ca

CA_DER = bytes.fromhex("3003020101")
CN = "dsm-test-server"
KEYS = GateKeys.from_ca_der(CA_DER, CN)
NOW = 1_800_000_000.0  # a multiple of 300: the start of window w
SRC = ("192.0.2.1", 51820)


class _Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def _gate(clock: _Clock | None = None) -> HandshakeGate:
    return HandshakeGate(
        KEYS, clock=clock if clock is not None else _Clock(), wall_clock=lambda: NOW
    )


def _msg1(seed: int, keys: GateKeys = KEYS, now: float = NOW) -> bytes:
    """A msg1 as a wire v2 client stamps it; the Noise part is random bytes."""
    frame = bytearray(random.Random(seed).randbytes(HANDSHAKE_FRAME_SIZE))
    stamp_msg1(frame, compute_mac1(bytes(frame[:32]), keys, now))
    return bytes(frame)


def _with_cookie(gate: HandshakeGate, msg1: bytes) -> bytes:
    """The client's resend after the gate's cookie reply."""
    reply = gate.cookie_reply(msg1, SRC)
    assert reply is not None
    cookie = open_cookie_reply(reply, KEYS, msg1[32:48])
    assert cookie is not None
    frame = bytearray(msg1)
    stamp_mac2(frame, cookie)
    return bytes(frame)


def test_a_stamped_msg1_is_admitted() -> None:
    assert _gate().check_msg1(_msg1(1), SRC, under_load=False) is Msg1Verdict.ADMIT


def test_a_bad_mac1_a_wrong_ca_or_cn_or_a_wrong_size_is_dropped() -> None:
    gate = _gate()
    good = _msg1(1)
    flipped_e = bytearray(good)
    flipped_e[0] ^= 0x01
    flipped_mac1 = bytearray(good)
    flipped_mac1[40] ^= 0x01
    bad = [
        bytes(flipped_e),
        bytes(flipped_mac1),
        _msg1(2, GateKeys.from_ca_der(b"another CA", CN)),
        _msg1(3, GateKeys.from_ca_der(CA_DER, "another-server")),
        good[:-1],
        good + b"\x00",
    ]
    for frame in bad:
        assert gate.check_msg1(frame, SRC, under_load=False) is Msg1Verdict.DROP


@pytest.mark.parametrize(
    ("windows", "admitted"),
    [(-2, False), (-1, True), (0, True), (1, True), (2, False)],
)
def test_the_clock_window_is_one_step_either_way(windows: int, admitted: bool) -> None:
    frame = _msg1(1, now=NOW + windows * 300)
    verdict = _gate().check_msg1(frame, SRC, under_load=False)
    assert (verdict is Msg1Verdict.ADMIT) is admitted


def test_a_cookie_is_bound_to_address_and_port_and_lasts_one_r_change() -> None:
    clock = _Clock()
    gate = _gate(clock)
    frame = _with_cookie(gate, _msg1(1))
    assert gate.check_msg1(frame, SRC, under_load=True) is Msg1Verdict.ADMIT
    other_port = (SRC[0], SRC[1] + 1)
    other_ip = ("192.0.2.2", SRC[1])
    assert (
        gate.check_msg1(frame, other_port, under_load=True) is Msg1Verdict.NEED_COOKIE
    )
    assert gate.check_msg1(frame, other_ip, under_load=True) is Msg1Verdict.NEED_COOKIE
    clock.now = 120.0  # R replaced once: the old R still counts
    assert gate.check_msg1(frame, SRC, under_load=True) is Msg1Verdict.ADMIT
    clock.now = 240.0  # replaced again: the cookie is too old
    assert gate.check_msg1(frame, SRC, under_load=True) is Msg1Verdict.NEED_COOKIE
    # Not under load, no cookie is needed.
    assert gate.check_msg1(_msg1(2), SRC, under_load=False) is Msg1Verdict.ADMIT


def test_a_cookie_reply_opens_only_with_its_own_mac1() -> None:
    gate = _gate()
    first, second = _msg1(1), _msg1(2)
    reply = gate.cookie_reply(first, SRC)
    assert reply is not None
    assert len(reply) == HANDSHAKE_FRAME_SIZE
    assert open_cookie_reply(reply, KEYS, first[32:48]) is not None
    assert open_cookie_reply(reply, KEYS, second[32:48]) is None
    other_keys = GateKeys.from_ca_der(b"another CA", CN)
    assert open_cookie_reply(reply, other_keys, first[32:48]) is None
    assert open_cookie_reply(reply[:-1], KEYS, first[32:48]) is None


def test_a_cookie_ends_on_the_120_s_grid_after_a_quiet_spell() -> None:
    clock = _Clock()
    gate = _gate(clock)
    frame = _with_cookie(gate, _msg1(1))  # at 0 s, under the first R
    clock.now = 239.0  # the first gate call since: R was replaced at 120 s
    assert gate.check_msg1(frame, SRC, under_load=True) is Msg1Verdict.ADMIT
    clock.now = 241.0  # replaced again at 240 s, not 120 s after the last call
    assert gate.check_msg1(frame, SRC, under_load=True) is Msg1Verdict.NEED_COOKIE


def test_a_gap_of_two_or_more_r_changes_ends_every_cookie() -> None:
    clock = _Clock()
    gate = _gate(clock)
    first = _with_cookie(gate, _msg1(1))  # at 0 s, under the first R
    clock.now = 250.0  # the first gate call since: R changed at 120 and 240 s
    assert gate.check_msg1(first, SRC, under_load=True) is Msg1Verdict.NEED_COOKIE
    second = _with_cookie(gate, _msg1(2))  # at 250 s, under the R of 240 s
    clock.now = 251.0
    assert gate.check_msg1(second, SRC, under_load=True) is Msg1Verdict.ADMIT
    clock.now = 370.0  # one change, at 360 s: second's R is now the previous
    assert gate.check_msg1(second, SRC, under_load=True) is Msg1Verdict.ADMIT
    clock.now = 1000.0  # five changes since: neither cookie counts
    assert gate.check_msg1(first, SRC, under_load=True) is Msg1Verdict.NEED_COOKIE
    assert gate.check_msg1(second, SRC, under_load=True) is Msg1Verdict.NEED_COOKIE


def test_wrong_size_frames_spend_no_cookie_reply_budget() -> None:
    gate = _gate()
    good = _msg1(1)
    for _ in range(100):
        assert gate.cookie_reply(good[:-1], SRC) is None
    replies = [gate.cookie_reply(good, SRC) for _ in range(int(COOKIE_REPLY_BURST))]
    assert all(r is not None for r in replies)


def test_two_cookie_replies_to_one_msg1_differ() -> None:
    gate = _gate()
    msg1 = _msg1(1)
    first, second = gate.cookie_reply(msg1, SRC), gate.cookie_reply(msg1, SRC)
    assert first is not None
    assert second is not None
    assert first[:24] != second[:24]  # a fresh nonce
    assert first[56:] != second[56:]  # a fresh random tail
    cookie = open_cookie_reply(first, KEYS, msg1[32:48])
    assert cookie is not None
    assert open_cookie_reply(second, KEYS, msg1[32:48]) == cookie


def test_msg2_frames_and_random_frames_are_never_cookie_replies() -> None:
    mac1 = _msg1(1)[32:48]
    rng = random.Random(9)
    for _ in range(10_000):
        frame = rng.randbytes(HANDSHAKE_FRAME_SIZE)
        assert open_cookie_reply(frame, KEYS, mac1) is None
    payload = bytes(tuncore.HANDSHAKE_ATTEST_PAYLOAD_SIZE)
    for _ in range(200):
        initiator = tuncore.NoiseInitiator(tuncore.IdentityKeyPair.generate())
        responder = tuncore.NoiseResponder(tuncore.IdentityKeyPair.generate())
        msg1 = bytearray(initiator.write_message_1())
        stamp_msg1(msg1, compute_mac1(bytes(msg1[:32]), KEYS, NOW))
        responder.read_message_1(bytes(msg1))  # Noise reads only e
        msg2 = bytes(responder.write_message_2(payload))
        assert open_cookie_reply(msg2, KEYS, bytes(msg1[32:48])) is None


def test_msg1_bytes_32_to_64_have_no_fixed_bytes_and_mac2_is_never_zero() -> None:
    frames: list[bytes] = []
    for _ in range(1000):
        initiator = tuncore.NoiseInitiator(tuncore.IdentityKeyPair.generate())
        msg1 = bytearray(initiator.write_message_1())
        stamp_msg1(msg1, compute_mac1(bytes(msg1[:32]), KEYS, NOW))
        assert len(msg1) == HANDSHAKE_FRAME_SIZE
        assert msg1[48:64] != bytes(16)
        frames.append(bytes(msg1))
    for offset in range(32, 64):
        assert len({f[offset] for f in frames}) > 1, offset


def test_the_mac2_filler_is_never_all_zero() -> None:
    draws = iter([bytes(16), bytes(16), b"\x01" * 16])
    msg1 = bytearray(HANDSHAKE_FRAME_SIZE)
    stamp_msg1(msg1, bytes(16), rand=lambda _n: next(draws))
    assert msg1[48:64] == b"\x01" * 16


def test_the_cookie_reply_budget_is_40_then_20_a_second() -> None:
    clock = _Clock()
    gate = _gate(clock)
    frame = _msg1(1)
    replies = [gate.cookie_reply(frame, SRC) for _ in range(50)]
    assert sum(r is not None for r in replies) == COOKIE_REPLY_BURST
    clock.now = 1.0
    replies = [gate.cookie_reply(frame, SRC) for _ in range(30)]
    assert sum(r is not None for r in replies) == 20


def test_a_bad_mac1_is_logged_at_info_once_a_minute_with_a_count(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="dsm")
    clock = _Clock()
    gate = _gate(clock)
    junk = random.Random(4).randbytes(HANDSHAKE_FRAME_SIZE)
    for at in (0.0, 0.0, 0.0, 59.0, 61.0):
        clock.now = at
        assert not gate.mac1_ok(junk)
    lines = [r for r in caplog.records if r.name == "dsm.net.handshake_gate"]
    assert [r.levelno for r in lines] == [logging.INFO, logging.INFO]
    assert lines[0].getMessage() == BAD_MAC1_LINE
    assert lines[1].getMessage() == f"{BAD_MAC1_LINE} (3 more in the last 61 s)"


def test_the_load_rule() -> None:
    # T10 §3.16 test 7: idle off, running on, trouble on for 30 s, extended.
    clock = _Clock()
    load = LoadTracker(clock=clock)
    assert not load.under_load(0)
    assert load.under_load(1)
    load.note_trouble()
    clock.now = 29.9
    assert load.under_load(0)
    load.note_trouble()
    clock.now = 59.0
    assert load.under_load(0)
    clock.now = 60.0
    assert not load.under_load(0)


def test_a_bad_mac1_is_not_trouble() -> None:
    gate = _gate()
    for seed in range(20):
        frame = random.Random(seed).randbytes(HANDSHAKE_FRAME_SIZE)
        assert gate.check_msg1(frame, SRC, under_load=False) is Msg1Verdict.DROP
    assert not gate.load.under_load(0)


def test_the_gate_never_raises_on_peer_bytes() -> None:
    gate = _gate()
    rng = random.Random(8)
    sources = [SRC, ("::1", 51820), ("not an address", 1), ("192.0.2.1", 70000)]
    for i in range(2000):
        frame = rng.randbytes(rng.choice((0, 1, 63, 64, 1399, 1400, 1401)))
        for src in sources:
            gate.check_msg1(frame, src, under_load=bool(i % 2))
            reply = gate.cookie_reply(frame, src)
            # Only a 1400-byte frame gets a reply, and the reply is no bigger.
            assert reply is None or len(reply) == len(frame) == FRAME_SIZE
    gate = _gate()  # a full reply budget: a None below is for the address
    good = _msg1(1)
    v6 = ("::1", 51820)
    assert gate.check_msg1(good, v6, under_load=True) is Msg1Verdict.NEED_COOKIE
    assert gate.cookie_reply(good, v6) is None  # no cookie for a non-IPv4 source


def test_gate_keys_come_from_the_ca_der_and_need_a_cn() -> None:
    ca = make_test_ca()
    der = ca.certificate.public_bytes(Encoding.DER)
    assert GateKeys.derive(ca.certificate, CN) == GateKeys.from_ca_der(der, CN)
    with pytest.raises(GateKeyError):
        GateKeys.from_ca_der(CA_DER, "")
    assert repr(KEYS) == "GateKeys()"


def test_the_frame_size_matches_the_handshake() -> None:
    assert FRAME_SIZE == HANDSHAKE_FRAME_SIZE == 1400
