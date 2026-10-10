"""Interop vectors (wire v2 spec §16.3), Python side: VM1 (the gate's keys
and MACs) and VC1 (the cookie reply seal, through tuncore and through the
gate); Task 10 adds VT1. The Rust tests check VH1, VP1, VK1, VR1 and VC1. A
future client (the Android replacement) must reproduce all of them.
Laptop: VM1 only (old wheel and shim). The two VC1 tests need tuncore's
xchacha_seal from the Task 5 wheel; CI checks them.
"""

from __future__ import annotations

import os

import tuncore
from dsm.net.handshake_gate import (
    GateKeys,
    HandshakeGate,
    compute_mac1,
    compute_mac2,
    make_cookie,
)

CA_DER = bytes.fromhex("3003020101")
CN = "dsm-test-server"
NOW = 1_800_000_000.0
E = bytes(range(32))
R = bytes(range(32))
SRC = ("192.0.2.1", 51820)
MAC1 = "7e514bf08f7358048433fedb4b9c47f7"
COOKIE = "b1db5839f9fd47f550c7fb7ecc003ab7"
NONCE = bytes(range(0x30, 0x48))
SEALED = "e71df6741aad7dd6b0fbb156ebcfc17bfd3310e8d1d75cfe09903429e604ebb6"


def test_vm1_gate_keys_and_macs() -> None:
    keys = GateKeys.from_ca_der(CA_DER, CN)
    assert (
        keys.mac1_key.hex()
        == "ed78ec68852a7782142a45c16ac278650af180f463e8ef77a6aa8718533cf42f"
    )
    assert (
        keys.cookie_key.hex()
        == "9277df7c0c97b8aeb1264a8500393c210c6cf3acd2770011f60045bb666dd289"
    )
    mac1 = compute_mac1(E, keys, NOW)
    assert mac1.hex() == MAC1
    cookie = make_cookie(R, SRC)
    assert cookie is not None
    assert cookie.hex() == COOKIE
    assert compute_mac2(E + mac1, cookie).hex() == "157f22e3a395e2b696f35c887fb19b0f"


def test_vc1_cookie_reply_seal() -> None:
    keys = GateKeys.from_ca_der(CA_DER, CN)
    sealed = tuncore.xchacha_seal(
        keys.cookie_key, NONCE, bytes.fromhex(COOKIE), bytes.fromhex(MAC1)
    )
    assert sealed.hex() == SEALED


def test_vc1_through_the_gate() -> None:
    keys = GateKeys.from_ca_der(CA_DER, CN)
    draws = iter([R, NONCE])  # the gate draws R first, then the reply's nonce

    def rand(n: int) -> bytes:
        return next(draws, None) or os.urandom(n)

    gate = HandshakeGate(keys, clock=lambda: 0.0, wall_clock=lambda: NOW, rand=rand)
    msg1 = E + bytes.fromhex(MAC1) + os.urandom(1400 - 48)
    reply = gate.cookie_reply(msg1, SRC)
    assert reply is not None
    assert reply[:24] == NONCE
    assert reply[24:56].hex() == SEALED
