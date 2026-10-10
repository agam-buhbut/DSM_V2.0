"""Wire v2 (spec §6, §14.1, §16.2): the tuncore calls that seal and open data
packets, and the cookie reply's XChaCha20-Poly1305. Real tuncore. Box only:
needs the new wheel. No sockets; nothing sleeps.
"""

from __future__ import annotations

import pytest

import tuncore


def _pair() -> tuple[tuncore.SessionKeyManager, tuncore.SessionKeyManager]:
    ours = tuncore.BootstrapEphemeral.generate()
    peer = tuncore.BootstrapEphemeral.generate()
    our_pub = bytes(ours.public_key_bytes)
    peer_pub = bytes(peer.public_key_bytes)
    sender = tuncore.complete_bootstrap(ours, peer_pub, True)
    receiver = tuncore.complete_bootstrap(peer, our_pub, False)
    return sender, receiver


def test_tuncore_speaks_wire_version_2() -> None:
    assert tuncore.WIRE_VERSION == 2


def test_seal_packet_returns_the_whole_wire_packet_as_bytes() -> None:
    sender, receiver = _pair()
    wire = sender.seal_packet(1, b"payload")
    assert isinstance(wire, bytes)
    assert len(wire) == 20 + len(b"payload") + 16
    opened = receiver.open_packet(wire)
    assert opened is not None
    seq, plaintext, used_prev = opened
    assert isinstance(plaintext, bytes)
    assert (seq, plaintext, used_prev) == (1, b"payload", False)


def test_the_v1_calls_are_gone() -> None:
    for name in ("encrypt", "decrypt", "try_decrypt_with_fallback"):
        assert not hasattr(tuncore.SessionKeyManager, name), name


def test_xchacha_round_trip_and_refusals() -> None:
    key, nonce = bytes(range(32)), bytes(range(24))
    sealed = tuncore.xchacha_seal(key, nonce, b"sixteen byte msg", b"aad")
    assert isinstance(sealed, bytes)
    assert len(sealed) == 32
    assert tuncore.xchacha_open(key, nonce, sealed, b"aad") == b"sixteen byte msg"
    assert tuncore.xchacha_open(key, nonce, sealed, b"bad") is None
    assert tuncore.xchacha_open(bytes(32), nonce, sealed, b"aad") is None
    assert tuncore.xchacha_open(key, nonce[:23], sealed, b"aad") is None
    with pytest.raises(ValueError):
        tuncore.xchacha_seal(key[:31], nonce, b"x", b"")
    with pytest.raises(ValueError):
        tuncore.xchacha_seal(key, nonce[:23], b"x", b"")
    with pytest.raises(ValueError):
        tuncore.xchacha_open(key[:31], nonce, sealed, b"aad")
