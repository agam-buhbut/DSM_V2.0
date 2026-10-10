"""Wire v2 (spec §6, §14.1, §16.2): the tuncore calls that seal and open data
packets, and the cookie reply's XChaCha20-Poly1305. Real tuncore. Box only:
needs the new wheel. No sockets; nothing sleeps.
"""

from __future__ import annotations

import random

import pytest

import tuncore
from dsm.core.protocol import (
    GCM_TAG_SIZE,
    INNER_HEADER_SIZE,
    INNER_STRUCT,
    OUTER_HEADER_SIZE,
    SIZE_CLASSES,
    WIRE_VERSION,
    PacketType,
)
from dsm.net.transport.udp import UDPTransport
from dsm.session import SequenceCounter, decrypt_packet, make_send_fn
from dsm.traffic.autocap import LinkStats


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


ADDR = ("198.51.100.7", 51820)


class _Wire(UDPTransport):
    """An unbound UDP socket that keeps what it is asked to send."""

    def __init__(self) -> None:
        super().__init__()
        self.sent: list[bytes] = []

    async def send(self, data: bytes, addr: tuple[str, int]) -> None:
        del addr
        self.sent.append(bytes(data))


def _plain(epoch: int, size: int) -> bytes:
    """A DATA inner packet that seals to exactly ``size`` wire bytes."""
    body = size - OUTER_HEADER_SIZE - GCM_TAG_SIZE - INNER_HEADER_SIZE
    payload = b"\x5a" * body
    return INNER_STRUCT.pack(PacketType.DATA, (epoch & 0x0F) << 4, body) + payload


def _rotate(
    initiator: tuncore.SessionKeyManager, responder: tuncore.SessionKeyManager
) -> None:
    """One key change through the two-phase calls the rekey code uses."""
    new_epoch, init_pub = initiator.initiate_rotation()
    resp_pub, _ = responder.prepare_rotation_responder(bytes(init_pub), new_epoch)
    responder.apply_rotation_responder()
    initiator.complete_rotation_initiator(bytes(resp_pub))


def test_dsm_speaks_wire_version_2() -> None:
    # Spec §16.2 item 8 (tuncore's half is test_tuncore_speaks_wire_version_2).
    assert WIRE_VERSION == 2


async def test_make_send_fn_packets_open_both_ways_at_every_size() -> None:
    # Item 1 (and the exact size TestOuterPacket used to check).
    client, server = _pair()
    for sender, receiver in ((client, server), (server, client)):
        wire = _Wire()
        send = make_send_fn(sender, wire, lambda: ADDR, SequenceCounter())
        replay = tuncore.ReplayWindow()
        for size in SIZE_CLASSES:
            await send(_plain(sender.send_epoch, size), size)
            assert len(wire.sent[-1]) == size
            result = decrypt_packet(wire.sent[-1], receiver, replay)
            assert result is not None
            assert result[0].ptype is PacketType.DATA


def test_junk_does_not_open_and_counts_as_junk() -> None:
    # Item 2.
    sender, receiver = _pair()
    replay, stats = tuncore.ReplayWindow(), LinkStats()
    genuine = sender.seal_packet(1, _plain(sender.send_epoch, 256))
    rng = random.Random(7)
    junk = [rng.randbytes(size) for size in SIZE_CLASSES]
    junk += [b"", bytes(35), rng.randbytes(1500)]
    for offset in (0, 7, 15, 16, 19):
        changed = bytearray(genuine)
        changed[offset] ^= 0x01
        junk.append(bytes(changed))
    tag = bytearray(genuine)
    tag[-1] ^= 0x01
    junk.append(bytes(tag))
    for packet in junk:
        assert decrypt_packet(packet, receiver, replay, link_stats=stats) is None
    assert (stats.received, stats.junk) == (0, len(junk))
    assert decrypt_packet(genuine, receiver, replay, link_stats=stats) is not None
    assert stats.received == 1


def test_a_replay_counts_as_junk_and_is_received_once() -> None:
    # Item 3.
    sender, receiver = _pair()
    replay, stats = tuncore.ReplayWindow(), LinkStats()
    wire = sender.seal_packet(1, _plain(sender.send_epoch, 128))
    assert decrypt_packet(wire, receiver, replay, link_stats=stats) is not None
    assert decrypt_packet(wire, receiver, replay, link_stats=stats) is None
    assert (stats.received, stats.junk) == (1, 1)


def test_header_bytes_look_random() -> None:
    # Item 4. About 4 zero bytes per offset are expected in 1000 packets; more
    # than 40 happens by chance about once in 10^26.
    sender, _ = _pair()
    plain = _plain(sender.send_epoch, 128)
    headers = [sender.seal_packet(seq, plain)[:20] for seq in range(1, 1001)]
    for offset in range(20):
        assert len({h[offset] for h in headers}) > 1, offset
    for offset in range(16):
        assert sum(h[offset] == 0 for h in headers) <= 40, offset
    assert any(h[:4] != bytes(4) for h in headers)


def test_a_packet_128_behind_after_a_key_change_is_dropped() -> None:
    # Item 5: today's rule across key changes, and step R's on_replay.
    client, server = _pair()
    replay, stats = tuncore.ReplayWindow(), LinkStats()
    straggler = client.seal_packet(1, _plain(client.send_epoch, 128))
    _rotate(client, server)
    for seq in range(2, 202):
        wire = client.seal_packet(seq, _plain(client.send_epoch, 128))
        assert decrypt_packet(wire, server, replay, link_stats=stats) is not None
    seen: list[int] = []
    result = decrypt_packet(
        straggler, server, replay, link_stats=stats, on_replay=lambda: seen.append(1)
    )
    assert result is None
    assert server.has_grace_period  # the previous key set would still open it
    assert seen == [1]
    assert stats.junk == 1


async def test_make_send_fn_refuses_a_wrong_target_size() -> None:
    # Item 6 (moved from TestOuterPacket).
    sender, _ = _pair()
    send = make_send_fn(sender, _Wire(), lambda: ADDR, SequenceCounter())
    with pytest.raises(
        ValueError, match="ciphertext sizing mismatch: wire=128, target=256"
    ):
        await send(_plain(sender.send_epoch, 128), 256)


def test_open_packet_never_raises() -> None:
    # Item 7.
    _, receiver = _pair()
    rng = random.Random(11)
    for _ in range(10_000):
        assert receiver.open_packet(rng.randbytes(rng.randrange(0, 1501))) is None


def test_a_packet_that_does_not_open_changes_nothing() -> None:
    # Review Focus 2 (spec §24.1): misses leave the windows where they were.
    a_client, a_server = _pair()
    b_client, _ = _pair()
    replay = tuncore.ReplayWindow()
    forged = bytearray(a_client.seal_packet(300, _plain(a_client.send_epoch, 128)))
    forged[-1] ^= 0x01
    near = a_client.seal_packet(3, _plain(a_client.send_epoch, 128))
    other = b_client.seal_packet(300, _plain(b_client.send_epoch, 128))
    for miss in (bytes(forged), other):
        assert decrypt_packet(miss, a_server, replay) is None
    # Neither window moved to 300: seq 3 is still in reach.
    assert decrypt_packet(near, a_server, replay) is not None
