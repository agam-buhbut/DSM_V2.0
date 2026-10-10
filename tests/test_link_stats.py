"""Receiver counts for the slow-link auto cap, in ``decrypt_packet``.

A packet counts once it passed AEAD with a seq not seen before: forged,
replayed and too-short packets do not count, and a genuine packet whose
inner part is dropped later (a type this build does not know, which is how
an old peer treats LINK_REPORT) still does. LINK_REPORT is exempt from the
epoch-nibble check. Real session keys from tuncore; no sockets.
"""

from __future__ import annotations

import logging

import pytest

import tuncore
from dsm.core.protocol import (
    INNER_STRUCT,
    LinkReport,
    PacketType,
)
from dsm.session import decrypt_packet
from dsm.traffic.autocap import LinkStats


def _pair() -> tuple[tuncore.SessionKeyManager, tuncore.SessionKeyManager]:
    ours = tuncore.BootstrapEphemeral.generate()
    peer = tuncore.BootstrapEphemeral.generate()
    our_pub = ours.public_key_bytes
    peer_pub = peer.public_key_bytes
    sender = tuncore.complete_bootstrap(ours, peer_pub, True)
    receiver = tuncore.complete_bootstrap(peer, our_pub, False)
    return sender, receiver


def _inner(
    keys: tuncore.SessionKeyManager,
    ptype: int,
    *,
    epoch_id: int | None = None,
    payload: bytes = b"x",
) -> bytes:
    """Inner plaintext built by hand, so any type byte can be used."""
    eid = keys.epoch & 0x0F if epoch_id is None else epoch_id
    return INNER_STRUCT.pack(ptype, (eid & 0x0F) << 4, len(payload)) + payload


def _wire(keys: tuncore.SessionKeyManager, seq: int, plaintext: bytes) -> bytes:
    return bytes(keys.seal_packet(seq, plaintext))


def test_counts_genuine_packets_and_tracks_the_highest_seq() -> None:
    sender, receiver = _pair()
    replay = tuncore.ReplayWindow()
    stats = LinkStats()
    data = _inner(sender, PacketType.DATA)
    for seq in (3, 1, 7):
        wire = _wire(sender, seq, data)
        assert decrypt_packet(wire, receiver, replay, link_stats=stats) is not None
    assert (stats.received, stats.highest_seq) == (3, 7)


def test_forged_replayed_and_short_packets_do_not_count() -> None:
    sender, receiver = _pair()
    replay = tuncore.ReplayWindow()
    stats = LinkStats()
    wire = _wire(sender, 5, _inner(sender, PacketType.DATA))
    assert decrypt_packet(wire, receiver, replay, link_stats=stats) is not None
    assert decrypt_packet(wire, receiver, replay, link_stats=stats) is None
    forged = bytearray(_wire(sender, 6, _inner(sender, PacketType.DATA)))
    forged[-1] ^= 0x01
    assert decrypt_packet(bytes(forged), receiver, replay, link_stats=stats) is None
    assert decrypt_packet(bytes(10), receiver, replay, link_stats=stats) is None
    assert (stats.received, stats.highest_seq) == (1, 5)


def test_an_unknown_type_is_dropped_quietly_and_still_counted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    sender, receiver = _pair()
    replay = tuncore.ReplayWindow()
    stats = LinkStats()
    wire = _wire(sender, 9, _inner(sender, 0x0B))
    with caplog.at_level(logging.DEBUG, logger="dsm.session"):
        assert decrypt_packet(wire, receiver, replay, link_stats=stats) is None
    assert (stats.received, stats.highest_seq) == (1, 9)
    levels = [r.levelno for r in caplog.records if r.name == "dsm.session"]
    assert levels == [logging.DEBUG]


def test_a_link_report_with_the_previous_epoch_nibble_passes() -> None:
    sender, receiver = _pair()
    replay = tuncore.ReplayWindow()
    old_eid = (receiver.epoch - 1) & 0x0F
    payload = LinkReport(highest_seq=10, received=8).serialize()
    plaintext = _inner(
        sender, PacketType.LINK_REPORT, epoch_id=old_eid, payload=payload
    )
    result = decrypt_packet(_wire(sender, 1, plaintext), receiver, replay)
    assert result is not None
    inner, _prev = result
    assert inner.ptype == PacketType.LINK_REPORT
    assert LinkReport.deserialize(inner.payload) == LinkReport(
        highest_seq=10, received=8
    )
    # Control: DATA with the same nibble is still dropped.
    data = _inner(sender, PacketType.DATA, epoch_id=old_eid)
    assert decrypt_packet(_wire(sender, 2, data), receiver, replay) is None


def test_without_link_stats_decrypt_works_as_before() -> None:
    sender, receiver = _pair()
    replay = tuncore.ReplayWindow()
    wire = _wire(sender, 4, _inner(sender, PacketType.DATA, payload=b"hi"))
    result = decrypt_packet(wire, receiver, replay)
    assert result is not None
    assert result[0].payload == b"hi"
