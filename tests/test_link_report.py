"""The LINK_REPORT message: type 0x0A, a 16-byte big-endian payload of
totals since the session started. Extra bytes are ignored; a shorter
payload is refused."""

from __future__ import annotations

import pytest

from dsm.core.protocol import LINK_REPORT_STRUCT, InnerPacket, LinkReport, PacketType

_MAX_U64 = 2**64 - 1


def test_the_type_is_0x0a() -> None:
    assert PacketType.LINK_REPORT == 0x0A


def test_round_trip() -> None:
    report = LinkReport(highest_seq=123_456, received=123_000)
    assert LinkReport.deserialize(report.serialize()) == report


def test_the_payload_is_16_big_endian_bytes() -> None:
    assert LINK_REPORT_STRUCT.size == 16
    data = LinkReport(highest_seq=1, received=2).serialize()
    assert data == bytes(7) + b"\x01" + bytes(7) + b"\x02"


def test_bytes_after_the_first_16_are_ignored() -> None:
    data = LinkReport(highest_seq=5, received=4).serialize() + b"later fields"
    assert LinkReport.deserialize(data) == LinkReport(highest_seq=5, received=4)


@pytest.mark.parametrize("length", range(16))
def test_a_shorter_payload_raises_value_error(length: int) -> None:
    with pytest.raises(ValueError):
        LinkReport.deserialize(bytes(length))


def test_values_up_to_two_to_the_64_minus_one() -> None:
    report = LinkReport(highest_seq=_MAX_U64, received=_MAX_U64)
    assert report.serialize() == b"\xff" * 16
    assert LinkReport.deserialize(report.serialize()) == report


def test_an_inner_packet_carries_it() -> None:
    payload = LinkReport(highest_seq=9, received=8).serialize()
    inner = InnerPacket(ptype=PacketType.LINK_REPORT, epoch_id=3, payload=payload)
    got = InnerPacket.deserialize(inner.serialize())
    assert got.ptype == PacketType.LINK_REPORT
    assert LinkReport.deserialize(got.payload) == LinkReport(highest_seq=9, received=8)
