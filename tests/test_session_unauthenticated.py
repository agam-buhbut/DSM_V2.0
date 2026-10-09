"""The live session hands each packet it cannot open (AEAD failed) to the
server's in-session accept, and nothing else (step R). Review Focus 2: the
live client's own traffic never goes there.

Real session keys from tuncore (as in test_link_stats.py); fakes elsewhere.
No sockets; nothing sleeps.
"""

from __future__ import annotations

import asyncio

import tuncore
from dsm.core.fsm import SessionFSM, State
from dsm.core.protocol import (
    INNER_STRUCT,
    OUTER_HEADER_SIZE,
    SEQ_STRUCT,
    OuterPacket,
    PacketType,
)
from dsm.net.transport.udp import UDPTransport
from dsm.session import (
    DataPathContext,
    LivenessState,
    RekeyState,
    decrypt_packet,
    run_data_loops,
)
from tests.test_link_report_flood import _no_send, _Scheduler, _Shaper

Addr = tuple[str, int]
LIVE: Addr = ("198.51.100.7", 40000)
NEW: Addr = ("198.51.100.7", 40001)
# A reconnecting client's msg1 as the live session sees it: 1400 bytes that
# do not open. Its first 8 bytes, read as a sequence number, are far ahead.
MSG1 = b"\x7f" * 1400


def _pair() -> tuple[tuncore.SessionKeyManager, tuncore.SessionKeyManager]:
    ours = tuncore.BootstrapEphemeral.generate()
    peer = tuncore.BootstrapEphemeral.generate()
    our_pub = ours.public_key_bytes
    peer_pub = peer.public_key_bytes
    sender = tuncore.complete_bootstrap(ours, peer_pub, True)
    receiver = tuncore.complete_bootstrap(peer, our_pub, False)
    return sender, receiver


def _plain(ptype: int, epoch: int, payload: bytes, *, flags: int = 0) -> bytes:
    return (
        INNER_STRUCT.pack(ptype, ((epoch & 0x0F) << 4) | flags, len(payload)) + payload
    )


def _wire(keys: tuncore.SessionKeyManager, seq: int, plaintext: bytes) -> bytes:
    nonce, ct, _epoch = keys.encrypt(plaintext, SEQ_STRUCT.pack(seq))
    outer = OuterPacket(seq=seq, nonce=bytes(nonce), ciphertext=bytes(ct))
    return outer.serialize(OUTER_HEADER_SIZE + len(ct))


def test_only_an_aead_failure_is_handed_over() -> None:
    sender, receiver = _pair()
    replay = tuncore.ReplayWindow()
    handed: list[int] = []

    def on_fail() -> None:
        handed.append(1)

    epoch = receiver.epoch
    genuine = _wire(sender, 5, _plain(PacketType.DATA, epoch, b"x" * 1360))
    assert len(genuine) == 1400  # a genuine packet the size of a msg1
    assert decrypt_packet(genuine, receiver, replay, on_auth_fail=on_fail) is not None
    # The same packet again: a replay, dropped before AEAD.
    assert decrypt_packet(genuine, receiver, replay, on_auth_fail=on_fail) is None
    # Too short to be a packet.
    assert decrypt_packet(bytes(10), receiver, replay, on_auth_fail=on_fail) is None
    # Opens, but the inner part is bad (a reserved flag bit set).
    bad_inner = _wire(sender, 6, _plain(PacketType.DATA, epoch, b"x", flags=0x01))
    assert decrypt_packet(bad_inner, receiver, replay, on_auth_fail=on_fail) is None
    # Opens, but the epoch nibble is wrong.
    wrong_epoch = _wire(sender, 7, _plain(PacketType.DATA, epoch + 3, b"x"))
    assert decrypt_packet(wrong_epoch, receiver, replay, on_auth_fail=on_fail) is None
    assert handed == []
    # Does not open: a new client's msg1, and a forged packet.
    assert decrypt_packet(MSG1, receiver, replay, on_auth_fail=on_fail) is None
    forged = bytearray(_wire(sender, 8, _plain(PacketType.DATA, epoch, b"y")))
    forged[-1] ^= 0x01
    assert decrypt_packet(bytes(forged), receiver, replay, on_auth_fail=on_fail) is None
    assert handed == [1, 1]


def test_without_the_callback_decrypt_works_as_before() -> None:
    sender, receiver = _pair()
    replay = tuncore.ReplayWindow()
    genuine = _wire(sender, 1, _plain(PacketType.DATA, receiver.epoch, b"hi"))
    result = decrypt_packet(genuine, receiver, replay)
    assert result is not None
    assert result[0].payload == b"hi"
    assert decrypt_packet(MSG1, receiver, replay) is None


class _Tun:
    def __init__(self) -> None:
        self.written: list[bytes] = []

    async def read(self) -> bytes:
        await asyncio.Event().wait()
        return b""

    async def awrite(self, data: bytes) -> None:
        self.written.append(bytes(data))


def _ctx(
    receiver: tuncore.SessionKeyManager, tun: _Tun
) -> tuple[DataPathContext, SessionFSM]:
    fsm = SessionFSM()
    for state in (State.CONNECTING, State.HANDSHAKING, State.ESTABLISHED):
        fsm.transition(state)
    ctx = DataPathContext(
        tun=tun,  # type: ignore[arg-type]
        session_keys=receiver,
        fsm=fsm,
        shaper=_Shaper(),  # type: ignore[arg-type]
        send_fn=_no_send,
        scheduler=_Scheduler(),  # type: ignore[arg-type]
        rekey=RekeyState(),
        liveness=LivenessState(),
        shutdown=asyncio.Event(),
    )
    return ctx, fsm


async def test_the_receive_loop_hands_over_only_packets_it_cannot_open() -> None:
    sender, receiver = _pair()
    tun = _Tun()
    ctx, fsm = _ctx(receiver, tun)
    transport = UDPTransport()  # never bound: the test fills its queue
    genuine = _wire(sender, 1, _plain(PacketType.DATA, receiver.epoch, b"x" * 1360))
    small_junk = b"\x7f" * 300
    for item in ((genuine, LIVE), (genuine, LIVE), (MSG1, NEW), (small_junk, NEW)):
        transport._recv_queue.put_nowait(item)
    handed: list[tuple[bytes, Addr]] = []

    def unauthenticated(data: bytes, addr: Addr) -> None:
        handed.append((data, addr))
        if len(handed) == 2:
            ctx.shutdown.set()

    await asyncio.wait_for(
        run_data_loops(
            ctx,
            transport,
            receiver,
            tuncore.ReplayWindow(),
            fsm,
            unauthenticated=unauthenticated,
        ),
        timeout=5.0,
    )
    # The session hands over every AEAD failure, any size (the server's
    # intake filters); the genuine packet and its replay never go there.
    assert handed == [(MSG1, NEW), (small_junk, NEW)]
    assert tun.written == [b"x" * 1360]
    assert fsm.state is State.IDLE
