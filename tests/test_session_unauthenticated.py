"""The live session hands each packet it cannot use (AEAD failed, or already
seen by the replay window) to the server's in-session accept, and nothing
else. Review Focus 2: a packet that opened, the live client's own traffic,
never goes there.

A reconnected client's first packet has seq 1 under the new keys, and the old
session's window has already seen seq 1, so it is rejected as a replay before
AEAD. It has to be handed over too, marked as seen: the accept wants it only
once a client won (until then it is the live client's own packet).

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


def test_only_packets_the_session_cannot_use_are_handed_over() -> None:
    sender, receiver = _pair()
    replay = tuncore.ReplayWindow()
    failed: list[int] = []
    seen: list[int] = []

    def decrypt(data: bytes) -> object:
        return decrypt_packet(
            data,
            receiver,
            replay,
            on_auth_fail=lambda: failed.append(1),
            on_replay=lambda: seen.append(1),
        )

    epoch = receiver.epoch
    genuine = _wire(sender, 5, _plain(PacketType.DATA, epoch, b"x" * 1360))
    assert len(genuine) == 1400  # a genuine packet the size of a msg1
    assert decrypt(genuine) is not None
    # Too short to be a packet.
    assert decrypt(bytes(10)) is None
    # Opens, but the inner part is bad (a reserved flag bit set).
    bad_inner = _wire(sender, 6, _plain(PacketType.DATA, epoch, b"x", flags=0x01))
    assert decrypt(bad_inner) is None
    # Opens, but the epoch nibble is wrong.
    wrong_epoch = _wire(sender, 7, _plain(PacketType.DATA, epoch + 3, b"x"))
    assert decrypt(wrong_epoch) is None
    assert (failed, seen) == ([], [])
    # Does not open: a new client's msg1, and a forged packet.
    assert decrypt(MSG1) is None
    forged = bytearray(_wire(sender, 8, _plain(PacketType.DATA, epoch, b"y")))
    forged[-1] ^= 0x01
    assert decrypt(bytes(forged)) is None
    assert (failed, seen) == ([1, 1], [])
    # Already seen: the replay window rejects it before AEAD. It goes to
    # on_replay, never on_auth_fail (it may be a new key's packet; see the
    # next test).
    assert decrypt(genuine) is None
    assert (failed, seen) == ([1, 1], [1])


def test_a_new_key_packet_the_old_window_already_saw_is_handed_over() -> None:
    # The exact failure: the client reconnects and sends seq 1 under the new
    # keys; the old session's window already saw seq 1, so it drops the packet
    # as a replay before AEAD. The in-session accept must still get it.
    old_sender, old_receiver = _pair()
    new_sender, _new_receiver = _pair()
    replay = tuncore.ReplayWindow()
    handed: list[int] = []
    epoch = old_receiver.epoch
    for seq in (1, 2, 3):
        old = _wire(old_sender, seq, _plain(PacketType.DATA, epoch, b"old"))
        assert decrypt_packet(old, old_receiver, replay) is not None

    first_new = _wire(new_sender, 1, _plain(PacketType.DATA, epoch, b"new"))
    result = decrypt_packet(
        first_new,
        old_receiver,
        replay,
        on_auth_fail=lambda: handed.append(0),
        on_replay=lambda: handed.append(1),
    )
    assert result is None
    assert handed == [1]


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


async def test_the_receive_loop_hands_over_only_packets_it_cannot_use() -> None:
    sender, receiver = _pair()
    tun = _Tun()
    ctx, fsm = _ctx(receiver, tun)
    transport = UDPTransport()  # never bound: the test fills its queue
    genuine = _wire(sender, 1, _plain(PacketType.DATA, receiver.epoch, b"x" * 1360))
    small_junk = b"\x7f" * 300
    for item in ((genuine, LIVE), (genuine, LIVE), (MSG1, NEW), (small_junk, NEW)):
        transport._recv_queue.put_nowait(item)
    handed: list[tuple[bytes, Addr, bool]] = []

    def unauthenticated(data: bytes, addr: Addr, seen: bool) -> None:
        handed.append((data, addr, seen))
        if len(handed) == 3:
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
    # The session hands over every packet it cannot use, any size (the
    # server's intake filters): the replay, marked as seen, and the two that
    # do not open. The genuine packet, which opened, never goes there.
    assert handed == [
        (genuine, LIVE, True),
        (MSG1, NEW, False),
        (small_junk, NEW, False),
    ]
    assert tun.written == [b"x" * 1360]
    assert fsm.state is State.IDLE
