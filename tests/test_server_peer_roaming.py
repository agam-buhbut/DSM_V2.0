"""Server-side peer-roaming / source-address learning regression tests.

The server has no single expected peer address: it learns the client's UDP
ephemeral source from the FIRST authenticated packet, and re-learns it when an
authenticated peer roams (NAT rebind, network change) to a new source addr.
That learning is wired in ``dsm/server.py::_run_one_session`` as
``_record_client_addr`` and handed to ``run_data_loops`` as the
``post_authenticate`` callback. ``dsm/session.py::run_data_loops`` (the real
function under test here) calls ``post_authenticate(recv_addr)`` ONLY after
``decrypt_packet`` returns non-None — i.e. only on an AEAD-authenticated
packet. ``make_send_fn``'s send closure reads the recorded addr at send time,
so the next reply follows the peer to its new addr.

Security property locked here:
  * A SPOOFED pre-auth datagram from an attacker-chosen source addr (wrong
    key / garbage ciphertext that fails AEAD) MUST NOT update the send-addr.
    Otherwise an off-path attacker could redirect the server's replies to an
    addr of their choosing by forging a single packet.
  * An AUTHENTICATED packet from a NEW source addr DOES update the send-addr,
    and the reply goes to that new addr (roaming works).

All collaborators are faked at the I/O boundary (the UDP socket). The session
keys are a REAL ``tuncore.SessionKeyManager`` bootstrap pair so the
authenticated-vs-forged distinction is exercised by real AEAD, not a stub —
a stub that always "authenticates" would make the discriminating assertion
worthless.
"""

from __future__ import annotations

import asyncio
import unittest

from dsm.core.fsm import SessionFSM, State
from dsm.core.protocol import (
    SEQ_STRUCT,
    InnerPacket,
    OuterPacket,
    PacketType,
)
from dsm.core.protocol import (
    GCM_TAG_SIZE,
    OUTER_HEADER_SIZE,
    PATH_TOKEN_SIZE,
)
from dsm.net.transport.udp import UDPTransport
from dsm.rekey import SendFn
from dsm.session import (
    DataPathContext,
    LivenessState,
    PathValidationState,
    RekeyState,
    SequenceCounter,
    _build_control_packet,
    decrypt_packet,
    make_addr_send_fn,
    make_send_fn,
    run_data_loops,
)

try:
    import tuncore

    _HAS_TUNCORE = True
except ImportError:
    tuncore = None  # type: ignore[assignment]
    _HAS_TUNCORE = False


# Source addresses used in the tests. The "spoofed" one is what an off-path
# attacker would put in a forged datagram; the "roamed" one is where the
# genuine client moves to after a NAT rebind.
_SPOOFED_ADDR: tuple[str, int] = ("203.0.113.66", 4444)
_ROAMED_ADDR: tuple[str, int] = ("198.51.100.7", 51820)


class _RecordingTun:
    """TUN fake: read() blocks forever (so tun_send_loop stays idle); writes
    are captured so a decrypted DATA packet's delivery is observable."""

    def __init__(self) -> None:
        self.received: list[bytes] = []

    async def read(self, bufsize: int = 2048) -> bytes:
        await asyncio.sleep(3600)
        return b""

    async def awrite(self, data: bytes) -> int:
        self.received.append(bytes(data))
        return len(data)


class _ScriptedUDPTransport(UDPTransport):
    """A ``UDPTransport`` whose recv() replays a scripted list of
    ``(wire, src_addr)`` datagrams, then blocks; send() records
    ``(wire, dest_addr)`` instead of touching a real socket.

    Subclasses ``UDPTransport`` (rather than duck-typing) because
    ``make_send_fn`` branches on ``isinstance(transport, UDPTransport)`` to
    decide whether to resolve the destination addr — the addr-resolution path
    is exactly what these tests exercise.
    """

    def __init__(self, inbound: list[tuple[bytes, tuple[str, int]]]) -> None:
        # Intentionally skip UDPTransport.__init__ (no real socket).
        self._inbound = list(inbound)
        self._idx = 0
        self.sent: list[tuple[bytes, tuple[str, int]]] = []

    async def recv(  # type: ignore[override]
        self, timeout: float | None = None
    ) -> tuple[bytes, tuple[str, int]]:
        if self._idx < len(self._inbound):
            item = self._inbound[self._idx]
            self._idx += 1
            return item
        # Script exhausted: block so recv_loop hits its wait_for timeout and
        # keeps polling (it will exit when the test sets shutdown).
        await asyncio.sleep(3600)
        raise AssertionError("unreachable")

    async def send(  # type: ignore[override]
        self, data: bytes, addr: tuple[str, int]
    ) -> None:
        self.sent.append((bytes(data), addr))


def _established_fsm() -> SessionFSM:
    fsm = SessionFSM()
    fsm.transition(State.CONNECTING)
    fsm.transition(State.HANDSHAKING)
    fsm.transition(State.ESTABLISHED)
    return fsm


def _bootstrap_pair() -> tuple[tuncore.SessionKeyManager, tuncore.SessionKeyManager]:
    """Two SessionKeyManagers sharing a session (client=initiator, server=
    responder), via the same bootstrap DH the handshake uses."""
    a = tuncore.BootstrapEphemeral.generate()
    b = tuncore.BootstrapEphemeral.generate()
    a_pub = bytes(a.public_key_bytes)
    b_pub = bytes(b.public_key_bytes)
    client_keys = tuncore.complete_bootstrap(a, b_pub, is_initiator=True)
    server_keys = tuncore.complete_bootstrap(b, a_pub, is_initiator=False)
    return client_keys, server_keys


def _frame_data(
    keys: tuncore.SessionKeyManager,
    seq_counter: SequenceCounter,
    payload: bytes,
) -> bytes:
    """Build a genuine wire DATA packet the way ``make_send_fn`` does:
    seq ‖ nonce ‖ AEAD(inner, aad=seq), with the live epoch nibble stamped
    into inner-header byte 1."""
    n = seq_counter.next()
    inner = InnerPacket(
        ptype=PacketType.DATA, epoch_id=keys.epoch & 0x0F, payload=payload
    )
    buf = bytearray(inner.serialize())
    if len(buf) >= 2:
        buf[1] = (buf[1] & 0x0F) | ((keys.epoch & 0x0F) << 4)
    nonce, ct, _epoch = keys.encrypt(bytes(buf), SEQ_STRUCT.pack(n))
    return OuterPacket(seq=n, nonce=nonce, ciphertext=ct).serialize()


def _forged_packet(seq: int, body_len: int = 64) -> bytes:
    """A well-formed-looking outer packet (valid framing, length >=
    OUTER_HEADER_SIZE) whose ciphertext is garbage, so AEAD authentication
    fails. This is what an off-path attacker can produce: they can pick the
    seq and the source addr but cannot forge a tag under the session key."""
    nonce = b"\x00" * 12
    ciphertext = b"\xab" * body_len
    return OuterPacket(seq=seq, nonce=nonce, ciphertext=ciphertext).serialize()


@unittest.skipUnless(
    _HAS_TUNCORE,
    "tuncore (Rust crypto core) not built; run `maturin develop` in rust/tuncore/",
)
class ServerPeerRoaming(unittest.IsolatedAsyncioTestCase):
    """Exercise the real ``run_data_loops`` recv path with the server's
    ``post_authenticate=_record_client_addr`` wiring (mirrored from
    ``dsm/server.py::_run_one_session``)."""

    async def _drive(
        self,
        inbound: list[tuple[bytes, tuple[str, int]]],
        server_keys: tuncore.SessionKeyManager,
    ) -> tuple[
        list[tuple[str, int]],
        list[bytes],
        _ScriptedUDPTransport,
        SendFn,
    ]:
        """Run ``run_data_loops`` on the server side against the scripted
        inbound datagrams, then shut down. Returns the ordered list of addrs
        that ``post_authenticate`` recorded, the TUN writes, the transport
        (with its ``.sent`` capture), and the live send_fn closure."""
        fsm = _established_fsm()
        transport = _ScriptedUDPTransport(inbound)
        tun = _RecordingTun()
        replay = tuncore.ReplayWindow()

        # Mirror server.py's mutable client-addr cell + post_authenticate.
        recorded: list[tuple[str, int]] = []
        client_addr: dict[str, tuple[str, int] | None] = {"addr": None}

        def _dest() -> tuple[str, int] | None:
            return client_addr["addr"]

        def _record_client_addr(addr: tuple[str, int]) -> None:
            client_addr["addr"] = addr
            recorded.append(addr)

        seq = SequenceCounter()
        liveness = LivenessState()
        shutdown = asyncio.Event()
        send_fn = make_send_fn(
            server_keys,
            transport,
            _dest,
            seq,
            liveness=liveness,
            shutdown=shutdown,
        )

        class _NoopScheduler:
            def enqueue(
                self, data: bytes, target_size: int, *, extra_delay: float = 0.0
            ) -> None:
                pass

        class _NoopShaper:
            def pad_packet(self, inner: InnerPacket) -> tuple[bytes, int]:
                return (b"\x00" * 16, 128)

        ctx = DataPathContext(
            tun=tun,  # type: ignore[arg-type]
            session_keys=server_keys,
            fsm=fsm,
            shaper=_NoopShaper(),  # type: ignore[arg-type]
            send_fn=send_fn,
            scheduler=_NoopScheduler(),  # type: ignore[arg-type]
            rekey=RekeyState(),
            liveness=liveness,
            shutdown=shutdown,
            reassembly=None,
        )

        async def _run() -> None:
            await run_data_loops(
                ctx,
                transport,
                server_keys,
                replay,
                fsm,
                post_authenticate=_record_client_addr,
                shutdown_log="server shutting down",
            )

        task = asyncio.create_task(_run())
        # Let recv_loop consume the scripted datagrams and dispatch them.
        for _ in range(200):
            if len(recorded) >= 1 and len(tun.received) >= 1:
                break
            await asyncio.sleep(0.01)
        shutdown.set()
        await asyncio.wait_for(task, timeout=5.0)
        return recorded, tun.received, transport, send_fn

    async def test_spoofed_preauth_packet_does_not_update_addr(self) -> None:
        """KEY (security) assertion: a forged datagram from an
        attacker-chosen source addr that FAILS AEAD must not be recorded as
        the peer addr. Only the genuine, authenticated packet's source is.

        The forged packet arrives FIRST (and from a different addr than the
        genuine one), so if ``post_authenticate`` fired pre-auth, the very
        first recorded addr would be ``_SPOOFED_ADDR``. It must instead be
        the genuine client's addr, and ``_SPOOFED_ADDR`` must never appear.
        """
        client_keys, server_keys = _bootstrap_pair()
        seq = SequenceCounter()
        genuine = _frame_data(client_keys, seq, b"genuine-payload")

        # Off-path attacker forges a packet with the SAME seq the genuine one
        # will carry next is unnecessary — pick a distinct low seq so even the
        # replay window can't be the reason it's dropped; the AEAD failure is.
        inbound = [
            (_forged_packet(seq=1), _SPOOFED_ADDR),  # fails AEAD → must be ignored
            (genuine, _ROAMED_ADDR),  # authenticates → addr learned
        ]

        recorded, tun_writes, transport, _send_fn = await self._drive(
            inbound, server_keys
        )

        self.assertNotIn(
            _SPOOFED_ADDR,
            recorded,
            "spoofed pre-auth source addr was recorded — replies could be "
            "redirected by an off-path forger",
        )
        self.assertEqual(
            recorded,
            [_ROAMED_ADDR],
            "only the authenticated packet's source must be recorded",
        )
        # The genuine DATA payload was delivered to TUN; the forged one was not.
        self.assertEqual(tun_writes, [b"genuine-payload"])

    async def test_authenticated_roam_updates_addr_and_reply_follows(
        self,
    ) -> None:
        """An authenticated packet from a NEW source addr updates the recorded
        addr, and the next reply (via the real ``make_send_fn`` closure, which
        reads the recorded addr at send time) goes to that NEW addr — proving
        roaming actually redirects egress, not just bookkeeping."""
        client_keys, server_keys = _bootstrap_pair()
        seq = SequenceCounter()
        genuine = _frame_data(client_keys, seq, b"roam-hello")

        inbound = [(genuine, _ROAMED_ADDR)]
        recorded, _tun_writes, transport, send_fn = await self._drive(
            inbound, server_keys
        )

        self.assertEqual(recorded, [_ROAMED_ADDR])

        # Now the server sends a reply. make_send_fn resolves the destination
        # via the same _dest() closure post_authenticate updated, so the wire
        # packet must be addressed to the roamed-to addr.
        transport.sent.clear()
        # make_send_fn encrypts the 16-byte body to 16+GCM_TAG=32 ciphertext;
        # wire size = OUTER_HEADER_SIZE(20) + 32 = 52 (serialize's exact check).
        await send_fn(b"\x00" * 16, 52)
        self.assertEqual(len(transport.sent), 1, "reply must be sent")
        _wire, dest = transport.sent[0]
        self.assertEqual(
            dest,
            _ROAMED_ADDR,
            "reply must follow the authenticated peer to its new addr",
        )

    async def test_reply_before_any_auth_triggers_shutdown_not_misroute(
        self,
    ) -> None:
        """Before ANY authenticated packet, the recorded addr is None. A send
        attempt in that window must hit make_send_fn's 'addr not yet known'
        guard (shutdown + drop), NOT pick a stale/attacker addr. This pins the
        fail-closed behavior the roaming learning relies on."""
        _client_keys, server_keys = _bootstrap_pair()
        shutdown = asyncio.Event()
        transport = _ScriptedUDPTransport([])
        client_addr: dict[str, tuple[str, int] | None] = {"addr": None}
        send_fn = make_send_fn(
            server_keys,
            transport,
            lambda: client_addr["addr"],
            SequenceCounter(),
            shutdown=shutdown,
        )

        await send_fn(b"\x00" * 16, 52)

        self.assertTrue(
            shutdown.is_set(),
            "send before addr known must trigger shutdown, not misroute",
        )
        self.assertEqual(transport.sent, [], "no datagram may leave with no dest")


if __name__ == "__main__":
    unittest.main()
