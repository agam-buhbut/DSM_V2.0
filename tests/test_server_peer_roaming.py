"""Server-side peer-roaming / source-address learning regression tests.

The server has no single expected peer address: it learns the client's UDP
ephemeral source from the FIRST authenticated packet, and may roam its egress
when an authenticated peer moves (NAT rebind, network change) to a new source
addr — but the roam is GATED behind a QUIC-style return-routability check.
That wiring lives in ``dsm/server.py::_run_one_session`` as
``_post_authenticate`` (a ``PathValidationState`` + a direct-to-candidate
``make_addr_send_fn`` PATH_CHALLENGE) and is handed to ``run_data_loops`` as
the ``post_authenticate`` callback. ``dsm/session.py::run_data_loops`` (the
real function under test here) calls ``await post_authenticate(recv_addr,
inner)`` ONLY after ``decrypt_packet`` returns non-None — i.e. only on an
AEAD-authenticated packet — and BEFORE ``dispatch_inner`` so the egress
decision is made before the payload is delivered. ``make_send_fn``'s send
closure reads the recorded (committed) addr at send time, so egress only
follows the peer once the roam has been validated.

Security properties locked here:
  * A SPOOFED pre-auth datagram from an attacker-chosen source addr (wrong
    key / garbage ciphertext that fails AEAD) MUST NOT touch the send-addr or
    fire ``post_authenticate`` at all — it is dropped at AEAD.
  * The FIRST authenticated addr commits the egress (no challenge for it).
  * An AUTHENTICATED packet from a NEW source addr does NOT immediately roam
    egress. It is held as an unvalidated candidate and probed with a
    PATH_CHALLENGE sent DIRECTLY to that candidate addr; egress STAYS on the
    committed real client. (The old behaviour — immediately roaming to any
    AEAD-valid new source — WAS the on-path egress-redirection vulnerability:
    an attacker who suppressed and reinjected a genuine packet with a SPOOFED
    victim source could redirect the server's replies to the victim. These
    tests assert the DEFENSE, not the vuln.)
  * Egress commits to the new addr ONLY when a valid PATH_RESPONSE echoing
    the challenge token arrives FROM that candidate addr. The genuine
    packet's payload still delivers to TUN throughout — only the egress
    SWITCH is gated.

All collaborators are faked at the I/O boundary (the UDP socket). The session
keys are a REAL ``tuncore.SessionKeyManager`` bootstrap pair so the
authenticated-vs-forged distinction is exercised by real AEAD, not a stub —
a stub that always "authenticates" would make the discriminating assertion
worthless. The ``PathValidationState`` clock is injected so timeouts are
deterministic — no sleeps, no network.
"""

from __future__ import annotations

import asyncio
import unittest

from dsm.core.fsm import SessionFSM, State
from dsm.core.protocol import (
    GCM_TAG_SIZE,
    OUTER_HEADER_SIZE,
    PATH_TOKEN_SIZE,
    SEQ_STRUCT,
    InnerPacket,
    OuterPacket,
    PacketType,
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
# attacker would put in a forged datagram; the "committed" one is the real
# client the egress is pinned to; the "roamed" one is where the genuine
# client moves to after a NAT rebind.
_SPOOFED_ADDR: tuple[str, int] = ("203.0.113.66", 4444)
_COMMITTED_ADDR: tuple[str, int] = ("198.51.100.7", 51820)
_ROAMED_ADDR: tuple[str, int] = ("192.0.2.99", 33333)


class _FakeClock:
    """Manually advanced monotonic clock for deterministic timeouts."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


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

    Subclasses ``UDPTransport`` (rather than duck-typing) because both
    ``make_send_fn`` and ``make_addr_send_fn`` branch on
    ``isinstance(transport, UDPTransport)`` to decide whether to resolve the
    destination addr — the addr-resolution path is exactly what these tests
    exercise. The ``_inbound`` list is appended to at runtime (after a
    challenge token is observed) so a freshly-random token can be echoed back.
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


class _NoopScheduler:
    """Records enqueued packets without sending. Server-side path validation
    does not enqueue, but ``run_data_loops`` (liveness loop) may; capturing
    keeps the harness faithful without a real send path."""

    def __init__(self) -> None:
        self.enqueued: list[tuple[bytes, int]] = []

    def enqueue(
        self, data: bytes, target_size: int, *, extra_delay: float = 0.0
    ) -> None:
        self.enqueued.append((bytes(data), target_size))


class _ChallengeShaper:
    """Build a REAL padded control packet so the 16-byte challenge token
    survives the round-trip. ``_build_control_packet`` calls ``pad_packet``;
    the server's PATH_CHALLENGE must carry the actual token (a no-op shaper
    returning zeros would destroy it). Pads to a fixed 128-byte size class
    (inner len <= token + inner header, well under the slot)."""

    def pad_packet(self, inner: InnerPacket) -> tuple[bytes, int]:
        wire_inner = inner.serialize()
        target = 128
        # plaintext slot = target - OUTER_HEADER - GCM_TAG (so after AEAD +
        # OuterPacket framing the wire is exactly `target`).
        slot = target - OUTER_HEADER_SIZE - GCM_TAG_SIZE
        buf = bytearray(slot)
        buf[: len(wire_inner)] = wire_inner
        return bytes(buf), target


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


def _frame(
    keys: tuncore.SessionKeyManager,
    seq_counter: SequenceCounter,
    ptype: PacketType,
    payload: bytes,
) -> bytes:
    """Build a genuine authenticated wire packet of ``ptype`` the way
    ``make_send_fn`` does: seq ‖ nonce ‖ AEAD(inner, aad=seq), with the live
    epoch nibble stamped into inner-header byte 1."""
    n = seq_counter.next()
    inner = InnerPacket(ptype=ptype, epoch_id=keys.epoch & 0x0F, payload=payload)
    buf = bytearray(inner.serialize())
    if len(buf) >= 2:
        buf[1] = (buf[1] & 0x0F) | ((keys.epoch & 0x0F) << 4)
    nonce, ct, _epoch = keys.encrypt(bytes(buf), SEQ_STRUCT.pack(n))
    return OuterPacket(seq=n, nonce=nonce, ciphertext=ct).serialize()


def _extract_token(wire: bytes, client_keys: tuncore.SessionKeyManager) -> bytes:
    """Decrypt a server-emitted PATH_CHALLENGE wire packet and return its
    16-byte token.

    AEAD is directional: the SERVER encrypts with its send key, so the CLIENT
    (whose receive key = server's send key) is the party that decrypts. The
    on-path attacker who spoofed the source addr does NOT hold these keys —
    that is exactly why it cannot answer the challenge. Uses a fresh replay
    window so it never collides with the driver's own window."""
    replay = tuncore.ReplayWindow()
    result = decrypt_packet(wire, client_keys, replay)
    assert result is not None, "server challenge did not authenticate"
    inner, _prev = result
    assert inner.ptype == PacketType.PATH_CHALLENGE
    assert len(inner.payload) == PATH_TOKEN_SIZE
    return inner.payload


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
    validated-roam ``post_authenticate`` wiring (mirrored faithfully from
    ``dsm/server.py::_run_one_session``)."""

    async def _drive(
        self,
        inbound: list[tuple[bytes, tuple[str, int]]],
        server_keys: tuncore.SessionKeyManager,
        *,
        committed_seed: tuple[str, int] | None = None,
        clock: _FakeClock | None = None,
        stop_when=None,
    ) -> tuple[
        dict[str, tuple[str, int] | None],
        list[bytes],
        _ScriptedUDPTransport,
        SendFn,
    ]:
        """Run ``run_data_loops`` server-side against the scripted inbound
        datagrams with the path-validation gating callback wired exactly like
        ``dsm/server.py``, then shut down.

        ``committed_seed`` pre-commits the egress (skipping the "first addr
        commits" branch) so a test starts already-established with a known
        committed peer. ``clock`` injects the ``PathValidationState`` clock for
        deterministic timeouts. ``stop_when(client_addr, transport, tun)`` is
        polled to decide when to set shutdown (defaults to "first addr
        committed and one TUN write").

        Returns the committed-addr cell, the TUN writes, the transport (with
        its ``.sent`` capture), and the live send_fn closure.
        """
        fsm = _established_fsm()
        transport = _ScriptedUDPTransport(inbound)
        tun = _RecordingTun()
        replay = tuncore.ReplayWindow()
        clock = clock or _FakeClock()

        # Mirror server.py's mutable committed-client-addr cell.
        client_addr: dict[str, tuple[str, int] | None] = {"addr": committed_seed}

        def _dest() -> tuple[str, int] | None:
            return client_addr["addr"]

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
        scheduler = _NoopScheduler()

        ctx = DataPathContext(
            tun=tun,  # type: ignore[arg-type]
            session_keys=server_keys,
            fsm=fsm,
            shaper=_ChallengeShaper(),  # type: ignore[arg-type]
            send_fn=send_fn,
            scheduler=scheduler,  # type: ignore[arg-type]
            rekey=RekeyState(),
            liveness=liveness,
            shutdown=shutdown,
            reassembly=None,
        )

        # Mirror dsm/server.py::_run_one_session path-validation wiring.
        # The challenge MUST go DIRECTLY to the pending candidate via a
        # by-addr send (NOT through the scheduler, which always targets the
        # committed egress, and WITHOUT mutating the committed egress).
        path_validation = PathValidationState(clock=clock)
        path_send = make_addr_send_fn(server_keys, transport, seq)

        async def _send_challenge(candidate: tuple[str, int], token: bytes) -> None:
            padded, target_size = _build_control_packet(
                ctx,
                PacketType.PATH_CHALLENGE,
                # payload IS a real kwarg (runtime sig: ctx, ptype, payload=b"");
                # production server.py uses the identical call pyright-clean.
                payload=token,  # pyright: ignore[reportCallIssue]
            )
            try:
                await asyncio.wait_for(
                    path_send(padded, target_size, candidate), timeout=5.0
                )
            except (TimeoutError, OSError):
                pass

        async def _post_authenticate(addr: tuple[str, int], inner: object) -> None:
            assert isinstance(inner, InnerPacket)
            committed = client_addr["addr"]
            # First authenticated addr: commit (no challenge for the first).
            if committed is None:
                client_addr["addr"] = addr
                return
            # A PATH_RESPONSE from the pending candidate with a matching token
            # COMMITS the roam. Checked BEFORE the same-addr fast path so a
            # response from the (different) candidate addr is acted on here.
            if inner.ptype == PacketType.PATH_RESPONSE:
                if path_validation.validate(addr, inner.payload):
                    client_addr["addr"] = addr
                    path_validation.clear()
                return
            # Same committed addr: steady state, nothing to do.
            if addr == committed:
                return
            # A DIFFERENT authenticated source: hold as the pending candidate
            # and (rate-limited) probe it. Egress stays on the committed addr.
            token = path_validation.should_challenge(addr)
            if token is not None:
                await _send_challenge(addr, token)

        async def _run() -> None:
            await run_data_loops(
                ctx,
                transport,
                server_keys,
                replay,
                fsm,
                post_authenticate=_post_authenticate,
                shutdown_log="server shutting down",
            )

        def _default_stop(addr_cell, _transport, _tun) -> bool:
            return addr_cell["addr"] is not None and bool(_tun.received)

        stop = stop_when or _default_stop

        task = asyncio.create_task(_run())
        for _ in range(400):
            if stop(client_addr, transport, tun):
                break
            await asyncio.sleep(0.01)
        shutdown.set()
        await asyncio.wait_for(task, timeout=5.0)
        return client_addr, tun.received, transport, send_fn

    async def test_spoofed_preauth_packet_does_not_update_addr(self) -> None:
        """KEY (security) assertion: a forged datagram from an
        attacker-chosen source addr that FAILS AEAD must not be committed as
        the peer addr — ``post_authenticate`` never even fires for it. Only
        the genuine, authenticated packet's source is committed.

        The forged packet arrives FIRST (and from a different addr than the
        genuine one), so if the AEAD pre-check were bypassed the very first
        committed addr would be ``_SPOOFED_ADDR``. It must instead be the
        genuine client's addr, and ``_SPOOFED_ADDR`` must never appear.
        """
        client_keys, server_keys = _bootstrap_pair()
        cseq = SequenceCounter()
        genuine = _frame(client_keys, cseq, PacketType.DATA, b"genuine-payload")

        # Off-path attacker forges a packet (fails AEAD) from a spoofed addr,
        # then the genuine authenticated packet arrives from the real client.
        inbound = [
            (_forged_packet(seq=1), _SPOOFED_ADDR),  # fails AEAD → ignored
            (genuine, _ROAMED_ADDR),  # authenticates → addr committed
        ]

        addr_cell, tun_writes, transport, _send_fn = await self._drive(
            inbound, server_keys
        )

        # Spoofed source never became the egress, and the only committed addr
        # is the genuine client's.
        self.assertNotEqual(
            addr_cell["addr"],
            _SPOOFED_ADDR,
            "spoofed pre-auth source addr was committed — replies could be "
            "redirected by an off-path forger",
        )
        self.assertEqual(
            addr_cell["addr"],
            _ROAMED_ADDR,
            "only the authenticated packet's source must be committed",
        )
        # Nothing was ever sent to the spoofed addr (no challenge: the forged
        # packet failed AEAD before post_authenticate, so it is not even a
        # roam candidate).
        self.assertFalse(
            any(d == _SPOOFED_ADDR for _w, d in transport.sent),
            "a packet that failed AEAD must not produce any egress to its "
            "spoofed source",
        )
        # The genuine DATA payload was delivered to TUN; the forged one was not.
        self.assertEqual(tun_writes, [b"genuine-payload"])

    async def test_new_source_emits_challenge_and_does_not_commit_egress(
        self,
    ) -> None:
        """An AEAD-valid packet from a NEW source addr (different from the
        committed client) does NOT immediately roam egress — that immediate
        roam WAS the vulnerability. Instead the server emits a PATH_CHALLENGE
        DIRECTLY to the candidate addr and egress STAYS on the committed real
        client. The packet's payload still delivers to TUN. With no valid
        PATH_RESPONSE, the egress never moves."""
        client_keys, server_keys = _bootstrap_pair()
        cseq = SequenceCounter()
        # Genuine AEAD-valid DATA, but from a NEW source. (In the on-path
        # attack this is a suppressed-and-reinjected packet with a SPOOFED
        # victim source; here we just assert the gating for any new source.)
        new_source = _frame(client_keys, cseq, PacketType.DATA, b"roam-hello")

        def _stop(addr_cell, transport, tun) -> bool:
            # Stop once the challenge has been emitted to the new source AND
            # the payload delivered.
            challenged = any(d == _ROAMED_ADDR for _w, d in transport.sent)
            return challenged and bool(tun.received)

        addr_cell, tun_writes, transport, _send_fn = await self._drive(
            [(new_source, _ROAMED_ADDR)],
            server_keys,
            committed_seed=_COMMITTED_ADDR,
            stop_when=_stop,
        )

        # Egress did NOT roam to the new source.
        self.assertEqual(
            addr_cell["addr"],
            _COMMITTED_ADDR,
            "an AEAD-valid packet from a new source roamed egress with no "
            "return-routability check — the redirect vuln is NOT fixed",
        )
        # Exactly ONE packet went to the new source: the PATH_CHALLENGE probe.
        to_candidate = [(w, d) for w, d in transport.sent if d == _ROAMED_ADDR]
        self.assertEqual(
            len(to_candidate),
            1,
            "exactly one PATH_CHALLENGE to the unvalidated candidate expected",
        )
        # Everything else (incl. teardown SESSION_CLOSE) goes to the COMMITTED
        # egress — confirming egress genuinely never moved.
        self.assertTrue(
            all(d == _COMMITTED_ADDR for _w, d in transport.sent if d != _ROAMED_ADDR),
            "non-challenge egress must stay on the committed real client",
        )
        # The probe is a real PATH_CHALLENGE carrying a 16-byte token,
        # decryptable only by the client's keys (an off-path spoofer holds no
        # keys, so it could neither produce nor answer it).
        self.assertEqual(
            len(_extract_token(to_candidate[0][0], client_keys)),
            PATH_TOKEN_SIZE,
        )
        # The new-source packet's payload still delivered to TUN (only the
        # egress switch is gated).
        self.assertEqual(tun_writes, [b"roam-hello"])

    async def test_valid_path_response_commits_roam_and_reply_follows(
        self,
    ) -> None:
        """A client that has roamed to a NEW addr, receives the challenge
        there, and echoes the token in a valid PATH_RESPONSE DOES get
        committed — and the next reply (via the real ``make_send_fn`` closure,
        which reads the committed addr at send time) goes to the roamed addr,
        proving the validated roam actually redirects egress.

        The token is freshly random per run, so the response can only be built
        AFTER observing the challenge: the driver captures the live token from
        the server's emitted PATH_CHALLENGE and injects a matching
        PATH_RESPONSE from the roamed addr."""
        client_keys, server_keys = _bootstrap_pair()
        cseq = SequenceCounter()
        roam_trigger = _frame(client_keys, cseq, PacketType.DATA, b"roam-hello")

        fsm = _established_fsm()
        tun = _RecordingTun()
        replay = tuncore.ReplayWindow()
        clock = _FakeClock()
        client_addr: dict[str, tuple[str, int] | None] = {"addr": _COMMITTED_ADDR}
        inbound: list[tuple[bytes, tuple[str, int]]] = [(roam_trigger, _ROAMED_ADDR)]
        transport = _ScriptedUDPTransport(inbound)

        def _dest() -> tuple[str, int] | None:
            return client_addr["addr"]

        seq = SequenceCounter()
        liveness = LivenessState()
        shutdown = asyncio.Event()
        send_fn = make_send_fn(
            server_keys, transport, _dest, seq, liveness=liveness, shutdown=shutdown
        )
        scheduler = _NoopScheduler()

        ctx = DataPathContext(
            tun=tun,  # type: ignore[arg-type]
            session_keys=server_keys,
            fsm=fsm,
            shaper=_ChallengeShaper(),  # type: ignore[arg-type]
            send_fn=send_fn,
            scheduler=scheduler,  # type: ignore[arg-type]
            rekey=RekeyState(),
            liveness=liveness,
            shutdown=shutdown,
            reassembly=None,
        )
        path_validation = PathValidationState(clock=clock)
        path_send = make_addr_send_fn(server_keys, transport, seq)

        async def _send_challenge(candidate: tuple[str, int], token: bytes) -> None:
            padded, target_size = _build_control_packet(
                ctx,
                PacketType.PATH_CHALLENGE,
                # payload IS a real kwarg (runtime sig: ctx, ptype, payload=b"");
                # production server.py uses the identical call pyright-clean.
                payload=token,  # pyright: ignore[reportCallIssue]
            )
            await path_send(padded, target_size, candidate)

        async def _post_authenticate(addr: tuple[str, int], inner: object) -> None:
            assert isinstance(inner, InnerPacket)
            committed = client_addr["addr"]
            if committed is None:
                client_addr["addr"] = addr
                return
            if inner.ptype == PacketType.PATH_RESPONSE:
                if path_validation.validate(addr, inner.payload):
                    client_addr["addr"] = addr
                    path_validation.clear()
                return
            if addr == committed:
                return
            token = path_validation.should_challenge(addr)
            if token is not None:
                await _send_challenge(addr, token)

        async def _run() -> None:
            await run_data_loops(
                ctx,
                transport,
                server_keys,
                replay,
                fsm,
                post_authenticate=_post_authenticate,
                shutdown_log="server shutting down",
            )

        task = asyncio.create_task(_run())
        # Wait for the challenge to be emitted to the roamed addr.
        for _ in range(400):
            if any(d == _ROAMED_ADDR for _w, d in transport.sent):
                break
            await asyncio.sleep(0.01)
        # Capture the live token and craft the matching PATH_RESPONSE from the
        # client (it is AT the roamed addr and holds the keys to decrypt the
        # challenge — an off-path spoofer does not).
        token = _extract_token(transport.sent[0][0], client_keys)
        response = _frame(client_keys, cseq, PacketType.PATH_RESPONSE, token)
        transport._inbound.append((response, _ROAMED_ADDR))
        for _ in range(400):
            if client_addr["addr"] == _ROAMED_ADDR:
                break
            await asyncio.sleep(0.01)

        self.assertEqual(
            client_addr["addr"],
            _ROAMED_ADDR,
            "a roamed client that answered the challenge must be committed",
        )

        # Now the server sends a reply. make_send_fn resolves the destination
        # via the same _dest() closure the commit updated, so the wire packet
        # must be addressed to the roamed addr.
        transport.sent.clear()
        # make_send_fn encrypts the 16-byte body to 16+GCM_TAG=32 ciphertext;
        # wire size = OUTER_HEADER_SIZE(20) + 32 = 52 (serialize's exact check).
        await send_fn(b"\x00" * 16, 52)
        self.assertEqual(len(transport.sent), 1, "reply must be sent")
        _wire, dest = transport.sent[0]
        self.assertEqual(
            dest,
            _ROAMED_ADDR,
            "after a validated roam the reply must follow the peer to its " "new addr",
        )

        shutdown.set()
        await asyncio.wait_for(task, timeout=5.0)

    async def test_wrong_token_response_does_not_commit_roam(self) -> None:
        """A PATH_RESPONSE from the candidate addr carrying a WRONG token must
        NOT commit — egress stays on the committed real client. This is the
        on-path attacker's best shot (it cannot read the token, so it can only
        guess): the guess must fail."""
        client_keys, server_keys = _bootstrap_pair()
        cseq = SequenceCounter()
        roam_trigger = _frame(client_keys, cseq, PacketType.DATA, b"roam-hello")

        fsm = _established_fsm()
        tun = _RecordingTun()
        replay = tuncore.ReplayWindow()
        clock = _FakeClock()
        client_addr: dict[str, tuple[str, int] | None] = {"addr": _COMMITTED_ADDR}
        inbound: list[tuple[bytes, tuple[str, int]]] = [(roam_trigger, _ROAMED_ADDR)]
        transport = _ScriptedUDPTransport(inbound)

        def _dest() -> tuple[str, int] | None:
            return client_addr["addr"]

        seq = SequenceCounter()
        liveness = LivenessState()
        shutdown = asyncio.Event()
        send_fn = make_send_fn(
            server_keys, transport, _dest, seq, liveness=liveness, shutdown=shutdown
        )
        scheduler = _NoopScheduler()

        ctx = DataPathContext(
            tun=tun,  # type: ignore[arg-type]
            session_keys=server_keys,
            fsm=fsm,
            shaper=_ChallengeShaper(),  # type: ignore[arg-type]
            send_fn=send_fn,
            scheduler=scheduler,  # type: ignore[arg-type]
            rekey=RekeyState(),
            liveness=liveness,
            shutdown=shutdown,
            reassembly=None,
        )
        path_validation = PathValidationState(clock=clock)
        path_send = make_addr_send_fn(server_keys, transport, seq)

        async def _send_challenge(candidate: tuple[str, int], token: bytes) -> None:
            padded, target_size = _build_control_packet(
                ctx,
                PacketType.PATH_CHALLENGE,
                # payload IS a real kwarg (runtime sig: ctx, ptype, payload=b"");
                # production server.py uses the identical call pyright-clean.
                payload=token,  # pyright: ignore[reportCallIssue]
            )
            await path_send(padded, target_size, candidate)

        async def _post_authenticate(addr: tuple[str, int], inner: object) -> None:
            assert isinstance(inner, InnerPacket)
            committed = client_addr["addr"]
            if committed is None:
                client_addr["addr"] = addr
                return
            if inner.ptype == PacketType.PATH_RESPONSE:
                if path_validation.validate(addr, inner.payload):
                    client_addr["addr"] = addr
                    path_validation.clear()
                return
            if addr == committed:
                return
            token = path_validation.should_challenge(addr)
            if token is not None:
                await _send_challenge(addr, token)

        async def _run() -> None:
            await run_data_loops(
                ctx,
                transport,
                server_keys,
                replay,
                fsm,
                post_authenticate=_post_authenticate,
                shutdown_log="server shutting down",
            )

        task = asyncio.create_task(_run())
        for _ in range(400):
            if any(d == _ROAMED_ADDR for _w, d in transport.sent):
                break
            await asyncio.sleep(0.01)
        # Capture the real token, flip a byte → a token the attacker did NOT
        # learn, and send it back from the candidate addr.
        token = _extract_token(transport.sent[0][0], client_keys)
        bad_token = bytes((token[0] ^ 0xFF,)) + token[1:]
        response = _frame(client_keys, cseq, PacketType.PATH_RESPONSE, bad_token)
        transport._inbound.append((response, _ROAMED_ADDR))
        # Give the (rejected) response time to be processed.
        for _ in range(50):
            await asyncio.sleep(0.01)

        self.assertEqual(
            client_addr["addr"],
            _COMMITTED_ADDR,
            "a mismatched token must not commit the roam",
        )

        shutdown.set()
        await asyncio.wait_for(task, timeout=5.0)

    async def test_reply_before_any_auth_triggers_shutdown_not_misroute(
        self,
    ) -> None:
        """Before ANY authenticated packet, the committed addr is None. A send
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
