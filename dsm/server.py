"""DSM VPN server mode."""

from __future__ import annotations

import asyncio
import getpass
import logging
import signal
import struct

from dsm.core.config import Config
from dsm.core.fsm import SessionFSM, State
from dsm.core.protocol import InnerPacket, OuterPacket, PacketType, OUTER_HEADER_SIZE
from dsm.crypto.keystore import KeyStore
from dsm.net.tunnel import TunDevice
from dsm.net.transport.udp import UDPTransport
from dsm.net.transport.tcp import TCPTransport
from dsm.traffic.shaper import TrafficShaper
from dsm.traffic.scheduler import SendScheduler
from dsm.rekey import initiate_rekey, handle_rekey_init, handle_rekey_ack

log = logging.getLogger(__name__)


async def _make_chaff(shaper: TrafficShaper) -> tuple[bytes, int]:
    chaff = shaper.make_chaff()
    padded, target = shaper.pad_packet(chaff)
    return padded, target


async def run_server(config: Config) -> None:
    """Run DSM in server mode."""
    import tuncore

    tuncore.disable_core_dumps()

    fsm = SessionFSM()

    # Load identity
    keystore = KeyStore(config.key_file)
    passphrase = bytearray(getpass.getpass("Key passphrase: ").encode())
    try:
        if keystore.exists():
            pub = keystore.load(bytes(passphrase))
        else:
            pub = keystore.generate(bytes(passphrase))
    finally:
        passphrase[:] = b"\x00" * len(passphrase)
        del passphrase
    log.info("server identity loaded")

    # Transport
    if config.transport == "udp":
        transport = UDPTransport()
        await transport.bind(local_port=config.listen_port)
    else:
        transport = TCPTransport()
        await transport.listen(port=config.listen_port)

    log.info("server listening on port %d (%s)", config.listen_port, config.transport)

    # Wait for handshake
    from dsm.crypto.handshake import server_handshake

    fsm.transition(State.CONNECTING)
    fsm.transition(State.HANDSHAKING)

    session_keys, client_pub = await server_handshake(transport, keystore.identity)

    fsm.transition(State.ESTABLISHED)
    log.info("client connected")

    # TODO: integrate DNS proxying — intercept DNS queries from TUN, resolve, return answers.
    # DNS resolver is not yet wired into the data path.

    # TUN device
    tun = TunDevice(config.tun_name)
    tun.open()
    tun.configure(local_ip="10.8.0.1")

    shaper = TrafficShaper(config.padding_min, config.padding_max)
    replay = tuncore.ReplayWindow()

    server_seq = 0
    rekey_in_progress = False
    last_rekey_time: float | None = None
    pending_rekey_epoch: int | None = None

    shutdown = asyncio.Event()
    client_addr: tuple[str, int] | None = None

    def handle_signal() -> None:
        shutdown.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, handle_signal)

    async def recv_loop() -> None:
        nonlocal client_addr, rekey_in_progress, last_rekey_time, pending_rekey_epoch
        while not shutdown.is_set():
            recv_addr: tuple[str, int] | None = None
            try:
                if isinstance(transport, UDPTransport):
                    data, recv_addr = await asyncio.wait_for(transport.recv(), timeout=0.1)
                else:
                    data = await asyncio.wait_for(transport.recv(), timeout=0.1)
            except asyncio.TimeoutError:
                session_keys.tick()
                continue

            if len(data) < OUTER_HEADER_SIZE:
                log.debug("packet too short, dropping")
                continue

            seq = struct.unpack("!Q", data[:8])[0]
            if not replay.check(seq):
                log.debug("replay detected, dropping seq=%d", seq)
                continue

            nonce_bytes = data[8:20]
            ciphertext = data[OUTER_HEADER_SIZE:]
            aad = struct.pack("!Q", seq)

            decrypted_prev_epoch = False
            try:
                plaintext = session_keys.decrypt(nonce_bytes, ciphertext, aad, seq, False)
            except Exception:
                if session_keys.has_grace_period:
                    try:
                        plaintext = session_keys.decrypt(nonce_bytes, ciphertext, aad, seq, True)
                        decrypted_prev_epoch = True
                    except Exception:
                        log.debug("decrypt failed (both epochs), dropping packet")
                        continue
                else:
                    log.debug("decrypt failed, dropping packet")
                    continue

            replay.update(seq)

            # Update peer address only after successful authentication
            if recv_addr is not None:
                client_addr = recv_addr

            try:
                inner = InnerPacket.deserialize(plaintext)
            except ValueError:
                log.debug("malformed inner packet, dropping")
                continue

            # Verify epoch_id matches the key epoch used for decryption
            if inner.ptype != PacketType.CHAFF:
                if decrypted_prev_epoch:
                    expected_eid = (session_keys.epoch - 1) & 0x03
                else:
                    expected_eid = session_keys.epoch & 0x03
                if inner.epoch_id != expected_eid:
                    log.debug("epoch_id mismatch: got %d, expected %d", inner.epoch_id, expected_eid)
                    continue

            if inner.ptype == PacketType.CHAFF:
                continue
            elif inner.ptype == PacketType.DATA:
                await tun.awrite(inner.payload)
            elif inner.ptype == PacketType.REKEY_INIT:
                last_rekey_time = await handle_rekey_init(
                    inner.payload, session_keys, fsm, shaper, server_send_packet,
                    last_rekey_time,
                )
            elif inner.ptype == PacketType.REKEY_ACK:
                ts = handle_rekey_ack(
                    inner.payload, session_keys, fsm, pending_rekey_epoch,
                )
                if ts is not None:
                    last_rekey_time = ts
                    pending_rekey_epoch = None
                rekey_in_progress = False
            elif inner.ptype == PacketType.SESSION_CLOSE:
                shutdown.set()
                break

    async def server_send_packet(data: bytes, target_size: int) -> None:
        nonlocal server_seq
        server_seq += 1
        if server_seq >= 2**64:
            raise RuntimeError("sequence number overflow — session must be rekeyed")
        aad = struct.pack("!Q", server_seq)
        nonce, ct, _epoch = session_keys.encrypt(data, aad)
        outer = OuterPacket(seq=server_seq, nonce=bytes(nonce), ciphertext=ct)
        wire = outer.serialize(target_size)
        if isinstance(transport, UDPTransport):
            assert client_addr is not None, "UDP requires client address"
            await transport.send(wire, client_addr)
        else:
            await transport.send(wire)

    server_scheduler = SendScheduler(
        send_fn=server_send_packet,
        chaff_fn=lambda: _make_chaff(shaper),
        should_chaff_fn=shaper.should_send_chaff,
        jitter_ms_min=config.jitter_ms_min,
        jitter_ms_max=config.jitter_ms_max,
    )
    await server_scheduler.start()

    async def tun_to_client() -> None:
        nonlocal rekey_in_progress, last_rekey_time, pending_rekey_epoch
        while not shutdown.is_set():
            if session_keys.needs_rotation() and not rekey_in_progress:
                rekey_in_progress = True
                last_rekey_time, pending_rekey_epoch = await initiate_rekey(
                    session_keys, fsm, shaper, server_send_packet, last_rekey_time,
                )

            try:
                pkt = await asyncio.wait_for(tun.read(), timeout=0.1)
            except asyncio.TimeoutError:
                continue

            inner = InnerPacket(
                ptype=PacketType.DATA,
                epoch_id=session_keys.epoch & 0x03,
                payload=pkt,
            )
            padded, target_size = shaper.pad_packet(inner)
            shaper.observe_real_packet(target_size)
            server_scheduler.enqueue(padded, target_size)

    try:
        await asyncio.gather(recv_loop(), tun_to_client())
    except asyncio.CancelledError:
        pass
    finally:
        log.info("server shutting down")
        await server_scheduler.stop()
        tun.close()
        keystore.unload()
        await transport.aclose()
        fsm.transition(State.TEARDOWN)
        fsm.transition(State.IDLE)
