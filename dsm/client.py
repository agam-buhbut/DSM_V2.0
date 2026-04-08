"""DSM VPN client mode."""

from __future__ import annotations

import asyncio
import getpass
import logging
import signal
import struct
from pathlib import Path

from dsm.core.config import Config
from dsm.core.fsm import SessionFSM, State
from dsm.core.protocol import InnerPacket, OuterPacket, PacketType, OUTER_HEADER_SIZE
from dsm.crypto.keystore import KeyStore
from dsm.net.nftables import NFTablesManager
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


async def run_client(config: Config) -> None:
    """Run DSM in client mode."""
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
            log.info("generated new identity keypair")
    finally:
        passphrase[:] = b"\x00" * len(passphrase)
        del passphrase
    log.info("identity loaded")

    # Setup components
    nft = NFTablesManager(config.server_ip, config.server_port, config.tun_name)
    tun = TunDevice(config.tun_name)
    shaper = TrafficShaper(config.padding_min, config.padding_max)

    # Transport
    if config.transport == "udp":
        transport = UDPTransport()
        await transport.bind(local_port=config.listen_port)
    else:
        transport = TCPTransport()
        await transport.connect(config.server_ip, config.server_port)

    server_addr = (config.server_ip, config.server_port)

    # FSM: IDLE -> CONNECTING -> HANDSHAKING
    fsm.transition(State.CONNECTING)
    fsm.transition(State.HANDSHAKING)

    from dsm.crypto.handshake import client_handshake

    try:
        session_keys, _handshake_hash = await client_handshake(
            transport,
            keystore.identity,
            server_addr,
            known_hosts_path=Path("/opt/mtun/known_hosts.json"),
        )
    except Exception as e:
        log.error("handshake failed: %s", e)
        fsm.transition(State.TEARDOWN)
        transport.close()
        return

    # FSM: HANDSHAKING -> ESTABLISHED
    fsm.transition(State.ESTABLISHED)

    # Configure TUN and nftables
    tun.open()
    tun.configure()
    nft.apply()

    log.info("tunnel established")

    seq_counter = 0
    replay = tuncore.ReplayWindow()
    rekey_in_progress = False
    last_rekey_time: float | None = None

    async def send_packet(data: bytes, target_size: int) -> None:
        nonlocal seq_counter
        seq_counter += 1
        if seq_counter >= 2**64:
            raise RuntimeError("sequence number overflow — session must be rekeyed")
        aad = struct.pack("!Q", seq_counter)
        nonce, ct, _epoch = session_keys.encrypt(data, aad)
        outer = OuterPacket(seq=seq_counter, nonce=bytes(nonce), ciphertext=ct)
        wire = outer.serialize(target_size)
        if isinstance(transport, UDPTransport):
            await transport.send(wire, server_addr)
        else:
            await transport.send(wire)

    scheduler = SendScheduler(
        send_fn=send_packet,
        chaff_fn=lambda: _make_chaff(shaper),
        should_chaff_fn=shaper.should_send_chaff,
        jitter_ms_min=config.jitter_ms_min,
        jitter_ms_max=config.jitter_ms_max,
    )
    await scheduler.start()

    # Signal handling for graceful shutdown
    shutdown = asyncio.Event()

    def handle_signal() -> None:
        shutdown.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, handle_signal)

    async def recv_loop() -> None:
        nonlocal rekey_in_progress, last_rekey_time
        while not shutdown.is_set():
            try:
                if isinstance(transport, UDPTransport):
                    data, _addr = await asyncio.wait_for(transport.recv(), timeout=0.1)
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

            try:
                plaintext = session_keys.decrypt(nonce_bytes, ciphertext, aad, seq, False)
            except Exception:
                if session_keys.has_grace_period:
                    try:
                        plaintext = session_keys.decrypt(nonce_bytes, ciphertext, aad, seq, True)
                    except Exception:
                        log.debug("decrypt failed (both epochs), dropping packet")
                        continue
                else:
                    log.debug("decrypt failed, dropping packet")
                    continue

            replay.update(seq)

            try:
                inner = InnerPacket.deserialize(plaintext)
            except ValueError:
                log.debug("malformed inner packet, dropping")
                continue

            if inner.ptype == PacketType.CHAFF:
                continue
            elif inner.ptype == PacketType.DATA:
                await tun.awrite(inner.payload)
            elif inner.ptype == PacketType.REKEY_ACK:
                ts = handle_rekey_ack(inner.payload, session_keys, fsm)
                if ts is not None:
                    last_rekey_time = ts
                rekey_in_progress = False
            elif inner.ptype == PacketType.REKEY_INIT:
                last_rekey_time = await handle_rekey_init(
                    inner.payload, session_keys, fsm, shaper, send_packet,
                    last_rekey_time,
                )
            elif inner.ptype == PacketType.SESSION_CLOSE:
                shutdown.set()
                break

    async def send_loop() -> None:
        nonlocal rekey_in_progress, last_rekey_time
        while not shutdown.is_set():
            if session_keys.needs_rotation() and not rekey_in_progress:
                rekey_in_progress = True
                last_rekey_time = await initiate_rekey(
                    session_keys, fsm, shaper, send_packet, last_rekey_time,
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
            scheduler.enqueue(padded, target_size)

    try:
        await asyncio.gather(recv_loop(), send_loop())
    except asyncio.CancelledError:
        pass
    finally:
        log.info("shutting down")
        await scheduler.stop()
        nft.remove()
        tun.close()
        keystore.unload()
        await transport.aclose()
        fsm.transition(State.TEARDOWN)
        fsm.transition(State.IDLE)
