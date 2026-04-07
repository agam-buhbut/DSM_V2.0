"""DSM VPN entry point.

Usage:
    python -m dsm --mode client
    python -m dsm --mode server
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import getpass
import hashlib
import logging
import os
import signal
import struct
import sys
from pathlib import Path

from dsm.core import log as dsm_log
from dsm.core.config import Config, load
from dsm.core.fsm import SessionFSM, State
from dsm.crypto.keystore import KeyStore
from dsm.net.nftables import NFTablesManager
from dsm.net.tunnel import TunDevice
from dsm.net.transport.udp import UDPTransport
from dsm.net.transport.tcp import TCPTransport
from dsm.traffic.shaper import TrafficShaper
from dsm.traffic.scheduler import SendScheduler
from dsm.core.protocol import (
    InnerPacket,
    OuterPacket,
    PacketType,
    OUTER_HEADER_SIZE,
    GCM_TAG_SIZE,
)

log = logging.getLogger(__name__)


async def _make_chaff(shaper: TrafficShaper) -> tuple[bytes, int]:
    """Generate a chaff packet with padding. Shared by client and server."""
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

    # FSM: IDLE -> CONNECTING
    fsm.transition(State.CONNECTING)

    # FSM: CONNECTING -> HANDSHAKING
    fsm.transition(State.HANDSHAKING)

    from dsm.crypto.handshake import client_handshake

    try:
        noise = await client_handshake(
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

    # Derive per-session epoch from identity + server address to avoid nonce reuse across restarts
    epoch_seed = hashlib.sha256(pub + os.urandom(16)).digest()
    session_epoch = int.from_bytes(epoch_seed[:4], "big") | 1  # ensure non-zero

    seq_counter = 0
    nonce_gen = tuncore.NonceGenerator(epoch=session_epoch)
    replay = tuncore.ReplayWindow()

    async def send_packet(data: bytes, target_size: int) -> None:
        nonlocal seq_counter
        seq_counter += 1
        if seq_counter >= 2**64:
            raise RuntimeError("sequence number overflow — session must be rekeyed")
        # Snow transport manages its own AES-GCM nonces internally.
        # The outer nonce is metadata for the replay window / anti-analysis, not the crypto nonce.
        ct = noise.encrypt(data)
        nonce_bytes = nonce_gen.next()
        outer = OuterPacket(seq=seq_counter, nonce=bytes(nonce_bytes), ciphertext=ct)
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
        """Receive from transport, decrypt, write to TUN."""
        while not shutdown.is_set():
            try:
                if isinstance(transport, UDPTransport):
                    data, _addr = await asyncio.wait_for(transport.recv(), timeout=0.1)
                else:
                    data = await asyncio.wait_for(transport.recv(), timeout=0.1)
            except asyncio.TimeoutError:
                continue

            if len(data) < OUTER_HEADER_SIZE:
                log.debug("packet too short, dropping")
                continue

            seq = struct.unpack("!Q", data[:8])[0]
            if not replay.check(seq):
                log.debug("replay detected, dropping seq=%d", seq)
                continue

            ciphertext = data[OUTER_HEADER_SIZE:]

            try:
                plaintext = noise.decrypt(ciphertext)
            except Exception:
                log.debug("decrypt failed, dropping packet")
                continue

            # Commit seq to replay window only after successful authentication
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
            elif inner.ptype == PacketType.SESSION_CLOSE:
                shutdown.set()
                break

    async def send_loop() -> None:
        """Read from TUN, encrypt, send to server."""
        while not shutdown.is_set():
            try:
                pkt = await asyncio.wait_for(tun.read(), timeout=0.1)
            except asyncio.TimeoutError:
                continue

            inner = InnerPacket(
                ptype=PacketType.DATA,
                epoch_id=0,
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
        # FSM: -> TEARDOWN
        log.info("shutting down")
        await scheduler.stop()
        nft.remove()
        tun.close()
        keystore.unload()
        await transport.aclose()
        fsm.transition(State.TEARDOWN)
        fsm.transition(State.IDLE)


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

    noise, client_pub = await server_handshake(transport, keystore.identity)

    fsm.transition(State.ESTABLISHED)
    log.info("client connected")

    # Setup DNS resolver
    from dsm.net.dns import DNSResolver

    dns = DNSResolver(providers=config.dns_providers)

    # TUN device
    tun = TunDevice(config.tun_name)
    tun.open()
    tun.configure(local_ip="10.8.0.1")

    shaper = TrafficShaper(config.padding_min, config.padding_max)
    replay = tuncore.ReplayWindow()

    # Derive per-session epoch from server identity + client pubkey
    server_epoch_seed = hashlib.sha256(pub + os.urandom(16)).digest()
    server_epoch = int.from_bytes(server_epoch_seed[:4], "big") | 1

    server_seq = 0
    server_nonce_gen = tuncore.NonceGenerator(epoch=server_epoch)

    shutdown = asyncio.Event()
    client_addr: tuple[str, int] | None = None

    def handle_signal() -> None:
        shutdown.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, handle_signal)

    async def recv_loop() -> None:
        """Receive from transport, decrypt, write to TUN."""
        nonlocal client_addr
        while not shutdown.is_set():
            try:
                if isinstance(transport, UDPTransport):
                    data, addr = await asyncio.wait_for(transport.recv(), timeout=0.1)
                    client_addr = addr
                else:
                    data = await asyncio.wait_for(transport.recv(), timeout=0.1)
            except asyncio.TimeoutError:
                continue

            # Parse outer packet framing
            if len(data) < OUTER_HEADER_SIZE:
                log.debug("packet too short, dropping")
                continue

            seq = struct.unpack("!Q", data[:8])[0]
            if not replay.check(seq):
                log.debug("replay detected, dropping seq=%d", seq)
                continue

            # Strip outer header, pass ciphertext to noise (ignore outer padding via GCM)
            ciphertext = data[OUTER_HEADER_SIZE:]

            try:
                plaintext = noise.decrypt(ciphertext)
            except Exception:
                log.debug("decrypt failed, dropping packet")
                continue

            # Commit seq to replay window only after successful authentication
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
            elif inner.ptype == PacketType.SESSION_CLOSE:
                shutdown.set()
                break

    async def server_send_packet(data: bytes, target_size: int) -> None:
        """Encrypt and send a packet from server to client with proper framing."""
        nonlocal server_seq
        server_seq += 1
        if server_seq >= 2**64:
            raise RuntimeError("sequence number overflow — session must be rekeyed")
        ct = noise.encrypt(data)
        nonce_bytes = server_nonce_gen.next()
        outer = OuterPacket(seq=server_seq, nonce=bytes(nonce_bytes), ciphertext=ct)
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
        """Read from TUN, encrypt via scheduler (with jitter), send back to client."""
        while not shutdown.is_set():
            try:
                pkt = await asyncio.wait_for(tun.read(), timeout=0.1)
            except asyncio.TimeoutError:
                continue

            inner = InnerPacket(
                ptype=PacketType.DATA,
                epoch_id=0,
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
        dns.flush_cache()
        fsm.transition(State.TEARDOWN)
        fsm.transition(State.IDLE)


def main() -> None:
    parser = argparse.ArgumentParser(description="DSM VPN")
    parser.add_argument(
        "--mode",
        choices=["client", "server"],
        help="Override config mode",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Config file path (default: /opt/mtun/config.toml)",
    )
    args = parser.parse_args()

    config = load(args.config)
    if args.mode:
        # Override mode from command line
        config = Config(**{**dataclasses.asdict(config), "mode": args.mode})

    dsm_log.configure(config.log_level)

    mode = config.mode
    if mode == "client":
        asyncio.run(run_client(config))
    elif mode == "server":
        asyncio.run(run_server(config))
    else:
        print(f"mode {mode!r} is not yet implemented", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
