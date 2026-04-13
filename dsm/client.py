"""DSM VPN client mode."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from dsm.core.config import Config
from dsm.core.fsm import SessionFSM, State
from dsm.crypto.keystore import KeyStore
from dsm.net.nftables import NFTablesManager
from dsm.net.tunnel import TunDevice
from dsm.net.transport.udp import UDPTransport
from dsm.net.transport.tcp import TCPTransport
from dsm.session import (
    RekeyState, decrypt_packet, dispatch_inner, make_send_fn,
    setup_signal_handlers, tun_send_loop,
)
from dsm.traffic.shaper import TrafficShaper, make_chaff_packet
from dsm.traffic.scheduler import SendScheduler

log = logging.getLogger(__name__)


async def run_client(config: Config) -> None:
    """Run DSM in client mode."""
    import tuncore

    tuncore.disable_core_dumps()

    fsm = SessionFSM()

    # Load identity
    keystore = KeyStore(config.key_file)
    keystore.load_or_generate_interactive()

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

    seq = [0]
    replay = tuncore.ReplayWindow()
    rekey = RekeyState()

    send_packet = make_send_fn(session_keys, transport, lambda: server_addr, seq)

    scheduler = SendScheduler(
        send_fn=send_packet,
        chaff_fn=lambda: make_chaff_packet(shaper),
        should_chaff_fn=shaper.should_send_chaff,
        jitter_ms_min=config.jitter_ms_min,
        jitter_ms_max=config.jitter_ms_max,
    )
    await scheduler.start()

    shutdown = asyncio.Event()
    setup_signal_handlers(shutdown)

    async def recv_loop() -> None:
        while not shutdown.is_set():
            try:
                if isinstance(transport, UDPTransport):
                    data, recv_addr = await asyncio.wait_for(transport.recv(), timeout=0.1)
                    if recv_addr != server_addr:
                        log.debug("packet from unexpected source %s, dropping", recv_addr)
                        continue
                else:
                    data = await asyncio.wait_for(transport.recv(), timeout=0.1)
            except asyncio.TimeoutError:
                session_keys.tick()
                continue

            result = decrypt_packet(data, session_keys, replay)
            if result is None:
                continue

            inner, _prev_epoch = result
            await dispatch_inner(
                inner, tun, session_keys, fsm, shaper, send_packet, rekey, shutdown,
            )

    try:
        await asyncio.gather(
            recv_loop(),
            tun_send_loop(
                tun, session_keys, fsm, shaper, send_packet, scheduler, rekey, shutdown,
            ),
        )
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
