"""DSM VPN server mode."""

from __future__ import annotations

import asyncio
import logging

from dsm.core.config import Config
from dsm.core.fsm import SessionFSM, State
from dsm.crypto.keystore import KeyStore
from dsm.net.tunnel import TunDevice
from dsm.net.transport.udp import UDPTransport
from dsm.net.transport.tcp import TCPTransport
from dsm.core.protocol import ReassemblyBuffer
from dsm.session import (
    RekeyState, decrypt_packet, dispatch_inner, make_send_fn,
    setup_signal_handlers, tun_send_loop,
)
from dsm.traffic.shaper import TrafficShaper, make_chaff_packet
from dsm.traffic.scheduler import SendScheduler

log = logging.getLogger(__name__)


async def run_server(config: Config) -> None:
    """Run DSM in server mode."""
    import tuncore

    tuncore.disable_core_dumps()

    fsm = SessionFSM()

    # Load identity
    keystore = KeyStore(config.key_file)
    keystore.load_or_generate_interactive()

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

    session_keys, _client_pub = await server_handshake(transport, keystore.identity)

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

    seq = [0]
    rekey = RekeyState()
    reassembly = ReassemblyBuffer()

    shutdown = asyncio.Event()
    setup_signal_handlers(shutdown)
    client_addr: list[tuple[str, int] | None] = [None]

    send_packet = make_send_fn(
        session_keys, transport, lambda: client_addr[0], seq,
    )

    # Guard chaff generation until client_addr is known — the scheduler
    # starts immediately but chaff requires a destination for UDP.
    def _should_chaff() -> bool:
        return client_addr[0] is not None and shaper.should_send_chaff()

    server_scheduler = SendScheduler(
        send_fn=send_packet,
        chaff_fn=lambda: make_chaff_packet(shaper, session_keys.epoch & 0x03),
        should_chaff_fn=_should_chaff,
        jitter_ms_min=config.jitter_ms_min,
        jitter_ms_max=config.jitter_ms_max,
    )
    await server_scheduler.start()

    async def recv_loop() -> None:
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

            result = decrypt_packet(data, session_keys, replay)
            if result is None:
                continue

            # Update peer address only after successful authentication
            if recv_addr is not None:
                client_addr[0] = recv_addr

            inner, _prev_epoch = result
            await dispatch_inner(
                inner, tun, session_keys, fsm, shaper, send_packet, rekey, shutdown,
                reassembly,
            )

    try:
        await asyncio.gather(
            recv_loop(),
            tun_send_loop(
                tun, session_keys, fsm, shaper, send_packet, server_scheduler,
                rekey, shutdown,
            ),
        )
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
