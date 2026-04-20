"""DSM VPN server mode."""

from __future__ import annotations

import asyncio
import logging
import time
from contextlib import AsyncExitStack

from dsm.core.config import Config
from dsm.core.fsm import SessionFSM, State
from dsm.crypto.authorized_clients import AuthorizedClients
from dsm.crypto.keystore import KeyStore
from dsm.net.dns import DNSResolver
from dsm.net.dns_proxy import LocalDNSProxy
from dsm.net.nftables import ServerRateLimitManager, TcpTimestampsDisabler
from dsm.net.tunnel import TunDevice
from dsm.net.transport.udp import UDPTransport
from dsm.net.transport.tcp import TCPTransport
from dsm.core.protocol import ReassemblyBuffer
from dsm.session import (
    DataPathContext, LivenessState, RekeyState, SequenceCounter, decrypt_packet,
    dispatch_inner, liveness_loop, make_send_fn, setup_signal_handlers,
    tun_send_loop,
)
from dsm.traffic.shaper import TrafficShaper, make_chaff_packet
from dsm.traffic.scheduler import SendScheduler

SERVER_TUN_IP = "10.8.0.1"

log = logging.getLogger(__name__)


class _TransportContext:
    """Wrapper to use transport as async context manager."""

    def __init__(self, transport: UDPTransport | TCPTransport) -> None:
        self.transport = transport

    async def __aenter__(self) -> UDPTransport | TCPTransport:
        return self.transport

    async def __aexit__(self, *args: object) -> None:
        await self.transport.aclose()


class _TunContext:
    """Wrapper to use TUN device as async context manager."""

    def __init__(self, tun: TunDevice) -> None:
        self.tun = tun

    async def __aenter__(self) -> TunDevice:
        return self.tun

    async def __aexit__(self, *args: object) -> None:
        self.tun.close()


class _RateLimiterContext:
    """Wrapper for rate limiter as context manager."""

    def __init__(self, rl: ServerRateLimitManager) -> None:
        self.rl = rl

    async def __aenter__(self) -> ServerRateLimitManager:
        return self.rl

    async def __aexit__(self, *args: object) -> None:
        self.rl.remove()


class _TcpTsContext:
    """Wrapper for TCP timestamps disabler as context manager."""

    def __init__(self, ts: TcpTimestampsDisabler) -> None:
        self.ts = ts

    async def __aenter__(self) -> TcpTimestampsDisabler:
        return self.ts

    async def __aexit__(self, *args: object) -> None:
        self.ts.remove()


async def run_server(config: Config) -> None:
    """Run DSM in server mode using transactional resource management."""
    import tuncore

    tuncore.harden_process()

    fsm = SessionFSM()

    # Load identity
    keystore = KeyStore(config.key_file)
    keystore.load_or_generate_interactive()

    async with AsyncExitStack() as stack:
        # Apply rate limiter and TCP timestamp disabler
        rate_limiter = ServerRateLimitManager(config.listen_port)
        rate_limiter.apply()
        stack.push_async_callback(rate_limiter.remove)

        tcp_ts = TcpTimestampsDisabler()
        tcp_ts.apply()
        stack.push_async_callback(tcp_ts.remove)

        # Transport
        if config.transport == "udp":
            transport = UDPTransport()
            await transport.bind(local_port=config.listen_port)
        else:
            transport = TCPTransport()
            await transport.listen(port=config.listen_port)

        stack.push_async_callback(transport.aclose)

        log.info("server listening on port %d (%s)", config.listen_port, config.transport)

        # Wait for handshake
        from dsm.crypto.handshake import server_handshake

        fsm.transition(State.CONNECTING)
        fsm.transition(State.HANDSHAKING)

        try:
            session_keys, client_pub = await server_handshake(transport, keystore.identity)
        except Exception as e:
            log.error("handshake failed: %s", e)
            raise

        # Check client authorization
        authorized_clients = AuthorizedClients(
            config.config_dir / "authorized_clients.json", keystore.identity
        )
        authorized_clients.load()

        if not authorized_clients.is_authorized(client_pub):
            log.warning("unauthorized client: %s", client_pub.hex())
            raise RuntimeError("client not authorized")

        log.info("client authorized: %s", client_pub.hex()[:16])

        fsm.transition(State.ESTABLISHED)
        log.info("client connected")

        # TUN device
        tun = TunDevice(config.tun_name)
        tun.open()
        tun.configure(local_ip=SERVER_TUN_IP)
        stack.push_async_callback(tun.close)

        # DNS proxy: listen on the TUN address for DNS queries arriving from
        # clients through the tunnel. Forwards to the pinned DoH/DoT resolver.
        resolver = DNSResolver(
            providers=config.dns_providers,
            provider_pins=config.dns_provider_pins,
        )
        dns_proxy = LocalDNSProxy(
            resolver, bind_ip=SERVER_TUN_IP, bind_port=53, debug_dns=config.debug_dns,
        )
        await dns_proxy.start()
        stack.push_async_callback(dns_proxy.stop)
        stack.push_async_callback(resolver.close)

        shaper = TrafficShaper(config.padding_min, config.padding_max)
        replay = tuncore.ReplayWindow()

        seq = SequenceCounter()
        rekey = RekeyState()
        liveness = LivenessState()
        reassembly = ReassemblyBuffer()

        shutdown = asyncio.Event()
        setup_signal_handlers(shutdown)
        client_addr: list[tuple[str, int] | None] = [None]

        send_packet = make_send_fn(
            session_keys, transport, lambda: client_addr[0], seq, liveness=liveness,
        )

        # Guard chaff generation until client_addr is known — the scheduler
        # starts immediately but chaff requires a destination for UDP.
        def _should_chaff() -> bool:
            return client_addr[0] is not None and shaper.should_send_chaff()

        # Scheduler+shaper params must mirror the client's — divergence here
        # reintroduces a direction-correlation fingerprint. See
        # tests/test_symmetric_shaping.py for the regression lock.
        server_scheduler = SendScheduler(
            send_fn=send_packet,
            chaff_fn=lambda: make_chaff_packet(shaper, session_keys.epoch & 0x03),
            should_chaff_fn=_should_chaff,
            jitter_ms_min=config.jitter_ms_min,
            jitter_ms_max=config.jitter_ms_max,
        )
        await server_scheduler.start()
        stack.push_async_callback(server_scheduler.stop)

        ctx = DataPathContext(
            tun=tun,
            session_keys=session_keys,
            fsm=fsm,
            shaper=shaper,
            send_fn=send_packet,
            scheduler=server_scheduler,
            rekey=rekey,
            liveness=liveness,
            shutdown=shutdown,
            reassembly=reassembly,
        )

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

                liveness.last_recv_time = time.monotonic()

                # Update peer address only after successful authentication
                if recv_addr is not None:
                    client_addr[0] = recv_addr

                inner, _prev_epoch = result
                await dispatch_inner(ctx, inner)

        try:
            await asyncio.gather(
                recv_loop(),
                tun_send_loop(ctx),
                liveness_loop(ctx),
            )
        except asyncio.CancelledError:
            pass
        finally:
            log.info("server shutting down")
            keystore.unload()
            fsm.transition(State.TEARDOWN)
            fsm.transition(State.IDLE)
            # AsyncExitStack cleanup happens automatically here
