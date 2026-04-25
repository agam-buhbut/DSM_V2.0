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
    dispatch_inner, liveness_loop, make_send_fn, send_session_close,
    setup_signal_handlers, tun_send_loop,
)
from dsm.traffic.shaper import TrafficShaper, make_chaff_packet
from dsm.traffic.scheduler import SendScheduler

SERVER_TUN_IP = "10.8.0.1"

log = logging.getLogger(__name__)


async def run_server(
    config: Config,
    passphrase_fd: int | None = None,
    passphrase_env_file: str | None = None,
) -> None:
    """Run DSM in server mode using transactional resource management."""
    import tuncore

    try:
        tuncore.harden_process()
    except Exception as e:
        log.warning(
            "process hardening partially failed: %s — continuing without it. "
            "Ensure the service has CAP_SYS_RESOURCE and unrestricted prctl.",
            e,
        )

    fsm = SessionFSM()

    # Load identity — uses non-interactive sources when provided, falls back
    # to interactive TTY prompt only if none are set.
    keystore = KeyStore(config.key_file)
    keystore.load_or_generate(
        passphrase_fd=passphrase_fd,
        passphrase_env_file=passphrase_env_file,
    )

    async with AsyncExitStack() as stack:
        # Sync cleanup callbacks use stack.callback; async ones use
        # stack.push_async_callback. Mixing them is the most common
        # AsyncExitStack footgun — see typing on contextlib.AsyncExitStack.

        rate_limiter = ServerRateLimitManager(config.listen_port)
        rate_limiter.apply()
        stack.callback(rate_limiter.remove)

        tcp_ts = TcpTimestampsDisabler()
        tcp_ts.apply()
        stack.callback(tcp_ts.remove)

        # Transport
        if config.transport == "udp":
            transport = UDPTransport()
            await transport.bind(
                local_port=config.listen_port,
                pmtu_discover=config.pmtu_discover,
            )
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

        # Check client authorization. Authorization happens AFTER the expensive
        # handshake because the handshake must complete to learn the client's
        # static pubkey (Noise XX pattern). A malicious client pays the same
        # handshake cost regardless.
        client_pub_bytes = bytes(client_pub)
        authorized_clients = AuthorizedClients(
            config.config_dir / "authorized_clients.json", keystore.identity
        )
        authorized_clients.load()

        if authorized_clients.is_authorized(client_pub_bytes):
            log.info("client authorized: %s", client_pub_bytes.hex()[:16])
        elif not config.strict_client_auth and len(authorized_clients) == 0:
            # TOFU bootstrap: accept the first client on a fresh allowlist.
            # Future connections from other clients will still be rejected
            # (allowlist no longer empty). Log loudly — this is a security
            # event the operator should notice.
            authorized_clients.add(client_pub_bytes)
            authorized_clients.save()
            log.warning(
                "TOFU bootstrap: first client authorized (pubkey %s). "
                "Flip strict_client_auth=True in config; future different "
                "clients will now be rejected.",
                client_pub_bytes.hex(),
            )
        else:
            log.warning("unauthorized client: %s", client_pub_bytes.hex())
            raise RuntimeError(
                f"client not authorized: {client_pub_bytes.hex()}. "
                f"Add with: dsm authorize {client_pub_bytes.hex()}"
            )

        fsm.transition(State.ESTABLISHED)
        log.info("client connected")

        # TUN device
        tun = TunDevice(config.tun_name)
        tun.open()
        tun.configure(local_ip=SERVER_TUN_IP, mtu=config.mtu)
        stack.callback(tun.close)

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
        stack.callback(dns_proxy.stop)             # sync
        stack.push_async_callback(resolver.close)  # async (httpx.aclose)

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
            # Notify peer first (before scheduler + transport tear down),
            # so it sees a fast graceful close rather than DEAD_PEER_TIMEOUT.
            await send_session_close(ctx)
            keystore.unload()
            fsm.transition(State.TEARDOWN)
            fsm.transition(State.IDLE)
            # AsyncExitStack cleanup happens automatically here
