"""DSM VPN client mode."""

from __future__ import annotations

import asyncio
import logging
import time
from contextlib import AsyncExitStack
from pathlib import Path

from dsm.core.config import Config
from dsm.core.fsm import SessionFSM, State
from dsm.crypto.keystore import KeyStore
from dsm.net.nftables import NFTablesManager, TcpTimestampsDisabler
from dsm.net.resolv_conf import ResolvConfManager
from dsm.net.tunnel import TunDevice
from dsm.net.transport.udp import UDPTransport
from dsm.net.transport.tcp import TCPTransport

VPN_DNS_SERVER = "10.8.0.1"  # server's TUN address; DNS proxy listens there
from dsm.core.protocol import ReassemblyBuffer
from dsm.session import (
    DataPathContext, LivenessState, RekeyState, SequenceCounter, decrypt_packet,
    dispatch_inner, liveness_loop, make_send_fn, send_session_close,
    setup_signal_handlers, tun_send_loop,
)
from dsm.traffic.shaper import TrafficShaper, make_chaff_packet
from dsm.traffic.scheduler import SendScheduler

log = logging.getLogger(__name__)


async def run_client(
    config: Config,
    passphrase_fd: int | None = None,
    passphrase_env_file: str | None = None,
) -> None:
    """Run DSM in client mode using transactional resource management.

    Every resource that mutates host state (TUN, nftables, resolv.conf, etc.)
    is registered with an ``AsyncExitStack`` the moment it succeeds so that
    any failure downstream unwinds them in reverse order — never leaving
    the host in a half-configured state.
    """
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

    keystore = KeyStore(config.key_file)
    keystore.load_or_generate(
        passphrase_fd=passphrase_fd,
        passphrase_env_file=passphrase_env_file,
    )

    shaper = TrafficShaper(config.padding_min, config.padding_max)

    async with AsyncExitStack() as stack:
        # Keystore unload happens last (first registered, unwound last) so
        # the encrypted identity material is kept in memory for the lifetime
        # of the session.
        stack.callback(keystore.unload)

        # Transport
        if config.transport == "udp":
            transport = UDPTransport()
            await transport.bind(
                local_port=config.listen_port,
                pmtu_discover=config.pmtu_discover,
            )
        else:
            transport = TCPTransport()
            await transport.connect(config.server_ip, config.server_port)
        stack.push_async_callback(transport.aclose)

        server_addr = (config.server_ip, config.server_port)

        fsm.transition(State.CONNECTING)
        fsm.transition(State.HANDSHAKING)

        from dsm.crypto.handshake import DEFAULT_KNOWN_HOSTS_PATH, client_handshake

        known_hosts_path = (
            Path(config.known_hosts_path)
            if config.known_hosts_path
            else DEFAULT_KNOWN_HOSTS_PATH
        )

        try:
            session_keys, _handshake_hash = await client_handshake(
                transport,
                keystore.identity,
                server_addr,
                known_hosts_path=known_hosts_path,
            )
        except Exception as e:
            log.error("handshake failed: %s", e)
            fsm.transition(State.TEARDOWN)
            return  # AsyncExitStack unwinds transport + keystore

        fsm.transition(State.ESTABLISHED)

        # Host-mutating resources: register each with the stack as soon as
        # it succeeds, so any later failure unwinds only what was applied.
        # Unwind order is the REVERSE of registration, which matches the
        # safe teardown order (scheduler → resolv → tun → nft → tcp_ts →
        # transport → keystore).

        tcp_ts = TcpTimestampsDisabler()
        tcp_ts.apply()
        stack.callback(tcp_ts.remove)

        nft = NFTablesManager(config.server_ip, config.server_port, config.tun_name)
        nft.apply()
        stack.callback(nft.remove)

        tun = TunDevice(config.tun_name)
        tun.open()
        tun.configure(mtu=config.mtu)
        stack.callback(tun.close)

        # Swap /etc/resolv.conf AFTER nft.apply so the kill switch is already
        # up when the new resolver becomes visible — any in-flight DNS to the
        # old resolver is dropped, not leaked.
        resolv = ResolvConfManager(nameserver=VPN_DNS_SERVER)
        resolv.apply()
        stack.callback(resolv.remove)

        log.info("tunnel established")

        # After the handshake has exchanged several full-size datagrams,
        # the kernel may have learned the path MTU via ICMP. Log it once
        # so the operator can tell whether the configured tun MTU is a
        # good fit. Warn if the path MTU can't carry the wire overhead.
        if isinstance(transport, UDPTransport):
            path_mtu = transport.get_path_mtu()
            if path_mtu is not None:
                # IP(20) + UDP(8) + outer(20) + GCM tag(16) + inner(4) = 68
                # plus any extra encapsulation (PPPoE, GRE, etc.) below us.
                WIRE_OVERHEAD = 68
                usable = path_mtu - WIRE_OVERHEAD
                log.info("kernel path MTU = %d (usable inner %d)", path_mtu, usable)
                if usable < config.mtu:
                    log.warning(
                        "configured tun mtu=%d exceeds usable inner %d "
                        "(path MTU %d); lower `mtu` in config to avoid fragmentation",
                        config.mtu, usable, path_mtu,
                    )

        seq = SequenceCounter()
        replay = tuncore.ReplayWindow()
        rekey = RekeyState()
        liveness = LivenessState()
        reassembly = ReassemblyBuffer()

        send_packet = make_send_fn(
            session_keys, transport, lambda: server_addr, seq, liveness=liveness,
        )

        scheduler = SendScheduler(
            send_fn=send_packet,
            chaff_fn=lambda: make_chaff_packet(shaper, session_keys.epoch & 0x03),
            should_chaff_fn=shaper.should_send_chaff,
            jitter_ms_min=config.jitter_ms_min,
            jitter_ms_max=config.jitter_ms_max,
        )
        await scheduler.start()
        stack.push_async_callback(scheduler.stop)

        shutdown = asyncio.Event()
        setup_signal_handlers(shutdown)

        ctx = DataPathContext(
            tun=tun,
            session_keys=session_keys,
            fsm=fsm,
            shaper=shaper,
            send_fn=send_packet,
            scheduler=scheduler,
            rekey=rekey,
            liveness=liveness,
            shutdown=shutdown,
            reassembly=reassembly,
        )

        async def recv_loop() -> None:
            while not shutdown.is_set():
                try:
                    if isinstance(transport, UDPTransport):
                        data, recv_addr = await asyncio.wait_for(
                            transport.recv(), timeout=0.1,
                        )
                        if recv_addr != server_addr:
                            log.debug(
                                "packet from unexpected source %s, dropping",
                                recv_addr,
                            )
                            continue
                    else:
                        data = await asyncio.wait_for(transport.recv(), timeout=0.1)
                except asyncio.TimeoutError:
                    session_keys.tick()
                    continue

                result = decrypt_packet(data, session_keys, replay)
                if result is None:
                    continue

                liveness.last_recv_time = time.monotonic()

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
            log.info("shutting down")
            # Notify peer first (best-effort) so it sees a fast graceful
            # close rather than DEAD_PEER_TIMEOUT. Must fire BEFORE the
            # AsyncExitStack unwinds — once scheduler/transport are gone
            # the send_fn is useless.
            await send_session_close(ctx)
            fsm.transition(State.TEARDOWN)
            fsm.transition(State.IDLE)
            # AsyncExitStack unwinds remaining resources in reverse order.
