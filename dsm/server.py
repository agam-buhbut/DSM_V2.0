"""DSM VPN server mode."""

from __future__ import annotations

import asyncio
import logging
import time
from contextlib import AsyncExitStack
from pathlib import Path

from cryptography.x509.oid import ExtendedKeyUsageOID

from dsm.core import netaudit
from dsm.core.config import Config
from dsm.core.fsm import SessionFSM, State
from dsm.core.passphrase import read_passphrase, wipe_passphrase
from dsm.crypto.attest_store import AttestStore
from dsm.crypto.auth_loader import AuthMaterialsError, load_cert_materials
from dsm.crypto.cert_allowlist import CNAllowlist, CNAllowlistError
from dsm.crypto.keystore import KeyStore
from dsm.net.dns import DNSResolver
from dsm.net.dns_proxy import LocalDNSProxy
from dsm.net.forwarding import IPForwardingManager, MasqueradeManager
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

    # Cert auth materials must load BEFORE we touch any host state, so a
    # missing cert file aborts cleanly with no rules / no TUN created.
    try:
        materials = load_cert_materials(config)
    except AuthMaterialsError as e:
        log.error("cert auth materials missing or invalid: %s", e)
        return

    if not config.allowed_cns_file:
        log.error(
            "server mode requires allowed_cns_file in config "
            "(validated by Config; should not reach this branch)"
        )
        return
    try:
        cn_allowlist = CNAllowlist.from_file(Path(config.allowed_cns_file))
    except CNAllowlistError as e:
        log.error("CN allowlist load failed: %s", e)
        return
    if len(cn_allowlist) == 0:
        log.error(
            "CN allowlist at %s is empty; refusing to start (would accept no clients)",
            config.allowed_cns_file,
        )
        return
    log.info("CN allowlist loaded (%d entries)", len(cn_allowlist))

    # Read the passphrase once and unlock both stores.
    keystore = KeyStore(config.key_file)
    attest_store = AttestStore(config.attest_key_file)
    passphrase = read_passphrase(
        passphrase_fd=passphrase_fd,
        passphrase_env_file=passphrase_env_file,
    )
    try:
        keystore.load_or_generate_with_passphrase(passphrase)
        try:
            attest_store.load_with_passphrase(passphrase)
        except RuntimeError as e:
            log.error("attest store: %s", e)
            keystore.unload()
            return
    finally:
        wipe_passphrase(passphrase)

    async with AsyncExitStack() as stack:
        # Sync cleanup callbacks use stack.callback; async ones use
        # stack.push_async_callback. Mixing them is the most common
        # AsyncExitStack footgun — see typing on contextlib.AsyncExitStack.

        # Register keystore unload first so it unwinds last — the
        # encrypted identity must stay in memory for the lifetime of
        # the session. Mirrors client.py.
        stack.callback(keystore.unload)
        stack.callback(attest_store.unload)

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

        # Wait for handshake — cert chain + binding-extension match +
        # CN allowlist + (optional) CRL all run inside server_handshake.
        from dsm.crypto.handshake import (
            CertAuthError,
            CertRevokedError,
            CNNotAllowedError,
            HandshakeError,
            server_handshake,
        )

        fsm.transition(State.CONNECTING)
        fsm.transition(State.HANDSHAKING)

        try:
            session_keys, client_pub = await server_handshake(
                transport,
                keystore.identity,
                attest_key=attest_store.attest_key,
                cert_der=materials.cert_der,
                ca_root=materials.ca_root,
                cn_allowlist=cn_allowlist,
                crl=materials.crl,
                required_client_eku=ExtendedKeyUsageOID.CLIENT_AUTH,
                rotation_packets=config.rotation_packets,
                rotation_seconds=config.rotation_seconds,
            )
        except CNNotAllowedError as e:
            log.warning("client CN not in allowlist: %s", e)
            netaudit.emit(
                "handshake_end", role="server", outcome="failed",
                error="CNNotAllowedError", message=str(e),
            )
            fsm.transition(State.TEARDOWN)
            return
        except CertRevokedError as e:
            log.warning("client cert revoked: %s", e)
            netaudit.emit(
                "handshake_end", role="server", outcome="failed",
                error="CertRevokedError", message=str(e),
            )
            fsm.transition(State.TEARDOWN)
            return
        except CertAuthError as e:
            log.warning("client cert auth failed: %s", e)
            netaudit.emit(
                "handshake_end", role="server", outcome="failed",
                error="CertAuthError", message=str(e),
            )
            fsm.transition(State.TEARDOWN)
            return
        except HandshakeError as e:
            log.error("handshake failed: %s", e)
            netaudit.emit(
                "handshake_end", role="server", outcome="failed",
                error="HandshakeError", message=str(e),
            )
            fsm.transition(State.TEARDOWN)
            return

        client_pub_bytes = bytes(client_pub)
        log.info("client connected (noise_static=%s)", client_pub_bytes.hex()[:16])

        fsm.transition(State.ESTABLISHED)

        # TUN device
        tun = TunDevice(config.tun_name)
        tun.open()
        tun.configure(local_ip=SERVER_TUN_IP, mtu=config.mtu)
        stack.callback(tun.close)

        # Enable IPv4 forwarding + MASQUERADE so decrypted client traffic
        # actually reaches the internet. Without these, the kernel either
        # drops the packet (forwarding off) or replies are unroutable
        # (replies addressed to 10.8.0.0/24, no NAT). Apply AFTER the TUN
        # exists so the MASQUERADE rule can reference its name.
        ip_forward = IPForwardingManager(tun_name=config.tun_name)
        ip_forward.apply()
        stack.callback(ip_forward.remove)

        masquerade = MasqueradeManager(tun_name=config.tun_name)
        masquerade.apply()
        stack.callback(masquerade.remove)

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
        # Assumes client_addr is monotonic-set-once: it's populated on the
        # first authenticated packet and never cleared. If a future change
        # ever resets it to None, _should_chaff and chaff_fn race across
        # the scheduler tick's await and chaff_fn() will hit the
        # "UDP send requires destination" branch in send_packet.
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
                except ConnectionError as e:
                    log.info("transport closed by peer: %s", e)
                    shutdown.set()
                    return

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
            fsm.transition(State.TEARDOWN)
            fsm.transition(State.IDLE)
            # AsyncExitStack cleanup happens automatically here
            # (including keystore.unload — see top of stack).
