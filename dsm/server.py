"""DSM VPN server mode."""

from __future__ import annotations

import asyncio
import logging
from contextlib import AsyncExitStack
from pathlib import Path

from cryptography.x509.oid import ExtendedKeyUsageOID

# Backoff parameters for failed handshake retries. UDP retries cycle very
# fast because there's no kernel-side rate limit on bad packets reaching
# the handshake coroutine; TCP retries are gated by the kernel's accept
# queue but a malicious peer racing the listen() can still burn slots in
# a tight loop. A small jittered sleep between retries gives legitimate
# clients a chance to win against a flood.
_HANDSHAKE_RETRY_BACKOFF_BASE = 0.5  # seconds
_HANDSHAKE_RETRY_BACKOFF_MAX = 5.0  # seconds
_HANDSHAKE_RETRY_BACKOFF_JITTER = 0.5  # ±this fraction of base

from dsm.core import netaudit
from dsm.core.config import Config
from dsm.core.fsm import SessionFSM, State
from dsm.core.protocol import ReassemblyBuffer
from dsm.crypto.attest_store import AttestStore
from dsm.crypto.auth_loader import (
    AuthMaterialsError,
    load_cert_materials,
    verify_cert_matches_identity,
)
from dsm.crypto.cert_allowlist import CNAllowlist, CNAllowlistError
from dsm.crypto.keystore import KeyStore
from dsm.net._addresses import SERVER_TUN_IP
from dsm.net.dns import DNSResolver
from dsm.net.dns_proxy import LocalDNSProxy
from dsm.net.forwarding import IPForwardingManager, MasqueradeManager
from dsm.net.nftables import ServerRateLimitManager, TcpTimestampsDisabler
from dsm.net.transport.tcp import TCPTransport
from dsm.net.transport.udp import UDPTransport
from dsm.net.tunnel import TunDevice
from dsm.session import (
    DataPathContext,
    LivenessState,
    RekeyState,
    SequenceCounter,
    make_send_fn,
    setup_signal_handlers,
)
from dsm.traffic.scheduler import SendScheduler
from dsm.traffic.shaper import TrafficShaper, make_chaff_packet

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
    from dsm.crypto._stores import load_daemon_stores

    keystore = KeyStore(config.key_file)
    attest_store = AttestStore(config.attest_key_file)
    if not load_daemon_stores(
        keystore,
        attest_store,
        passphrase_fd=passphrase_fd,
        passphrase_env_file=passphrase_env_file,
    ):
        return

    # With both stores unlocked, confirm the loaded cert was issued for
    # THIS device's keys. Catches the cert_file substitution failure mode
    # at startup with a clear error, rather than at first peer's
    # AttestBindingMismatchError much later.
    try:
        verify_cert_matches_identity(materials.cert_der, keystore, attest_store)
    except AuthMaterialsError as e:
        log.error("cert/identity consistency check failed: %s", e)
        attest_store.unload()
        keystore.unload()
        return

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

        # Handshake error imports surfaced early so the retry loop can name them.
        from dsm.crypto.handshake import (
            CertAuthError,
            CertRevokedError,
            CNNotAllowedError,
            HandshakeError,
            server_handshake,
        )

        # Shutdown event — set up BEFORE the handshake loop so a SIGTERM
        # arriving while we're waiting for msg1 unblocks the loop instead of
        # being deferred until after a successful client connects.
        shutdown = asyncio.Event()
        setup_signal_handlers(shutdown)

        # Transport: UDP transport lives for the whole run; TCP requires a
        # fresh transport per handshake attempt because listen() accepts one
        # connection and closes its server socket. The TCP transport is only
        # registered with the AsyncExitStack after a successful handshake;
        # failed-attempt transports are closed manually inside the loop.
        transport_obj: UDPTransport | TCPTransport | None
        if config.transport == "udp":
            transport_obj = UDPTransport()
            await transport_obj.bind(
                local_port=config.listen_port,
                pmtu_discover=config.pmtu_discover,
            )
            stack.push_async_callback(transport_obj.aclose)
            log.info("server listening on UDP port %d", config.listen_port)
        else:
            transport_obj = None

        fsm.transition(State.CONNECTING)
        session_keys = None
        client_pub: bytes | None = None
        consecutive_failures = 0
        while not shutdown.is_set():
            # For TCP, re-create the listening transport on each attempt
            # (and close any previous failed-attempt transport).
            if config.transport == "tcp":
                if transport_obj is not None:
                    await transport_obj.aclose()
                transport_obj = TCPTransport()
                await transport_obj.listen(port=config.listen_port)
                log.info("server listening on TCP port %d", config.listen_port)

            fsm.transition(State.HANDSHAKING)
            if transport_obj is None:
                # Unreachable in practice — UDP path sets it once before the
                # loop, TCP path sets it on every iteration above. Explicit
                # check keeps the type narrowing for the handshake call.
                raise RuntimeError("internal: handshake reached with no transport")
            try:
                session_keys, client_pub = await server_handshake(
                    transport_obj,
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
                break  # success → fall through to data path
            except (
                CNNotAllowedError,
                CertRevokedError,
                CertAuthError,
                HandshakeError,
            ) as e:
                err_name = type(e).__name__
                # Anti-information-leak: at INFO/WARNING, log only an
                # opaque "cert auth failed" so an attacker who can read
                # journald (or a log shipper) cannot distinguish "this
                # cert is on the CRL" from "this CN is not in the
                # allowlist" from "binding mismatch" — each of those
                # would otherwise let them enumerate the negative space
                # of the allowlist or partially recover CRL contents
                # through trial. The specific class name (and the
                # exception message) is only emitted at DEBUG.
                if isinstance(e, (CNNotAllowedError, CertRevokedError, CertAuthError)):
                    log.warning(
                        "handshake rejected (cert auth) — waiting for next client"
                    )
                    log.debug(
                        "cert auth detail: %s: %s",
                        err_name,
                        e,
                    )
                else:
                    log.info(
                        "handshake failed — waiting for next client",
                    )
                    log.debug(
                        "handshake failure detail: %s: %s",
                        err_name,
                        e,
                    )
                netaudit.emit(
                    "handshake_end",
                    role="server",
                    outcome="failed",
                    error=err_name,
                    message=str(e),
                )
                # Reset FSM for the next attempt: HANDSHAKING → TEARDOWN → IDLE → CONNECTING.
                fsm.transition(State.TEARDOWN)
                fsm.transition(State.IDLE)
                fsm.transition(State.CONNECTING)

                # Backoff before the next attempt. Doubles per failure up
                # to _HANDSHAKE_RETRY_BACKOFF_MAX, with ±50% jitter so a
                # flood of bad handshakes does not produce a deterministic
                # retry cadence an attacker can synchronize to.
                consecutive_failures += 1
                base = min(
                    _HANDSHAKE_RETRY_BACKOFF_BASE
                    * (2 ** min(consecutive_failures - 1, 4)),
                    _HANDSHAKE_RETRY_BACKOFF_MAX,
                )
                # Use the same CSPRNG-backed helper the shaper uses for
                # jitter, then clamp. Imported lazily to avoid a top-level
                # dependency on dsm.core.rand from server.py.
                from dsm.core.rand import csprng_float

                jitter = (csprng_float() - 0.5) * _HANDSHAKE_RETRY_BACKOFF_JITTER * base
                delay = max(0.0, base + jitter)
                try:
                    await asyncio.wait_for(shutdown.wait(), timeout=delay)
                    return  # shutdown arrived during backoff
                except asyncio.TimeoutError:
                    pass

        if (
            shutdown.is_set()
            or session_keys is None
            or client_pub is None
            or transport_obj is None
        ):
            # Shutdown was triggered while waiting for a successful handshake;
            # close any held TCP transport manually since it was never
            # registered with the AsyncExitStack.
            if config.transport == "tcp" and transport_obj is not None:
                await transport_obj.aclose()
            return

        # Successful TCP transport: register cleanup now that we keep it.
        if config.transport == "tcp":
            stack.push_async_callback(transport_obj.aclose)

        transport: UDPTransport | TCPTransport = transport_obj
        # name used by the rest of run_server
        client_pub_bytes = bytes(client_pub)
        # Log a hash, not the raw key prefix. The Noise static is a
        # stable per-device identifier; logging even 64 bits of it lets
        # a journald reader correlate sessions across server restarts,
        # defeating the anonymity property. The first 16 hex chars of
        # SHA-256(pub) are still device-stable so operators can
        # cross-reference logs to known clients, but don't expose the
        # raw key material in journald.
        import hashlib as _hl

        log.info(
            "client connected (noise_static_sha256=%s)",
            _hl.sha256(client_pub_bytes).hexdigest()[:16],
        )

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
            debug_dns=config.debug_dns,
        )
        dns_proxy = LocalDNSProxy(
            resolver,
            bind_ip=SERVER_TUN_IP,
            bind_port=53,
            debug_dns=config.debug_dns,
        )
        await dns_proxy.start()
        stack.callback(dns_proxy.stop)  # sync
        stack.push_async_callback(resolver.close)  # async (httpx.aclose)

        shaper = TrafficShaper(config.padding_min, config.padding_max)
        replay = tuncore.ReplayWindow()

        seq = SequenceCounter()
        rekey = RekeyState()
        liveness = LivenessState()
        reassembly = ReassemblyBuffer()

        # shutdown + signal handlers were set up before the handshake loop.
        # M-BUG-9: wrap the client_addr cell in a small class that
        # enforces the monotonic-set-once invariant via type-system
        # rather than convention. set() rejects None and any change
        # from a previously-set value (post_authenticate may overwrite
        # with the SAME addr — or a new src port after rebind — which
        # is allowed; setting to None is now a programming error).
        class _ClientAddr:
            __slots__ = ("_addr",)

            def __init__(self) -> None:
                self._addr: tuple[str, int] | None = None

            def set(self, addr: tuple[str, int]) -> None:
                # Defensive runtime guard against a future caller passing
                # None or wrong shape (the type annotation is the primary
                # contract; this catches type-eraser misuse).
                if addr is None or len(addr) != 2:  # type: ignore[unreachable]
                    raise TypeError(f"client_addr must be (host, port), got {addr!r}")
                self._addr = addr

            def get(self) -> tuple[str, int] | None:
                return self._addr

        client_addr = _ClientAddr()

        send_packet = make_send_fn(
            session_keys,
            transport,
            client_addr.get,
            seq,
            liveness=liveness,
            shutdown=shutdown,
        )

        # Guard chaff generation until client_addr is known — the scheduler
        # starts immediately but chaff requires a destination for UDP.
        # The monotonic-set-once invariant is now enforced by _ClientAddr.set;
        # _should_chaff just checks for the initial None state.
        def _should_chaff() -> bool:
            return client_addr.get() is not None and shaper.should_send_chaff()

        # Scheduler+shaper params must mirror the client's — divergence here
        # reintroduces a direction-correlation fingerprint. See
        # tests/test_symmetric_shaping.py for the regression lock.
        server_scheduler = SendScheduler(
            send_fn=send_packet,
            chaff_fn=lambda: make_chaff_packet(shaper, session_keys.epoch & 0x0F),
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
            # M-BUG-1: static pubs for mutual-init tie-break.
            local_static_pub=bytes(keystore.identity.public_key),
            remote_static_pub=client_pub_bytes,
        )

        # Hand off the steady-state recv/send/liveness loops to the
        # shared driver. Server-specific bit: post_authenticate records
        # the source addr of the first authenticated packet into the
        # mutable cell that send_fn dereferences. No udp_addr_filter —
        # the server has no single expected peer addr until that first
        # authenticated packet lands. No extra_loops — auto_mtu_loop is
        # client-only.
        def _record_client_addr(addr: tuple[str, int]) -> None:
            client_addr.set(addr)

        from dsm.session import run_data_loops

        await run_data_loops(
            ctx,
            transport,
            session_keys,
            replay,
            fsm,
            post_authenticate=_record_client_addr,
            shutdown_log="server shutting down",
        )
        # AsyncExitStack cleanup happens automatically here
        # (including keystore.unload — see top of stack).
