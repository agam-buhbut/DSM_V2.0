"""DSM VPN client mode."""

from __future__ import annotations

import asyncio
import logging
from contextlib import AsyncExitStack

from cryptography.x509.oid import ExtendedKeyUsageOID

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
from dsm.crypto.keystore import KeyStore
from dsm.net._addresses import SERVER_TUN_IP
from dsm.net.nftables import (
    NFTablesManager,
    PreHandshakeKillSwitch,
    TcpTimestampsDisabler,
)
from dsm.net.resolv_conf import ResolvConfManager
from dsm.net.transport.tcp import TCPTransport
from dsm.net.transport.udp import UDPTransport
from dsm.net.tunnel import TunDevice
from dsm.session import (
    DataPathContext,
    LivenessState,
    RekeyState,
    SequenceCounter,
    auto_mtu_loop,
    make_send_fn,
    setup_signal_handlers,
)
from dsm.traffic.scheduler import SendScheduler
from dsm.traffic.shaper import TrafficShaper, make_chaff_packet

# Re-export under the historical name for any external code that imports
# `dsm.client.VPN_DNS_SERVER`. Internal uses go through SERVER_TUN_IP.
VPN_DNS_SERVER = SERVER_TUN_IP

log = logging.getLogger(__name__)


def _emit_handshake_failure(err: Exception) -> None:
    """Emit the failed-handshake audit event WITHOUT the exception
    message.

    The operator-facing ERROR log already carries the full detail (a
    client owns its server and needs to debug its cert), but the netaudit
    stream (a separate, machine-readable sink that may be shipped or
    retained differently) is kept minimal and symmetric with the
    server-side emit — only the exception class, never str(err)."""
    netaudit.emit(
        "handshake_end",
        role="client",
        outcome="failed",
        error=type(err).__name__,
    )


async def run_client(
    config: Config,
    passphrase_fd: int | None = None,
    passphrase_env_file: str | None = None,
) -> int:
    """Run DSM in client mode using transactional resource management.

    Every resource that mutates host state (TUN, nftables, resolv.conf, etc.)
    is registered with an ``AsyncExitStack`` the moment it succeeds so that
    any failure downstream unwinds them in reverse order — never leaving
    the host in a half-configured state.

    Returns:
        0 on a clean shutdown (signal / SESSION_CLOSE / dead-peer), 1 on any
        startup or handshake error path. ``main()`` ``sys.exit``s this so a
        failed connection is a nonzero exit (so ``Restart=on-failure`` fires
        and the kill switch is not left masking a silent outage).
    """
    import tuncore

    try:
        tuncore.harden_process()
    except Exception as e:  # noqa: BLE001  # see linter report
        log.warning(
            "process hardening partially failed: %s — continuing without it. "
            "Ensure the service has CAP_SYS_RESOURCE and unrestricted prctl.",
            e,
        )

    # Independent ctypes backstop for the most security-critical bit, in
    # case harden_process() above failed partway: a crash must not dump
    # key material to a core file.
    from dsm.core.hardening import ProcessHardeningError, set_process_nondumpable

    try:
        set_process_nondumpable()
    except ProcessHardeningError as e:
        log.warning("core-dump backstop (PR_SET_DUMPABLE) failed: %s", e)

    from dsm.crypto.attest_gate import (
        MalformedAttestBuildError,
        SoftAttestNotAllowedError,
        enforce_attest_backend_policy,
    )

    try:
        enforce_attest_backend_policy(config)
    except (SoftAttestNotAllowedError, MalformedAttestBuildError) as e:
        log.error("%s", e)
        return 1

    fsm = SessionFSM()

    # Cert auth materials must load BEFORE we touch any host state, so a
    # missing cert file aborts cleanly with no rules / no TUN created.
    try:
        materials = load_cert_materials(config)
    except AuthMaterialsError as e:
        log.error("cert auth materials missing or invalid: %s", e)
        return 1

    async with AsyncExitStack() as stack:
        # Phase 1.8 (H10): create the shutdown event and install signal
        # handlers BEFORE the pre-handshake kill switch. A SIGTERM during
        # connect/handshake must trigger the AsyncExitStack unwind (removing
        # the kill switch) rather than killing the process with the kill
        # switch still applied and the host offline.
        shutdown = asyncio.Event()
        setup_signal_handlers(shutdown)

        # Pre-handshake kill switch: applied BEFORE the (possibly interactive)
        # passphrase read + key unlock below, so the host is fail-closed for
        # the ENTIRE startup window — not just from socket bind onward. A slow
        # passphrase prompt or key load must never leave user traffic
        # unprotected. Allows only loopback, DHCP renewal, and the configured
        # server endpoint; upgraded atomically to the full kill switch (which
        # also covers the TUN interface and DNS leaks) by NFTablesManager
        # .apply() below, once the TUN is up.
        pre_killswitch = PreHandshakeKillSwitch(config.server_ip, config.server_port)
        try:
            pre_killswitch.apply()
        except OSError as e:
            # Fail closed: never proceed to connect without the egress lock.
            # OSError covers a missing/unresolvable nft (FileNotFoundError).
            log.error(
                "pre-handshake kill switch could not be installed: %s — "
                "refusing to start (fail-closed). Ensure nftables is present "
                "and the daemon has CAP_NET_ADMIN.",
                e,
            )
            return 1
        stack.callback(pre_killswitch.remove)

        # Read the passphrase once and unlock both stores, now BEHIND the kill
        # switch. Identity (X25519 Noise static) and attest key (ECDSA P-256)
        # live behind the same passphrase by design — both are provisioned
        # together by `dsm enroll`. On failure the AsyncExitStack unwinds,
        # removing the kill switch and restoring the host.
        from dsm.crypto._stores import load_daemon_stores

        keystore = KeyStore(config.key_file)
        attest_store = AttestStore(config.attest_key_file)
        if not load_daemon_stores(
            keystore,
            attest_store,
            passphrase_fd=passphrase_fd,
            passphrase_env_file=passphrase_env_file,
        ):
            return 1

        # Register the unloads now that the stores are loaded. They unwind
        # before the kill switch is removed (the nft teardown does not need
        # the keys); the identity stays resident for the whole session.
        stack.callback(keystore.unload)
        stack.callback(attest_store.unload)

        # With both stores unlocked, confirm the loaded cert was issued for
        # THIS device's keys. Catches the cert_file substitution failure mode
        # at startup with a clear error, rather than at the server's
        # AttestBindingMismatchError much later in the handshake. On failure
        # the stack unwinds (unloading the stores, removing the kill switch).
        try:
            verify_cert_matches_identity(materials.cert_der, keystore, attest_store)
        except AuthMaterialsError as e:
            log.error("cert/identity consistency check failed: %s", e)
            return 1

        shaper = TrafficShaper(
            config.padding_min,
            config.padding_max,
            envelope_idle_floor_min_pps=config.envelope_idle_floor_min_pps,
            envelope_idle_floor_max_pps=config.envelope_idle_floor_max_pps,
            envelope_ceiling_pps=config.envelope_ceiling_pps,
            envelope_rise_per_s=config.envelope_rise_per_s,
            envelope_fall_half_life_s=config.envelope_fall_half_life_s,
            envelope_latency_budget_ms=config.envelope_latency_budget_ms,
        )

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

        from dsm.crypto.handshake import (
            CertAuthError,
            CertRevokedError,
            CNMismatchError,
            HandshakeError,
            client_handshake,
        )

        # Per-error-class log prefix. Lookup is by exact type(e); the
        # tuple in the except clause below preserves catch order
        # (subclasses before parent classes is irrelevant here because
        # every entry is checked by isinstance via the tuple, and the
        # log prefix is then resolved from the concrete class).
        _CLIENT_HANDSHAKE_ERR_LABELS: dict[type[BaseException], str] = (
            {  # pylint: disable=invalid-name  # intentional/false positive (see report)
                CNMismatchError: "server CN check failed",
                CertRevokedError: "server cert revoked",
                CertAuthError: "server cert auth failed",
                HandshakeError: "handshake failed",
            }
        )

        assert (
            config.expected_server_cn is not None
        ), "client mode requires expected_server_cn (validated in Config)"

        try:
            session_keys, _handshake_hash, server_static_pub = await client_handshake(
                transport,
                keystore.identity,
                server_addr,
                attest_key=attest_store.attest_key,
                cert_der=materials.cert_der,
                ca_root=materials.ca_root,
                expected_server_cn=config.expected_server_cn,
                crl=materials.crl,
                required_server_eku=ExtendedKeyUsageOID.SERVER_AUTH,
                rotation_packets=config.rotation_packets,
                rotation_seconds=config.rotation_seconds,
            )
        except (
            CNMismatchError,
            CertRevokedError,
            CertAuthError,
            HandshakeError,
        ) as e:
            # Resolve the most-specific label: walk the dict in MRO order
            # so e.g. CNMismatchError (subclass of CertAuthError) gets
            # its dedicated prefix rather than CertAuthError's.
            prefix = next(
                (
                    _CLIENT_HANDSHAKE_ERR_LABELS[cls]
                    for cls in type(e).__mro__
                    if cls in _CLIENT_HANDSHAKE_ERR_LABELS
                ),
                "handshake failed",
            )
            log.error("%s: %s", prefix, e)
            _emit_handshake_failure(e)
            fsm.transition(State.TEARDOWN)
            return 1  # AsyncExitStack unwinds transport + keystore

        fsm.transition(State.ESTABLISHED)

        # Host-mutating resources.
        #
        # Apply order is fixed by dependency:
        #   tcp_ts → tun → nft → resolv
        # (nft references tun's name; resolv goes last so the kill switch
        # is already up when the new resolver becomes visible.)
        #
        # Unwind order is anonymity-critical: the kill switch (nft) MUST
        # stay applied while the TUN is being torn down. Tun teardown
        # briefly removes the routing rule that forces traffic through
        # the tunnel; during that window unmarked traffic can fall to
        # the main routing table and hit the WAN interface. If the kill
        # switch is gone by then, that traffic leaks. If it is still up,
        # nftables drops it.
        #
        # Desired unwind: resolv → tun → nft → tcp_ts
        # Reverse of that (= AsyncExitStack registration order):
        #         tcp_ts, nft, tun, resolv
        # which is NOT the apply order. We use an explicit try/except
        # block to keep partial-failure safety: if any apply between tun
        # and resolv fails, we manually unwind what was already applied
        # before re-raising.

        tcp_ts = TcpTimestampsDisabler()
        tcp_ts.apply()
        stack.callback(tcp_ts.remove)

        # TUN must be opened/configured before nftables (kill-switch rules
        # reference TUN by name). Apply tun + nft + resolv in that order
        # but DEFER the cleanup-callback registration so we control the
        # unwind sequence.
        tun = TunDevice(config.tun_name)
        tun.open()
        try:
            tun.configure(mtu=config.mtu)
            nft = NFTablesManager(config.server_ip, config.server_port, config.tun_name)
            nft.apply()
            try:
                resolv = ResolvConfManager(nameserver=SERVER_TUN_IP)
                resolv.apply()
            except Exception:
                # resolv failed after nft was applied. Undo nft, then
                # let the outer except undo tun.
                try:
                    nft.remove()
                except Exception:  # noqa: BLE001  # see linter report
                    log.warning("nft.remove during failed apply also failed")
                raise
        except Exception:
            # tun.configure or nft.apply (or resolv.apply if it re-raised
            # above) failed. Undo tun.close manually since we never
            # registered the cleanup.
            try:
                tun.close()
            except Exception:  # noqa: BLE001  # see linter report
                log.warning("tun.close during failed apply also failed")
            raise

        # All three host-mutating resources are up. Register cleanups in
        # REVERSE of desired unwind order. AsyncExitStack pops LIFO, so:
        #   register nft.remove  → unwinds 3rd (LAST: kill switch down)
        #   register tun.close   → unwinds 2nd (kill switch still up)
        #   register resolv.remove → unwinds 1st (DNS reverted while kill switch up)
        stack.callback(nft.remove)
        stack.callback(tun.close)
        stack.callback(resolv.remove)

        log.info("tunnel established")

        # After the handshake has exchanged several full-size datagrams,
        # the kernel may have learned the path MTU via ICMP. Log it once
        # so the operator can tell whether the configured tun MTU is a
        # good fit. When `auto_mtu` is on, the adapter loop below will
        # also act on this information; we still log the warning when
        # `auto_mtu` is off so a misconfigured static MTU is visible at
        # startup.
        if isinstance(transport, UDPTransport):
            path_mtu = transport.get_path_mtu()
            if path_mtu is not None:
                # See dsm.session.WIRE_OVERHEAD for the breakdown.
                from dsm.session import WIRE_OVERHEAD

                usable = path_mtu - WIRE_OVERHEAD
                log.info("kernel path MTU = %d (usable inner %d)", path_mtu, usable)
                if usable < config.mtu and not config.auto_mtu:
                    log.warning(
                        "configured tun mtu=%d exceeds usable inner %d "
                        "(path MTU %d); enable `auto_mtu` or lower `mtu` "
                        "in config to avoid fragmentation",
                        config.mtu,
                        usable,
                        path_mtu,
                    )

        seq = SequenceCounter()
        replay = tuncore.ReplayWindow()
        rekey = RekeyState()
        liveness = LivenessState()
        reassembly = ReassemblyBuffer()

        # shutdown + signal handlers were installed at the top of the stack
        # (Phase 1.8 H10), before the pre-handshake kill switch. Reuse that
        # same event here so make_send_fn / DataPathContext observe signals.
        send_packet = make_send_fn(
            session_keys,
            transport,
            lambda: server_addr,
            seq,
            liveness=liveness,
            shutdown=shutdown,
        )

        # Phase 2: envelope-driven. The shaper's paced wire budget
        # (release_budget) decides how many packets (real first, chaff fill)
        # leave per poll, so the wire rate is independent of real volume.
        # should_chaff_fn is intentionally omitted (envelope mode).
        scheduler = SendScheduler(
            send_fn=send_packet,
            chaff_fn=lambda: make_chaff_packet(shaper, session_keys.epoch & 0x0F),
            jitter_ms_min=config.jitter_ms_min,
            jitter_ms_max=config.jitter_ms_max,
            shaper=shaper,
        )
        await scheduler.start()
        stack.push_async_callback(scheduler.stop)

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
            # H-ANON-4: pass the UDPTransport so post-rekey hook can
            # rebind to a fresh ephemeral src port; None on TCP.
            udp_transport=transport if isinstance(transport, UDPTransport) else None,
            # M-BUG-1 / audit H1: static pubs for mutual-init tie-break.
            local_static_pub=bytes(keystore.identity.public_key),
            remote_static_pub=server_static_pub,
        )

        # Hand off the steady-state recv/send/liveness loops to the
        # shared driver. Client-specific bits passed in:
        #   * udp_addr_filter: drop UDP datagrams not from server_addr.
        #     TCP doesn't need this (one connection only).
        #   * extra_loops: auto_mtu_loop is client-only.
        # The AsyncExitStack stays in this module; ``run_data_loops``
        # only owns the loops + the SESSION_CLOSE / FSM teardown.
        from dsm.session import run_data_loops

        await run_data_loops(
            ctx,
            transport,
            session_keys,
            replay,
            fsm,
            extra_loops=(auto_mtu_loop(ctx, transport, config),),
            udp_addr_filter=lambda addr: addr == server_addr,
            shutdown_log="shutting down",
        )
        # AsyncExitStack unwinds remaining resources in reverse order.

    # Clean shutdown (signal / SESSION_CLOSE / dead-peer): exit 0.
    return 0
