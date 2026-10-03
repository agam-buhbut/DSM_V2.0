package com.dsm.android

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import com.dsm.android.attest.AndroidKeystoreKeyHandle
import com.dsm.android.config.DsmConfig
import com.dsm.android.config.Provisioning
import com.dsm.android.config.ProvisioningException
import com.dsm.android.config.ProvisioningLayout
import com.dsm.android.config.ProvisioningLoader
import com.dsm.android.core.AttestPayloadCodec
import com.dsm.android.core.FileTunIo
import com.dsm.android.core.HandshakeDriver
import com.dsm.android.core.MonotonicClock
import com.dsm.android.core.RealShaper
import com.dsm.android.core.SessionRunner
import com.dsm.android.core.TransportChannel
import com.dsm.android.core.TuncoreClientCore
import com.dsm.android.core.TuncoreReplayGate
import com.dsm.android.core.TuncoreSessionCrypto
import com.dsm.android.core.UdpTransportChannel
import com.dsm.android.core.buildHandshakeInputs
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import uniffi.tuncore.ReplayWindow
import uniffi.tuncore.attestBackendIsSoftware
import uniffi.tuncore.handshakeAttestPayloadSize

/**
 * A default route installed into the TUN (address + prefix length). Modeled as
 * plain data so the [TUN_ROUTES] capture policy — critically, that IPv6 is
 * captured and cannot leak (AND-1) — stays unit-testable without a real
 * `VpnService.Builder` (a system class that returns stubs under JVM unit tests).
 */
internal data class TunRoute(val address: String, val prefixLength: Int)

/**
 * AND-1: the TUN capture policy — the default routes pulled into the tunnel.
 * Declared top-level (not inline `addRoute` calls, and OFF the VpnService
 * subclass) so the critical invariant "IPv6 is captured, never left to leak" is
 * unit-testable under a plain JVM test with no Android class-loading.
 * [DsmVpnService.buildTun] installs exactly these; the regression test asserts
 * `::/0` is present.
 */
internal val TUN_ROUTES: List<TunRoute> = listOf(
    TunRoute("0.0.0.0", 0), // all IPv4
    TunRoute("::", 0), // all IPv6 (AND-1 leak guard)
)

/**
 * DSM VPN tunnel service.
 *
 * On connect it loads the B1 provisioning bundle from the app's private
 * `filesDir` ([ProvisioningLayout]) and:
 *  - opens the server socket and **`protect()`s it before connect** so the
 *    tunnel's own packets are not routed back into the TUN (the routing loop),
 *  - builds the TUN via [VpnService.Builder] (address / route / DNS / inner MTU
 *    from config — default 1360, no inner fragmentation),
 *  - unseals the persisted Noise identity, reuses the B1-attested Keystore key,
 *    and drives [HandshakeDriver] (server pinned to the provisioned CA root +
 *    `expected_server_cn`, client attesting with the device cert + Keystore key),
 *  - on success runs the [SessionRunner] steady-state data loop.
 *
 * An un-provisioned device fails closed: [ProvisioningLoader.load] throws a
 * [ProvisioningException] and the worker exits without opening a tunnel.
 */
class DsmVpnService : VpnService() {

    @Volatile
    private var worker: Thread? = null

    @Volatile
    private var tun: ParcelFileDescriptor? = null

    @Volatile
    private var channel: TransportChannel? = null

    @Volatile
    private var runner: SessionRunner? = null

    // AND-3 kill-switch flag: set ONLY by an explicit user/system stop
    // (ACTION_DISCONNECT / onDestroy). The supervisor loop uses it to tell a
    // transient session drop (keep the TUN up, fail CLOSED, retry) apart from a
    // real stop (tear the interface down and revert apps to cleartext egress).
    @Volatile
    private var stopRequested = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_DISCONNECT) {
            // Explicit user stop: the ONLY path (besides onDestroy) that performs
            // the real teardown closing the TUN. AND-3: a transient session drop
            // must NEVER reach here, or every app reverts to cleartext egress.
            stopRequested = true
            worker?.interrupt()
            teardownVpn()
            stopSelf()
            return START_NOT_STICKY
        }
        startTunnel()
        return START_STICKY
    }

    private fun startTunnel() {
        if (worker != null) {
            Log.w(TAG, "tunnel already running; ignoring start")
            return
        }
        val t = Thread({ runTunnel() }, "dsm-tunnel")
        worker = t
        t.start()
    }

    private fun runTunnel() {
        // Load + validate the B1 provisioning bundle ONCE. An un-provisioned
        // device has no tunnel to protect, so failing closed here simply means
        // not bringing one up — nothing to leak — and we exit without supervising.
        val provisioning = try {
            ProvisioningLoader(ProvisioningLayout.dir(filesDir)).load()
        } catch (e: ProvisioningException) {
            // Not enrolled / artifact missing or invalid. The message names the
            // artifact; do not log key material.
            Log.e(TAG, "cannot connect — provisioning invalid: ${e.message}")
            worker = null
            return
        }
        Log.i(
            TAG,
            "attest backend is " + if (attestBackendIsSoftware()) "SOFTWARE (dev)" else "hardware",
        )

        // AND-3 kill-switch supervisor. Each iteration drives ONE session. A
        // session that ends for ANY reason other than an explicit stop is a
        // TRANSIENT failure (handshake fail after the TUN is up, dead-peer
        // timeout, rekey give-up, transport error). On those we must NOT revert
        // apps to cleartext: we keep a TUN established — which drops/blackholes
        // app packets, i.e. fails CLOSED — and re-establish a fresh session. Only
        // an explicit stop (ACTION_DISCONNECT / onDestroy, which set
        // stopRequested) runs the real teardown that closes the interface. The
        // loop retries indefinitely by design: the kill-switch stays shut until
        // the user disconnects.
        //
        // TODO(owner): verify kill-switch behavior on-device. This relies on (a)
        // VpnService.establish() reconfiguring the existing VPN in place so app
        // traffic stays captured across a reconnect, and (b) app packets written
        // to an unserviced TUN fd being dropped, not leaked — both are
        // OEM/OS-version sensitive. There is also a brief window between the
        // SessionRunner closing the old TUN fd (it owns that close) and the
        // supervisor establishing the next one; confirm no cleartext escapes it.
        var backoffMs = RECONNECT_BACKOFF_MIN_MS
        while (!stopRequested) {
            try {
                runSession(provisioning)
            } catch (e: InterruptedException) {
                Log.i(TAG, "tunnel worker interrupted; shutting down")
                break
            } catch (e: ProvisioningException) {
                // Identity failed to unseal this attempt (e.g. a transient native
                // error). Treat as transient and keep failing closed.
                Log.e(TAG, "session failed — provisioning: ${e.message}")
            } catch (e: Exception) {
                Log.e(TAG, "session failed (transient): ${e.message}", e)
            }
            if (stopRequested) break

            // Session ended without an explicit stop → stay failed CLOSED while
            // reconnecting. The SessionRunner has already closed this session's
            // TUN fd, so establish a fresh blackhole TUN (captures all traffic,
            // nothing services it → packets dropped) to hold the kill-switch shut
            // across the backoff, then retry.
            runCatching { establishTun(provisioning.config) }
            if (sleepInterruptibly(backoffMs)) break
            backoffMs = (backoffMs * 2).coerceAtMost(RECONNECT_BACKOFF_MAX_MS)
        }

        // Reached only on an explicit stop / interrupt: perform the real teardown
        // that closes the interface and reverts apps to normal egress.
        teardownVpn()
    }

    /**
     * Drive a single session end-to-end: open the protected transport, (re)build
     * the TUN, run the handshake, then block on the steady-state data loop until
     * it tears down. Returns normally on a session drop; [runTunnel] decides
     * whether to retry (fail closed) or stop. Throws on a setup failure, which
     * the supervisor also treats as a transient error.
     */
    private fun runSession(provisioning: Provisioning) {
        if (stopRequested) return
        val config = provisioning.config

        // 1. Establish the protected server socket BEFORE building the TUN route
        //    (resolves the server off-tunnel) and protect() it so its egress does
        //    not loop back into the TUN.
        val server = InetSocketAddress(
            InetAddress.getByName(config.serverIp),
            config.serverPort,
        )
        val channel = openProtectedChannel(config, server)
        this.channel = channel

        // 2. (Re)establish the TUN (inner MTU from config; captures BOTH IPv4 and
        //    IPv6 — see buildTun / AND-1). On a reconnect this replaces the prior
        //    interface in place so app traffic stays captured throughout.
        val pfd = establishTun(config)

        // 3. Drive the handshake into an established session over the core.
        //    Identity + device cert + pinned CA root come from B1 provisioning;
        //    the attest signer REUSES the already-attested Keystore key (it must
        //    not be regenerated, or the issued device cert's binding breaks).
        val identity = provisioning.openIdentity()
        val core = TuncoreClientCore(
            identity = identity,
            rotationPackets = config.rotationPackets?.toULong(),
            rotationSeconds = config.rotationSeconds?.toULong(),
        )
        val codec = AttestPayloadCodec(handshakeAttestPayloadSize().toInt())
        val inputs = buildHandshakeInputs(
            caRoot = provisioning.caRoot,
            deviceCertDer = provisioning.deviceCertDer,
            expectedServerCn = config.expectedServerCn,
            codec = codec,
            keyHandle = AndroidKeystoreKeyHandle.open(config.keystoreAlias),
        )
        val driver = HandshakeDriver(
            core = core,
            channel = channel,
            signer = inputs.signer,
            codec = codec,
            serverVerifier = inputs.serverVerifier,
            certDer = inputs.deviceCertDer,
            expectedServerCn = inputs.expectedServerCn,
        )
        val result = driver.connect()
        Log.i(TAG, "handshake established with server CN ${result.serverCn}")

        // 4. Run the steady-state data loop (port of dsm/session.py): TUN.read ->
        //    inner DATA -> shaper (pad + pace) -> encrypt -> packOuter -> send;
        //    recv -> unpackOuter -> replay -> decrypt(+grace) -> dispatch -> TUN;
        //    plus liveness keepalive (15 s) / dead-peer teardown (60 s) and rekey
        //    (initiate/respond + UDP rebind). Blocks until the session tears down.
        runDataLoop(core, channel, pfd, result.serverStaticPub)
    }

    /** Open + `protect()` the server socket, then connect. UDP path implemented. */
    private fun openProtectedChannel(
        config: DsmConfig,
        server: InetSocketAddress,
    ): TransportChannel =
        when (config.transport) {
            DsmConfig.Transport.UDP -> {
                // Factory: each call mints a freshly protect()-ed + connected
                // socket. CRITICAL: protect before connect so the tunnel's own
                // packets egress the real underlying network, not the TUN. Reused
                // on rekey for the H-ANON-4 fresh-source-port rebind.
                val socketFactory = {
                    val socket = DatagramSocket()
                    if (!protect(socket)) {
                        socket.close()
                        throw IllegalStateException("VpnService.protect(udp) failed")
                    }
                    socket.connect(server)
                    socket
                }
                UdpTransportChannel(server, socketFactory)
            }
        }

    /**
     * Build a fresh TUN that captures ALL traffic — both IPv4 and IPv6.
     *
     * AND-1: with only a v4 address + a `0.0.0.0/0` route, the OS leaves IPv6 on
     * the underlying network, so on a dual-stack link every v6 flow and AAAA DNS
     * lookup egresses in cleartext OUTSIDE the tunnel — a total anonymity break.
     * A ULA v6 address plus a `::/0` route pulls v6 into the tunnel as well. The
     * data path is v4-only today, so captured v6 is blackholed here (dropped),
     * which fails CLOSED rather than leaking. [TUN_ROUTES] is the single source
     * of truth for the capture policy so it stays unit-testable off-device.
     */
    private fun buildTun(config: DsmConfig): ParcelFileDescriptor {
        val builder = Builder()
            .setSession("DSM")
            .setMtu(config.mtu)
            .addAddress(config.tunAddress, DsmConfig.TUN_PREFIX_LEN)
            .addAddress(TUN6_ADDRESS, TUN6_PREFIX_LEN)
            .addDnsServer(config.dns)
        // Route all traffic (both families) into the tunnel.
        for (route in TUN_ROUTES) {
            builder.addRoute(route.address, route.prefixLength)
        }
        return builder.establish()
            ?: throw IllegalStateException("VpnService.Builder.establish() returned null")
    }

    /**
     * Establish a fresh TUN and atomically make it the current one. The new
     * interface is established BEFORE the previous fd is closed, so app traffic
     * is never briefly reverted to cleartext across the swap (AND-3: fail CLOSED).
     */
    private fun establishTun(config: DsmConfig): ParcelFileDescriptor {
        val previous = tun
        val pfd = buildTun(config)
        tun = pfd
        runCatching { previous?.close() }
        return pfd
    }

    /**
     * Sleep [ms], waking immediately on interrupt. Returns true if interrupted
     * (an explicit stop requested mid-backoff), false if the delay fully elapsed.
     */
    private fun sleepInterruptibly(ms: Long): Boolean =
        try {
            Thread.sleep(ms)
            false
        } catch (e: InterruptedException) {
            true
        }

    private fun runDataLoop(
        core: TuncoreClientCore,
        channel: TransportChannel,
        pfd: ParcelFileDescriptor,
        serverStaticPub: ByteArray,
    ) {
        val session = core.session
            ?: throw IllegalStateException("handshake completed but no session established")
        Log.i(TAG, "session established (epoch=${session.epoch()}); starting data loop")

        val sessionRunner = SessionRunner(
            crypto = TuncoreSessionCrypto(session),
            replay = TuncoreReplayGate(ReplayWindow()),
            channel = channel,
            tun = FileTunIo(pfd),
            localStaticPub = core.localStaticPublic(),
            remoteStaticPub = serverStaticPub,
            // Task B3b: RealShaper mirrors the Python traffic shaper/scheduler —
            // fixed-prior size-class padding, adaptive-envelope chaff, per-packet
            // jitter/reordering — so the Android client's wire behavior matches
            // the desktop client's. CSPRNG-backed (SecureRandom). Envelope +
            // padding + jitter use the config defaults (padding 128-1400, jitter
            // 1-100 ms, idle floor 0.5-2 pps, 600 pps ceiling, 1 s budget).
            shaper = RealShaper(),
            clock = MonotonicClock.SYSTEM,
            // The supervisor loop ([runTunnel]) owns the VPN lifecycle now. When a
            // session tears itself down (dead peer, rekey give-up, transport
            // error), finalizeSession has already closed this session's transport
            // and TUN fd, and the worker regains control from awaitAndFinalize to
            // decide retry-vs-stop. So this hook must NOT close the interface or
            // clear the worker — doing so would defeat the AND-3 kill-switch.
            onTeardown = {},
            log = { msg -> Log.i(TAG, msg) },
        )
        runner = sessionRunner
        sessionRunner.start()
        // Block this worker until the loop tears down (peer close, dead-peer
        // timeout, rekey give-up, or an external requestShutdown()).
        sessionRunner.awaitAndFinalize()
    }

    /**
     * Real teardown: closes the transport AND the TUN, reverting apps to normal
     * (cleartext) egress. AND-3: reached ONLY on an explicit user/system stop
     * (ACTION_DISCONNECT / onDestroy) — never on a transient session drop, which
     * the supervisor instead handles by keeping the interface up and failing
     * closed.
     */
    private fun teardownVpn() {
        runCatching { runner?.requestShutdown() }
        runner = null
        runCatching { channel?.close() }
        channel = null
        runCatching { tun?.close() }
        tun = null
        worker = null
    }

    override fun onDestroy() {
        // System stop: a real teardown is correct here — the service is going
        // away, so keeping the interface up would strand it.
        stopRequested = true
        runCatching { runner?.requestShutdown() }
        worker?.interrupt()
        teardownVpn()
        super.onDestroy()
    }

    companion object {
        private const val TAG = "DsmVpnService"
        const val ACTION_DISCONNECT = "com.dsm.android.DISCONNECT"

        // AND-1: a private-range (ULA, fd00::/8) IPv6 address for the TUN so the
        // ::/0 route below has a matching source interface. Fixed, non-secret.
        private const val TUN6_ADDRESS = "fd00:dead:beef::2"
        private const val TUN6_PREFIX_LEN = 64

        // AND-3 reconnect backoff bounds (exponential, capped). There is
        // intentionally no max-attempt cap: the kill-switch stays CLOSED and the
        // supervisor keeps retrying until the user disconnects.
        private const val RECONNECT_BACKOFF_MIN_MS = 500L
        private const val RECONNECT_BACKOFF_MAX_MS = 8_000L
    }
}
