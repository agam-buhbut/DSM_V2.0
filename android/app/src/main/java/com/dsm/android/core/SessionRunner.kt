package com.dsm.android.core

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * DSM steady-state data loop, porting `dsm/session.py` to the Android client.
 *
 * Given an established session ([SessionCrypto] + [ReplayGate]), the
 * `protect()`-ed [TransportChannel], and the TUN ([TunIo]), it runs three loops:
 *
 *  * **outbound** ([runOutboundOnce]) — TUN read → inner DATA packet →
 *    [Shaper] → AEAD encrypt → [WireFraming.packOuter] → channel send;
 *    `tun_send_loop` (session.py:1188).
 *  * **inbound** ([pumpInbound]) — channel recv → [WireFraming.unpackOuter] →
 *    [ReplayGate.check] → [SessionCrypto.tryDecryptWithFallback] (current then
 *    prev-epoch grace) → epoch-nibble check → dispatch → TUN write;
 *    `recv_loop` + `decrypt_packet` + `dispatch_inner` (session.py:963/506/838).
 *  * **liveness** ([tickLiveness]) — KEEPALIVE on 15 s real-send idle, teardown
 *    on 60 s recv idle; `liveness_loop` (session.py:846).
 *
 * Rekey (`tun_send_loop` initiate/retry + the recv-side REKEY_INIT/ACK handling)
 * is delegated to [RekeyEngine]. The single [SessionCrypto] handles both
 * directions, mirroring session.py exactly (NOT one manager per direction).
 *
 * The pump methods are individually callable so the data path is unit-tested
 * deterministically with fakes + an injected [MonotonicClock]; [start] wires the
 * same methods into dedicated threads for the on-device run (B4).
 *
 * No plaintext or key material is ever logged.
 */
class SessionRunner(
    private val crypto: SessionCrypto,
    private val replay: ReplayGate,
    private val channel: TransportChannel,
    private val tun: TunIo,
    localStaticPub: ByteArray,
    remoteStaticPub: ByteArray,
    private val shaper: Shaper = NullShaper,
    private val clock: MonotonicClock = MonotonicClock.SYSTEM,
    private val onTeardown: () -> Unit = {},
    private val log: (String) -> Unit = {},
) {
    private val running = AtomicBoolean(false)
    private val shutdown = AtomicBoolean(false)
    private val finalized = AtomicBoolean(false)
    private val shutdownLatch = CountDownLatch(1)

    // Outer sequence counter. next() pre-increments → first packet is seq=1
    // (mirrors SequenceCounter in session.py).
    private val seqCounter = AtomicLong(0)

    private val liveness = Liveness(clock.nowMillis())
    private val rekeyState = RekeyState()
    private val rekey = RekeyEngine(
        crypto = crypto,
        state = rekeyState,
        localStaticPub = localStaticPub,
        remoteStaticPub = remoteStaticPub,
        clock = clock,
        sendInner = ::sendInner,
        onTeardown = ::signalTeardown,
        onRekeyComplete = { runCatching { channel.rebindToFreshPort() } },
        log = log,
    )

    // Paced send loop (Task B3b). Present only when [shaper] is a [PacingShaper]
    // (production [RealShaper]); with the [NullShaper] default the loop sends
    // directly. Chaff, real data, keepalive, and rekey all ride the same
    // [transmit] via this scheduler, so they are indistinguishable on the wire.
    private val scheduler: SendScheduler? = (shaper as? PacingShaper)?.let { ps ->
        SendScheduler(
            shaper = ps,
            send = ::transmit,
            chaffEpoch = { crypto.epoch() and 0x0F },
            clock = clock,
            log = log,
        )
    }

    @Volatile
    private var threads: List<Thread> = emptyList()

    // ── Outbound ──────────────────────────────────────────────────────────

    /**
     * One outbound iteration: rekey housekeeping, then read+send one TUN packet.
     * Returns false when no packet was available (TUN EOF/closed). Mirrors one
     * pass of `tun_send_loop`.
     */
    fun runOutboundOnce(): Boolean {
        rekey.maybeInitiate()
        rekey.maybeRetry()
        if (shutdown.get()) return false

        val pkt = tun.read() ?: return false
        if (pkt.size > InnerPacket.MAX_INNER_PAYLOAD) {
            // Inner fragmentation is still deferred (the FRAGMENT path is not
            // ported). The TUN MTU (1360) keeps every IP packet inside a single
            // inner that the shaper pads up to at most the 1400 class; a larger
            // packet is dropped rather than crash.
            log("dropping oversized TUN packet (${pkt.size} bytes) — fragmentation deferred")
            return true
        }
        // M-BUG-15: a REAL-data send resets the keepalive idle timer.
        liveness.lastRealSendMs = clock.nowMillis()
        sendInner(InnerPacket(PacketType.DATA, crypto.epoch() and 0x0F, pkt))
        return true
    }

    /**
     * Single send choke point: size-class-pad the inner packet, then either pace
     * it through the [scheduler] (paced [PacingShaper] path — jitter, envelope,
     * reordering, chaff interleave) or [transmit] it directly ([NullShaper]).
     * Data, keepalive, and rekey all pass through here so the [Shaper] seam
     * applies uniformly.
     */
    private fun sendInner(inner: InnerPacket) {
        val padded = shaper.shapeInner(inner.serialize())
        val sch = scheduler
        if (sch != null) sch.enqueue(padded) else transmit(padded)
    }

    /**
     * Frame, encrypt, and send one already-padded inner plaintext. The wire-tail
     * shared by the direct path and the paced [scheduler]'s real+chaff fill, so
     * the seq/nonce/AAD framing is identical for every packet type. Mirrors
     * `send_packet` (session.py:201).
     */
    private fun transmit(paddedInner: ByteArray) {
        val data = restampEpoch(paddedInner)
        val seq = nextSeq() ?: return
        val aad = WireFraming.seqToAad(seq)
        val enc = crypto.encrypt(data, aad)
        val wire = WireFraming.packOuter(seq, enc.nonce, enc.ciphertext)
        channel.send(wire)
    }

    /**
     * H-BUG-1 send-time epoch-nibble re-stamp. In the paced path a packet is
     * padded under the queue-time epoch but encrypted here at send time; if a
     * rekey completed in between, the header would carry the OLD epoch nibble
     * with the NEW AEAD key and the receiver would drop it. Patch byte 1 (top
     * nibble = epoch_id, low 4 reserved) with the live epoch. Mirrors
     * `send_packet` (session.py:230). No-op (and no copy) on the common path —
     * including the whole direct [NullShaper] path — where the nibble matches.
     */
    private fun restampEpoch(data: ByteArray): ByteArray {
        if (data.size < 2) return data
        val want = (data[1].toInt() and 0x0F) or ((crypto.epoch() and 0x0F) shl 4)
        if ((data[1].toInt() and 0xFF) == want) return data
        val buf = data.copyOf()
        buf[1] = want.toByte()
        return buf
    }

    private fun nextSeq(): Long? {
        val v = seqCounter.incrementAndGet()
        if (v < 0) {
            // Wrapped past 2^63 (Long). The Python counter exhausts at 2^64; a
            // real session never reaches 2^63 packets. Fail closed regardless.
            log("sequence counter exhausted — triggering shutdown")
            signalTeardown()
            return null
        }
        return v
    }

    // ── Inbound ───────────────────────────────────────────────────────────

    /** Process one received datagram. Mirrors one pass of `recv_loop`. */
    fun pumpInbound(data: ByteArray) {
        val inner = decryptPacket(data) ?: return
        liveness.lastRecvMs = clock.nowMillis()
        dispatchInner(inner)
    }

    /**
     * Parse, replay-check, decrypt (current then prev-epoch grace), and validate
     * one packet. Returns null on any drop. Mirrors `decrypt_packet`.
     */
    private fun decryptPacket(data: ByteArray): InnerPacket? {
        if (data.size < WireFraming.OUTER_HEADER_SIZE) {
            log("packet too short, dropping")
            return null
        }
        val outer = WireFraming.unpackOuter(data)
        val seq = outer.seq
        // check() BEFORE the AEAD work (drop replays cheaply); update() only
        // after a successful decrypt below (M-BUG-14 ordering).
        if (!replay.check(seq)) {
            log("replay detected, dropping seq=$seq")
            return null
        }
        val aad = WireFraming.seqToAad(seq)
        val result = crypto.tryDecryptWithFallback(outer.nonce, outer.ciphertext, aad, seq)
            ?: return null
        replay.update(seq)

        val inner = try {
            InnerPacket.deserialize(result.plaintext)
        } catch (e: IllegalArgumentException) {
            log("malformed inner packet, dropping")
            return null
        }

        // Epoch-nibble check (audit M3). CHAFF / REKEY_ACK / PATH_* self-validate
        // (AEAD + their own fields) and may be built under one epoch and arrive
        // across a grace window, so they are exempt — exactly as decrypt_packet.
        if (inner.ptype !in EPOCH_EXEMPT) {
            val expected = if (result.usedPrevEpoch) {
                (crypto.epoch() - 1) and 0x0F
            } else {
                crypto.epoch() and 0x0F
            }
            if (inner.epochId != expected) {
                log("epoch_id mismatch: got ${inner.epochId}, expected $expected")
                return null
            }
        }
        return inner
    }

    /** Route a decrypted inner packet by type. Mirrors `_DISPATCH`. */
    private fun dispatchInner(inner: InnerPacket) {
        when (inner.ptype) {
            PacketType.DATA -> tun.write(inner.payload)
            // Liveness is accounted in pumpInbound; CHAFF/KEEPALIVE are no-ops.
            PacketType.CHAFF, PacketType.KEEPALIVE -> Unit
            PacketType.REKEY_INIT -> rekey.handleInit(inner.payload)
            // handleAck rebinds the UDP port via onRekeyComplete on success.
            PacketType.REKEY_ACK -> rekey.handleAck(inner.payload)
            PacketType.SESSION_CLOSE -> signalTeardown()
            PacketType.FRAGMENT ->
                // Reassembly is paired with the (still-deferred) sender-side
                // fragmenter; until then the sender never fragments, so a
                // FRAGMENT here is unexpected and dropped rather than mishandled.
                log("FRAGMENT received but reassembly is deferred; dropping")
            // Server-egress return-routability — the client never commits egress,
            // so PATH_* are no-ops on this side (mirrors _handle_noop / Python
            // client never receiving a PATH_RESPONSE).
            PacketType.PATH_CHALLENGE, PacketType.PATH_RESPONSE -> Unit
            PacketType.HANDSHAKE -> Unit
        }
    }

    // ── Liveness ──────────────────────────────────────────────────────────

    /**
     * One liveness check: expire grace keys, tear down on dead-peer timeout, and
     * emit a KEEPALIVE on real-send idle. Mirrors one pass of `liveness_loop`
     * plus the recv-timeout `session_keys.tick()` (here on the liveness cadence).
     */
    fun tickLiveness() {
        crypto.tick()
        val now = clock.nowMillis()

        val recvIdle = now - liveness.lastRecvMs
        if (recvIdle > DEAD_PEER_TIMEOUT_MS) {
            log("dead peer: no packets received for ${recvIdle}ms, tearing down session")
            signalTeardown()
            return
        }

        // M-BUG-15: trigger on real-data idleness, not all-send idleness, so
        // (future) chaff cannot suppress the fixed-cadence keepalive.
        if (now - liveness.lastRealSendMs > KEEPALIVE_SEND_INTERVAL_MS) {
            sendInner(InnerPacket(PacketType.KEEPALIVE, crypto.epoch() and 0x0F, EMPTY))
            liveness.lastRealSendMs = now
        }
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────

    /**
     * Spawn the recv / outbound / liveness loops (and, in the paced path, the
     * pacer loop). Idempotent; non-blocking.
     */
    fun start() {
        if (!running.compareAndSet(false, true)) return
        val loops = mutableListOf(
            Thread(::recvLoop, "dsm-recv"),
            Thread(::outboundLoop, "dsm-tun-send"),
            Thread(::livenessLoop, "dsm-liveness"),
        )
        if (scheduler != null) loops.add(Thread(::pacerLoop, "dsm-pacer"))
        threads = loops
        threads.forEach { it.isDaemon = true; it.start() }
    }

    /**
     * Block until any loop signals teardown, then finalize (best-effort
     * SESSION_CLOSE, close transport+TUN, join loops, [onTeardown]). Intended to
     * be called by the VPN worker thread after [start].
     */
    fun awaitAndFinalize() {
        try {
            shutdownLatch.await()
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
        }
        finalizeSession()
    }

    /** Request a clean shutdown from another thread (VPN stop / onDestroy). */
    fun requestShutdown() {
        signalTeardown()
    }

    /** True once any loop has signalled teardown (dead peer, close, rekey give-up). */
    fun isShuttingDown(): Boolean = shutdown.get()

    private fun signalTeardown() {
        shutdown.set(true)
        shutdownLatch.countDown()
    }

    private fun finalizeSession() {
        if (!finalized.compareAndSet(false, true)) return
        // Notify the peer first (best-effort) so it sees a fast graceful close
        // rather than waiting out DEAD_PEER_TIMEOUT. Must precede the transport
        // close. Sent DIRECTLY (not via the paced queue) so it leaves before the
        // transport tears down — mirrors send_session_close bypassing the
        // scheduler (session.py:796).
        runCatching {
            val padded = shaper.shapeInner(
                InnerPacket(PacketType.SESSION_CLOSE, crypto.epoch() and 0x0F, EMPTY).serialize(),
            )
            transmit(padded)
        }
        // Closing the channel/TUN unblocks the recv/outbound loops' blocking I/O.
        runCatching { channel.close() }
        runCatching { tun.close() }
        val joiners = threads
        joiners.forEach { it.interrupt() }
        joiners.forEach { runCatching { it.join(THREAD_JOIN_TIMEOUT_MS) } }
        running.set(false)
        runCatching { onTeardown() }
    }

    private fun recvLoop() {
        try {
            while (!shutdown.get()) {
                val data = try {
                    channel.recv()
                } catch (e: Exception) {
                    if (!shutdown.get()) {
                        log("transport recv error: ${e.message}")
                        signalTeardown()
                    }
                    return
                }
                pumpInbound(data)
            }
        } finally {
            signalTeardown()
        }
    }

    private fun outboundLoop() {
        try {
            while (!shutdown.get()) {
                val produced = try {
                    runOutboundOnce()
                } catch (e: Exception) {
                    if (!shutdown.get()) {
                        log("outbound loop error: ${e.message}")
                        signalTeardown()
                    }
                    return
                }
                if (!produced && shutdown.get()) return
            }
        } finally {
            signalTeardown()
        }
    }

    private fun livenessLoop() {
        try {
            while (!shutdown.get()) {
                // Wake early on shutdown; otherwise wake on the check cadence.
                if (shutdownLatch.await(LIVENESS_CHECK_INTERVAL_MS, TimeUnit.MILLISECONDS)) return
                tickLiveness()
            }
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
        } finally {
            signalTeardown()
        }
    }

    /**
     * Paced-send loop (only when a [scheduler] is present). Wakes every jittered
     * poll interval and runs one envelope [SendScheduler.tick] — draining due
     * real packets and filling the rest of the wire budget with chaff. Mirrors
     * `SendScheduler._run` (scheduler.py:133). Kept alive on a tick error
     * (DSM-002) so chaff never silently stops.
     */
    private fun pacerLoop() {
        val sch = scheduler ?: return
        try {
            while (!shutdown.get()) {
                if (shutdownLatch.await(sch.pollJitterMs(), TimeUnit.MILLISECONDS)) return
                try {
                    sch.tick()
                } catch (e: Exception) {
                    if (!shutdown.get()) log("pacer tick error: ${e.message}")
                }
            }
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
        } finally {
            signalTeardown()
        }
    }

    private class Liveness(now: Long) {
        @Volatile var lastRecvMs = now
        @Volatile var lastRealSendMs = now
    }

    companion object {
        /** Emit KEEPALIVE after this much real-send idle. `KEEPALIVE_SEND_INTERVAL`. */
        const val KEEPALIVE_SEND_INTERVAL_MS = 15_000L

        /** Tear down after this much recv idle. `DEAD_PEER_TIMEOUT`. */
        const val DEAD_PEER_TIMEOUT_MS = 60_000L

        /** Liveness wake cadence. `LIVENESS_CHECK_INTERVAL`. */
        const val LIVENESS_CHECK_INTERVAL_MS = 5_000L

        private const val THREAD_JOIN_TIMEOUT_MS = 2_000L

        private val EMPTY = ByteArray(0)

        // CHAFF / REKEY_ACK / PATH_* are exempt from the inner epoch-nibble check.
        private val EPOCH_EXEMPT = setOf(
            PacketType.CHAFF,
            PacketType.REKEY_ACK,
            PacketType.PATH_CHALLENGE,
            PacketType.PATH_RESPONSE,
        )
    }
}
