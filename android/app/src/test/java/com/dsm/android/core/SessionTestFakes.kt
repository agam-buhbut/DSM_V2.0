package com.dsm.android.core

import java.net.SocketException
import java.security.MessageDigest
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.atomic.AtomicInteger

/**
 * Deterministic fakes for the data-loop tests. The native FFI cannot be loaded
 * in a host `testDebugUnitTest` (the x86_64 `.so` is an Android/bionic build),
 * so these substitute at the [SessionCrypto] / [ReplayGate] / [TunIo] /
 * [TransportChannel] boundaries — the same fake-at-the-boundary pattern the
 * handshake tests use ([ClientCore] / `FakeClientCore`).
 */

/** Injectable monotonic clock. */
class FakeClock(var now: Long = 0L) : MonotonicClock {
    override fun nowMillis(): Long = now
    fun advance(ms: Long) {
        now += ms
    }
}

/**
 * A faithful-enough paired AEAD fake. Both endpoints share the same integrity
 * transform (a SHA-256 tag over `epoch ‖ aad ‖ plaintext`), so a roundtrip
 * verifies, a tampered byte or wrong AAD fails (forgery → null), and the epoch
 * is carried so current-vs-grace decryption can be exercised. The two-phase
 * rotation mirrors the UniFFI preconditions (responder requires
 * `new_epoch == epoch + 1`; only one pending initiator rotation at a time).
 *
 * It deliberately does NOT model directional key separation — irrelevant to the
 * loop logic under test, which is what [SessionRunner] drives.
 */
class FakeSessionCrypto(@Suppress("UNUSED_PARAMETER") name: String = "ep") : SessionCrypto {
    private var epochVal = 0
    private var graceEpoch: Int? = null
    private var pendingInit: Int? = null
    private var pendingResp: Int? = null

    /** Test toggle for [needsRotation]. */
    var rotateDue = false

    @Synchronized
    override fun encrypt(plaintext: ByteArray, aad: ByteArray): EncryptOut {
        val ct = ByteArray(1 + TAG_LEN + plaintext.size)
        ct[0] = epochVal.toByte()
        System.arraycopy(macOf(epochVal, aad, plaintext), 0, ct, 1, TAG_LEN)
        System.arraycopy(plaintext, 0, ct, 1 + TAG_LEN, plaintext.size)
        val nonce = ByteArray(12).also { it[0] = epochVal.toByte() }
        return EncryptOut(nonce, ct, epochVal)
    }

    @Synchronized
    override fun tryDecryptWithFallback(
        nonce: ByteArray,
        ciphertext: ByteArray,
        aad: ByteArray,
        seq: Long,
    ): DecryptOut? {
        if (ciphertext.size < 1 + TAG_LEN) return null
        val ctEpoch = ciphertext[0].toInt() and 0xFF
        val mac = ciphertext.copyOfRange(1, 1 + TAG_LEN)
        val pt = ciphertext.copyOfRange(1 + TAG_LEN, ciphertext.size)
        if (!MessageDigest.isEqual(mac, macOf(ctEpoch, aad, pt))) return null // forgery
        return when (ctEpoch) {
            epochVal -> DecryptOut(pt, false)
            graceEpoch -> DecryptOut(pt, true)
            else -> null
        }
    }

    @Synchronized override fun needsRotation(): Boolean = rotateDue

    @Synchronized
    override fun initiateRotation(): RotationInit {
        check(pendingInit == null) { "rotation already in progress" }
        val newEpoch = epochVal + 1
        pendingInit = newEpoch
        return RotationInit(newEpoch, encodeEph(newEpoch))
    }

    @Synchronized
    override fun completeRotationInitiator(remoteEphemeralPub: ByteArray): Int {
        val p = pendingInit ?: error("no pending rotation")
        require(remoteEphemeralPub.size == 32) { "bad ephemeral pub" }
        graceEpoch = epochVal
        epochVal = p
        pendingInit = null
        rotateDue = false
        return epochVal
    }

    @Synchronized
    override fun prepareRotationResponder(
        remoteEphemeralPub: ByteArray,
        newEpoch: Int,
    ): RotationResponder {
        require(newEpoch == epochVal + 1) { "responder rotation must be epoch+1" }
        pendingResp = newEpoch
        return RotationResponder(encodeEph(newEpoch), newEpoch)
    }

    @Synchronized
    override fun applyRotationResponder(): Int {
        val pr = pendingResp ?: error("no prepared responder rotation")
        graceEpoch = epochVal
        epochVal = pr
        pendingResp = null
        rotateDue = false
        return epochVal
    }

    @Synchronized
    override fun abortRotation(): Boolean {
        val had = pendingInit != null
        pendingInit = null
        return had
    }

    /** Clear the grace key — call to simulate the grace window expiring. */
    @Synchronized override fun tick() {
        graceEpoch = null
    }

    @Synchronized override fun epoch(): Int = epochVal

    // Shared across both paired endpoints (no per-instance key) so each can
    // decrypt the other's packets — modelling real DSM's shared directional
    // keys. Still binds epoch + aad(seq) + plaintext, so a tampered byte or a
    // wrong-epoch packet fails to "decrypt" (returns null).
    private fun macOf(epoch: Int, aad: ByteArray, pt: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        md.update(epoch.toByte())
        md.update(aad)
        md.update(pt)
        return md.digest().copyOf(TAG_LEN)
    }

    private fun encodeEph(epoch: Int): ByteArray =
        ByteArray(32).also {
            it[0] = ((epoch ushr 24) and 0xFF).toByte()
            it[1] = ((epoch ushr 16) and 0xFF).toByte()
            it[2] = ((epoch ushr 8) and 0xFF).toByte()
            it[3] = (epoch and 0xFF).toByte()
        }

    private companion object {
        const val TAG_LEN = 8
    }
}

/** Minimal monotonic sliding replay window mirroring the loop's check/update use. */
class FakeReplayGate(private val window: Long = 1024) : ReplayGate {
    private val seen = HashSet<Long>()
    private var maxSeq = 0L

    @Synchronized
    override fun check(seq: Long): Boolean {
        if (seq <= maxSeq - window) return false
        return seq !in seen
    }

    @Synchronized
    override fun update(seq: Long) {
        seen.add(seq)
        if (seq > maxSeq) maxSeq = seq
        seen.removeIf { it <= maxSeq - window }
    }
}

/**
 * In-memory TUN. [enqueueInbound] queues an IP packet for the loop to read;
 * [written] collects packets the loop delivered. [read] blocks until a packet or
 * [close] (returns null) so the threaded shutdown test parks cleanly.
 */
class FakeTunIo : TunIo {
    private val toRead = LinkedBlockingQueue<ByteArray>()
    val written = ConcurrentLinkedQueue<ByteArray>()

    @Volatile
    var closed = false
        private set

    fun enqueueInbound(packet: ByteArray) {
        toRead.add(packet)
    }

    override fun read(): ByteArray? {
        val p = toRead.take()
        if (p === POISON) return null
        return p
    }

    override fun write(packet: ByteArray) {
        written.add(packet)
    }

    override fun close() {
        closed = true
        toRead.add(POISON)
    }

    private companion object {
        val POISON = ByteArray(0)
    }
}

/**
 * Loopback [TransportChannel]. Frames sent are appended to [outbox] (drain it and
 * feed the peer's [SessionRunner.pumpInbound] in tests); [recv] blocks on [inbox]
 * (fed only the close poison here) so the threaded shutdown test parks cleanly.
 */
class LoopbackChannel : TransportChannel {
    val outbox = ConcurrentLinkedQueue<ByteArray>()
    private val inbox = LinkedBlockingQueue<ByteArray>()
    val rebindCount = AtomicInteger(0)

    @Volatile
    var closed = false
        private set

    override fun send(frame: ByteArray) {
        outbox.add(frame)
    }

    override fun recv(): ByteArray {
        val f = inbox.take()
        if (f === POISON) throw SocketException("channel closed")
        return f
    }

    override fun close() {
        closed = true
        inbox.add(POISON)
    }

    override fun rebindToFreshPort() {
        rebindCount.incrementAndGet()
    }

    /** Drain everything sent so far, in order. */
    fun drainOutbox(): List<ByteArray> {
        val out = ArrayList<ByteArray>()
        while (true) {
            out.add(outbox.poll() ?: break)
        }
        return out
    }

    private companion object {
        val POISON = ByteArray(0)
    }
}
