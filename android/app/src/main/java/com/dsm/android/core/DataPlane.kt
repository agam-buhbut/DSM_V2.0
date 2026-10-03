package com.dsm.android.core

/**
 * One IP packet at a time over the TUN device. Abstracted so [SessionRunner] is
 * host-JVM testable with an in-memory fake; the real implementation
 * ([FileTunIo]) wraps the VpnService [android.os.ParcelFileDescriptor] streams.
 */
interface TunIo {
    /** Read one IP packet (blocking). Returns null on EOF / closed device. */
    fun read(): ByteArray?

    /** Write one IP packet to the TUN. */
    fun write(packet: ByteArray)

    fun close()
}

/**
 * Monotonic clock in milliseconds. Injectable so liveness / rekey timing is
 * deterministic in tests (no `Thread.sleep`, no wall-clock dependence).
 */
fun interface MonotonicClock {
    fun nowMillis(): Long

    companion object {
        val SYSTEM = MonotonicClock { System.nanoTime() / 1_000_000L }
    }
}

/**
 * Anonymity-shaper seam — the per-packet padding transform.
 *
 * The Python client (`dsm/traffic/scheduler.py` + `dsm/traffic/shaper.py`)
 * shapes every outbound inner packet before AEAD: size-class padding to a fixed
 * published prior (up to 1400 B), per-packet jitter, the adaptive-envelope chaff
 * idle floor, and packet reordering. [shapeInner] is the padding half of that;
 * the pacing half (jitter / envelope / chaff / reordering) lives in
 * [PacingShaper] + [SendScheduler], driven by [SessionRunner].
 *
 * [RealShaper] (Task B3b) is the full-parity implementation and is the default
 * in `DsmVpnService`. [NullShaper] remains a pass-through for tests that
 * exercise the non-shaping data-loop logic (framing / replay / rekey / liveness)
 * — with it the loop sends directly, without a paced queue.
 */
interface Shaper {
    /**
     * Transform a serialized inner-packet plaintext prior to AEAD. The result is
     * what gets encrypted; [RealShaper] appends size-class inner padding here so
     * the post-AEAD wire size lands on a published size class.
     */
    fun shapeInner(innerBytes: ByteArray): ByteArray
}

/**
 * A [Shaper] that also drives the paced send loop: per-packet jitter, the
 * adaptive wire-rate envelope (rise/fall/idle-floor/ceiling), and chaff
 * generation. When [SessionRunner] is given a [PacingShaper] it runs the
 * [SendScheduler] paced path (real-then-chaff fill); otherwise it sends directly.
 *
 * All timings are in milliseconds (the Kotlin [MonotonicClock] granularity);
 * the underlying rate constants (pps, half-life) are per second, converted
 * internally. Mirrors the split of `dsm/traffic/shaper.py::TrafficShaper`
 * (this interface) and `scheduler.py::SendScheduler` ([SendScheduler]).
 */
interface PacingShaper : Shaper {
    /** Build a padded CHAFF packet (single fixed-prior draw). `make_chaff_padded`. */
    fun makeChaffPadded(epochId: Int): ByteArray

    /** Per-packet send jitter in ms, uniform `[jitterMsMin, jitterMsMax)`. */
    fun jitterDelayMs(): Long

    /** Inter-tick poll cadence in ms, uniform `[30, 70)`. */
    fun pollJitterMs(): Long

    /** Advance the paced wire-rate envelope one tick. `update_envelope`. */
    fun updateEnvelope(nowMs: Long, realQueueDepth: Int, oldestRealAgeMs: Long)

    /** Packets the scheduler may emit this tick. `release_budget`. */
    fun releaseBudget(nowMs: Long): Int
}

/** Pass-through shaper: no padding, jitter, chaff, or reordering (see [Shaper]). */
object NullShaper : Shaper {
    override fun shapeInner(innerBytes: ByteArray): ByteArray = innerBytes
}
