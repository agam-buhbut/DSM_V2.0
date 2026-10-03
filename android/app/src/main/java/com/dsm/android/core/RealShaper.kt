package com.dsm.android.core

import java.security.SecureRandom
import kotlin.math.pow

/**
 * CSPRNG surface the shaper draws from. Abstracted so the size-class sampling,
 * jitter, chaff, and the per-session idle-floor draw are deterministic under an
 * injected seed in host-JVM tests while production uses a real
 * [java.security.SecureRandom].
 *
 * Anonymity-critical: production MUST use a CSPRNG (never `java.util.Random`)
 * so a passive observer cannot predict padding / jitter / chaff and thereby
 * strip the shaping.
 */
interface ShaperRandom {
    /** Uniform double in `[0.0, 1.0)`. Mirrors `dsm.core.rand.csprng_float`. */
    fun nextUnitFloat(): Double

    /** Uniform int in `[0, bound)`; `bound` must be > 0. Mirrors `secrets.randbelow`. */
    fun nextInt(bound: Int): Int

    /** Fill [dst] with random bytes (packet padding). Mirrors `os.urandom`. */
    fun nextBytes(dst: ByteArray)
}

/** Production [ShaperRandom] backed by a thread-safe [SecureRandom]. */
class SecureShaperRandom(private val rng: SecureRandom = SecureRandom()) : ShaperRandom {
    override fun nextUnitFloat(): Double = rng.nextDouble()
    override fun nextInt(bound: Int): Int = rng.nextInt(bound)
    override fun nextBytes(dst: ByteArray) = rng.nextBytes(dst)
}

/**
 * Faithful Kotlin port of `dsm/traffic/shaper.py`'s `TrafficShaper` — the
 * anonymity shaper's padding + adaptive-envelope + chaff engine.
 *
 * WIRE PARITY (anonymity-critical). Every value below is copied verbatim from
 * the Python source of truth so the Android client's wire behavior is
 * indistinguishable from the desktop client's:
 *
 *  * [SIZE_CLASSES] / [SIZE_CLASS_WEIGHTS] — the FIXED published size prior
 *    (`dsm/core/protocol.py:34,40`). Both real and chaff packets pad to a class
 *    drawn from this prior (renormalized over the active `[paddingMin,
 *    paddingMax]` / ceiling subset), so the aggregate wire-size histogram trends
 *    to the fleet-wide prior rather than the user's app profile.
 *  * The envelope constants (`dsm/core/config.py:115-130`, mirrored in
 *    `shaper.py:79-86`): idle floor 0.5-2 pps (drawn once per session), 600 pps
 *    ceiling, x2/s rise cap, 4 s fall half-life, 1000 ms latency budget.
 *
 * PADDING LAYER. [shapeInner] pads the serialized INNER plaintext (inside the
 * AEAD envelope) up to `target_outer - OUTER_HEADER - GCM_TAG` bytes, exactly as
 * Python's `_serialize_padded` (shaper.py:315). After AEAD (+16 tag) and outer
 * framing (+20 header) the wire packet lands on the sampled size class — the
 * same layer, the same distribution as the Python client.
 *
 * THREADING. The envelope fields (envelopePps etc.) are advanced only by the
 * pacer thread via [updateEnvelope]/[releaseBudget]; [shapeInner] (producer
 * thread) and [makeChaffPadded] (pacer thread) touch only the immutable sampling
 * tables and the thread-safe [random].
 */
class RealShaper(
    private val random: ShaperRandom = SecureShaperRandom(),
    private val paddingMin: Int = 128,
    private val paddingMax: Int = 1400,
    private val jitterMsMin: Int = 1,
    private val jitterMsMax: Int = 100,
    envelopeIdleFloorMinPps: Double = 0.5,
    envelopeIdleFloorMaxPps: Double = 2.0,
    envelopeCeilingPps: Double = 600.0,
    envelopeRisePerS: Double = 2.0,
    envelopeFallHalfLifeS: Double = 4.0,
    envelopeLatencyBudgetMs: Int = 1000,
) : PacingShaper {

    // Active size classes = published classes within [paddingMin, paddingMax].
    private val activeClasses: IntArray = filterClasses(paddingMin, paddingMax)

    // Precomputed ascending cumulative weights (sum 1.0) over [activeClasses],
    // for an allocation-free single-scan sample in [sampleSizeClassIndex].
    private val sizePriorCumulative: DoubleArray = buildSizePriorCumulative()

    // ── Adaptive envelope state (pacer-thread-only) ──────────────────────────
    private val ceilingPps = envelopeCeilingPps
    private val risePerS = envelopeRisePerS
    private val fallHalfLifeS = envelopeFallHalfLifeS
    private val latencyBudgetS = envelopeLatencyBudgetMs / 1000.0

    // Per-session randomized idle floor (Fork 4): drawn ONCE and fixed for the
    // session lifetime — re-drawing would itself be a time-varying signal.
    private val idleFloorPps =
        envelopeIdleFloorMinPps +
            random.nextUnitFloat() * (envelopeIdleFloorMaxPps - envelopeIdleFloorMinPps)

    private var envelopePps = idleFloorPps
    private var lastEnvTimeMs: Long? = null
    private var lastReleaseTimeMs: Long? = null
    private var releaseCredit = 0.0
    private var deadlinePending = false

    // ── Size-class sampling ──────────────────────────────────────────────────

    private fun filterClasses(min: Int, max: Int): IntArray {
        val kept = SIZE_CLASSES.filter { it in min..max }
        if (kept.isNotEmpty()) return kept.toIntArray()
        // padding_min may exceed the largest class while still passing config's
        // <=1500 check — keep the smallest class >= min, else the largest.
        val candidates = SIZE_CLASSES.filter { it >= min }
        return intArrayOf(if (candidates.isNotEmpty()) candidates.first() else SIZE_CLASSES.last())
    }

    private fun buildSizePriorCumulative(): DoubleArray {
        // activeClasses is a subset of SIZE_CLASSES, so index the weights by the
        // class's position in the fixed prior (no map build needed).
        val weights = activeClasses.map { cls ->
            val i = SIZE_CLASSES.indexOf(cls)
            (if (i >= 0) SIZE_CLASS_WEIGHTS[i] else 1).toDouble()
        }
        var total = weights.sum()
        val effective = if (total <= 0.0) {
            total = activeClasses.size.toDouble()
            List(activeClasses.size) { 1.0 }
        } else {
            weights
        }
        val cumulative = DoubleArray(effective.size)
        var running = 0.0
        for (i in effective.indices) {
            running += effective[i] / total
            cumulative[i] = running
        }
        return cumulative
    }

    /** One CSPRNG draw + cumulative scan over the FIXED prior. Returns the index. */
    private fun sampleSizeClassIndex(): Int {
        val r = random.nextUnitFloat()
        for (i in sizePriorCumulative.indices) {
            if (r < sizePriorCumulative[i]) return i
        }
        return activeClasses.size - 1
    }

    /**
     * Chaff wire class = fixed-prior draw + a ±1-class perturbation (Fork 6):
     * up with prob [CHAFF_PERTURB_UP_P], down within the next slice, else
     * unchanged (clamped at the active-set boundaries). Real packets draw from
     * the SAME prior but WITHOUT this perturbation.
     */
    private fun sampleChaffWireClassIndex(): Int {
        val idx = sampleSizeClassIndex()
        val r = random.nextUnitFloat()
        return when {
            r < CHAFF_PERTURB_UP_P -> if (idx + 1 < activeClasses.size) idx + 1 else idx
            r < CHAFF_PERTURB_DOWN_P -> if (idx > 0) idx - 1 else idx
            else -> idx
        }
    }

    // ── Padding ──────────────────────────────────────────────────────────────

    /**
     * Pad a REAL serialized inner packet up to a fixed-prior size class.
     *
     * Mirrors `TrafficShaper.pad_packet` + `_serialize_padded` (shaper.py:267,
     * 315): draw the target class from the fixed prior (no chaff perturbation),
     * bump it UP to the smallest class that fits the payload, then append random
     * inner padding so the post-AEAD wire size equals that class. Stateless —
     * the chosen class is never fed back, so the real-traffic size histogram
     * cannot collapse onto one dominant class (H-ANON).
     */
    override fun shapeInner(innerBytes: ByteArray): ByteArray =
        serializePadded(innerBytes, sampleSizeClassIndex())

    private fun serializePadded(serialized: ByteArray, startIdx: Int): ByteArray {
        val serializedLen = serialized.size
        var idx = startIdx
        var targetOuter = activeClasses[idx]
        val minOuter = OUTER_HEADER_SIZE + serializedLen + GCM_TAG_SIZE
        while (targetOuter < minOuter) {
            if (idx + 1 < activeClasses.size) {
                idx += 1
                targetOuter = activeClasses[idx]
            } else {
                targetOuter = minOuter // "can't pad down" floor
                break
            }
        }
        return padTo(serialized, targetOuter)
    }

    private fun padTo(serialized: ByteArray, targetOuter: Int): ByteArray {
        val targetCt = targetOuter - OUTER_HEADER_SIZE
        val innerPadLen = maxOf(0, targetCt - GCM_TAG_SIZE - serialized.size)
        if (innerPadLen == 0) return serialized
        val buf = ByteArray(serialized.size + innerPadLen)
        System.arraycopy(serialized, 0, buf, 0, serialized.size)
        val pad = ByteArray(innerPadLen)
        random.nextBytes(pad)
        System.arraycopy(pad, 0, buf, serialized.size, innerPadLen)
        return buf
    }

    // ── Chaff ──────────────────────────────────────────────────────────────

    /**
     * Build a padded CHAFF packet with a SINGLE fixed-prior size draw.
     *
     * Mirrors `make_chaff_padded` (shaper.py:469): draw the wire class once
     * (fixed prior + ±1 perturbation), pick the payload length uniformly within
     * that class's plaintext budget (M-ANON-8 — so the chaff's inner_length
     * matches real DATA's variable length), and pad to the drawn class. A chaff
     * packet is therefore wire-indistinguishable from a real one: same class
     * set, same-shape length field, random contents inside the AEAD envelope.
     */
    override fun makeChaffPadded(epochId: Int): ByteArray {
        val sizeClass = activeClasses[sampleChaffWireClassIndex()]
        val maxPayload =
            maxOf(0, sizeClass - OUTER_HEADER_SIZE - GCM_TAG_SIZE - INNER_HEADER_SIZE)
        val payloadLen = if (maxPayload > 0) random.nextInt(maxPayload + 1) else 0
        val payload = ByteArray(payloadLen)
        random.nextBytes(payload)
        val serialized = InnerPacket(PacketType.CHAFF, epochId and 0x0F, payload).serialize()
        return padTo(serialized, sizeClass)
    }

    // ── Jitter ──────────────────────────────────────────────────────────────

    /**
     * Per-packet send jitter in ms, uniform `[jitterMsMin, jitterMsMax)`.
     * Mirrors `SendScheduler.enqueue`'s jitter draw (scheduler.py:110). The
     * spread reorders adjacent packets within the window, breaking the
     * enqueue-order timing signature.
     */
    override fun jitterDelayMs(): Long {
        val span = jitterMsMax - jitterMsMin
        if (span <= 0) return jitterMsMin.toLong()
        return (jitterMsMin + random.nextUnitFloat() * span).toLong()
    }

    /**
     * Inter-tick poll cadence in ms, uniform `[30, 70)`. Mirrors
     * `_POLL_JITTER_MIN`/`_POLL_JITTER_RANGE` (scheduler.py:35): a fixed cadence
     * would fingerprint the scheduler on the wire.
     */
    override fun pollJitterMs(): Long =
        (POLL_JITTER_MIN_MS + random.nextUnitFloat() * POLL_JITTER_RANGE_MS).toLong()

    // ── Adaptive envelope ────────────────────────────────────────────────────

    /**
     * Advance the paced wire-rate envelope one tick. Mirrors
     * `TrafficShaper.update_envelope` (shaper.py:353) exactly, in ms:
     *
     *  * budget override (age-based) fires even on the cold-start tick;
     *  * a zero/negative dt does NOT move the envelope (no sub-tick snap);
     *  * idle → exponential decay toward the per-session floor (half-life);
     *  * backlog → multiplicative rise capped at [risePerS]/s and [ceilingPps].
     */
    override fun updateEnvelope(nowMs: Long, realQueueDepth: Int, oldestRealAgeMs: Long) {
        val oldestAgeS = oldestRealAgeMs / 1000.0
        if (realQueueDepth > 0 && oldestAgeS >= latencyBudgetS) {
            val desired = realQueueDepth / latencyBudgetS
            envelopePps = maxOf(envelopePps, desired)
            deadlinePending = true
            lastEnvTimeMs = nowMs
            return
        }
        val last = lastEnvTimeMs
        if (last == null) {
            lastEnvTimeMs = nowMs
            return
        }
        val dtS = (nowMs - last) / 1000.0
        if (dtS <= 0.0) return
        lastEnvTimeMs = nowMs
        if (realQueueDepth <= 0) {
            val decay = 0.5.pow(dtS / fallHalfLifeS)
            envelopePps = idleFloorPps + (envelopePps - idleFloorPps) * decay
            return
        }
        val desired = realQueueDepth / latencyBudgetS
        val maxRise = risePerS.pow(dtS)
        val target = minOf(desired, envelopePps * maxRise, ceilingPps)
        envelopePps = maxOf(envelopePps, target)
    }

    /**
     * Packets the scheduler may emit this tick. Mirrors
     * `TrafficShaper.release_budget` (shaper.py:417): fractional-packet credit
     * avoids low-rate rounding bias; a budget-breached backlog releases at least
     * one packet even on a cold-start tick. MUST be called exactly once per
     * [updateEnvelope] tick — it advances the release clock.
     */
    override fun releaseBudget(nowMs: Long): Int {
        val deadline = deadlinePending
        deadlinePending = false
        val last = lastReleaseTimeMs
        if (last == null) {
            lastReleaseTimeMs = nowMs
            return if (deadline) 1 else 0
        }
        val dtS = (nowMs - last) / 1000.0
        if (dtS <= 0.0) return if (deadline) 1 else 0
        lastReleaseTimeMs = nowMs
        releaseCredit += envelopePps * dtS
        val n = releaseCredit.toInt() // floor for the non-negative credit
        releaseCredit -= n
        return if (deadline) maxOf(n, 1) else n
    }

    companion object {
        // Copied verbatim from dsm/core/protocol.py:25-40.
        const val OUTER_HEADER_SIZE = 20
        const val INNER_HEADER_SIZE = 4
        const val GCM_TAG_SIZE = 16

        /** Fixed published padding size classes. `dsm/core/protocol.py:34`. */
        val SIZE_CLASSES = intArrayOf(
            128, 256, 384, 512, 640, 768, 896, 1024, 1152, 1280, 1400,
        )

        /** Fixed published sampling prior for [SIZE_CLASSES]. `protocol.py:40`. */
        val SIZE_CLASS_WEIGHTS = intArrayOf(20, 15, 12, 10, 8, 7, 6, 6, 5, 6, 5)

        // Chaff ±1-class perturbation probabilities. `shaper.py:93-94`.
        const val CHAFF_PERTURB_UP_P = 0.15
        const val CHAFF_PERTURB_DOWN_P = 0.30

        // Poll cadence 30-70 ms. `scheduler.py:35-36`.
        const val POLL_JITTER_MIN_MS = 30.0
        const val POLL_JITTER_RANGE_MS = 40.0
    }
}
