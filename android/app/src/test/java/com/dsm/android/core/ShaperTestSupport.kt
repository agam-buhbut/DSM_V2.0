package com.dsm.android.core

import java.util.Random

/**
 * Deterministic [ShaperRandom] for host-JVM tests: a seeded [java.util.Random]
 * stream. NOT for production (that MUST use [SecureShaperRandom]) — here it only
 * gives reproducible size-class / jitter / chaff draws so the distribution and
 * pacing assertions are non-flaky.
 */
class SeededShaperRandom(seed: Long) : ShaperRandom {
    private val r = Random(seed)
    override fun nextUnitFloat(): Double = r.nextDouble()
    override fun nextInt(bound: Int): Int = r.nextInt(bound)
    override fun nextBytes(dst: ByteArray) = r.nextBytes(dst)
}

/**
 * Scripted [ShaperRandom]: [nextUnitFloat] replays [floats] in order and then
 * repeats the last value; [nextInt] returns 0 and [nextBytes] zero-fills. Lets a
 * test pin the per-session idle-floor draw (draw #0 at construction) and each
 * subsequent jitter draw so packet reordering is exactly controlled.
 */
class ScriptedShaperRandom(private val floats: DoubleArray) : ShaperRandom {
    private var i = 0
    override fun nextUnitFloat(): Double {
        val v = floats[minOf(i, floats.size - 1)]
        i++
        return v
    }

    override fun nextInt(bound: Int): Int = 0
    override fun nextBytes(dst: ByteArray) {
        // Deterministic zero fill — contents are irrelevant to reordering tests.
    }
}
