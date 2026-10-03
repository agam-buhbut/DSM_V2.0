package com.dsm.android.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Wire-parity tests for [RealShaper] — the Kotlin mirror of Python's
 * `TrafficShaper`. These pin the anonymity-critical invariants that the desktop
 * `tests/test_shaper.py` + `tests/test_adaptive_envelope.py` check, so a
 * divergence that would make the Android client's traffic distinguishable fails
 * here. All draws come from a seeded [ShaperRandom] so the distribution
 * assertions are deterministic.
 */
class RealShaperTest {

    private val classSet = RealShaper.SIZE_CLASSES.toHashSet()

    // wire size = padded inner plaintext + outer header (20) + GCM tag (16).
    private fun wireSize(paddedInner: ByteArray): Int =
        paddedInner.size + RealShaper.OUTER_HEADER_SIZE + RealShaper.GCM_TAG_SIZE

    private fun shaper(
        seed: Long = 1L,
        floor: Double = 1.0,
        ceiling: Double = 100.0,
        rise: Double = 2.0,
        halfLife: Double = 4.0,
        budgetMs: Int = 250,
    ) = RealShaper(
        random = SeededShaperRandom(seed),
        envelopeIdleFloorMinPps = floor,
        envelopeIdleFloorMaxPps = floor,
        envelopeCeilingPps = ceiling,
        envelopeRisePerS = rise,
        envelopeFallHalfLifeS = halfLife,
        envelopeLatencyBudgetMs = budgetMs,
    )

    // ── Size-class distribution ──────────────────────────────────────────────

    @Test
    fun realPacketSizeClassesFollowTheFixedPrior() {
        val s = shaper(seed = 123)
        val n = 40_000
        val counts = HashMap<Int, Int>()
        // Tiny payload fits every class, so no bump-up: the wire class equals the
        // prior draw and the histogram must reproduce SIZE_CLASS_WEIGHTS.
        val inner = InnerPacket(PacketType.DATA, 0, ByteArray(1)).serialize()
        repeat(n) {
            val wire = wireSize(s.shapeInner(inner))
            assertTrue("wire $wire not a size class", wire in classSet)
            assertTrue("wire $wire outside padding bounds", wire in 128..1400)
            counts[wire] = (counts[wire] ?: 0) + 1
        }
        val totalWeight = RealShaper.SIZE_CLASS_WEIGHTS.sum().toDouble()
        for (i in RealShaper.SIZE_CLASSES.indices) {
            val cls = RealShaper.SIZE_CLASSES[i]
            val expected = RealShaper.SIZE_CLASS_WEIGHTS[i] / totalWeight
            val actual = (counts[cls] ?: 0).toDouble() / n
            assertEquals("class $cls proportion off prior", expected, actual, 0.02)
        }
    }

    @Test
    fun paddingBoundsAreRespected() {
        // padding_min 256, padding_max 1024 -> only classes in [256, 1024].
        val s = RealShaper(
            random = SeededShaperRandom(9),
            paddingMin = 256,
            paddingMax = 1024,
            envelopeIdleFloorMinPps = 1.0,
            envelopeIdleFloorMaxPps = 1.0,
        )
        val inner = InnerPacket(PacketType.DATA, 0, ByteArray(1)).serialize()
        repeat(5_000) {
            val wire = wireSize(s.shapeInner(inner))
            assertTrue("wire $wire below padding_min", wire >= 256)
            assertTrue("wire $wire above padding_max", wire <= 1024)
            assertTrue(wire in classSet)
        }
    }

    // ── Padding ──────────────────────────────────────────────────────────────

    @Test
    fun padsUpNeverTruncatesAndKeepsPayloadPrefix() {
        val s = shaper(seed = 7)
        for (payloadLen in listOf(1, 37, 100, 300, 900)) {
            val serialized = InnerPacket(PacketType.DATA, 3, ByteArray(payloadLen) {
                (it and 0xFF).toByte()
            }).serialize()
            val minOuter = RealShaper.OUTER_HEADER_SIZE + serialized.size + RealShaper.GCM_TAG_SIZE
            repeat(50) {
                val padded = s.shapeInner(serialized)
                // Never truncated: the whole serialized packet is a byte-for-byte
                // prefix of the padded output.
                assertTrue("padded shorter than input", padded.size >= serialized.size)
                for (j in serialized.indices) {
                    assertEquals("payload byte $j altered", serialized[j], padded[j])
                }
                val wire = wireSize(padded)
                // Wire is a published class, or the "can't pad down" floor when
                // the payload exceeds the largest class.
                assertTrue("wire $wire below min_outer", wire >= minOuter)
                assertTrue("wire $wire neither a class nor min_outer",
                    wire in classSet || wire == minOuter)
            }
        }
    }

    @Test
    fun padBytesAreRandomNotConstant() {
        val s = shaper(seed = 44)
        val serialized = InnerPacket(PacketType.DATA, 0, ByteArray(50)).serialize()
        val bySize = HashMap<Int, MutableList<ByteArray>>()
        repeat(600) {
            val p = s.shapeInner(serialized)
            bySize.getOrPut(p.size) { mutableListOf() }.add(p)
        }
        // Pick a class that actually added padding and appeared at least twice;
        // its pad regions must differ (proving the pad is random, not zero/const).
        val group = bySize.values.first { it.size >= 2 && it[0].size > serialized.size }
        val tailA = group[0].copyOfRange(serialized.size, group[0].size)
        val tailB = group[1].copyOfRange(serialized.size, group[1].size)
        assertFalse("pad bytes identical across two packets", tailA.contentEquals(tailB))
    }

    // ── Chaff ────────────────────────────────────────────────────────────────

    @Test
    fun chaffWireSizesAreValidClassesWithVariableInnerLength() {
        val s = shaper(seed = 99)
        val counts = HashMap<Int, Int>()
        val innerLens = HashSet<Int>()
        repeat(20_000) {
            val padded = s.makeChaffPadded(0)
            val wire = wireSize(padded)
            assertTrue("chaff wire $wire not a size class", wire in classSet)
            assertTrue("chaff wire $wire outside bounds", wire in 128..1400)
            counts[wire] = (counts[wire] ?: 0) + 1
            val inner = InnerPacket.deserialize(padded)
            assertEquals(PacketType.CHAFF, inner.ptype)
            innerLens.add(inner.payload.size)
        }
        // Not collapsed onto one class; spans the prior (perturbed).
        assertTrue("chaff should span many classes", counts.size >= 6)
        // M-ANON-8: inner_length varies (never always == the class max), so it is
        // not a second distinguishing signal vs real DATA.
        assertTrue("chaff inner_length should vary", innerLens.size > 20)
    }

    @Test
    fun chaffAndRealDrawFromTheSameSizeClassSet() {
        val s = shaper(seed = 5)
        val realSizes = HashSet<Int>()
        val chaffSizes = HashSet<Int>()
        val innerReal = InnerPacket(PacketType.DATA, 0, ByteArray(1)).serialize()
        repeat(5_000) {
            realSizes.add(wireSize(s.shapeInner(innerReal)))
            chaffSizes.add(wireSize(s.makeChaffPadded(0)))
        }
        // Every chaff wire size is a class a real packet can also emit — so at
        // the size-class level a chaff packet is indistinguishable from a real
        // one (both draw from the same published prior).
        assertTrue(realSizes.all { it in classSet })
        assertTrue(chaffSizes.all { it in classSet })
        assertTrue("real should span the class set", realSizes.size >= 8)
        assertTrue("chaff should span the class set", chaffSizes.size >= 8)
    }

    // ── Jitter ───────────────────────────────────────────────────────────────

    @Test
    fun jitterDelaysStayWithinConfiguredRangeAndVary() {
        val s = RealShaper(
            random = SeededShaperRandom(42),
            jitterMsMin = 1,
            jitterMsMax = 100,
            envelopeIdleFloorMinPps = 1.0,
            envelopeIdleFloorMaxPps = 1.0,
        )
        val seen = HashSet<Long>()
        repeat(5_000) {
            val d = s.jitterDelayMs()
            assertTrue("jitter $d below min", d >= 1)
            assertTrue("jitter $d above max", d <= 100)
            seen.add(d)
        }
        // The spread is what induces reordering — it must actually vary.
        assertTrue("jitter should vary across the window", seen.size > 20)
    }

    // ── Adaptive envelope (ms clock; mirrors test_adaptive_envelope.py) ──────

    @Test
    fun idleReleaseTracksFloor() {
        val s = shaper(floor = 1.0)
        var released = 0L
        var now = 1_000L
        repeat(1_000) {
            now += 10
            s.updateEnvelope(now, 0, 0)
            released += s.releaseBudget(now)
        }
        // 1 pps over 10 s ≈ 10 packets.
        assertEquals(10.0, released.toDouble(), 2.0)
    }

    @Test
    fun burstOnsetIsSmearedNotStepped() {
        val s = shaper(floor = 1.0, budgetMs = 250)
        var depth = 200
        var released = 0
        var now = 1_000L
        repeat(10) { // 10 x 10 ms = 100 ms
            now += 10
            s.updateEnvelope(now, depth, 0)
            val n = s.releaseBudget(now)
            released += n
            depth = maxOf(0, depth - n)
        }
        assertTrue("onset not smeared: released $released", released < 50)
        assertTrue("drained too much: depth $depth", depth > 100)
    }

    @Test
    fun latencyBudgetOverridesRiseCap() {
        val s = shaper(budgetMs = 250)
        var now = 1_000L
        now += 300 // 300 ms > 250 ms budget
        s.updateEnvelope(now, 1, 300)
        assertTrue(s.releaseBudget(now) >= 1)
    }
}
