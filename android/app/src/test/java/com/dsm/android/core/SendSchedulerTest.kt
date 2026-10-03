package com.dsm.android.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Paced-loop tests for [SendScheduler] — the Kotlin mirror of Python's
 * `SendScheduler` envelope path. Driven by a [FakeClock] + a seeded/scripted
 * [ShaperRandom] so jitter, reordering, the envelope-driven real-then-chaff
 * fill, and the idle chaff floor are asserted deterministically (no wall-clock
 * sleeps). The `send` callback here just collects the padded inner bytes the
 * scheduler would hand to [SessionRunner.transmit], so chaff and real packets
 * are inspected pre-AEAD.
 */
class SendSchedulerTest {

    private fun typeOf(paddedInner: ByteArray): PacketType =
        InnerPacket.deserialize(paddedInner).ptype

    @Test
    fun jitterReordersPacketsWithinTheWindow() {
        val clock = FakeClock(0)
        // Draw #0 (idle floor) is irrelevant (min==max). Draws #1/#2 are the
        // jitters for the two enqueues: 0.9 -> ~91 ms, 0.1 -> ~11 ms.
        val rng = ScriptedShaperRandom(doubleArrayOf(0.0, 0.9, 0.1))
        val shaper = RealShaper(
            random = rng,
            jitterMsMin = 1,
            jitterMsMax = 101,
            envelopeIdleFloorMinPps = 1_000.0,
            envelopeIdleFloorMaxPps = 1_000.0,
            envelopeCeilingPps = 1_000.0,
        )
        val sent = mutableListOf<ByteArray>()
        val sch = SendScheduler(
            shaper = shaper,
            send = { sent.add(it) },
            chaffEpoch = { 0 },
            clock = clock,
            chaffAllowed = { false }, // isolate ordering: no chaff noise
        )
        val a = byteArrayOf(0xAA.toByte())
        val b = byteArrayOf(0xBB.toByte())
        sch.enqueue(a) // sendTime ~91
        sch.enqueue(b) // sendTime ~11 -> should leave FIRST despite enqueuing second
        clock.now = 100 // both due
        sch.tick() // primes release/env clocks (budget 0)
        clock.now = 1_100 // +1 s -> ample budget
        sch.tick()
        assertEquals(2, sent.size)
        assertArrayEquals("later-jitter packet must send second", b, sent[0])
        assertArrayEquals(a, sent[1])
    }

    @Test
    fun idleChaffFillsBudgetAtFloorRate() {
        val clock = FakeClock(1_000)
        val shaper = RealShaper(
            random = SeededShaperRandom(11),
            envelopeIdleFloorMinPps = 5.0,
            envelopeIdleFloorMaxPps = 5.0,
            envelopeCeilingPps = 100.0,
        )
        val sent = mutableListOf<ByteArray>()
        val sch = SendScheduler(shaper, send = { sent.add(it) }, chaffEpoch = { 0 }, clock = clock)
        // Empty queue for 10 s at 10 ms ticks: chaff must fill at ~5 pps -> ~50.
        repeat(1_000) { clock.advance(10); sch.tick() }
        assertTrue("no chaff emitted while idle", sent.isNotEmpty())
        for (p in sent) assertEquals("idle fill must be chaff", PacketType.CHAFF, typeOf(p))
        assertEquals(50.0, sent.size.toDouble(), 12.0)
    }

    @Test
    fun realDrainsBeforeChaffFillsRemainingBudget() {
        val clock = FakeClock(1_000)
        val shaper = RealShaper(
            random = SeededShaperRandom(3),
            jitterMsMin = 0,
            jitterMsMax = 1, // ~0 ms jitter: packets due immediately
            envelopeIdleFloorMinPps = 100.0,
            envelopeIdleFloorMaxPps = 100.0,
            envelopeCeilingPps = 100.0,
        )
        val sent = mutableListOf<ByteArray>()
        val sch = SendScheduler(shaper, send = { sent.add(it) }, chaffEpoch = { 0 }, clock = clock)
        val real = InnerPacket(PacketType.DATA, 0, ByteArray(10)).serialize()
        repeat(3) { sch.enqueue(shaper.shapeInner(real)) }
        clock.advance(10)
        sch.tick() // prime
        clock.advance(100)
        sch.tick() // budget = 100 pps * 0.1 s = 10 -> 3 real + 7 chaff
        val types = sent.map { typeOf(it) }
        assertEquals("all 3 real packets must drain", 3, types.count { it == PacketType.DATA })
        assertTrue("chaff must fill the rest of the budget",
            types.count { it == PacketType.CHAFF } >= 1)
        // Real packets precede chaff within the tick.
        val lastData = types.lastIndexOf(PacketType.DATA)
        val firstChaff = types.indexOf(PacketType.CHAFF)
        assertTrue("real must drain before chaff fills", lastData < firstChaff)
    }

    @Test
    fun chaffGatedOffLeavesBudgetUnfilled() {
        val clock = FakeClock(1_000)
        val shaper = RealShaper(
            random = SeededShaperRandom(8),
            envelopeIdleFloorMinPps = 50.0,
            envelopeIdleFloorMaxPps = 50.0,
            envelopeCeilingPps = 100.0,
        )
        val sent = mutableListOf<ByteArray>()
        val sch = SendScheduler(
            shaper = shaper,
            send = { sent.add(it) },
            chaffEpoch = { 0 },
            clock = clock,
            chaffAllowed = { false }, // gate: e.g. server before client addr known
        )
        repeat(50) { clock.advance(10); sch.tick() }
        // Empty queue + chaff gated off: nothing leaves.
        assertTrue("no packets should leave when chaff is gated and queue empty", sent.isEmpty())
    }
}
