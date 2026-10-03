package com.dsm.android.core

import java.util.PriorityQueue

/**
 * Faithful Kotlin port of `dsm/traffic/scheduler.py`'s `SendScheduler`
 * envelope-driven path — the jittered priority queue + paced release that turns
 * a [PacingShaper]'s envelope into the actual wire cadence.
 *
 * Behavior mirrored exactly (anonymity-critical):
 *
 *  * [enqueue] stamps each packet with `sendTime = now + jitter` (jitter drawn
 *    from the shaper, uniform `[jitterMin, jitterMax)`), so adjacent packets can
 *    REORDER within the jitter window — the enqueue-order timing signature is
 *    broken. Ties in `sendTime` keep FIFO order (insertion tiebreak).
 *  * [tick] asks the shaper for this tick's wire budget and emits exactly that
 *    many packets: a REAL queued packet whose `sendTime` has arrived drains
 *    first, else CHAFF fills the slot (via [PacingShaper.makeChaffPadded]), else
 *    — when chaff is gated off — the slot is left unfilled. The envelope governs
 *    the COUNT (decoupling the wire rate from real volume); the per-packet
 *    jitter still governs intra-tick ordering.
 *  * The queue is bounded ([MAX_QUEUE_SIZE]); when full it drops the head, which
 *    is anonymity-safe because real/chaff are indistinguishable on the wire.
 *
 * Chaff rides the SAME [send] callback as real packets, so they pass through an
 * identical AEAD + framing + transport path and are indistinguishable on the
 * wire. This class holds no crypto or transport state — [send] is
 * [SessionRunner.transmit]. It is threadsafe: [enqueue] runs on the producer
 * (TUN / liveness / rekey) threads while [tick] runs on the pacer thread.
 *
 * Deterministic under an injected [clock] + a seeded [ShaperRandom] in the
 * shaper, so the pacing math and reordering are unit-tested without wall-clock
 * sleeps (see `SendSchedulerTest`).
 */
class SendScheduler(
    private val shaper: PacingShaper,
    private val send: (ByteArray) -> Unit,
    private val chaffEpoch: () -> Int,
    private val clock: MonotonicClock,
    private val chaffAllowed: () -> Boolean = { true },
    private val log: (String) -> Unit = {},
) {
    private class Scheduled(val sendTime: Long, val tiebreak: Long, val data: ByteArray)

    private val lock = Any()
    private val queue = PriorityQueue<Scheduled>(
        MAX_QUEUE_SIZE,
        compareBy({ it.sendTime }, { it.tiebreak }),
    )
    private var tiebreak = 0L

    /**
     * Enqueue an already-padded inner-plaintext packet with a per-packet jitter
     * delay. Mirrors `SendScheduler.enqueue` (scheduler.py:91).
     */
    fun enqueue(data: ByteArray) {
        val jitter = shaper.jitterDelayMs()
        val sendTime = clock.nowMillis() + jitter
        synchronized(lock) {
            if (queue.size >= MAX_QUEUE_SIZE) {
                queue.poll() // drop head (mirrors heapq drop on a full queue)
                log("scheduler queue full, dropping packet")
            }
            queue.add(Scheduled(sendTime, tiebreak++, data))
        }
    }

    /**
     * One paced tick: update the envelope from the current backlog, then emit
     * the envelope's budget as real-then-chaff. Mirrors `_envelope_tick`
     * (scheduler.py:183). Call once per poll cadence.
     */
    fun tick() {
        val now = clock.nowMillis()
        val depth: Int
        val oldestAgeMs: Long
        synchronized(lock) {
            depth = queue.size
            val head = queue.peek()
            oldestAgeMs =
                if (head != null && head.sendTime <= now) maxOf(0L, now - head.sendTime) else 0L
        }
        shaper.updateEnvelope(now, depth, oldestAgeMs)
        val budget = shaper.releaseBudget(now)
        val chaffOk = chaffAllowed()
        repeat(budget) {
            val due = synchronized(lock) {
                val head = queue.peek()
                if (head != null && head.sendTime <= now) queue.poll() else null
            }
            when {
                due != null -> send(due.data)
                chaffOk -> send(shaper.makeChaffPadded(chaffEpoch() and 0x0F))
                else -> return // no real due + chaff gated off: leave the budget unfilled
            }
        }
    }

    /** Jittered inter-tick poll interval in ms. */
    fun pollJitterMs(): Long = shaper.pollJitterMs()

    companion object {
        /**
         * Bounded queue. `MAX_QUEUE_SIZE` in scheduler.py:29 — sized for low-RAM
         * targets (512 * ~1500 B ≈ 768 KiB worst case).
         */
        const val MAX_QUEUE_SIZE = 512
    }
}
