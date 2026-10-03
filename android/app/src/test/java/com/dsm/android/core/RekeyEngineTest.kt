package com.dsm.android.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RekeyEngineTest {

    private val clock = FakeClock()
    private val sent = mutableListOf<InnerPacket>()
    private var tornDown = false
    private var rekeyCompletes = 0

    private fun engine(
        crypto: SessionCrypto,
        state: RekeyState = RekeyState(),
        localPub: ByteArray = ByteArray(32) { 0x01 },
        remotePub: ByteArray = ByteArray(32) { 0x02 },
    ) = RekeyEngine(
        crypto = crypto,
        state = state,
        localStaticPub = localPub,
        remoteStaticPub = remotePub,
        clock = clock,
        sendInner = { sent += it },
        onTeardown = { tornDown = true },
        onRekeyComplete = { rekeyCompletes += 1 },
    )

    /** Build a REKEY_INIT/ACK payload: epoch(4 BE) ‖ ephemeral pub(32). */
    private fun rekeyPayload(epoch: Int, fill: Byte = 0x09): ByteArray {
        val buf = ByteArray(36)
        buf[0] = ((epoch ushr 24) and 0xFF).toByte()
        buf[1] = ((epoch ushr 16) and 0xFF).toByte()
        buf[2] = ((epoch ushr 8) and 0xFF).toByte()
        buf[3] = (epoch and 0xFF).toByte()
        for (i in 4 until 36) buf[i] = fill
        return buf
    }

    @Test
    fun initiateSendsRekeyInit() {
        val crypto = FakeSessionCrypto("c").apply { rotateDue = true }
        val state = RekeyState()
        engine(crypto, state).maybeInitiate()

        assertEquals(1, sent.size)
        assertEquals(PacketType.REKEY_INIT, sent[0].ptype)
        assertTrue(state.inProgress)
        assertEquals(1, state.pendingEpoch)
    }

    @Test
    fun rateLimitedSkipsInitiate() {
        val crypto = FakeSessionCrypto("c").apply { rotateDue = true }
        val state = RekeyState().apply { lastTimeMs = 0L } // just rekeyed at t=0
        clock.now = 1_000L // 1 s later — inside the 60 s window
        engine(crypto, state).maybeInitiate()

        assertTrue(sent.isEmpty())
        assertFalse(state.inProgress)
    }

    @Test
    fun handleAckCompletesRotationAndRebinds() {
        val crypto = FakeSessionCrypto("c").apply { rotateDue = true }
        val state = RekeyState()
        val e = engine(crypto, state)
        e.maybeInitiate() // -> REKEYING, pendingEpoch=1
        sent.clear()

        val completed = e.handleAck(rekeyPayload(epoch = 1))

        assertTrue(completed)
        assertEquals(1, rekeyCompletes)
        assertEquals(1, crypto.epoch())
        assertFalse(state.inProgress)
        assertEquals(null, state.pendingEpoch)
        assertEquals(SessionState.ESTABLISHED, e.fsmState)
    }

    @Test
    fun handleAckEpochMismatchDoesNotCompleteButClearsState() {
        val crypto = FakeSessionCrypto("c").apply { rotateDue = true }
        val state = RekeyState()
        val e = engine(crypto, state)
        e.maybeInitiate()

        val completed = e.handleAck(rekeyPayload(epoch = 2)) // expected 1

        assertFalse(completed)
        assertEquals(0, rekeyCompletes)
        assertEquals(0, crypto.epoch()) // no rotation
        assertFalse(state.inProgress)
        assertEquals(null, state.pendingEpoch)
    }

    @Test
    fun responderHandleInitSendsAckAndApplies() {
        val crypto = FakeSessionCrypto("s")
        val state = RekeyState() // no prior rekey -> not rate-limited
        val e = engine(crypto, state)

        e.handleInit(rekeyPayload(epoch = 1))

        assertEquals(1, sent.size)
        assertEquals(PacketType.REKEY_ACK, sent[0].ptype)
        assertEquals(1, crypto.epoch()) // applied
        assertEquals(1, state.cachedAckEpoch)
        assertEquals(SessionState.ESTABLISHED, e.fsmState)
    }

    @Test
    fun mutualInitLowerLocalPubKeepsOurs() {
        val crypto = FakeSessionCrypto("c").apply { rotateDue = true }
        val state = RekeyState()
        // local 0x01.. < remote 0x02.. -> we keep our INIT, ignore peer's.
        val e = engine(crypto, state, localPub = ByteArray(32) { 0x01 }, remotePub = ByteArray(32) { 0x02 })
        e.maybeInitiate()
        sent.clear()

        e.handleInit(rekeyPayload(epoch = 1))

        assertTrue(sent.isEmpty()) // no responder ACK
        assertTrue(state.inProgress) // our INIT still in flight
        assertEquals(SessionState.REKEYING, e.fsmState)
    }

    @Test
    fun mutualInitHigherLocalPubYieldsAndAborts() {
        val crypto = FakeSessionCrypto("c").apply { rotateDue = true }
        val state = RekeyState()
        // local 0x05.. > remote 0x02.. -> we yield: abort our pending init.
        val e = engine(crypto, state, localPub = ByteArray(32) { 0x05 }, remotePub = ByteArray(32) { 0x02 })
        e.maybeInitiate()
        assertTrue(state.inProgress)
        sent.clear()

        e.handleInit(rekeyPayload(epoch = 1))

        // Yielded: pending initiator rotation aborted, back to ESTABLISHED. The
        // peer's INIT is then rate-limited (our own initiate set lastTimeMs), so
        // no ACK yet — recovery is via the initiator's retransmit budget.
        assertFalse(state.inProgress)
        assertEquals(SessionState.ESTABLISHED, e.fsmState)
    }

    @Test
    fun retryRetransmitsThenTearsDown() {
        val crypto = FakeSessionCrypto("c").apply { rotateDue = true }
        val state = RekeyState()
        val e = engine(crypto, state)
        e.maybeInitiate() // INIT #1 at t=0
        val initialSends = sent.size

        // Each timeout window triggers one retransmit, up to MAX_REKEY_RETRIES.
        repeat(RekeyEngine.MAX_REKEY_RETRIES) {
            clock.advance(RekeyEngine.REKEY_ACK_TIMEOUT_MS)
            e.maybeRetry()
        }
        assertEquals(RekeyEngine.MAX_REKEY_RETRIES, state.retriesUsed)
        assertEquals(initialSends + RekeyEngine.MAX_REKEY_RETRIES, sent.size)
        assertFalse(tornDown)

        // One more timeout with the budget exhausted -> teardown, no new send.
        clock.advance(RekeyEngine.REKEY_ACK_TIMEOUT_MS)
        e.maybeRetry()
        assertTrue(tornDown)
        assertEquals(initialSends + RekeyEngine.MAX_REKEY_RETRIES, sent.size)
    }
}
