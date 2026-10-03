package com.dsm.android.core

import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Data-loop tests. Two paired [FakeSessionCrypto] endpoints stand in for the
 * client and server `SessionKeyManager` (the FFI cannot load in a host JVM run);
 * the loop's framing, replay handling, epoch-grace decrypt, liveness, rekey, and
 * shutdown logic are exercised directly via the pump methods with a [FakeClock].
 * No `Thread.sleep`.
 */
class SessionRunnerTest {

    private val clock = FakeClock()

    private val clientCrypto = FakeSessionCrypto("client")
    private val serverCrypto = FakeSessionCrypto("server")
    private val clientChan = LoopbackChannel()
    private val serverChan = LoopbackChannel()
    private val clientTun = FakeTunIo()
    private val serverTun = FakeTunIo()

    private val clientPub = ByteArray(32) { 0x01 }
    private val serverPub = ByteArray(32) { 0x02 }

    private var clientTornDown = false

    private fun client() = SessionRunner(
        crypto = clientCrypto,
        replay = FakeReplayGate(),
        channel = clientChan,
        tun = clientTun,
        localStaticPub = clientPub,
        remoteStaticPub = serverPub,
        clock = clock,
        onTeardown = { clientTornDown = true },
    )

    private fun server() = SessionRunner(
        crypto = serverCrypto,
        replay = FakeReplayGate(),
        channel = serverChan,
        tun = serverTun,
        localStaticPub = serverPub,
        remoteStaticPub = clientPub,
        clock = clock,
    )

    private fun aad(seq: Long): ByteArray =
        ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN).putLong(seq).array()

    private fun decodeType(crypto: SessionCrypto, wire: ByteArray): PacketType {
        val outer = WireFraming.unpackOuter(wire)
        val dec = crypto.tryDecryptWithFallback(outer.nonce, outer.ciphertext, aad(outer.seq), outer.seq)
            ?: error("decrypt failed")
        return InnerPacket.deserialize(dec.plaintext).ptype
    }

    @Test
    fun outboundFramedEncryptedAndInboundDecryptedDelivered() {
        val client = client()
        val server = server()
        val payload = ByteArray(60) { (it + 7).toByte() }

        clientTun.enqueueInbound(payload)
        assertTrue(client.runOutboundOnce())

        val frames = clientChan.drainOutbox()
        assertEquals(1, frames.size)
        // Wire is the outer frame: seq(8) ‖ nonce(12) ‖ ciphertext. (The fake
        // AEAD does not hide the payload bytes — only the real FFI does — so we
        // verify the framing via the seq and the decrypt roundtrip, not secrecy.)
        val outer = WireFraming.unpackOuter(frames[0])
        assertEquals(1L, outer.seq)
        assertEquals(WireFraming.OUTER_HEADER_SIZE + 1 + 8 + InnerPacket.INNER_HEADER_SIZE + payload.size, frames[0].size)

        server.pumpInbound(frames[0])
        assertEquals(1, serverTun.written.size)
        assertArrayEquals(payload, serverTun.written.poll())
    }

    @Test
    fun replayIsDropped() {
        val client = client()
        val server = server()
        val payload = ByteArray(40) { it.toByte() }

        clientTun.enqueueInbound(payload)
        client.runOutboundOnce()
        val wire = clientChan.drainOutbox().single()

        server.pumpInbound(wire) // delivered
        server.pumpInbound(wire) // replay -> dropped at the replay gate
        assertEquals(1, serverTun.written.size)
    }

    @Test
    fun prevEpochGraceDecryptWorksAcrossRekey() {
        val client = client()
        val server = server()
        val payload = ByteArray(50) { (0x30 + it).toByte() }

        // A rekey is due AND a data packet is queued: runOutboundOnce sends the
        // REKEY_INIT first, then the DATA packet (still under the OLD epoch).
        clientCrypto.rotateDue = true
        clientTun.enqueueInbound(payload)
        client.runOutboundOnce()

        val frames = clientChan.drainOutbox()
        assertEquals(2, frames.size)
        assertEquals(PacketType.REKEY_INIT, decodeType(serverCrypto, frames[0]))

        // Server processes the INIT: rotates to epoch 1, keeps epoch 0 in grace.
        server.pumpInbound(frames[0])
        assertEquals(1, serverCrypto.epoch())

        // The OLD-epoch DATA packet still decrypts via the prev-epoch grace key.
        server.pumpInbound(frames[1])
        assertEquals(1, serverTun.written.size)
        assertArrayEquals(payload, serverTun.written.poll())

        // The server's REKEY_ACK completes the client's rotation and triggers the
        // UDP fresh-port rebind (H-ANON-4).
        val ack = serverChan.drainOutbox().single()
        assertEquals(PacketType.REKEY_ACK, decodeType(clientCrypto, ack))
        client.pumpInbound(ack)
        assertEquals(1, clientCrypto.epoch())
        assertEquals(1, clientChan.rebindCount.get())
    }

    @Test
    fun keepaliveFiresOnRealSendIdle() {
        val client = client()

        // No idle yet: nothing emitted.
        client.tickLiveness()
        assertTrue(clientChan.outbox.isEmpty())

        // Past the 15 s real-send-idle threshold: one KEEPALIVE.
        clock.now = SessionRunner.KEEPALIVE_SEND_INTERVAL_MS + 1_000L
        client.tickLiveness()
        val frames = clientChan.drainOutbox()
        assertEquals(1, frames.size)
        assertEquals(PacketType.KEEPALIVE, decodeType(serverCrypto, frames[0]))
        assertFalse(client.isShuttingDown())
    }

    @Test
    fun deadPeerTearsDownAndEmitsNoKeepalive() {
        val client = client()

        clock.now = SessionRunner.DEAD_PEER_TIMEOUT_MS + 1_000L
        client.tickLiveness()

        assertTrue(client.isShuttingDown())
        assertTrue("dead-peer must return before emitting a keepalive", clientChan.outbox.isEmpty())
    }

    @Test
    fun cleanShutdownCancelsLoopsAndClosesTransport() {
        val client = client()
        client.start()
        // Loops are parked on blocking recv()/read(); request a shutdown.
        client.requestShutdown()
        // Finalize on this thread: best-effort SESSION_CLOSE, close I/O, join loops.
        client.awaitAndFinalize()

        assertTrue(client.isShuttingDown())
        assertTrue(clientChan.closed)
        assertTrue(clientTun.closed)
        assertTrue(clientTornDown)
    }
}
