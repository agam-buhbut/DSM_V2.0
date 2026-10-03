package com.dsm.android.core

import java.util.ArrayDeque
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.tuncore.AttestSigner

private const val FRAME = WireFraming.HANDSHAKE_FRAME_SIZE

/** In-memory channel: records sends, replays a fixed recv queue. */
private class FakeChannel(recvFrames: List<ByteArray>) : TransportChannel {
    val sent = mutableListOf<ByteArray>()
    private val queue = ArrayDeque(recvFrames)
    var closed = false

    override fun send(frame: ByteArray) {
        sent += frame
    }

    override fun recv(): ByteArray =
        queue.poll() ?: error("recv() called more times than queued frames")

    override fun close() {
        closed = true
    }
}

/**
 * Fake core that returns deterministic values and records the order of calls,
 * so the test can assert the handshake-hash snapshot discipline.
 */
private class FakeClientCore(
    private val serverStatic: ByteArray,
    private val serverBootstrapPub: ByteArray,
    private val hashes: List<ByteArray>,
) : ClientCore {
    val order = mutableListOf<String>()
    var hashIndex = 0
    var msg3Payload: ByteArray? = null
    var completedWith: ByteArray? = null
    val clientStatic = ByteArray(32) { 0x55 }

    override fun writeMessage1(): ByteArray {
        order += "writeMessage1"
        return ByteArray(FRAME) { 0x01 }
    }

    override fun getHandshakeHash(): ByteArray {
        order += "getHandshakeHash"
        val h = hashes[minOf(hashIndex, hashes.size - 1)]
        hashIndex++
        return h
    }

    override fun readMessage2(msg: ByteArray): Msg2 {
        order += "readMessage2"
        return Msg2(serverStatic, ByteArray(64) { 0x02 })
    }

    override fun writeMessage3(attestPayload: ByteArray): ByteArray {
        order += "writeMessage3"
        msg3Payload = attestPayload
        return ByteArray(FRAME) { 0x03 }
    }

    override fun finishHandshake() {
        order += "finishHandshake"
    }

    override fun bootstrapPublic(): ByteArray {
        order += "bootstrapPublic"
        return ByteArray(32) { 0x06 }
    }

    override fun transportEncrypt(plaintext: ByteArray): ByteArray {
        order += "transportEncrypt"
        return ByteArray(WireFraming.BOOTSTRAP_CIPHERTEXT_SIZE) { 0x07 }
    }

    override fun transportDecrypt(ciphertext: ByteArray): ByteArray {
        order += "transportDecrypt"
        return serverBootstrapPub
    }

    override fun completeBootstrap(serverPublic: ByteArray) {
        order += "completeBootstrap"
        completedWith = serverPublic
    }

    override fun localStaticPublic(): ByteArray = clientStatic
}

private class EchoSigner : AttestSigner {
    var lastChallenge: ByteArray? = null

    override fun sign(challenge: ByteArray): ByteArray {
        lastChallenge = challenge
        return ByteArray(64) { 0x7E }
    }

    override fun publicSpkiDer(): ByteArray = ByteArray(0)

    override fun attestationCertChain(): List<ByteArray> = emptyList()
}

class HandshakeDriverTest {

    private val serverStatic = ByteArray(32) { 0xAB.toByte() }
    private val serverBootstrapPub = ByteArray(32) { 0xCD.toByte() }
    private val hash1 = ByteArray(32) { 0x31 } // snapshot before readMessage2
    private val hash2 = ByteArray(32) { 0x32 } // snapshot before writeMessage3
    private val expectedCn = "dsm-test-server"

    private fun driver(
        core: FakeClientCore,
        channel: FakeChannel,
        signer: AttestSigner,
        verifier: ServerAttestVerifier,
    ) = HandshakeDriver(
        core = core,
        channel = channel,
        signer = signer,
        codec = AttestPayloadCodec(512),
        serverVerifier = verifier,
        certDer = ByteArray(50) { 0x09 },
        expectedServerCn = expectedCn,
    )

    @Test
    fun fullHandshakeEstablishesAndKeepsOrdering() {
        val core = FakeClientCore(serverStatic, serverBootstrapPub, listOf(hash1, hash2))
        val channel = FakeChannel(
            listOf(ByteArray(FRAME) { 0x22 }, ByteArray(FRAME) { 0x44 }),
        )
        val signer = EchoSigner()
        var verifierBindingHash: ByteArray? = null
        var verifierStatic: ByteArray? = null
        val verifier = ServerAttestVerifier { _, remoteStatic, bindingHash ->
            verifierStatic = remoteStatic
            verifierBindingHash = bindingHash
            expectedCn
        }

        val d = driver(core, channel, signer, verifier)
        val result = d.connect()

        assertEquals(expectedCn, result.serverCn)
        assertArrayEquals(serverStatic, result.serverStaticPub)
        assertEquals(HandshakeDriver.Phase.ESTABLISHED, d.phase)

        // The binding hash handed to the verifier is the FIRST snapshot, taken
        // BEFORE readMessage2 advanced the Noise state.
        assertArrayEquals(hash1, verifierBindingHash)
        assertArrayEquals(serverStatic, verifierStatic)

        // The attestation pre-image carries the SECOND snapshot (pre-writeMessage3).
        val challenge = signer.lastChallenge!!
        assertArrayEquals(hash2, challenge.copyOfRange(21, 53))

        // Ordering discipline: getHandshakeHash precedes the read/write it binds.
        val firstHash = core.order.indexOf("getHandshakeHash")
        val read = core.order.indexOf("readMessage2")
        val write = core.order.indexOf("writeMessage3")
        assertTrue("hash snapshot before readMessage2", firstHash in 0 until read)
        assertTrue("readMessage2 before writeMessage3", read < write)
        assertTrue("finishHandshake before bootstrap", core.order.indexOf("finishHandshake") < core.order.indexOf("bootstrapPublic"))

        // Bootstrap completed with the server's decrypted ephemeral public.
        assertArrayEquals(serverBootstrapPub, core.completedWith)
        // Three frames sent: msg1, msg3, bootstrap-init.
        assertEquals(3, channel.sent.size)
    }

    @Test
    fun cnMismatchFailsClosed() {
        val core = FakeClientCore(serverStatic, serverBootstrapPub, listOf(hash1, hash2))
        val channel = FakeChannel(listOf(ByteArray(FRAME) { 0x22 }))
        val signer = EchoSigner()
        val verifier = ServerAttestVerifier { _, _, _ -> "some-other-cn" }

        val d = driver(core, channel, signer, verifier)
        assertThrows(CnMismatchException::class.java) { d.connect() }
        assertEquals(HandshakeDriver.Phase.FAILED, d.phase)
        // Never advanced to sending msg3.
        assertEquals(1, channel.sent.size)
    }

    @Test
    fun throwingVerifierFailsClosed() {
        val core = FakeClientCore(serverStatic, serverBootstrapPub, listOf(hash1, hash2))
        val channel = FakeChannel(listOf(ByteArray(FRAME) { 0x22 }))
        // A verifier that cannot authenticate the server must fail the handshake
        // closed (mirrors the fail-closed placeholder that used to live here).
        val failingVerifier = ServerAttestVerifier { _, _, _ ->
            throw HandshakeException("server attestation unavailable")
        }
        val d = driver(core, channel, EchoSigner(), failingVerifier)
        assertThrows(HandshakeException::class.java) { d.connect() }
        assertEquals(HandshakeDriver.Phase.FAILED, d.phase)
    }
}
