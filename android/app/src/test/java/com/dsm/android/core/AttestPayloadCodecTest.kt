package com.dsm.android.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import uniffi.tuncore.AttestSigner

/** Records the pre-image it is asked to sign and returns a canned signature. */
private class RecordingSigner(private val sig: ByteArray) : AttestSigner {
    var lastChallenge: ByteArray? = null

    override fun sign(challenge: ByteArray): ByteArray {
        lastChallenge = challenge
        return sig
    }

    override fun publicSpkiDer(): ByteArray = ByteArray(0)

    override fun attestationCertChain(): List<ByteArray> = emptyList()
}

class AttestPayloadCodecTest {

    private val payloadSize = 1024
    private val codec = AttestPayloadCodec(payloadSize)

    @Test
    fun bindingPreImageLayoutMatchesSpec() {
        val hash = ByteArray(32) { 0x11 }
        val staticPub = ByteArray(32) { 0x22 }
        val pre = codec.bindingPreImage(
            timestamp = 0x00000000DEADBEEFL,
            handshakeHash = hash,
            noiseStaticPub = staticPub,
            role = AttestPayloadCodec.PeerRole.RESPONDER,
        )

        assertEquals(AttestPayloadCodec.PRE_IMAGE_LEN, pre.size)
        assertEquals(86, pre.size)
        // Domain: "DSM-BIND-v1\0".
        assertArrayEquals(AttestPayloadCodec.BINDING_DOMAIN, pre.copyOfRange(0, 12))
        assertEquals(0x00.toByte(), pre[11]) // NUL terminator
        assertEquals(AttestPayloadCodec.BINDING_VERSION.toByte(), pre[12])
        assertArrayEquals(hash, pre.copyOfRange(21, 53))
        assertArrayEquals(staticPub, pre.copyOfRange(53, 85))
        assertEquals(1.toByte(), pre[85]) // RESPONDER role
    }

    @Test
    fun frameUnframeRoundTrips() {
        val cert = ByteArray(120) { it.toByte() }
        val sig = ByteArray(70) { (it + 1).toByte() }
        val framed = codec.frame(cert, sig, timestampSecs = 1_700_000_000L)

        assertEquals(payloadSize, framed.size)
        val out = codec.unframe(framed)
        assertEquals(1_700_000_000L, out.timestampSecs)
        assertArrayEquals(cert, out.certDer)
        assertArrayEquals(sig, out.sigDer)
    }

    @Test
    fun buildSignsBindingHashAndFrames() {
        val sig = ByteArray(72) { 0x7F }
        val signer = RecordingSigner(sig)
        val cert = ByteArray(40) { 0x09 }
        val hash = ByteArray(32) { 0x33 }
        val staticPub = ByteArray(32) { 0x44 }

        val payload = codec.build(
            signer = signer,
            certDer = cert,
            handshakeHash = hash,
            ourStaticPub = staticPub,
            role = AttestPayloadCodec.PeerRole.INITIATOR,
            timestampSecs = 42L,
        )

        // The signer saw the exact 86-byte binding pre-image carrying the hash.
        val challenge = signer.lastChallenge!!
        assertEquals(86, challenge.size)
        assertArrayEquals(hash, challenge.copyOfRange(21, 53))
        assertEquals(0.toByte(), challenge[85]) // INITIATOR

        val out = codec.unframe(payload)
        assertEquals(42L, out.timestampSecs)
        assertArrayEquals(cert, out.certDer)
        assertArrayEquals(sig, out.sigDer)
    }

    @Test
    fun frameRejectsOversizePayload() {
        val cert = ByteArray(payloadSize) // cannot possibly fit with headers
        assertThrows(AttestPayloadCodec.FormatException::class.java) {
            codec.frame(cert, ByteArray(8), 0L)
        }
    }

    @Test
    fun unframeRejectsWrongSize() {
        assertThrows(AttestPayloadCodec.FormatException::class.java) {
            codec.unframe(ByteArray(payloadSize - 1))
        }
    }
}
