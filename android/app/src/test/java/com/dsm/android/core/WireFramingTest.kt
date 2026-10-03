package com.dsm.android.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class WireFramingTest {

    @Test
    fun outerPacketRoundTrips() {
        val nonce = ByteArray(12) { it.toByte() }
        val ct = ByteArray(40) { (200 - it).toByte() }
        val packed = WireFraming.packOuter(seq = 0x0102030405060708L, nonce = nonce, ciphertext = ct)

        assertEquals(WireFraming.OUTER_HEADER_SIZE + ct.size, packed.size)
        val parsed = WireFraming.unpackOuter(packed)
        assertEquals(0x0102030405060708L, parsed.seq)
        assertArrayEquals(nonce, parsed.nonce)
        assertArrayEquals(ct, parsed.ciphertext)
        // AAD is the 8-byte big-endian sequence.
        assertArrayEquals(byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8), WireFraming.seqToAad(parsed.seq))
    }

    @Test
    fun packOuterRejectsWrongNonce() {
        assertThrows(IllegalArgumentException::class.java) {
            WireFraming.packOuter(1L, ByteArray(11), ByteArray(4))
        }
    }

    @Test
    fun unpackOuterRejectsTooShort() {
        assertThrows(IllegalArgumentException::class.java) {
            WireFraming.unpackOuter(ByteArray(WireFraming.OUTER_HEADER_SIZE - 1))
        }
    }

    @Test
    fun handshakeFramePadRoundTrips() {
        val ct = ByteArray(WireFraming.BOOTSTRAP_CIPHERTEXT_SIZE) { 0x5A }
        val frame = WireFraming.padToFrame(ct, WireFraming.BOOTSTRAP_CIPHERTEXT_SIZE)
        assertEquals(WireFraming.HANDSHAKE_FRAME_SIZE, frame.size)
        val recovered = WireFraming.unpadFromFrame(frame, WireFraming.BOOTSTRAP_CIPHERTEXT_SIZE)
        assertArrayEquals(ct, recovered)
    }

    @Test
    fun padToFrameRejectsWrongSize() {
        assertThrows(IllegalArgumentException::class.java) {
            WireFraming.padToFrame(ByteArray(10), WireFraming.BOOTSTRAP_CIPHERTEXT_SIZE)
        }
    }

    @Test
    fun unpadFromFrameRejectsWrongFrameSize() {
        assertThrows(IllegalArgumentException::class.java) {
            WireFraming.unpadFromFrame(ByteArray(100), WireFraming.BOOTSTRAP_CIPHERTEXT_SIZE)
        }
    }
}
