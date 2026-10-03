package com.dsm.android.core

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom

/**
 * Wire framing for the DSM data path and handshake, mirroring the
 * authoritative Python implementation in `dsm/core/protocol.py` and
 * `dsm/crypto/handshake.py`.
 *
 * These layouts are part of the on-the-wire protocol contract and MUST match
 * the server byte-for-byte; they are pure functions over byte arrays so they
 * are fully unit-testable off-device.
 */
object WireFraming {

    /** Outer header: seq(8 BE) ‖ nonce(12) ‖ ciphertext. Mirrors OUTER_HEADER_SIZE. */
    const val OUTER_HEADER_SIZE = 20
    const val SEQ_SIZE = 8
    const val NONCE_SIZE = 12

    /** Every handshake frame on the wire is exactly this many bytes (HANDSHAKE_FRAME_SIZE). */
    const val HANDSHAKE_FRAME_SIZE = 1400

    /** Bootstrap plaintext is a 32-byte X25519 pub; NoiseTransport adds a 16-byte tag. */
    const val BOOTSTRAP_CIPHERTEXT_SIZE = 32 + 16

    private val rng = SecureRandom()

    /** The 8-byte big-endian sequence number used as the AEAD AAD. */
    fun seqToAad(seq: Long): ByteArray =
        ByteBuffer.allocate(SEQ_SIZE).order(ByteOrder.BIG_ENDIAN).putLong(seq).array()

    /**
     * Pack an outer data packet: seq(8 BE) ‖ nonce(12) ‖ ciphertext.
     *
     * @throws IllegalArgumentException if the nonce is not exactly 12 bytes.
     */
    fun packOuter(seq: Long, nonce: ByteArray, ciphertext: ByteArray): ByteArray {
        require(nonce.size == NONCE_SIZE) { "nonce must be $NONCE_SIZE bytes, got ${nonce.size}" }
        val out = ByteArray(OUTER_HEADER_SIZE + ciphertext.size)
        ByteBuffer.wrap(out, 0, SEQ_SIZE).order(ByteOrder.BIG_ENDIAN).putLong(seq)
        System.arraycopy(nonce, 0, out, SEQ_SIZE, NONCE_SIZE)
        System.arraycopy(ciphertext, 0, out, OUTER_HEADER_SIZE, ciphertext.size)
        return out
    }

    /** Parsed outer packet. */
    data class OuterPacket(val seq: Long, val nonce: ByteArray, val ciphertext: ByteArray) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is OuterPacket) return false
            return seq == other.seq &&
                nonce.contentEquals(other.nonce) &&
                ciphertext.contentEquals(other.ciphertext)
        }

        override fun hashCode(): Int {
            var result = seq.hashCode()
            result = 31 * result + nonce.contentHashCode()
            result = 31 * result + ciphertext.contentHashCode()
            return result
        }
    }

    /**
     * Parse an outer data packet.
     *
     * @throws IllegalArgumentException if the buffer is shorter than the header.
     */
    fun unpackOuter(data: ByteArray): OuterPacket {
        require(data.size >= OUTER_HEADER_SIZE) {
            "outer packet too short: ${data.size} < $OUTER_HEADER_SIZE"
        }
        val seq = ByteBuffer.wrap(data, 0, SEQ_SIZE).order(ByteOrder.BIG_ENDIAN).long
        val nonce = data.copyOfRange(SEQ_SIZE, OUTER_HEADER_SIZE)
        val ciphertext = data.copyOfRange(OUTER_HEADER_SIZE, data.size)
        return OuterPacket(seq, nonce, ciphertext)
    }

    /**
     * Pad a handshake ciphertext up to [HANDSHAKE_FRAME_SIZE] with CSPRNG bytes.
     *
     * @throws IllegalArgumentException if `data.size != expectedSize`.
     */
    fun padToFrame(data: ByteArray, expectedSize: Int): ByteArray {
        require(data.size == expectedSize) {
            "handshake payload size mismatch: ${data.size} != $expectedSize"
        }
        val out = ByteArray(HANDSHAKE_FRAME_SIZE)
        System.arraycopy(data, 0, out, 0, data.size)
        val pad = ByteArray(HANDSHAKE_FRAME_SIZE - data.size)
        rng.nextBytes(pad)
        System.arraycopy(pad, 0, out, data.size, pad.size)
        return out
    }

    /**
     * Extract the leading `expectedSize` bytes from a fixed-size handshake frame.
     *
     * @throws IllegalArgumentException if the frame is not [HANDSHAKE_FRAME_SIZE] bytes.
     */
    fun unpadFromFrame(blob: ByteArray, expectedSize: Int): ByteArray {
        require(blob.size == HANDSHAKE_FRAME_SIZE) {
            "handshake frame wrong size: ${blob.size} != $HANDSHAKE_FRAME_SIZE"
        }
        return blob.copyOfRange(0, expectedSize)
    }
}
