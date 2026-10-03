package com.dsm.android.core

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom
import uniffi.tuncore.AttestSigner

/**
 * Per-handshake binding-attestation payload, mirroring `dsm/crypto/attest.py`.
 *
 * Wire framing inside `handshakeAttestPayloadSize()` bytes:
 * ```
 * ts(8 BE) | cert_len(2 BE) | cert_der | sig_len(2 BE) | sig_der | random_pad
 * ```
 *
 * Signed binding pre-image (86 bytes):
 * ```
 * "DSM-BIND-v1\0"(12) | version(1) | ts(8 BE) | hash(32) | static_pub(32) | role(1)
 * ```
 *
 * The signature is produced by the device's Android-Keystore key (via the
 * UniFFI [AttestSigner] callback) and is freshness- and role-bound, so a
 * captured payload cannot be replayed into another handshake or role.
 */
class AttestPayloadCodec(private val payloadSize: Int) {

    /** Which side of the handshake produced a signature. Matches `PeerRole`. */
    enum class PeerRole(val wire: Int) {
        INITIATOR(0), // client
        RESPONDER(1), // server
    }

    /** Malformed attest payload framing. Mirrors `AttestPayloadFormatError`. */
    class FormatException(message: String) : Exception(message)

    private val rng = SecureRandom()

    /**
     * Build the domain-separated signed pre-image (86 bytes).
     *
     * @throws IllegalArgumentException on wrong-length hash or static pub.
     */
    fun bindingPreImage(
        timestamp: Long,
        handshakeHash: ByteArray,
        noiseStaticPub: ByteArray,
        role: PeerRole,
    ): ByteArray {
        require(handshakeHash.size == HANDSHAKE_HASH_LEN) {
            "handshake_hash must be $HANDSHAKE_HASH_LEN bytes, got ${handshakeHash.size}"
        }
        require(noiseStaticPub.size == NOISE_STATIC_PUB_LEN) {
            "noise_static_pub must be $NOISE_STATIC_PUB_LEN bytes, got ${noiseStaticPub.size}"
        }
        val buf = ByteBuffer.allocate(PRE_IMAGE_LEN).order(ByteOrder.BIG_ENDIAN)
        buf.put(BINDING_DOMAIN)
        buf.put(BINDING_VERSION.toByte())
        buf.putLong(timestamp)
        buf.put(handshakeHash)
        buf.put(noiseStaticPub)
        buf.put(role.wire.toByte())
        return buf.array()
    }

    /**
     * Build the full attest payload: sign the binding pre-image with [signer]
     * and frame `cert_der`/`sig_der` to exactly [payloadSize] bytes.
     *
     * Mirrors `build_attest_payload`. `timestampSecs` defaults to wall-clock
     * UTC seconds; an explicit value is accepted for deterministic testing.
     */
    fun build(
        signer: AttestSigner,
        certDer: ByteArray,
        handshakeHash: ByteArray,
        ourStaticPub: ByteArray,
        role: PeerRole,
        timestampSecs: Long = System.currentTimeMillis() / 1000L,
    ): ByteArray {
        val preImage = bindingPreImage(timestampSecs, handshakeHash, ourStaticPub, role)
        val sigDer = signer.sign(preImage)
        return frame(certDer, sigDer, timestampSecs)
    }

    /** Parsed wire framing: `(timestamp, certDer, sigDer)`. Trailing pad ignored. */
    data class Unframed(val timestampSecs: Long, val certDer: ByteArray, val sigDer: ByteArray) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Unframed) return false
            return timestampSecs == other.timestampSecs &&
                certDer.contentEquals(other.certDer) &&
                sigDer.contentEquals(other.sigDer)
        }

        override fun hashCode(): Int {
            var result = timestampSecs.hashCode()
            result = 31 * result + certDer.contentHashCode()
            result = 31 * result + sigDer.contentHashCode()
            return result
        }
    }

    /** Build `ts | cert_len | cert | sig_len | sig | pad`. Mirrors `_frame_payload`. */
    fun frame(certDer: ByteArray, sigDer: ByteArray, timestampSecs: Long): ByteArray {
        if (certDer.size > 0xFFFF) {
            throw FormatException("cert too large to frame: ${certDer.size} bytes")
        }
        if (sigDer.size > 0xFFFF) {
            throw FormatException("signature too large to frame: ${sigDer.size} bytes")
        }
        val framedLen = 8 + 2 + certDer.size + 2 + sigDer.size
        if (framedLen > payloadSize) {
            throw FormatException(
                "framed cert+sig exceeds attest payload size: $framedLen > $payloadSize",
            )
        }
        val out = ByteArray(payloadSize)
        val buf = ByteBuffer.wrap(out).order(ByteOrder.BIG_ENDIAN)
        buf.putLong(timestampSecs)
        buf.putShort(certDer.size.toShort())
        buf.put(certDer)
        buf.putShort(sigDer.size.toShort())
        buf.put(sigDer)
        val pad = ByteArray(payloadSize - framedLen)
        rng.nextBytes(pad)
        buf.put(pad)
        return out
    }

    /** Inverse of [frame]. Mirrors `_unframe_payload`. */
    fun unframe(payload: ByteArray): Unframed {
        if (payload.size != payloadSize) {
            throw FormatException("attest payload wrong size: ${payload.size} != $payloadSize")
        }
        if (payload.size < 8 + 2) {
            throw FormatException("attest payload truncated")
        }
        val buf = ByteBuffer.wrap(payload).order(ByteOrder.BIG_ENDIAN)
        val timestamp = buf.long
        val certLen = buf.short.toInt() and 0xFFFF
        val certEnd = 10 + certLen
        if (certEnd + 2 > payloadSize) {
            throw FormatException("attest payload cert_len overflows frame")
        }
        val certDer = payload.copyOfRange(10, certEnd)
        val sigLen =
            ByteBuffer.wrap(payload, certEnd, 2).order(ByteOrder.BIG_ENDIAN).short.toInt() and 0xFFFF
        val sigEnd = certEnd + 2 + sigLen
        if (sigEnd > payloadSize) {
            throw FormatException("attest payload sig_len overflows frame")
        }
        val sigDer = payload.copyOfRange(certEnd + 2, sigEnd)
        return Unframed(timestamp, certDer, sigDer)
    }

    companion object {
        // b"DSM-BIND-v1\x00": 11 ASCII chars + a NUL terminator = 12 bytes.
        // Must match `BINDING_DOMAIN` in dsm/crypto/attest.py byte-for-byte.
        val BINDING_DOMAIN: ByteArray =
            "DSM-BIND-v1".toByteArray(Charsets.US_ASCII) + byteArrayOf(0x00)
        const val BINDING_VERSION = 0x01
        const val HANDSHAKE_HASH_LEN = 32
        const val NOISE_STATIC_PUB_LEN = 32

        /** 12 (domain) + 1 (version) + 8 (ts) + 32 (hash) + 32 (static) + 1 (role) = 86. */
        const val PRE_IMAGE_LEN =
            12 + 1 + 8 + HANDSHAKE_HASH_LEN + NOISE_STATIC_PUB_LEN + 1
    }
}
