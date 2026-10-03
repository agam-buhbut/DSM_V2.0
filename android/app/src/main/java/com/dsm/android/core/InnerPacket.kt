package com.dsm.android.core

/**
 * Inner (post-AEAD) packet types. Mirrors `PacketType` in `dsm/core/protocol.py`.
 */
enum class PacketType(val value: Int) {
    DATA(0x00),
    HANDSHAKE(0x01),
    REKEY_INIT(0x02),
    REKEY_ACK(0x03),
    CHAFF(0x04),
    KEEPALIVE(0x05),
    SESSION_CLOSE(0x06),
    FRAGMENT(0x07),
    PATH_CHALLENGE(0x08),
    PATH_RESPONSE(0x09),
    ;

    companion object {
        private val BY_VALUE = values().associateBy { it.value }

        /** The [PacketType] for a raw wire byte, or null if unknown. */
        fun fromValue(v: Int): PacketType? = BY_VALUE[v]
    }
}

/**
 * Decrypted inner packet, mirroring `InnerPacket` in `dsm/core/protocol.py`.
 *
 * Inner plaintext layout: `[type: 1][flags: 1][inner_len: 2 BE][payload]`.
 * `flags` carries the 4-bit `epoch_id` in its top nibble (audit M3); the low 4
 * bits are reserved and MUST be zero.
 */
class InnerPacket(val ptype: PacketType, val epochId: Int, val payload: ByteArray) {

    /**
     * Serialize to inner plaintext.
     *
     * @throws IllegalArgumentException if [epochId] is out of the 4-bit range or
     *   the payload exceeds [MAX_INNER_PAYLOAD].
     */
    fun serialize(): ByteArray {
        require(epochId in 0..0x0F) { "epoch_id out of 4-bit range: $epochId" }
        require(payload.size <= MAX_INNER_PAYLOAD) {
            "payload too large: ${payload.size} > $MAX_INNER_PAYLOAD"
        }
        val flags = (epochId and 0x0F) shl 4 // 4 MSBs = epoch_id, 4 LSBs reserved
        val innerLen = payload.size
        val buf = ByteArray(INNER_HEADER_SIZE + innerLen)
        buf[0] = ptype.value.toByte()
        buf[1] = flags.toByte()
        buf[2] = ((innerLen ushr 8) and 0xFF).toByte()
        buf[3] = (innerLen and 0xFF).toByte()
        System.arraycopy(payload, 0, buf, INNER_HEADER_SIZE, innerLen)
        return buf
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is InnerPacket) return false
        return ptype == other.ptype &&
            epochId == other.epochId &&
            payload.contentEquals(other.payload)
    }

    override fun hashCode(): Int {
        var result = ptype.hashCode()
        result = 31 * result + epochId
        result = 31 * result + payload.contentHashCode()
        return result
    }

    companion object {
        const val INNER_HEADER_SIZE = 4
        const val MAX_INNER_PAYLOAD = 1500

        /**
         * Parse inner plaintext.
         *
         * @throws IllegalArgumentException on a short buffer, unknown type, set
         *   reserved bits, or an inner length that runs past the buffer — every
         *   malformed-packet rejection in `InnerPacket.deserialize` (protocol.py).
         */
        fun deserialize(data: ByteArray): InnerPacket {
            require(data.size >= INNER_HEADER_SIZE) { "inner packet too short" }
            val ptypeRaw = data[0].toInt() and 0xFF
            val flags = data[1].toInt() and 0xFF
            val innerLen = ((data[2].toInt() and 0xFF) shl 8) or (data[3].toInt() and 0xFF)
            val ptype = PacketType.fromValue(ptypeRaw)
                ?: throw IllegalArgumentException("unknown packet type: $ptypeRaw")
            val epochId = (flags ushr 4) and 0x0F
            require(flags and 0x0F == 0) { "reserved flag bits set: $flags" }
            require(innerLen <= MAX_INNER_PAYLOAD) {
                "inner payload too large: $innerLen > $MAX_INNER_PAYLOAD"
            }
            val payloadEnd = INNER_HEADER_SIZE + innerLen
            require(payloadEnd <= data.size) { "inner length exceeds data" }
            val payload = data.copyOfRange(INNER_HEADER_SIZE, payloadEnd)
            // Trailing bytes (if any) are inner padding — ignored, per protocol.py.
            return InnerPacket(ptype = ptype, epochId = epochId, payload = payload)
        }
    }
}
