package com.dsm.android.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class InnerPacketTest {

    @Test
    fun roundTripsHeaderAndPayload() {
        val payload = ByteArray(40) { (it * 3 + 1).toByte() }
        val inner = InnerPacket(PacketType.DATA, epochId = 0x0A, payload = payload)
        val wire = inner.serialize()

        // [type][flags][len BE u16][payload]; flags top nibble = epoch_id.
        assertEquals(PacketType.DATA.value, wire[0].toInt() and 0xFF)
        assertEquals(0xA0, wire[1].toInt() and 0xFF)
        assertEquals(payload.size, ((wire[2].toInt() and 0xFF) shl 8) or (wire[3].toInt() and 0xFF))

        val parsed = InnerPacket.deserialize(wire)
        assertEquals(PacketType.DATA, parsed.ptype)
        assertEquals(0x0A, parsed.epochId)
        assertArrayEquals(payload, parsed.payload)
    }

    @Test
    fun emptyKeepalivePayloadRoundTrips() {
        val inner = InnerPacket(PacketType.KEEPALIVE, epochId = 0, payload = ByteArray(0))
        val parsed = InnerPacket.deserialize(inner.serialize())
        assertEquals(PacketType.KEEPALIVE, parsed.ptype)
        assertEquals(0, parsed.payload.size)
    }

    @Test
    fun deserializeRejectsReservedFlagBits() {
        // type=DATA, flags has a low reserved bit set, len=0.
        val bad = byteArrayOf(0x00, 0x01, 0x00, 0x00)
        assertThrows(IllegalArgumentException::class.java) { InnerPacket.deserialize(bad) }
    }

    @Test
    fun deserializeRejectsUnknownType() {
        val bad = byteArrayOf(0x7F, 0x00, 0x00, 0x00)
        assertThrows(IllegalArgumentException::class.java) { InnerPacket.deserialize(bad) }
    }

    @Test
    fun deserializeRejectsLengthPastBuffer() {
        // inner_len = 10 but only 2 payload bytes follow.
        val bad = byteArrayOf(0x00, 0x00, 0x00, 0x0A, 0x01, 0x02)
        assertThrows(IllegalArgumentException::class.java) { InnerPacket.deserialize(bad) }
    }

    @Test
    fun serializeRejectsOutOfRangeEpoch() {
        assertThrows(IllegalArgumentException::class.java) {
            InnerPacket(PacketType.DATA, epochId = 16, payload = ByteArray(0)).serialize()
        }
    }
}
