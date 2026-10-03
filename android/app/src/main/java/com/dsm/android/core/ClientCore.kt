package com.dsm.android.core

/**
 * One handshake frame transport (UDP datagram or TCP framed stream). This is
 * the I/O boundary the [HandshakeDriver] is written against, so the driver's
 * sequencing can be unit-tested with an in-memory fake channel.
 *
 * Implementations send/receive exactly [WireFraming.HANDSHAKE_FRAME_SIZE]-byte
 * frames during the handshake.
 */
interface TransportChannel {
    /** Send one frame. */
    fun send(frame: ByteArray)

    /** Receive one frame (blocking). */
    fun recv(): ByteArray

    fun close()

    /**
     * Rebind the transport to a fresh ephemeral local port (UDP roaming /
     * H-ANON-4): after a successful initiator rekey the client moves to a new
     * source port so an ISP-side passive observer cannot correlate the whole
     * session by a stable `(src_ip, src_port)`. Mirrors
     * `UDPTransport.rebind_to_fresh_port`. Default no-op for transports without
     * a roamable local port (TCP, the handshake fakes).
     */
    fun rebindToFreshPort() {}
}

/** Result of [ClientCore.readMessage2]. Mirrors the UniFFI `Msg2Result`. */
data class Msg2(val remoteStatic: ByteArray, val attestPayload: ByteArray) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Msg2) return false
        return remoteStatic.contentEquals(other.remoteStatic) &&
            attestPayload.contentEquals(other.attestPayload)
    }

    override fun hashCode(): Int =
        31 * remoteStatic.contentHashCode() + attestPayload.contentHashCode()
}

/**
 * The Noise-XX-initiator + bootstrap primitives the handshake driver needs,
 * abstracted over the UniFFI core so the driver is testable with a fake.
 * [TuncoreClientCore] is the real implementation over the generated bindings.
 *
 * Lifecycle: [writeMessage1] -> [readMessage2] -> [writeMessage3] ->
 * [finishHandshake] -> ([bootstrapPublic], [transportEncrypt]) ... ->
 * [completeBootstrap].
 */
interface ClientCore {
    fun writeMessage1(): ByteArray

    /** Current Noise handshake hash; snapshot it BEFORE the next read/write. */
    fun getHandshakeHash(): ByteArray

    fun readMessage2(msg: ByteArray): Msg2

    fun writeMessage3(attestPayload: ByteArray): ByteArray

    /** Consume the initiator and transition to Noise transport mode. */
    fun finishHandshake()

    /** Generate the bootstrap X25519 ephemeral and return its 32-byte public key. */
    fun bootstrapPublic(): ByteArray

    fun transportEncrypt(plaintext: ByteArray): ByteArray

    fun transportDecrypt(ciphertext: ByteArray): ByteArray

    /** Derive the session keys from the peer's bootstrap public key. */
    fun completeBootstrap(serverPublic: ByteArray)

    /** Local Noise static public key (this device's identity). */
    fun localStaticPublic(): ByteArray
}
