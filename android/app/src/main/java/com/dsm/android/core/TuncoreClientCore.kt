package com.dsm.android.core

import uniffi.tuncore.BootstrapEphemeral
import uniffi.tuncore.IdentityKeyPair
import uniffi.tuncore.NoiseInitiator
import uniffi.tuncore.NoiseTransport
import uniffi.tuncore.SessionKeyManager
import uniffi.tuncore.completeBootstrap

/**
 * Real [ClientCore] over the generated UniFFI bindings. Holds the live native
 * handshake objects and transitions them in lockstep with the protocol:
 * `NoiseInitiator` -> `NoiseTransport` -> `SessionKeyManager`.
 *
 * Calling any method here loads and drives the native `libtuncore` core, so it
 * is exercised on-device / via the bindings-linked APK (Phase B), not in host
 * JVM unit tests (which use a fake [ClientCore]).
 */
class TuncoreClientCore(
    private val identity: IdentityKeyPair,
    private val rotationPackets: ULong?,
    private val rotationSeconds: ULong?,
) : ClientCore {

    private var initiator: NoiseInitiator? = NoiseInitiator(identity)
    private var transport: NoiseTransport? = null
    private var ephemeral: BootstrapEphemeral? = null

    /** The established data-path session; non-null only after [completeBootstrap]. */
    var session: SessionKeyManager? = null
        private set

    private fun initiator(): NoiseInitiator =
        initiator ?: error("Noise initiator already consumed")

    private fun transport(): NoiseTransport =
        transport ?: error("Noise transport not yet established")

    override fun writeMessage1(): ByteArray = initiator().writeMessage1()

    override fun getHandshakeHash(): ByteArray = initiator().getHandshakeHash()

    override fun readMessage2(msg: ByteArray): Msg2 {
        val r = initiator().readMessage2(msg)
        return Msg2(r.remoteStatic, r.attestPayload)
    }

    override fun writeMessage3(attestPayload: ByteArray): ByteArray =
        initiator().writeMessage3(attestPayload)

    override fun finishHandshake() {
        val t = initiator().intoTransport()
        initiator = null
        transport = t
    }

    override fun bootstrapPublic(): ByteArray {
        val eph = BootstrapEphemeral.generate()
        ephemeral = eph
        return eph.publicKeyBytes()
    }

    override fun transportEncrypt(plaintext: ByteArray): ByteArray =
        transport().encrypt(plaintext)

    override fun transportDecrypt(ciphertext: ByteArray): ByteArray =
        transport().decrypt(ciphertext)

    override fun completeBootstrap(serverPublic: ByteArray) {
        val eph = ephemeral ?: error("bootstrap ephemeral not generated")
        session = completeBootstrap(
            eph,
            serverPublic,
            isInitiator = true,
            rotationPackets = rotationPackets,
            rotationSeconds = rotationSeconds,
        )
        ephemeral = null
    }

    override fun localStaticPublic(): ByteArray = identity.publicKey()
}
