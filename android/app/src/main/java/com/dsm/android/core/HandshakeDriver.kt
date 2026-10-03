package com.dsm.android.core

import uniffi.tuncore.AttestSigner

/** A handshake-protocol failure. Mirrors `HandshakeError`. */
open class HandshakeException(message: String) : Exception(message)

/** The server cert CN did not match the pinned `expected_server_cn`. */
class CnMismatchException(message: String) : HandshakeException(message)

/** Successful handshake outcome. */
data class HandshakeResult(
    /** The server's 32-byte X25519 Noise static (for the mutual-rekey tie-break). */
    val serverStaticPub: ByteArray,
    /** The validated server subject CN. */
    val serverCn: String,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is HandshakeResult) return false
        return serverStaticPub.contentEquals(other.serverStaticPub) && serverCn == other.serverCn
    }

    override fun hashCode(): Int = 31 * serverStaticPub.contentHashCode() + serverCn.hashCode()
}

/**
 * Client-side Noise XX handshake + session-bootstrap state machine, mirroring
 * `client_handshake` in `dsm/crypto/handshake.py`.
 *
 * The handshake is a fixed linear sequence; this driver makes the ordering
 * explicit and observable via [phase] so it can be unit-tested step by step
 * with a fake [ClientCore] and an in-memory [TransportChannel]. The two
 * load-bearing ordering rules it enforces — snapshot the handshake hash BEFORE
 * `readMessage2`, and again BEFORE `writeMessage3` — are exactly the binding
 * captures the attestation signatures depend on.
 *
 * Frame sizing: msg1/msg2/msg3 are produced pre-padded to
 * [WireFraming.HANDSHAKE_FRAME_SIZE] by the core; the bootstrap frames are
 * padded here (the transport AEAD returns only ciphertext+tag).
 */
class HandshakeDriver(
    private val core: ClientCore,
    private val channel: TransportChannel,
    private val signer: AttestSigner,
    private val codec: AttestPayloadCodec,
    private val serverVerifier: ServerAttestVerifier,
    private val certDer: ByteArray,
    private val expectedServerCn: String,
) {
    enum class Phase {
        INIT,
        SENT_MSG1,
        RECV_MSG2,
        SENT_MSG3,
        BOOTSTRAP_SENT,
        ESTABLISHED,
        FAILED,
    }

    var phase: Phase = Phase.INIT
        private set

    /**
     * Drive the full handshake to an established session.
     *
     * @throws HandshakeException / [CnMismatchException] on protocol or auth failure.
     */
    fun connect(): HandshakeResult {
        try {
            // msg1: -> e  (already frame-sized by the core).
            val msg1 = core.writeMessage1()
            channel.send(msg1)
            phase = Phase.SENT_MSG1

            // msg2: <- e, ee, s, es [+ server attest]. Snapshot the binding hash
            // BEFORE readMessage2 advances the Noise state past it.
            val msg2 = channel.recv()
            val bindingHashMsg2 = core.getHandshakeHash()
            val m2 = core.readMessage2(msg2)
            phase = Phase.RECV_MSG2

            val serverCn = serverVerifier.verify(m2.attestPayload, m2.remoteStatic, bindingHashMsg2)
            if (serverCn != expectedServerCn) {
                throw CnMismatchException(
                    "server CN \"$serverCn\" does not match expected \"$expectedServerCn\"",
                )
            }

            // msg3: -> s, se [+ client attest]. Snapshot the binding hash BEFORE
            // writeMessage3 advances the Noise state.
            val bindingHashMsg3 = core.getHandshakeHash()
            val ourAttest = codec.build(
                signer = signer,
                certDer = certDer,
                handshakeHash = bindingHashMsg3,
                ourStaticPub = core.localStaticPublic(),
                role = AttestPayloadCodec.PeerRole.INITIATOR,
            )
            val msg3 = core.writeMessage3(ourAttest)
            channel.send(msg3)
            phase = Phase.SENT_MSG3

            core.finishHandshake()

            // Bootstrap: send our ephemeral pub (encrypted under the Noise
            // transport, padded to a full frame), receive the server's.
            val ephPub = core.bootstrapPublic()
            val bootstrapInitCt = core.transportEncrypt(ephPub)
            channel.send(
                WireFraming.padToFrame(bootstrapInitCt, WireFraming.BOOTSTRAP_CIPHERTEXT_SIZE),
            )
            phase = Phase.BOOTSTRAP_SENT

            val bootstrapRespFrame = channel.recv()
            val bootstrapRespCt = WireFraming.unpadFromFrame(
                bootstrapRespFrame,
                WireFraming.BOOTSTRAP_CIPHERTEXT_SIZE,
            )
            val serverPublic = core.transportDecrypt(bootstrapRespCt)
            if (serverPublic.size != 32) {
                throw HandshakeException("invalid bootstrap ephemeral from server: ${serverPublic.size} bytes")
            }
            core.completeBootstrap(serverPublic)
            phase = Phase.ESTABLISHED

            return HandshakeResult(serverStaticPub = m2.remoteStatic, serverCn = serverCn)
        } catch (e: Exception) {
            phase = Phase.FAILED
            throw e
        }
    }
}
