package com.dsm.android.core

import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import uniffi.tuncore.ReplayWindow
import uniffi.tuncore.SessionKeyManager

/**
 * Real [SessionCrypto] over the UniFFI [SessionKeyManager]. Pure delegation; the
 * native object is internally `Mutex`-guarded so the data-loop threads may call
 * it concurrently. Loaded only with the bindings-linked APK (on-device / B4),
 * never in host JVM unit tests.
 */
class TuncoreSessionCrypto(private val skm: SessionKeyManager) : SessionCrypto {

    override fun encrypt(plaintext: ByteArray, aad: ByteArray): EncryptOut {
        val r = skm.encrypt(plaintext, aad)
        return EncryptOut(r.nonce, r.ciphertext, r.epoch.toInt())
    }

    override fun tryDecryptWithFallback(
        nonce: ByteArray,
        ciphertext: ByteArray,
        aad: ByteArray,
        seq: Long,
    ): DecryptOut? {
        val r = skm.tryDecryptWithFallback(nonce, ciphertext, aad, seq.toULong()) ?: return null
        return DecryptOut(r.plaintext, r.usedPrevEpoch)
    }

    override fun needsRotation(): Boolean = skm.needsRotation()

    override fun initiateRotation(): RotationInit {
        val r = skm.initiateRotation()
        return RotationInit(r.newEpoch.toInt(), r.ephemeralPub)
    }

    override fun completeRotationInitiator(remoteEphemeralPub: ByteArray): Int =
        skm.completeRotationInitiator(remoteEphemeralPub).toInt()

    override fun prepareRotationResponder(
        remoteEphemeralPub: ByteArray,
        newEpoch: Int,
    ): RotationResponder {
        val r = skm.prepareRotationResponder(remoteEphemeralPub, newEpoch.toUInt())
        return RotationResponder(r.ourEphemeralPub, r.newEpoch.toInt())
    }

    override fun applyRotationResponder(): Int = skm.applyRotationResponder().toInt()

    override fun abortRotation(): Boolean = skm.abortRotation()

    override fun tick() = skm.tick()

    override fun epoch(): Int = skm.epoch().toInt()
}

/** Real [ReplayGate] over the UniFFI [ReplayWindow]. */
class TuncoreReplayGate(private val rw: ReplayWindow) : ReplayGate {
    override fun check(seq: Long): Boolean = rw.check(seq.toULong())
    override fun update(seq: Long) = rw.update(seq.toULong())
}

/**
 * Real [TunIo] over the VpnService TUN [ParcelFileDescriptor]. Each read on a
 * TUN fd returns exactly one IP packet; each write injects one.
 */
class FileTunIo(pfd: ParcelFileDescriptor) : TunIo {
    private val input = FileInputStream(pfd.fileDescriptor)
    private val output = FileOutputStream(pfd.fileDescriptor)
    private val readBuf = ByteArray(MAX_PACKET)

    override fun read(): ByteArray? {
        val n = input.read(readBuf)
        if (n <= 0) return null
        return readBuf.copyOf(n)
    }

    override fun write(packet: ByteArray) {
        output.write(packet)
    }

    override fun close() {
        runCatching { input.close() }
        runCatching { output.close() }
    }

    private companion object {
        // Above the max TUN MTU plus inner/outer overhead; one packet per read.
        const val MAX_PACKET = 32_767
    }
}
