package com.dsm.android.core

/**
 * Data-path crypto surface the steady-state loop drives, abstracted over the
 * UniFFI `SessionKeyManager` so [SessionRunner] is unit-testable on the host JVM
 * with a fake — exactly as [ClientCore] abstracts the handshake primitives.
 *
 * The native `libtuncore.so` is cross-compiled only for Android ABIs (bionic),
 * so it cannot be loaded by JNA in a host `testDebugUnitTest` run; the real
 * implementation is [TuncoreSessionCrypto] (exercised on-device / in B4), and
 * tests substitute a deterministic fake at this boundary.
 *
 * Mirrors `dsm/session.py`: ONE manager per endpoint handles BOTH directions
 * (the send/recv key separation is internal to the manager, keyed by the
 * bootstrap `is_initiator` flag) — there is NOT one manager per direction.
 */
interface SessionCrypto {
    /** Encrypt [plaintext] with `aad == seq.to_be_bytes()` (8 bytes). */
    fun encrypt(plaintext: ByteArray, aad: ByteArray): EncryptOut

    /**
     * Non-raising decrypt: current epoch, then previous epoch during grace.
     * Returns null on auth failure (forgery / wrong epoch / replay-at-AEAD).
     */
    fun tryDecryptWithFallback(
        nonce: ByteArray,
        ciphertext: ByteArray,
        aad: ByteArray,
        seq: Long,
    ): DecryptOut?

    fun needsRotation(): Boolean

    fun initiateRotation(): RotationInit

    fun completeRotationInitiator(remoteEphemeralPub: ByteArray): Int

    fun prepareRotationResponder(remoteEphemeralPub: ByteArray, newEpoch: Int): RotationResponder

    fun applyRotationResponder(): Int

    /** Drop a pending initiator rotation (mutual-init yield). True if one existed. */
    fun abortRotation(): Boolean

    /** Periodic maintenance: expire grace keys, promote a deferred send-key swap. */
    fun tick()

    fun epoch(): Int
}

/** Result of [SessionCrypto.encrypt]; mirrors the UniFFI `EncryptResult`. */
class EncryptOut(val nonce: ByteArray, val ciphertext: ByteArray, val epoch: Int)

/** Result of [SessionCrypto.tryDecryptWithFallback]; mirrors `DecryptFallback`. */
class DecryptOut(val plaintext: ByteArray, val usedPrevEpoch: Boolean)

/** Result of [SessionCrypto.initiateRotation]; mirrors `RotationInitResult`. */
class RotationInit(val newEpoch: Int, val ephemeralPub: ByteArray)

/** Result of the responder rotation phases; mirrors `RotationResponderResult`. */
class RotationResponder(val ourEphemeralPub: ByteArray, val newEpoch: Int)

/**
 * Outer wire-sequence replay window, abstracted over the UniFFI `ReplayWindow`.
 *
 * `dsm/session.py::decrypt_packet` (M-BUG-14) deliberately calls [check] BEFORE
 * the AEAD work (drop replays cheaply) and [update] only AFTER a successful
 * authentication (so a forged packet with a fresh seq cannot advance the window
 * and lock out the legitimate packet). [SessionRunner] mirrors that ordering.
 */
interface ReplayGate {
    /** Read-only freshness check; does not advance the window. */
    fun check(seq: Long): Boolean

    /** Mark [seq] seen — call only after successful authentication. */
    fun update(seq: Long)
}
