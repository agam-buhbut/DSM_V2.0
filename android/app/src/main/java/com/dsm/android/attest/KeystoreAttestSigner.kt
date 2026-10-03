package com.dsm.android.attest

import uniffi.tuncore.AttestSigner
import uniffi.tuncore.FfiException

/**
 * Kotlin side of the per-handshake attestation: implements the UniFFI
 * [AttestSigner] callback the Rust attest backend invokes. All cryptographic
 * work is delegated to a [KeyHandle] (the Android Keystore on a device, a JVM
 * fake under test), so the signing scalar never crosses into Rust — it stays in
 * the secure element.
 *
 * Any failure is surfaced as [FfiException.Callback] so the Rust boundary maps
 * it to a typed error rather than aborting across the FFI boundary.
 */
class KeystoreAttestSigner(private val key: KeyHandle) : AttestSigner {

    override fun sign(challenge: ByteArray): ByteArray =
        guard("sign") { key.signEcdsaDer(challenge) }

    override fun publicSpkiDer(): ByteArray =
        guard("publicSpkiDer") { key.spkiDer() }

    override fun attestationCertChain(): List<ByteArray> =
        guard("attestationCertChain") { key.attestationChainDer() }

    private inline fun <T> guard(op: String, block: () -> T): T =
        try {
            block()
        } catch (e: FfiException) {
            throw e
        } catch (e: Exception) {
            // Catch-broad at the FFI boundary: any keystore/provider failure
            // must become a typed callback error, never an uncaught throw
            // unwinding across the Rust frame.
            throw FfiException.Callback("attest signer $op failed: ${e.message}")
        }
}
