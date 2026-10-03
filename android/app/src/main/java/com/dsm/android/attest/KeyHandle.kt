package com.dsm.android.attest

/**
 * Abstraction over the device's hardware-bound signing key.
 *
 * The production implementation ([AndroidKeystoreKeyHandle]) is backed by an EC
 * P-256 key generated non-extractably in the Android Keystore / StrongBox. This
 * interface is the seam that lets the [KeystoreAttestSigner] wiring be unit
 * tested off-device with an in-JVM fake key, since the AndroidKeyStore provider
 * is not available on the host JVM.
 *
 * No method ever exposes the private scalar — it stays in the secure element.
 */
interface KeyHandle {
    /** ASN.1 DER ECDSA (SHA-256) signature over [message]. */
    fun signEcdsaDer(message: ByteArray): ByteArray

    /** SubjectPublicKeyInfo (X.509) DER encoding of the public key. */
    fun spkiDer(): ByteArray

    /**
     * The key-attestation certificate chain, leaf first, each cert DER-encoded.
     * The server verifies this against the Google hardware-attestation root.
     */
    fun attestationChainDer(): List<ByteArray>
}
