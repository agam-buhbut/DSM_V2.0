package com.dsm.android.attest

import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.tuncore.FfiException

/**
 * Off-device [KeyHandle] backed by a host-JVM EC P-256 key (SunEC). Stands in
 * for the Android Keystore, which is not a host provider, so the
 * [KeystoreAttestSigner] wiring can be exercised deterministically.
 */
private class JvmEcKeyHandle(private val chain: List<ByteArray>) : KeyHandle {
    private val pair = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair()

    override fun signEcdsaDer(message: ByteArray): ByteArray =
        Signature.getInstance("SHA256withECDSA").run {
            initSign(pair.private)
            update(message)
            sign()
        }

    override fun spkiDer(): ByteArray = pair.public.encoded

    override fun attestationChainDer(): List<ByteArray> = chain

    fun verify(message: ByteArray, sigDer: ByteArray): Boolean =
        Signature.getInstance("SHA256withECDSA").run {
            initVerify(pair.public)
            update(message)
            verify(sigDer)
        }
}

private class ThrowingKeyHandle : KeyHandle {
    override fun signEcdsaDer(message: ByteArray): ByteArray = throw IllegalStateException("no key")
    override fun spkiDer(): ByteArray = throw IllegalStateException("no key")
    override fun attestationChainDer(): List<ByteArray> = throw IllegalStateException("no key")
}

class KeystoreAttestSignerTest {

    @Test
    fun signProducesVerifiableEcdsaSignature() {
        val key = JvmEcKeyHandle(chain = listOf(byteArrayOf(1, 2, 3)))
        val signer = KeystoreAttestSigner(key)

        val message = "DSM-BIND-v1".toByteArray()
        val sigDer = signer.sign(message)
        assertTrue("ECDSA signature must verify under the public key", key.verify(message, sigDer))
    }

    @Test
    fun publicSpkiDerPassesThroughKeyEncoding() {
        val key = JvmEcKeyHandle(chain = emptyList())
        val signer = KeystoreAttestSigner(key)
        assertArrayEquals(key.spkiDer(), signer.publicSpkiDer())
    }

    @Test
    fun attestationCertChainPassesThrough() {
        val chain = listOf(byteArrayOf(0x30, 0x01), byteArrayOf(0x30, 0x02))
        val signer = KeystoreAttestSigner(JvmEcKeyHandle(chain))
        val out = signer.attestationCertChain()
        assertEquals(2, out.size)
        assertArrayEquals(chain[0], out[0])
        assertArrayEquals(chain[1], out[1])
    }

    @Test
    fun keystoreFailureBecomesTypedCallbackError() {
        val signer = KeystoreAttestSigner(ThrowingKeyHandle())
        val e = assertThrows(FfiException.Callback::class.java) { signer.sign(ByteArray(4)) }
        assertTrue(e.message.contains("attest signer sign failed"))
    }
}
