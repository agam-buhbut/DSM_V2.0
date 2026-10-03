package com.dsm.android.core

import com.dsm.android.attest.KeyHandle
import com.dsm.android.attest.KeystoreAttestSigner
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Date
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Verifies the connect-path wiring selects the right verifier / signer from the
 * provisioned inputs, off-device (no FFI, no Keystore: the signing [KeyHandle]
 * is a JVM fake, the A6 seam).
 */
class HandshakeWiringTest {

    private val caCert: X509Certificate = selfSignedCa()
    private val certDer = ByteArray(40) { (it + 3).toByte() }
    private val spki = ByteArray(16) { 0x5C }

    @Test
    fun selectsRealVerifierAndKeystoreSigner() {
        val fakeKey = FakeKeyHandle(spki)
        val inputs = buildHandshakeInputs(
            caRoot = caCert,
            deviceCertDer = certDer,
            expectedServerCn = "dsm-wiring-server",
            codec = AttestPayloadCodec(512),
            keyHandle = fakeKey,
        )

        // CA-pinned real server verifier is wired in.
        assertTrue(inputs.serverVerifier is RealServerAttestVerifier)
        // Client attest signer wraps the provided KeyHandle: the signer's SPKI is
        // exactly the fake key's, proving the right key was wired in.
        assertTrue(inputs.signer is KeystoreAttestSigner)
        assertArrayEquals(spki, inputs.signer.publicSpkiDer())

        assertArrayEquals(certDer, inputs.deviceCertDer)
        assertEquals("dsm-wiring-server", inputs.expectedServerCn)
    }

    /** JVM fake of the hardware signing key (never touches AndroidKeyStore). */
    private class FakeKeyHandle(private val spki: ByteArray) : KeyHandle {
        override fun signEcdsaDer(message: ByteArray): ByteArray = ByteArray(0)
        override fun spkiDer(): ByteArray = spki
        override fun attestationChainDer(): List<ByteArray> = emptyList()
    }

    private fun selfSignedCa(): X509Certificate {
        val key: KeyPair = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()
        val dn = X500Name("CN=Test DSM CA")
        val now = System.currentTimeMillis()
        val builder = JcaX509v3CertificateBuilder(
            dn,
            BigInteger(64, SecureRandom()),
            Date(now - 86_400_000L),
            Date(now + 86_400_000L),
            dn,
            key.public,
        )
        val signer = JcaContentSignerBuilder("SHA256withECDSA").build(key.private)
        return JcaX509CertificateConverter().getCertificate(builder.build(signer))
    }
}
