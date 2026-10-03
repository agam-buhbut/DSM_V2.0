package com.dsm.android.config

import java.io.File
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.Date
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import uniffi.tuncore.IdentityKeyPair

/**
 * Off-device tests for the provisioning loader. The CA root is minted with
 * BouncyCastle (a TEST-ONLY dependency); the identity decrypt — the only step
 * that needs the native core — is exercised through the injectable
 * [IdentityDecryptor] seam so no `.so` is required.
 */
class ProvisioningTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val caKey: KeyPair = ecKeyPair()
    private val caDn = X500Name("CN=Test DSM CA,O=DSM")
    private val caCert: X509Certificate = buildCa(caDn, caKey)

    private val deviceCertDer = ByteArray(64) { (it + 1).toByte() }
    private val identityBlobBytes = ByteArray(48) { (0xF0 - it).toByte() }
    private val configText =
        """
        server_ip = "203.0.113.9"
        server_port = 51820
        expected_server_cn = "dsm-test-server"
        transport = "udp"
        identity_passphrase = "test-pass"
        """.trimIndent()

    /** Write a full, valid provisioning dir; returns the `dsm/` dir. */
    private fun provisioned(
        caRootName: String = ProvisioningLayout.CA_ROOT_PEM,
        caRootBytes: ByteArray = pem(caCert),
    ): File {
        val dir = tmp.newFolder("dsm")
        File(dir, ProvisioningLayout.CONFIG).writeText(configText)
        File(dir, ProvisioningLayout.IDENTITY_BLOB).writeBytes(identityBlobBytes)
        File(dir, ProvisioningLayout.DEVICE_CERT_DER).writeBytes(deviceCertDer)
        File(dir, caRootName).writeBytes(caRootBytes)
        return dir
    }

    @Test
    fun loadsFullBundle() {
        val prov = ProvisioningLoader(provisioned()).load()
        assertEquals("203.0.113.9", prov.config.serverIp)
        assertEquals(51820, prov.config.serverPort)
        assertEquals("dsm-test-server", prov.config.expectedServerCn)
        // Default mobile-provisioning knobs.
        assertEquals(DsmConfig.DEFAULT_KEYSTORE_ALIAS, prov.config.keystoreAlias)
        assertEquals(1360, prov.config.mtu)
        // Artifacts materialized verbatim.
        assertEquals(caCert.subjectX500Principal, prov.caRoot.subjectX500Principal)
        assertArrayEquals(deviceCertDer, prov.deviceCertDer)
    }

    @Test
    fun loadsCaRootFromDerVariant() {
        val prov = ProvisioningLoader(
            provisioned(caRootName = ProvisioningLayout.CA_ROOT_DER, caRootBytes = caCert.encoded),
        ).load()
        assertEquals(caCert.subjectX500Principal, prov.caRoot.subjectX500Principal)
    }

    @Test
    fun isProvisionedTrueOnlyWhenComplete() {
        val dir = provisioned()
        assertTrue(ProvisioningLoader(dir).isProvisioned())
        File(dir, ProvisioningLayout.IDENTITY_BLOB).delete()
        assertFalse(ProvisioningLoader(dir).isProvisioned())
    }

    @Test
    fun missingConfigFailsClosed() {
        val dir = provisioned()
        File(dir, ProvisioningLayout.CONFIG).delete()
        val e = assertThrows(ProvisioningException::class.java) { ProvisioningLoader(dir).load() }
        assertTrue(e.message!!.contains("config"))
    }

    @Test
    fun missingIdentityBlobFailsClosed() {
        val dir = provisioned()
        File(dir, ProvisioningLayout.IDENTITY_BLOB).delete()
        val e = assertThrows(ProvisioningException::class.java) { ProvisioningLoader(dir).load() }
        assertTrue(e.message!!.contains("identity"))
    }

    @Test
    fun missingDeviceCertFailsClosed() {
        val dir = provisioned()
        File(dir, ProvisioningLayout.DEVICE_CERT_DER).delete()
        val e = assertThrows(ProvisioningException::class.java) { ProvisioningLoader(dir).load() }
        assertTrue(e.message!!.contains("device certificate"))
    }

    @Test
    fun emptyDeviceCertFailsClosed() {
        val dir = provisioned()
        File(dir, ProvisioningLayout.DEVICE_CERT_DER).writeBytes(ByteArray(0))
        val e = assertThrows(ProvisioningException::class.java) { ProvisioningLoader(dir).load() }
        assertTrue(e.message!!.contains("empty"))
    }

    @Test
    fun missingCaRootFailsClosed() {
        val dir = provisioned()
        File(dir, ProvisioningLayout.CA_ROOT_PEM).delete()
        val e = assertThrows(ProvisioningException::class.java) { ProvisioningLoader(dir).load() }
        assertTrue(e.message!!.contains("CA root"))
    }

    @Test
    fun malformedConfigFailsClosed() {
        val dir = provisioned()
        // Missing the required server_port key.
        File(dir, ProvisioningLayout.CONFIG).writeText(
            "server_ip = \"1.2.3.4\"\nexpected_server_cn = \"srv\"",
        )
        val e = assertThrows(ProvisioningException::class.java) { ProvisioningLoader(dir).load() }
        assertTrue(e.message!!.contains("invalid client config"))
    }

    @Test
    fun unparseableCaRootFailsClosed() {
        val dir = provisioned()
        File(dir, ProvisioningLayout.CA_ROOT_PEM).writeBytes(byteArrayOf(0x00, 0x01, 0x02, 0x03))
        val e = assertThrows(ProvisioningException::class.java) { ProvisioningLoader(dir).load() }
        assertTrue(e.message!!.contains("CA root"))
    }

    @Test
    fun openIdentityPassesRightBlobAndPassphraseThenScrubs() {
        val prov = ProvisioningLoader(provisioned()).load()
        val cap = CapturingDecryptor()

        // The fake decrypt throws (it is not a real native decrypt), so the
        // attempt is wrapped fail-closed — but it still receives the inputs.
        val e = assertThrows(ProvisioningException::class.java) { prov.openIdentity(cap) }
        assertTrue(e.message!!.contains("identity"))

        // Correct blob + the configured passphrase reach the decryptor.
        assertArrayEquals(identityBlobBytes, cap.blob)
        assertArrayEquals("test-pass".toByteArray(), cap.passphraseSnapshot)
        // The passphrase array is zeroed after the attempt.
        assertArrayEquals(ByteArray(cap.passphraseRef!!.size), cap.passphraseRef)
    }

    @Test
    fun openIdentityUsesConfiguredPassphrase() {
        val dir = provisioned()
        File(dir, ProvisioningLayout.CONFIG).writeText(
            "$configText\nidentity_passphrase = \"custom-pass\"",
        )
        val prov = ProvisioningLoader(dir).load()
        val cap = CapturingDecryptor()
        assertThrows(ProvisioningException::class.java) { prov.openIdentity(cap) }
        assertArrayEquals("custom-pass".toByteArray(), cap.passphraseSnapshot)
    }

    /** Captures decrypt inputs, then throws (no real native decrypt off-device). */
    private class CapturingDecryptor : IdentityDecryptor {
        var blob: ByteArray? = null
        var passphraseRef: ByteArray? = null
        var passphraseSnapshot: ByteArray? = null

        override fun decrypt(blob: ByteArray, passphrase: ByteArray): IdentityKeyPair {
            this.blob = blob.copyOf()
            this.passphraseRef = passphrase
            this.passphraseSnapshot = passphrase.copyOf()
            throw RuntimeException("fake decryptor: not a real native decrypt")
        }
    }

    // --- BC fixtures (test-only) ----------------------------------------------

    private fun ecKeyPair(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()

    private fun buildCa(dn: X500Name, key: KeyPair): X509Certificate {
        val now = System.currentTimeMillis()
        val builder = JcaX509v3CertificateBuilder(
            dn,
            BigInteger(64, SecureRandom()),
            Date(now - 86_400_000L),
            Date(now + 86_400_000L * 365),
            dn,
            key.public,
        )
        builder.addExtension(Extension.basicConstraints, true, BasicConstraints(true))
        builder.addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.keyCertSign))
        val signer = JcaContentSignerBuilder("SHA256withECDSA").build(key.private)
        return JcaX509CertificateConverter().getCertificate(builder.build(signer))
    }

    private fun pem(cert: X509Certificate): ByteArray {
        val b64 = Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(cert.encoded)
        return "-----BEGIN CERTIFICATE-----\n$b64\n-----END CERTIFICATE-----\n".toByteArray()
    }
}
