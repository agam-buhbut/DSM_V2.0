package com.dsm.android.core

import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.util.Date
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Off-device verification tests for [RealServerAttestVerifier].
 *
 * Synthetic fixtures (a throwaway EC CA + server leaf carrying the critical
 * noiseStaticBinding extension + a per-handshake binding signature) are minted
 * with BouncyCastle (a TEST-ONLY dependency — the production verifier uses only
 * `java.security`). Every rejection path the Python source enforces is covered
 * and asserted to fail closed.
 */
class ServerAttestVerifierTest {

    private val payloadSize = 2048
    private val codec = AttestPayloadCodec(payloadSize)

    private val now = Instant.parse("2026-06-30T12:00:00Z")
    private val validNotBefore = Date.from(now.minusSeconds(DAY))
    private val validNotAfter = Date.from(now.plusSeconds(DAY * 365))

    private val expectedCn = "dsm-test-server"
    private val bindingHash = ByteArray(32) { 0x5A }
    private val noiseStatic = ByteArray(32) { (it + 1).toByte() }

    private val caDn = X500Name("CN=Test DSM CA,O=DSM")
    private val caKey = ecKeyPair()
    private val caCert = buildCa(caDn, caKey)

    private fun verifier(
        caRoot: X509Certificate = caCert,
        cn: String = expectedCn,
    ): RealServerAttestVerifier =
        RealServerAttestVerifier(
            caRoot = caRoot,
            expectedServerCn = cn,
            codec = codec,
            clockSkewSeconds = 300,
            clock = { now },
        )

    @Test
    fun happyPathAccepted() {
        val leafKey = ecKeyPair()
        val leaf = buildLeaf(
            issuerDn = caDn,
            issuerKey = caKey.private,
            subjectCn = expectedCn,
            subjectKey = leafKey.public,
            notBefore = validNotBefore,
            notAfter = validNotAfter,
            noiseStatic = noiseStatic,
        )
        val payload = attestPayload(leaf.encoded, leafKey.private, noiseStatic, now.epochSecond)

        assertEquals(expectedCn, verifier().verify(payload, noiseStatic, bindingHash))
    }

    @Test
    fun wrongCnRejected() {
        val leafKey = ecKeyPair()
        val leaf = buildLeaf(
            issuerDn = caDn,
            issuerKey = caKey.private,
            subjectCn = "dsm-impostor-server",
            subjectKey = leafKey.public,
            notBefore = validNotBefore,
            notAfter = validNotAfter,
            noiseStatic = noiseStatic,
        )
        val payload = attestPayload(leaf.encoded, leafKey.private, noiseStatic, now.epochSecond)

        assertThrows(CnMismatchException::class.java) {
            verifier().verify(payload, noiseStatic, bindingHash)
        }
    }

    @Test
    fun expiredCertRejected() {
        val leafKey = ecKeyPair()
        val leaf = buildLeaf(
            issuerDn = caDn,
            issuerKey = caKey.private,
            subjectCn = expectedCn,
            subjectKey = leafKey.public,
            notBefore = Date.from(now.minusSeconds(2 * DAY)),
            notAfter = Date.from(now.minusSeconds(DAY)), // expired before `now`
            noiseStatic = noiseStatic,
        )
        val payload = attestPayload(leaf.encoded, leafKey.private, noiseStatic, now.epochSecond)

        val e = assertThrows(ServerAttestException::class.java) {
            verifier().verify(payload, noiseStatic, bindingHash)
        }
        assertTrue(e.message!!.contains("expired"))
    }

    @Test
    fun certNotSignedByPinnedRootRejected() {
        // A rogue CA that copies the pinned CA's subject DN but holds a different
        // key: the issuer DN matches, so this isolates the signature check.
        val rogueCa = ecKeyPair()
        val leafKey = ecKeyPair()
        val leaf = buildLeaf(
            issuerDn = caDn,
            issuerKey = rogueCa.private, // NOT the pinned CA key
            subjectCn = expectedCn,
            subjectKey = leafKey.public,
            notBefore = validNotBefore,
            notAfter = validNotAfter,
            noiseStatic = noiseStatic,
        )
        val payload = attestPayload(leaf.encoded, leafKey.private, noiseStatic, now.epochSecond)

        val e = assertThrows(ServerAttestException::class.java) {
            verifier().verify(payload, noiseStatic, bindingHash)
        }
        assertTrue(e.message!!.contains("does not verify under the pinned CA"))
    }

    @Test
    fun badBindingSignatureRejected() {
        val leafKey = ecKeyPair()
        val wrongKey = ecKeyPair() // signs the binding instead of the leaf key
        val leaf = buildLeaf(
            issuerDn = caDn,
            issuerKey = caKey.private,
            subjectCn = expectedCn,
            subjectKey = leafKey.public,
            notBefore = validNotBefore,
            notAfter = validNotAfter,
            noiseStatic = noiseStatic,
        )
        val payload = attestPayload(leaf.encoded, wrongKey.private, noiseStatic, now.epochSecond)

        val e = assertThrows(ServerAttestException::class.java) {
            verifier().verify(payload, noiseStatic, bindingHash)
        }
        assertTrue(e.message!!.contains("binding signature"))
    }

    @Test
    fun staleTimestampRejected() {
        val leafKey = ecKeyPair()
        val leaf = buildLeaf(
            issuerDn = caDn,
            issuerKey = caKey.private,
            subjectCn = expectedCn,
            subjectKey = leafKey.public,
            notBefore = validNotBefore,
            notAfter = validNotAfter,
            noiseStatic = noiseStatic,
        )
        // 301 s in the past — just outside the ±300 s window. The signature is
        // valid (it is over this same ts), so only the freshness check fails.
        val staleTs = now.epochSecond - 301
        val payload = attestPayload(leaf.encoded, leafKey.private, noiseStatic, staleTs)

        val e = assertThrows(ServerAttestException::class.java) {
            verifier().verify(payload, noiseStatic, bindingHash)
        }
        assertTrue(e.message!!.contains("timestamp"))
    }

    @Test
    fun wrongNoiseStaticBindingRejected() {
        val leafKey = ecKeyPair()
        val certStatic = ByteArray(32) { 0x11 } // bound into the cert extension
        val handshakeStatic = ByteArray(32) { 0x22 } // recovered from Noise (differs)
        val leaf = buildLeaf(
            issuerDn = caDn,
            issuerKey = caKey.private,
            subjectCn = expectedCn,
            subjectKey = leafKey.public,
            notBefore = validNotBefore,
            notAfter = validNotAfter,
            noiseStatic = certStatic,
        )
        // Sign over the handshake static so the binding signature itself verifies;
        // only the cert-extension-vs-handshake-static check must fail.
        val payload = attestPayload(leaf.encoded, leafKey.private, handshakeStatic, now.epochSecond)

        val e = assertThrows(ServerAttestException::class.java) {
            verifier().verify(payload, handshakeStatic, bindingHash)
        }
        assertTrue(e.message!!.contains("noiseStaticBinding"))
    }

    // --- fixture builders (BouncyCastle, test-only) ---------------------------

    private fun attestPayload(
        certDer: ByteArray,
        signingKey: PrivateKey,
        preImageStatic: ByteArray,
        ts: Long,
    ): ByteArray {
        val preImage = codec.bindingPreImage(
            timestamp = ts,
            handshakeHash = bindingHash,
            noiseStaticPub = preImageStatic,
            role = AttestPayloadCodec.PeerRole.RESPONDER,
        )
        val sig = Signature.getInstance("SHA256withECDSA").run {
            initSign(signingKey)
            update(preImage)
            sign()
        }
        return codec.frame(certDer, sig, ts)
    }

    private fun ecKeyPair(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()

    private fun buildCa(dn: X500Name, key: KeyPair): X509Certificate {
        val builder = JcaX509v3CertificateBuilder(
            dn,
            BigInteger(64, SecureRandom()),
            validNotBefore,
            validNotAfter,
            dn,
            key.public,
        )
        builder.addExtension(Extension.basicConstraints, true, BasicConstraints(true))
        builder.addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.keyCertSign))
        val signer = JcaContentSignerBuilder("SHA256withECDSA").build(key.private)
        return JcaX509CertificateConverter().getCertificate(builder.build(signer))
    }

    private fun buildLeaf(
        issuerDn: X500Name,
        issuerKey: PrivateKey,
        subjectCn: String,
        subjectKey: PublicKey,
        notBefore: Date,
        notAfter: Date,
        noiseStatic: ByteArray,
    ): X509Certificate {
        val builder = JcaX509v3CertificateBuilder(
            issuerDn,
            BigInteger(64, SecureRandom()),
            notBefore,
            notAfter,
            X500Name("CN=$subjectCn"),
            subjectKey,
        )
        builder.addExtension(Extension.basicConstraints, true, BasicConstraints(false))
        builder.addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.digitalSignature))
        builder.addExtension(
            Extension.extendedKeyUsage,
            false,
            ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth),
        )
        builder.addExtension(
            ASN1ObjectIdentifier(RealServerAttestVerifier.OID_NOISE_STATIC_BINDING),
            true,
            DEROctetString(noiseStatic),
        )
        val signer = JcaContentSignerBuilder("SHA256withECDSA").build(issuerKey)
        return JcaX509CertificateConverter().getCertificate(builder.build(signer))
    }

    private companion object {
        const val DAY = 86_400L
    }
}
