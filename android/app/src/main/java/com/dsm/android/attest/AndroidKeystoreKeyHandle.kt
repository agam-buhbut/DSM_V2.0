package com.dsm.android.attest

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import androidx.annotation.RequiresApi
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * Production [KeyHandle] backed by an EC P-256 key in the Android Keystore.
 *
 * The key is generated non-extractably, with an attestation challenge so the
 * Keystore emits a hardware key-attestation certificate chain rooted at Google.
 * StrongBox (a discrete tamper-resistant secure element) is requested on API 28+
 * and the build falls back to TEE-backed keymint when StrongBox is unavailable.
 * On API 28+ the key is additionally bound to an unlocked device
 * (`setUnlockedDeviceRequired`), so it cannot be exercised while the device is
 * locked.
 *
 * This class is exercised on-device (Phase B / A7); off-device unit tests use a
 * JVM fake [KeyHandle] instead, since "AndroidKeyStore" is not a host JVM
 * provider.
 */
class AndroidKeystoreKeyHandle private constructor(
    private val alias: String,
) : KeyHandle {

    override fun signEcdsaDer(message: ByteArray): ByteArray {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val privateKey = ks.getKey(alias, null) as PrivateKey
        return Signature.getInstance(SIGN_ALGORITHM).run {
            initSign(privateKey)
            update(message)
            sign()
        }
    }

    override fun spkiDer(): ByteArray {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val cert = ks.getCertificate(alias)
            ?: throw IllegalStateException("no certificate for keystore alias $alias")
        // X.509 public-key encoding is exactly a SubjectPublicKeyInfo DER.
        return cert.publicKey.encoded
    }

    override fun attestationChainDer(): List<ByteArray> {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val chain = ks.getCertificateChain(alias)
            ?: throw IllegalStateException("no attestation chain for keystore alias $alias")
        return chain.map { it.encoded }
    }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val SIGN_ALGORITHM = "SHA256withECDSA"
        const val DEFAULT_ALIAS = "dsm_attest_p256"

        /**
         * Open an EXISTING Keystore key under [alias] without regenerating it.
         *
         * The B1 enroll already generated + attested this key (its attestation
         * challenge is the Noise static, and the issued device cert's
         * noiseStaticBinding is pinned to that static). Regenerating would mint a
         * fresh, differently-attested key and invalidate the issued cert, so a
         * connect MUST reopen the same alias. Fails closed if the alias is absent
         * (device not enrolled).
         *
         * @throws IllegalStateException if the alias does not exist.
         */
        @JvmStatic
        fun open(alias: String): AndroidKeystoreKeyHandle {
            val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            if (!ks.containsAlias(alias)) {
                throw IllegalStateException(
                    "keystore alias '$alias' not found; run B1 enroll on this device first",
                )
            }
            return AndroidKeystoreKeyHandle(alias)
        }

        @JvmStatic
        fun generate(
            alias: String = DEFAULT_ALIAS,
            attestationChallenge: ByteArray,
            preferStrongBox: Boolean = true,
        ): AndroidKeystoreKeyHandle {
            val strongBox =
                preferStrongBox &&
                    Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
                    tryGenerate(alias, attestationChallenge, strongBox = true)
            if (!strongBox) {
                generateKey(alias, attestationChallenge, strongBox = false)
            }
            return AndroidKeystoreKeyHandle(alias)
        }

        @RequiresApi(Build.VERSION_CODES.P)
        private fun tryGenerate(
            alias: String,
            challenge: ByteArray,
            strongBox: Boolean,
        ): Boolean =
            try {
                generateKey(alias, challenge, strongBox)
                true
            } catch (e: StrongBoxUnavailableException) {
                // Device has no StrongBox keymint; caller falls back to TEE.
                false
            }

        private fun generateKey(alias: String, challenge: ByteArray, strongBox: Boolean) {
            val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(challenge)
                .apply {
                    if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                        setIsStrongBoxBacked(true)
                    }
                    // AND-5: bind key USE to an unlocked device, so a lost or
                    // locked device cannot exercise the attestation signing key.
                    // The key is used only during the connect handshake
                    // (open() + signEcdsaDer), when the user has just unlocked the
                    // device to connect. Available on API 28+ (the StrongBox
                    // baseline), so it is guarded by the same version check.
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                        setUnlockedDeviceRequired(true)
                    }
                }
                .build()
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE).run {
                initialize(spec)
                generateKeyPair()
            }
        }
    }
}
