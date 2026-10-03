package com.dsm.android

import android.util.Base64
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.dsm.android.attest.AndroidKeystoreKeyHandle
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.tuncore.IdentityKeyPair

/**
 * Phase B/A7 fixture: on the device, generate the DSM Noise static (UniFFI),
 * attest a hardware Keystore signing key whose attestation challenge IS that
 * Noise static (so the server-side A5 binding check holds), and dump everything
 * (base64) to logcat. The host then runs the real attestation chain through the
 * A5 verifier and issues a DSM device cert (B1 enroll). Not an assertion test.
 */
@RunWith(AndroidJUnit4::class)
class AttestExtractionTest {

    @Test
    fun dumpRealEnrollment() {
        // 1) DSM Noise static (X25519) generated on-device.
        val identity = IdentityKeyPair.generate()
        val noiseStatic = identity.publicKey() // 32 bytes — the attest challenge

        // 2) Hardware Keystore signing key attested to that Noise static.
        val handle = AndroidKeystoreKeyHandle.generate(
            alias = "dsm_b1_real",
            attestationChallenge = noiseStatic,
            preferStrongBox = true,
        )

        Log.i(TAG, "BEGIN")
        Log.i(TAG, "SPKI=${b64(handle.spkiDer())}")
        handle.attestationChainDer().forEachIndexed { i, der ->
            Log.i(TAG, "CHAIN$i=${b64(der)}")
        }
        Log.i(TAG, "END")
    }

    private fun b64(b: ByteArray): String = Base64.encodeToString(b, Base64.NO_WRAP)

    private companion object {
        const val TAG = "DSM_ATTEST"
    }
}
