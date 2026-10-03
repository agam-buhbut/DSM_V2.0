package com.dsm.android

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import com.dsm.android.config.ProvisioningLayout
import com.dsm.android.config.ProvisioningLoader

/**
 * Minimal single-screen UI: a connect/disconnect button that drives the VPN
 * consent flow ([VpnService.prepare]) and starts/stops [DsmVpnService].
 *
 * Connect uses the B1 provisioning bundle in the app's private `filesDir`
 * ([ProvisioningLayout]); a device with no enrolled bundle shows a clear
 * "not provisioned" status instead of starting a tunnel that would fail closed.
 */
class MainActivity : Activity() {

    private lateinit var connectButton: Button
    private lateinit var statusText: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        statusText = findViewById(R.id.statusText)
        connectButton = findViewById(R.id.connectButton)
        connectButton.setOnClickListener { onConnectClicked() }
    }

    private fun onConnectClicked() {
        // VpnService.prepare returns a consent Intent the first time; null once granted.
        val consent = VpnService.prepare(this)
        if (consent != null) {
            startActivityForResult(consent, REQ_VPN_CONSENT)
        } else {
            onConsentGranted(Activity.RESULT_OK)
        }
    }

    @Deprecated("startActivityForResult is fine for a single foundation consent flow")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQ_VPN_CONSENT) {
            onConsentGranted(resultCode)
        }
    }

    private fun onConsentGranted(resultCode: Int) {
        if (resultCode != Activity.RESULT_OK) {
            statusText.text = getString(R.string.status_consent_denied)
            return
        }
        // The service loads the full provisioning bundle itself; here we only
        // pre-check so an un-enrolled device gets an actionable status rather
        // than a tunnel that immediately fails closed.
        if (!ProvisioningLoader(ProvisioningLayout.dir(filesDir)).isProvisioned()) {
            statusText.text = getString(R.string.status_not_provisioned)
            return
        }
        startService(Intent(this, DsmVpnService::class.java))
        statusText.text = getString(R.string.status_connecting)
    }

    private companion object {
        const val REQ_VPN_CONSENT = 1001
    }
}
