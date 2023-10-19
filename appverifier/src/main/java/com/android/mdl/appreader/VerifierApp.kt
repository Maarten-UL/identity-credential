package com.android.mdl.appreader

import android.app.Application
import com.android.identity.android.util.AndroidLogPrinter
import com.android.identity.util.Logger
import androidx.preference.PreferenceManager
import com.android.mdl.appreader.issuerauth.CaCertificateStore
import com.android.mdl.appreader.issuerauth.TrustManager
import com.android.mdl.appreader.issuerauth.VicalStore
import com.android.mdl.appreader.settings.UserPreferences
import com.android.mdl.appreader.util.KeysAndCertificates
import com.google.android.material.color.DynamicColors
import java.security.cert.X509Certificate

class VerifierApp : Application() {

    private val userPreferences by lazy {
        val sharedPreferences = PreferenceManager.getDefaultSharedPreferences(this)
        UserPreferences(sharedPreferences)
    }

    private val caCertificateStore by lazy {
        CaCertificateStore(this)
    }

    private val vicalStore by lazy {
        VicalStore(this)
    }

    private val trustManager by lazy {
        TrustManager({ KeysAndCertificates.getTrustedIssuerCertificates(this) + caCertificateStoreInstance.getAll() },
            { vicalStoreInstance.getAll() })
    }

    override fun onCreate() {
        super.onCreate()
        Logger.setLogPrinter(AndroidLogPrinter())
        DynamicColors.applyToActivitiesIfAvailable(this)
        userPreferencesInstance = userPreferences
        caCertificateStoreInstance = caCertificateStore
        vicalStoreInstance = vicalStore
        trustManagerInstance = trustManager

    }

    companion object {

        private lateinit var userPreferencesInstance: UserPreferences
        lateinit var caCertificateStoreInstance: CaCertificateStore
        lateinit var vicalStoreInstance: VicalStore
        lateinit var trustManagerInstance: TrustManager

        fun isDebugLogEnabled(): Boolean {
            return userPreferencesInstance.isDebugLoggingEnabled()
        }
    }
}