package com.android.mdl.appreader.issuerauth

import java.security.cert.PKIXCertPathChecker
import java.security.cert.X509Certificate

interface TrustManager {

    /**
     * Reset the [TrustManager] after adding or removing CA certificates and/or vicals
     */
    fun reset()

    /**
     * * Verify a certificate chain (without the self-signed root certificate) by mDoc type with
     * the possibility of custom validations on the certificates (mdocAndCRLPathCheckers),
     * for instance the mDL country code
     * @param [chain] the certificate chain without the self-signed root certificate
     * @param [mdocType] optional parameter mdocType. If left blank, the certificates that are not
     * specific for any mDoc type will be used
     * @param [customValidators] optional parameter with custom validators
     * @return the complete certificate chain including the root certificate or throws an exception
     * if the verification fails
     */
    fun verify(
        chain: List<X509Certificate>,
        mdocType: String = "",
        customValidators: List<PKIXCertPathChecker> = emptyList()
    ): List<X509Certificate>
}