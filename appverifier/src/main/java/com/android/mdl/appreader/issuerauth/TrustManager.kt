package com.android.mdl.appreader.issuerauth

import java.security.cert.PKIXCertPathChecker
import java.security.cert.X509Certificate

interface TrustManager {

    /**
     * Reset the [TrustManager] after adding new CA certificates or vicals
     */
    fun reset()

    /**
     * Verify a certificate chain (without the self-signed root certificate)
     * @return the complete certificate chain including the root certificate or throws an exception
     * if the verification fails
     */
    fun verify(chain: List<X509Certificate>): List<X509Certificate>

    /**
     * Verify a certificate chain (without the self-signed root certificate) by mDoc type
     * @return the complete certificate chain including the root certificate or throws an exception
     * if the verification fails
     */
    fun verify(mdocType: String, chain: List<X509Certificate>): List<X509Certificate>

    /**
     * * Verify a certificate chain (without the self-signed root certificate) by mDoc type with
     * the possibility of custom validations on the certificates (mdocAndCRLPathCheckers),
     * for instance the mDL country code
     * @return the complete certificate chain including the root certificate or throws an exception
     * if the verification fails
     */
    fun verify(
        mdocType: String,
        chain: List<X509Certificate>,
        mdocAndCRLPathCheckers: List<PKIXCertPathChecker>
    ): List<X509Certificate>
}