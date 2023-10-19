package com.android.mdl.appreader.issuerauth

import android.content.Context
import com.android.mdl.appreader.util.KeysAndCertificates
import org.bouncycastle.asn1.x500.X500Name
import java.security.cert.PKIXCertPathChecker
import java.security.cert.X509Certificate

/**
 * [TrustManager] class used for the verification of a certificate chain
 * Because of it's dependency of Context, this class should be used from VerifierApp.trustManagerInstance
 */
class TrustManager(private val context: Context, private val caCertificateStore: CaCertificateStore)  {
    private val certificatesForAllDocTypes: MutableMap<X500Name, X509Certificate>
    private val certificatesByDocType: MutableMap<String, MutableMap<X500Name, X509Certificate>>
    init{
        certificatesForAllDocTypes = HashMap()
        certificatesByDocType = HashMap()
        reset()
    }

    /**
     * Reset the [TrustManager] after adding or removing CA certificates and/or vicals
     */
    fun reset() {
        certificatesForAllDocTypes.clear()
        certificatesByDocType.clear()
        addCertificatesFromResources()
        addCertificatesFromStore()
        addVicalsFromStore()
    }

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
    ): List<X509Certificate> {
        val trustedRoot = findTrustedRoot(chain, mdocType)
            ?: throw Exception("Trusted root certificate could not be found")
        val completeChain = chain.toMutableList().plus(trustedRoot)
        validateCertificationTrustPath(completeChain, customValidators)
        return completeChain
    }

    private fun findTrustedRoot(chain: List<X509Certificate>, mdocType: String): X509Certificate? {
        chain.forEach { cert ->
            run {
                val name = X500Name(cert.issuerX500Principal.name)
                // look first in the certificates for all mdoc types
                if (certificatesForAllDocTypes.containsKey(name)) {
                    return certificatesForAllDocTypes[name]
                }
                // find the certificate by mdoc type
                if (certificatesByDocType.containsKey(mdocType) &&
                    certificatesByDocType[mdocType]?.containsKey(name) == true
                ) {
                    return certificatesByDocType[mdocType]?.get(name);
                }
            }
        }
        return null
    }

    private fun validateCertificationTrustPath(
        certificationTrustPath: List<X509Certificate>,
        customValidators: List<PKIXCertPathChecker>
    ) {
        val certIterator = certificationTrustPath.iterator()
        val leafCert = certIterator.next()
        CertificateValidations.checkKeyUsageDocumentSigner(leafCert)
        CertificateValidations.checkValidity(leafCert)
        CertificateValidations.executeCustomValidations(leafCert, customValidators)

        // Note that the signature of the trusted certificate itself is not verified even if it is self signed
        var prevCert = leafCert
        var caCert: X509Certificate
        while (certIterator.hasNext()) {
            caCert = certIterator.next()
            CertificateValidations.checkKeyUsageCaCertificate(caCert)
            CertificateValidations.checkCaIsIssuer(prevCert, caCert)
            CertificateValidations.verifySignature(prevCert, caCert)
            CertificateValidations.executeCustomValidations(caCert, customValidators)
            prevCert = caCert
        }
    }
    private fun addCertificatesFromResources() {
        KeysAndCertificates.getTrustedIssuerCertificates(context).forEach { cert ->
            run {
                val name = X500Name(cert.subjectX500Principal.name)
                if (!certificateExists(name)) {
                    certificatesForAllDocTypes[name] = cert
                }
            }
        }
    }

    private fun addCertificatesFromStore() {
        caCertificateStore.getAll().forEach { cert ->
            run {
                val name = X500Name(cert.subjectX500Principal.name)
                if (!certificateExists(name)) {
                    certificatesForAllDocTypes[name] = cert
                }
            }
        }
    }

    private fun addVicalsFromStore() {
        // TODO: get certificates by mdoc type from the vicals
        // VicalStore.getAll(context)
    }

    private fun certificateExists(name: X500Name): Boolean {
        if (certificatesForAllDocTypes.containsKey(name)) {
            return true
        }
        certificatesByDocType.forEach { entry ->
            if (entry.value.containsKey(name)) {
                return true
            }
        }
        return false
    }
}