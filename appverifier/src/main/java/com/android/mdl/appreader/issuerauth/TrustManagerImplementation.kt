package com.android.mdl.appreader.issuerauth

import android.content.Context
import com.android.mdl.appreader.VerifierApp
import com.android.mdl.appreader.util.KeysAndCertificates
import org.bouncycastle.asn1.x500.X500Name
import java.security.cert.PKIXCertPathChecker
import java.security.cert.X509Certificate

/**
 * Implementation of the TrustManager interface
 * Because of it's dependency of Context, this class should be used from VerifierApp.trustManagerInstance
 */
class TrustManagerImplementation(val context: Context) : TrustManager {
    private val certificatesForAllDocTypes: MutableMap<X500Name, X509Certificate>
    private val certificatesByDocType: MutableMap<String, MutableMap<X500Name, X509Certificate>>
    init{
        certificatesForAllDocTypes = HashMap()
        certificatesByDocType = HashMap()
        reset()
    }
    override fun reset() {
        certificatesForAllDocTypes.clear()
        certificatesByDocType.clear()
        addCertificatesFromResources()
        addCertificatesFromStore()
        addVicalsFromStore()
    }

    override fun verify(
        chain: List<X509Certificate>,
        mdocType: String,
        customValidators: List<PKIXCertPathChecker>
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
        VerifierApp.caCertificateStoreInstance.getAll().forEach { cert ->
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