package com.android.mdl.appreader.issuerauth

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.style.BCStyle
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.security.cert.PKIXCertPathChecker
import java.security.cert.X509Certificate

class CountryValidator : PKIXCertPathChecker() {
    private var previousCountryCode: String = ""
    override fun init(p0: Boolean) {
        // intentionally left empty
    }

    override fun isForwardCheckingSupported(): Boolean {
        return true
    }

    override fun check(certificate: Certificate?, state: MutableCollection<String>?) {
        if (certificate is X509Certificate) {
            val countryCode = readCountryCode(certificate)
            if (countryCode.isBlank()) {
                throw CertificateException("Country code is not present in certificate " + certificate.subjectX500Principal.name)
            }
            if (previousCountryCode.isNotBlank() && previousCountryCode.uppercase() != countryCode.uppercase()) {
                throw CertificateException("There are different country codes in the certificate chain: $previousCountryCode and $countryCode")
            } else {
                previousCountryCode = countryCode
            }
        }
    }

    override fun getSupportedExtensions(): MutableSet<String> {
        return mutableSetOf()
    }

    private fun readCountryCode(certificate: X509Certificate): String {
        val name = X500Name(certificate.subjectX500Principal.name)
        for (rdn in name.getRDNs(BCStyle.C)) {
            val attributes = rdn.typesAndValues
            for (attribute in attributes) {
                return attribute.value.toString()
            }
        }
        return ""
    }
}