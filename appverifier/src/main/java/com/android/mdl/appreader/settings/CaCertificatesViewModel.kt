package com.android.mdl.appreader.settings

import android.content.Context
import androidx.compose.ui.text.toUpperCase
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import com.android.identity.internal.Util
import com.android.mdl.appreader.VerifierApp
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DERPrintableString
import org.bouncycastle.asn1.x500.RDN
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.X509Name
import org.bouncycastle.jce.PrincipalUtil
import java.lang.StringBuilder
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.time.LocalDateTime

class CaCertificatesViewModel(val context: Context) : ViewModel() {

    private val _screenState = MutableStateFlow(CaCertificatesScreenState())
    val screenState: StateFlow<CaCertificatesScreenState> = _screenState.asStateFlow()

    private val _currentCertificateItem = MutableStateFlow<CertificateItem?>(null)
    val currentCertificateItem = _currentCertificateItem.asStateFlow()
    fun loadCertificates() {
        val certificates = VerifierApp.caCertificateStoreInstance.getAll().map { convert(it) }
        _screenState.update { it.copy(certificates = certificates) }
    }

    fun setCurrentCertificateItem(certificateItem: CertificateItem) {
        _currentCertificateItem.update { certificateItem }
    }

    fun deleteCertificate() {
        _currentCertificateItem.value?.certificate?.let { VerifierApp.caCertificateStoreInstance.delete(it) }
    }

    companion object {
        fun factory(context: Context): ViewModelProvider.Factory {
            return viewModelFactory {
                initializer { CaCertificatesViewModel(context) }
            }
        }
    }

    private fun convert(certificate: X509Certificate): CertificateItem {
        val subject = X500Name(certificate.subjectX500Principal.name)
        val issuer = X500Name(certificate.issuerX500Principal.name)
        val sha255Fingerprint = hexWithSpaces(
            MessageDigest.getInstance("SHA-256").digest(
                certificate.encoded
            )
        );
        val sha1Fingerprint = hexWithSpaces(
            MessageDigest.getInstance("SHA-1").digest(
                certificate.encoded
            )
        );

        return CertificateItem(
            title = certificate.subjectX500Principal.name,
            commonNameSubject = readRdn(subject, BCStyle.CN),
            organisationSubject = readRdn(subject, BCStyle.O),
            organisationalUnitSubject = readRdn(subject, BCStyle.OU),
            commonNameIssuer = readRdn(issuer, BCStyle.CN),
            organisationIssuer = readRdn(issuer, BCStyle.O),
            organisationalUnitIssuer = readRdn(issuer, BCStyle.OU),
            notBefore = certificate.notBefore,
            notAfter = certificate.notAfter,
            sha255Fingerprint = sha255Fingerprint,
            sha1Fingerprint = sha1Fingerprint,
            certificate = certificate
        )
    }

    private fun readRdn(name: X500Name, field: ASN1ObjectIdentifier): String {
        for (rdn in name.getRDNs(field)) {
            val attributes = rdn.typesAndValues
            for (attribute in attributes) {
                return attribute.value.toString()
            }
        }
        return "<Not part of certificate>"
    }

    private fun hexWithSpaces(byteArray: ByteArray): String {
        val stringBuilder = StringBuilder()
        byteArray.forEach {
            if (stringBuilder.length > 0){
                stringBuilder.append(" ")
            }
            stringBuilder.append(String.format("%02X", it))
        }
        return stringBuilder.toString()
    }

}