package com.android.mdl.appreader.settings

import java.security.cert.X509Certificate

data class CaCertificatesScreenState    (
    val certificates: List<CertificateItem> = emptyList()
) {

}