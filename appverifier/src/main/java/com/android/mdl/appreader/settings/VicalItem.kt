package com.android.mdl.appreader.settings

import com.android.mdl.appreader.issuerauth.vical.Vical


data class VicalItem(
    val title: String,
    val certificateItems: List<CertificateItem>,
    val vical: Vical?
) {
}