package com.android.mdl.appreader.issuerauth.vical

import kotlin.Throws
import com.android.mdl.appreader.issuerauth.vical.VicalVerificationResult
import java.lang.Exception

interface VicalVerifier {
    @Throws(Exception::class)
    fun verifyCose1Signature(signatureWithData: ByteArray): VicalVerificationResult
}