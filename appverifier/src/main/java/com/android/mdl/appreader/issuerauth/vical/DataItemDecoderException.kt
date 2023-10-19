package com.android.mdl.appreader.issuerauth.vical

import java.lang.Exception

class DataItemDecoderException : Exception {
    /**
     * Indicates that a problem occurred during the decoding of a VICAL or CertificateInfo field.
     * @param message the problem indication
     */
    constructor(message: String?) : super(message)

    /**
     * Indicates that a problem occurred during the decoding of a VICAL or CertificateInfo field.
     * @param message the problem indication
     * @param cause the cause of the problem, never null
     */
    constructor(message: String?, cause: Throwable?) : super(message, cause)

    companion object {
        private const val serialVersionUID = 1L
    }
}