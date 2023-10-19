package com.android.mdl.appreader.issuerauth.vical

import java.lang.Exception

class VicalBuilderException : Exception {
    constructor(message: String?) : super(message) {}
    constructor(message: String?, cause: Throwable?) : super(message, cause) {}
}