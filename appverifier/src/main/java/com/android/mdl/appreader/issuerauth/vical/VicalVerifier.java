package com.android.mdl.appreader.issuerauth.vical;

public interface VicalVerifier {

    VicalVerificationResult verifyCose1Signature(byte[] signatureWithData) throws Exception;
}