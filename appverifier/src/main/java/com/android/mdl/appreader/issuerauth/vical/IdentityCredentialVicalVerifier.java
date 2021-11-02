package com.android.mdl.appreader.issuerauth.vical;

import java.security.cert.X509Certificate;
import java.util.List;

import co.nstant.in.cbor.model.DataItem;

public class IdentityCredentialVicalVerifier implements VicalVerifier {

    private static final byte[] NO_AAD = new byte[0];
    
    @Override
    public VicalVerificationResult verifyCose1Signature(byte[] signatureWithData) throws Exception {
        
        DataItem decoded;
        try {
            decoded = IdentityUtil.cborDecode(signatureWithData);
        } catch(Exception e) {
            return new VicalVerificationResult(VicalVerificationResult.Code.DECODING_ERROR, null, null);
        }
        
        List<X509Certificate> vicalSigningChain;
        try {
            vicalSigningChain = IdentityUtil.coseSign1GetX5Chain(decoded);
            
        } catch (Exception e) {
            return new VicalVerificationResult(VicalVerificationResult.Code.DECODING_ERROR, null, null);
        }

        // TODO maybe allow for more certs
        if (vicalSigningChain.isEmpty()) {
            return new VicalVerificationResult(VicalVerificationResult.Code.DECODING_ERROR, null, null);
        }

        // NOTE assumes leaf is first certificate
        X509Certificate vicalSigningCert = vicalSigningChain.get(0);

        boolean verificationResult = IdentityUtil.coseSign1CheckSignature(decoded, NO_AAD, vicalSigningCert.getPublicKey());
        VicalVerificationResult.Code code =
                verificationResult
                        ? VicalVerificationResult.Code.VERIFICATION_SUCCEEDED
                        : VicalVerificationResult.Code.VERIFICATION_FAILED;
        
        return new VicalVerificationResult(code, vicalSigningCert, decoded);
    }

}
