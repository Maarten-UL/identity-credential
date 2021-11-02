package com.android.mdl.appreader.issuerauth.vical;

import java.security.cert.CertificateEncodingException;

/**
 * Uses COSE signatures to 
 * @author UL TS BV
 *
 */
public interface VicalSigner {

    /**
     * Creates a signed COSE v1 signature container from the provided <code>vicalData</code>, which is included within the signature.
     * 
     * @param vicalData A byte array containing the data to be signed.
     * @return A byte array containing the COSE v1 signature container
     */
    byte[] createCose1Signature(byte[] vicalData)
            throws CertificateEncodingException;

}