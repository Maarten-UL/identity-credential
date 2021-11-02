package com.android.mdl.appreader.issuerauth.vical;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collections;

import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.DataItem;

/**
 * Can be used to generate a COSE1 signature over data.
 * 
 * The certificate and data will be included in the CBOR envelope according to ISO/IEC 18013-5.
 * The protected header in the signing structure will contain the algorithm indication:
 * <pre>
 * [
 *     "Signature1",
 *     {
 *         "type": "Buffer",
 *         "data": [
 *             161,
 *             1,
 *             38
 *         ]
 *     },
 *     {
 *         "type": "Buffer",
 *         "data": []
 *     },
 *     {
 *         "type": "Buffer",
 *         "data": [
 *             0
 *         ]
 *     }
 * ]
 * </pre>
 * 
 * @author UL TS BV
 */
public class IdentityCredentialVicalSigner implements VicalSigner {

    private X509Certificate signCert;
    private PrivateKey signKey;
    private String signatureAlgorithm;

    
    
    public IdentityCredentialVicalSigner(X509Certificate signCert, PrivateKey signKey, String signatureAlgorithm) {
        this.signCert = signCert;
        this.signKey = signKey;
        this.signatureAlgorithm = signatureAlgorithm;
    }

    @Override
    public byte[] createCose1Signature(byte[] vicalData) throws CertificateEncodingException {
        
        DataItem signedData = IdentityUtil.coseSign1Sign(signKey, signatureAlgorithm, vicalData, null, Collections.singletonList(signCert));
        try (ByteArrayOutputStream outStream = new ByteArrayOutputStream()) {
            CborEncoder enc = new CborEncoder(outStream);
            enc.encode(signedData);
            return outStream.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("ByteArrayOutputStream should not throw I/O exceptions", e);
        } catch (CborException e) {
            // TODO provide better runtime exception
            throw new RuntimeException("Error encoding newly generated signature", e);
        }
    }

}
