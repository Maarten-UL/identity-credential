package com.android.mdl.appreader.issuerauth.vical;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.util.encoders.Hex;

import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.DataItem;

/**
 * A COSE1 signature within ISO/IEC 18013-5 consists of a structure which consists of an algorithm specification
 * in the protected parameters, a single leaf certificate and the encapsulated data.
 * 
 * This result structure consists of an error code which is always <code>VERIFICATION_SUCCEEDED</code> if
 * the signature verification was successful, or one of the other error codes if verification failed. Some implementations
 * may return more precise information than others; implementations should at least offer VERIFICATION_SUCCEEDED,
 * VERIFICATION_FAILED if the signature doesn't match and DECODING_ERROR as fallback.
 * 
 * If verification was successful then the {@link VicalVerificationResult#signingCertificate} and
 * {@link VicalVerificationResult#content}methods should return the certificate and content, otherwise these
 * fields may return <code>null</code>.
 *  
 * @author UL TS BV
 *
 */
public class VicalVerificationResult {
    private static final int SHA1_HASH_OUTPUT_SIZE = 20;

    public enum Code {
        VERIFICATION_SUCCEEDED,
        DECODING_ERROR,
        CERTIFICATE_NOT_FOUND,
        DATA_NOT_INCLUDED,
        VERIFICATION_FAILED,
        UNKNOWN_SIGNING_ALGORITHM,
        PUBLIC_KEY_DOESNT_MATCH_ALGORITHM;
    }

    private Code code;
    private X509Certificate signingCertificate;
    
    // TODO check if CBOR level data is more efficient
    private DataItem content;
    
    VicalVerificationResult(Code code, X509Certificate signingCertificate, DataItem content) {
        super();
        this.code = code;
        this.signingCertificate = signingCertificate;
        this.content = content;
    }

    public Code code() {
        return code;
    }

    public X509Certificate signingCertificate() {
        return signingCertificate;
    }

    public DataItem content() {
        return content;
    }
    
    @Override
    public String toString() {
        
        MessageDigest sha1;
        try {
            sha1 = MessageDigest.getInstance("SHA1");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-1 should always be available, security configuration error", e);
        }

        String hashOverCertificate;
        if (signingCertificate != null) {
            try {
                hashOverCertificate = Hex.toHexString(sha1.digest(signingCertificate.getEncoded()));
            } catch (CertificateEncodingException e) {
                hashOverCertificate = "[Certificate encoding failed]";
            }
        } else {
            hashOverCertificate = "[No certificate available]";
        }

        String hashOverContent;
        if (content != null) { 
            try (ByteArrayOutputStream hashOutput = new ByteArrayOutputStream(SHA1_HASH_OUTPUT_SIZE)) {
                CborEncoder encoder = new CborEncoder(new DigestOutputStream(hashOutput, sha1));
                encoder.encode(content);
                hashOverContent = Hex.toHexString(sha1.digest());
            } catch (IOException e) {
                throw new RuntimeException("ByteArrayOutputStream should not throw an I/O exception", e);
            } catch (CborException e) {
                hashOverContent = "[Content encoding failed]";
            }
            
        } else {
            hashOverContent = "[No content available]";
        }
        
        return String.format("Verification result: %s, certificate hash: %s, VICAL hash: %s",
                code, hashOverCertificate, hashOverContent);
    }
}
