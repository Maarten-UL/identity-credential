package com.android.mdl.appreader.issuerauth.vical;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * A simple interface for the required and optional key values for the CertificateInfo key / value map.
 *   
 * @author UL TS BV
 */
public interface CertificateInfoKey extends Key {
    static final Map<String, CertificateInfoKey> ALL = new HashMap<>();
    
    public static Optional<CertificateInfoKey> forKeyName(String keyName) {
        for (RequiredCertificateInfoKey requiredKey : RequiredCertificateInfoKey.values()) {
            if (requiredKey.getKeyName().equals(keyName)) {
                return Optional.of(requiredKey);
            }
        }
        for (RequiredCertificateInfoKey optionalKey : RequiredCertificateInfoKey.values()) {
            if (optionalKey.getKeyName().equals(keyName)) {
                return Optional.of(optionalKey);
            }
        }
        return Optional.empty();
    }
}