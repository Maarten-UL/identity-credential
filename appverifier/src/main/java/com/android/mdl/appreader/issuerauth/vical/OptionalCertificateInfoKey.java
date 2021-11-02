package com.android.mdl.appreader.issuerauth.vical;

import java.util.EnumSet;
import java.util.Set;

public enum OptionalCertificateInfoKey implements Key, CertificateInfoKey {
    CERTIFICATE_PROFILE,
    ISSUING_AUTHORITY,
    ISSUING_COUNTRY,
    STATE_OR_PROVINCE_NAME,
    ISSUER,
    SUBJECT,
    NOT_BEFORE,
    NOT_AFTER,
    EXTENSIONS;
    
    private static Set<OptionalCertificateInfoKey> CERTIFICATE_BASED_FIELDS = EnumSet.of(CERTIFICATE_PROFILE, ISSUING_COUNTRY, STATE_OR_PROVINCE_NAME, ISSUER, SUBJECT, NOT_BEFORE, NOT_AFTER);
    
    public static Set<OptionalCertificateInfoKey> getCertificateBasedFields() {
        return CERTIFICATE_BASED_FIELDS;
    }
}
