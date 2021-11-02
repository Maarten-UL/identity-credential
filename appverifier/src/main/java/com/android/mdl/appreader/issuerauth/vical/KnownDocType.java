package com.android.mdl.appreader.issuerauth.vical;

import java.util.Optional;

/**
 * KnownDocType is a helper class that provides an easy-to-use enum for DocType and maps OID's to the DocTypes.
 * 
 * This helper class is not used in the API as it only captures some of the possible mappings from docType to keyUsage.
 * 
 * @author UL TS BV
 */
// TODO this mapping should probably be dynamic and configurable for a VICAL
public enum KnownDocType {
    MDL("org.iso.18013.5.1.mDL", "1.0.18013.5.1.7"),
    MEKB("nl.rdw.mekb.1", "2.16.528.1.1010.2.2.1"),
    MICOV("org.micov.1", "not.defined");

    private String docType;
    private String keyUsage;

    private KnownDocType(String docType, String keyUsage) {
        this.docType = docType;
        this.keyUsage = keyUsage;
    }

    /**
     * Retrieves the full DocType string (e.g. "org.iso.18013.5.1.mDL")
     * 
     * @return the full DocType
     */
    public String getDocType() {
        return docType;
    }

    /**
     * Retrieves the extended key usage for the specific DocType.
     * @return the extended key usage
     */
    public String getExtendedKeyUsage() {
        return keyUsage;
    }

    /**
     * Returns the DocType associated with the specific key usage OID, or empty if no document type has been configured.
     * @param keyUsage
     * @return
     */
    public static Optional<KnownDocType> forKeyUsage(String keyUsage) {
        for (KnownDocType docType : KnownDocType.values()) {
            if (docType.keyUsage.equalsIgnoreCase(keyUsage)) {
                return Optional.of(docType);
            }
        }
        return Optional.empty();
    }
}