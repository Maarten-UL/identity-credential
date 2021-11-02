package com.android.mdl.appreader.issuerauth.vical;

import co.nstant.in.cbor.model.UnicodeString;

/**
 * Represents a (UnicodeString) key in a CDDL defined MAP.
 * This interface automatically converts the enum identifiers to camelCase identifiers used in the CBOR structures.
 * 
 * @author UL TS BV
 */
public interface Key {
    public static String enumToKeyName(String enumName) {
        StringBuilder keyNameSB = new StringBuilder(); 
        String[] elts = enumName.split("_");
        keyNameSB.append(elts[0].toLowerCase());
        for (int i = 1; i < elts.length; i++) {
            String keyName = elts[i];
            keyNameSB.append(keyName.charAt(0));
            keyNameSB.append(keyName.substring(1).toLowerCase());
        }
        return keyNameSB.toString();
    }

    public static String keyNameToEnum(String keyName) {
        StringBuilder enumSB = new StringBuilder();
        // positive lookahead for an uppercase character, i.e. not part of the match
        String[] elts = keyName.split("(?=\\p{Lu})");
        enumSB.append(elts[0].toUpperCase());
        for (int i = 1; i < elts.length; i++) {
            String enumName = elts[i];
            enumSB.append("_");
            enumSB.append(enumName.toUpperCase());
        }
        return enumSB.toString();
    }
    
    /**
     * Always implemented by enums, required to access it using the default methods.
     * 
     * @return the name of the enum
     */
    String name();
    
    /**
     * Gets the name of the key, also returned as UnicodeString.
     * 
     * @return the name of the key in camelCase, e.g. <code>DOC_TYPE -> docType</code>
     */
    default String getKeyName() {
        StringBuilder keyNameSB = new StringBuilder(); 
        String[] elts = this.name().split("_");
        keyNameSB.append(elts[0].toLowerCase());
        for (int i = 1; i < elts.length; i++) {
            String keyName = elts[i];
            keyNameSB.append(keyName.charAt(0));
            keyNameSB.append(keyName.substring(1).toLowerCase());
        }
        return keyNameSB.toString();
    }

    /**
     * The name of the key as UnicodeString, @see #getKeyName()
     * 
     * @return the name of the key in camelCase, e.g. <code>DOC_TYPE -> docType</code>, wrapped by a UnicodeString
     */
    default UnicodeString getUnicodeString() {
        return new UnicodeString(getKeyName());
    }

    // TODO move to tests
    public static void main(String[] args) {
        String one = enumToKeyName(OptionalCertificateInfoKey.STATE_OR_PROVINCE_NAME.name());
        System.out.println(one);
        String two = keyNameToEnum(one);
        System.out.println(two);
    }
}