package com.android.mdl.appreader.issuerauth.vical;

public class VicalBuilderException extends Exception {
    private static final long serialVersionUID = 1L;

    public VicalBuilderException(String message) {
        super(message);
    }
    
    public VicalBuilderException(String message, Throwable cause) {
        super(message, cause);
    }
}
