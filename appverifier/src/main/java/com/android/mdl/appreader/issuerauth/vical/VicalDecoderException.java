package com.android.mdl.appreader.issuerauth.vical;

public class VicalDecoderException extends Exception {
    private static final long serialVersionUID = 1L;

    public VicalDecoderException(String message) {
        super(message);
    }
    
    public VicalDecoderException(String message, Throwable cause) {
        super(message, cause);
    }
}
