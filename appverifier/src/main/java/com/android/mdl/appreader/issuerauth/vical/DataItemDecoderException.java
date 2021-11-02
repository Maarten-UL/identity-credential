package com.android.mdl.appreader.issuerauth.vical;

public class DataItemDecoderException extends Exception {

    private static final long serialVersionUID = 1L;

    /**
     * Indicates that a problem occurred during the decoding of a VICAL or CertificateInfo field.
     * @param message the problem indication
     */
    public DataItemDecoderException(String message) {
        super(message);
    }

    /**
     * Indicates that a problem occurred during the decoding of a VICAL or CertificateInfo field.
     * @param message the problem indication
     * @param cause the cause of the problem, never null
     */
    public DataItemDecoderException(String message, Throwable cause) {
        super(message, cause);
    }
}
