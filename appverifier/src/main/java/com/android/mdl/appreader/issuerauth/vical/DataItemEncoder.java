package com.android.mdl.appreader.issuerauth.vical;

import co.nstant.in.cbor.model.DataItem;

/**
 * This interface establishes the contract for the internal {@link Vical} and {@link CertificateInfo} encoders.
 * 
 * The interface is specific to the co.nstant.in.cbor CBOR package. 
 * @author UL TS BV
 *
 * @param <DI>
 * @param <T>
 */
public interface DataItemEncoder<DI extends DataItem, T> {
    /**
     * Encodes the provided data of type T into a DataItem of type DI.
     * 
     * @param t the data to be encoded
     * @return a DataItem of type DI
     */
    DI encode(T t);
    
    /**
     * 
     * 
     * @param t
     * @return
     */
    default byte[] encodeToBytes(T t) {
        DI di = encode(t);
        return IdentityUtil.cborEncode(di);
    }
}
