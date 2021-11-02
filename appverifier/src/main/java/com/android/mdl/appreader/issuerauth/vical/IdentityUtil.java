/*
 * Copyright 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.mdl.appreader.issuerauth.vical;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECField;
import java.security.spec.ECPoint;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequenceGenerator;
import org.bouncycastle.util.Bytes;
import org.bouncycastle.util.encoders.Hex;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.builder.ArrayBuilder;
import co.nstant.in.cbor.builder.MapBuilder;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.MajorType;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.NegativeInteger;
import co.nstant.in.cbor.model.Number;
import co.nstant.in.cbor.model.SimpleValue;
import co.nstant.in.cbor.model.SimpleValueType;
import co.nstant.in.cbor.model.SpecialType;
import co.nstant.in.cbor.model.UnicodeString;
import co.nstant.in.cbor.model.UnsignedInteger;

/**
 * Utility functions.
 */
class IdentityUtil {
    private static final long COSE_LABEL_ALG = 1;
    private static final long COSE_LABEL_X5CHAIN = 33; // temporary identifier
    // From RFC 8152: Table 5: ECDSA Algorithm Values
    private static final long COSE_ALG_ECDSA_256 = -7;
    private static final long COSE_ALG_ECDSA_384 = -35;
    private static final long COSE_ALG_ECDSA_512 = -36;
    private static final long COSE_ALG_HMAC_256_256 = 5;
    private static final long CBOR_SEMANTIC_TAG_ENCODED_CBOR = 24;
    private static final long COSE_KEY_KTY = 1;
    private static final long COSE_KEY_TYPE_EC2 = 2;
    private static final long COSE_KEY_EC2_CRV = -1;
    private static final long COSE_KEY_EC2_X = -2;
    private static final long COSE_KEY_EC2_Y = -3;
    private static final long COSE_KEY_EC2_CRV_P256 = 1;

    // Not called.
    private IdentityUtil() {
    }

    static byte[] cborEncode(DataItem dataItem) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            new CborEncoder(baos).encode(dataItem);
        } catch (CborException e) {
            // This should never happen and we don't want cborEncode() to throw since that
            // would complicate all callers. Log it instead.
            throw new IllegalStateException("Unexpected failure encoding data", e);
        }
        return baos.toByteArray();
    }

    static byte[] cborEncodeWithoutCanonicalizing(DataItem dataItem) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            new CborEncoder(baos).nonCanonical().encode(dataItem);
        } catch (CborException e) {
            // This should never happen and we don't want cborEncode() to throw since that
            // would complicate all callers. Log it instead.
            throw new IllegalStateException("Unexpected failure encoding data", e);
        }
        return baos.toByteArray();
    }

    static byte[] cborEncodeBoolean(boolean value) {
        return cborEncode(new CborBuilder().add(value).build().get(0));
    }

    static byte[] cborEncodeString(String value) {
        return cborEncode(new CborBuilder().add(value).build().get(0));
    }

    static byte[] cborEncodeNumber(long value) {
        return cborEncode(new CborBuilder().add(value).build().get(0));
    }

    static byte[] cborEncodeBytestring(byte[] value) {
        return cborEncode(new CborBuilder().add(value).build().get(0));
    }

    // Used Timestamp: Android API version of Instant
    static byte[] cborEncodeDateTime(Instant timestamp) {
        return cborEncode(cborBuildDateTime(timestamp));
    }

    /**
     * Returns #6.0(tstr) where tstr is the ISO 8601 encoding of the given point in time.
     * Only supports UTC times.
     */
    // Used Timestamp: Android API version of Instant
    static DataItem cborBuildDateTime(Instant timestamp) {
        SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX", Locale.US);
        df.setTimeZone(TimeZone.getTimeZone("UTC"));
        Date val = new Date(timestamp.toEpochMilli());
        String dateString = df.format(val);
        DataItem dataItem = new UnicodeString(dateString);
        dataItem.setTag(0);
        return dataItem;
    }

    static DataItem cborDecode(byte[] encodedBytes) {
        ByteArrayInputStream bais = new ByteArrayInputStream(encodedBytes);
        List<DataItem> dataItems = null;
        try {
            dataItems = new CborDecoder(bais).decode();
        } catch (CborException e) {
            throw new IllegalArgumentException("Error decoding CBOR", e);
        }
        if (dataItems.size() != 1) {
            throw new IllegalArgumentException("Unexpected number of items, expected 1 got "
                    + dataItems.size());
        }
        return dataItems.get(0);
    }

    static boolean cborDecodeBoolean(byte[] data) {
        SimpleValue simple = (SimpleValue) cborDecode(data);
        return simple.getSimpleValueType() == SimpleValueType.TRUE;
    }

    /**
     * Accepts a {@code DataItem}, attempts to cast it to a {@code Number}, then returns the value
     * Throws {@code IllegalArgumentException} if the {@code DataItem} is not a {@code Number}. This
     * method also checks bounds, and if the given data item is too large to fit in a long, it
     * throws {@code ArithmeticException}.
     */
    static long checkedLongValue(DataItem item) {
        final BigInteger bigNum = castTo(Number.class, item).getValue();
        final long result = bigNum.longValue();
        if (!bigNum.equals(BigInteger.valueOf(result))) {
            throw new ArithmeticException("Expected long value, got '" + bigNum + "'");
        }
        return result;
    }

    static String cborDecodeString(byte[] data) {
        return checkedStringValue(cborDecode(data));
    }

    /**
     * Accepts a {@code DataItem}, attempts to cast it to a {@code UnicodeString}, then returns the
     * value. Throws {@code IllegalArgumentException} if the {@code DataItem} is not a
     * {@code UnicodeString}.
     */
    static String checkedStringValue(DataItem item) {
        return castTo(UnicodeString.class, item).getString();
    }

    static long cborDecodeLong(byte[] data) {
        return checkedLongValue(cborDecode(data));
    }

    static byte[] cborDecodeByteString(byte[] data) {
        DataItem dataItem = cborDecode(data);
        return castTo(ByteString.class, dataItem).getBytes();
    }

    static Instant cborDecodeDateTime(byte[] data) {
        return cborDecodeDateTime(cborDecode(data));
    }

    static Instant cborDecodeDateTime(DataItem di) {
        if (!(di instanceof UnicodeString)) {
            throw new IllegalArgumentException("Passed in data is not a Unicode-string");
        }
        if (!di.hasTag() || di.getTag().getValue() != 0) {
            throw new IllegalArgumentException("Passed in data is not tagged with tag 0");
        }
        String dateString = checkedStringValue(di);

        // Manually parse the timezone
        TimeZone parsedTz = TimeZone.getTimeZone("UTC");
        if (!dateString.endsWith("Z")) {
            String timeZoneSubstr = dateString.substring(dateString.length() - 6);
            parsedTz = TimeZone.getTimeZone("GMT" + timeZoneSubstr);
        }

        SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss", Locale.US);
        df.setTimeZone(parsedTz);
        Date date = null;
        try {
            date = df.parse(dateString);
        } catch (ParseException e) {
            throw new RuntimeException("Error parsing string", e);
        }

        return Instant.ofEpochMilli(date.getTime());
    }

    /**
     * Similar to a typecast of {@code value} to the given type {@code clazz}, except:
     * <ul>
     * <li>Throws {@code IllegalArgumentException} instead of {@code ClassCastException} if
     * {@code !clazz.isAssignableFrom(value.getClass())}.</li>
     * <li>Also throws {@code IllegalArgumentException} if {@code value == null}.</li>
     * </ul>
     */
    static <T extends V, V> T castTo(Class<T> clazz, V value) {
        if (value == null || !clazz.isAssignableFrom(value.getClass())) {
            String valueStr = (value == null) ? "null" : value.getClass().toString();
            throw new IllegalArgumentException("Expected type " + clazz + ", got type " + valueStr);
        } else {
            @SuppressWarnings("unchecked")
            T valueAsType = (T) value;
            return valueAsType;
        }
    }

    /**
     * Helper function to check if a given certificate chain is valid.
     *
     * NOTE NOTE NOTE: We only check that the certificates in the chain sign each other. We
     * <em>specifically</em> don't check that each certificate is also a CA certificate.
     * 
     * @param certificateChain the chain to validate.
     * @return <code>true</code> if valid, <code>false</code> otherwise.
     */
    static boolean validateCertificateChain(
            Collection<X509Certificate> certificateChain) {
        // First check that each certificate signs the previous one...
        X509Certificate prevCertificate = null;
        for (X509Certificate certificate : certificateChain) {
            if (prevCertificate != null) {
                // We're not the leaf certificate...
                //
                // Check the previous certificate was signed by this one.
                try {
                    prevCertificate.verify(certificate.getPublicKey());
                } catch (CertificateException
                        | InvalidKeyException
                        | NoSuchAlgorithmException
                        | NoSuchProviderException
                        | SignatureException e) {
                    return false;
                }
            } else {
                // we're the leaf certificate so we're not signing anything nor
                // do we need to be e.g. a CA certificate.
            }
            prevCertificate = certificate;
        }
        return true;
    }

    private static byte[] coseBuildToBeSigned(byte[] encodedProtectedHeaders,
            byte[] payload,
            byte[] detachedContent) {
        CborBuilder sigStructure = new CborBuilder();
        ArrayBuilder<CborBuilder> array = sigStructure.addArray();

        array.add("Signature1");
        array.add(encodedProtectedHeaders);

        // We currently don't support Externally Supplied Data (RFC 8152 section 4.3)
        // so external_aad is the empty bstr
        byte[] emptyExternalAad = new byte[0];
        array.add(emptyExternalAad);

        // Next field is the payload, independently of how it's transported (RFC
        // 8152 section 4.4). Since our API specifies only one of |data| and
        // |detachedContent| can be non-empty, it's simply just the non-empty one.
        if (payload != null && payload.length > 0) {
            array.add(payload);
        } else {
            array.add(detachedContent);
        }
        array.end();
        return cborEncode(sigStructure.build().get(0));
    }

    /*
     * From RFC 8152 section 8.1 ECDSA:
     *
     * The signature algorithm results in a pair of integers (R, S).  These
     * integers will be the same length as the length of the key used for
     * the signature process.  The signature is encoded by converting the
     * integers into byte strings of the same length as the key size.  The
     * length is rounded up to the nearest byte and is left padded with zero
     * bits to get to the correct length.  The two integers are then
     * concatenated together to form a byte string that is the resulting
     * signature.
     * 
     * 
     */
    /**
     * 
     * Converts a DER / X9.62 encoded signature to a "flat" signature consisting of just the r and s components as
     * unsigned, statically sized, big endian integers. The size will be twice the key size in bytes.  
     * 
     * @param signature the signature
     * @param keySize the key size that needs to be used
     * @return the signature as a concatenation of the r- and s-values
     */
    private static byte[] signatureDerToCose(byte[] signature, int keySize) {

        ASN1Primitive asn1;
        try {
            asn1 = new ASN1InputStream(new ByteArrayInputStream(signature)).readObject();
        } catch (IOException e) {
            throw new IllegalArgumentException("Error decoding DER signature", e);
        }
        ASN1Encodable[] asn1Encodables = castTo(ASN1Sequence.class, asn1).toArray();
        if (asn1Encodables.length != 2) {
            throw new IllegalArgumentException("Expected two items in sequence");
        }
        BigInteger r = castTo(ASN1Integer.class, asn1Encodables[0].toASN1Primitive()).getValue();
        BigInteger s = castTo(ASN1Integer.class, asn1Encodables[1].toASN1Primitive()).getValue();

        byte[] rBytes = stripLeadingZeroes(r.toByteArray());
        byte[] sBytes = stripLeadingZeroes(s.toByteArray());
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            for (int n = 0; n < keySize - rBytes.length; n++) {
                baos.write(0x00);
            }
            baos.write(rBytes);
            for (int n = 0; n < keySize - sBytes.length; n++) {
                baos.write(0x00);
            }
            baos.write(sBytes);
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        }
        return baos.toByteArray();
    }

    private static byte[] signatureCoseToDer(byte[] signature) {
        // r and s are always positive and may use all bits so use the constructor which
        // parses them as unsigned.
        
        int keySizeBytes = signature.length / 2; 
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(
                signature, 0, keySizeBytes));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(
                signature, keySizeBytes, signature.length));

        ;
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()){
            DERSequenceGenerator seq = new DERSequenceGenerator(baos);
            seq.addObject(new ASN1Integer(r.toByteArray()));
            seq.addObject(new ASN1Integer(s.toByteArray()));
            seq.close();
            
            return baos.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException("Error generating DER signature", e);
        }
    }

    /**
     * Note: this uses the default JCA provider which may not support a lot of curves, for
     * example it doesn't support Brainpool curves. If you need to use such curves, use
     * {@link #coseSign1Sign(Signature, byte[], byte[], Collection)} instead with a
     * Signature created using a provider that does have support.
     *
     * Currently only ECDSA signatures are supported.
     *
     * TODO: add support and tests for Ed25519 and Ed448.
     */
    static DataItem coseSign1Sign(PrivateKey key,
            String algorithm, byte[] data,
            byte[] additionalData,
            Collection<X509Certificate> certificateChain) {

        Signature s;
        try {
            s = Signature.getInstance(algorithm);
            s.initSign(key);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException("Caught exception", e);
        }
        
        if (!(key instanceof ECPrivateKey)) {
            throw new IllegalArgumentException("Only EC private keys supported at this time");
        }
        
        ECPrivateKey ecKey = (ECPrivateKey) key; 
        
        int keySize = determineKeySize(ecKey);
        
        int dataLen = (data != null ? data.length : 0);
        int detachedContentLen = (additionalData != null ? additionalData.length : 0);
        if (dataLen > 0 && detachedContentLen > 0) {
            throw new IllegalArgumentException("data and detachedContent cannot both be non-empty");
        }
        
        long alg;
        if (s.getAlgorithm().equalsIgnoreCase("SHA256withECDSA")) {
            alg = COSE_ALG_ECDSA_256;
        } else if (s.getAlgorithm().equalsIgnoreCase("SHA384withECDSA")) {
            alg = COSE_ALG_ECDSA_384;
        } else if (s.getAlgorithm().equalsIgnoreCase("SHA512withECDSA")) {
            alg = COSE_ALG_ECDSA_512;
        } else {
            throw new IllegalArgumentException("Unsupported algorithm " + s.getAlgorithm());
        }
        
        CborBuilder protectedHeaders = new CborBuilder();
        MapBuilder<CborBuilder> protectedHeadersMap = protectedHeaders.addMap();
        protectedHeadersMap.put(COSE_LABEL_ALG, alg);
        byte[] protectedHeadersBytes = cborEncode(protectedHeaders.build().get(0));
        
        byte[] toBeSigned = coseBuildToBeSigned(protectedHeadersBytes, data, additionalData);
        
        byte[] coseSignature = null;
        try {
            s.update(toBeSigned);
            byte[] derSignature = s.sign();
            coseSignature = signatureDerToCose(derSignature, keySize);
        } catch (SignatureException e) {
            throw new IllegalStateException("Error signing data", e);
        }
        
        CborBuilder builder = new CborBuilder();
        ArrayBuilder<CborBuilder> array = builder.addArray();
        array.add(protectedHeadersBytes);
        MapBuilder<ArrayBuilder<CborBuilder>> unprotectedHeaders = array.addMap();
        try {
            if (certificateChain != null && certificateChain.size() > 0) {
                if (certificateChain.size() == 1) {
                    X509Certificate cert = certificateChain.iterator().next();
                    unprotectedHeaders.put(COSE_LABEL_X5CHAIN, cert.getEncoded());
                } else {
                    ArrayBuilder<MapBuilder<ArrayBuilder<CborBuilder>>> x5chainsArray = unprotectedHeaders
                            .putArray(COSE_LABEL_X5CHAIN);
                    for (X509Certificate cert : certificateChain) {
                        x5chainsArray.add(cert.getEncoded());
                    }
                }
            }
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException("Error encoding certificate", e);
        }
        if (data == null || data.length == 0) {
            array.add(new SimpleValue(SimpleValueType.NULL));
        } else {
            array.add(data);
        }
        array.add(coseSignature);
        
        return builder.build().get(0);
    }

    private static int determineKeySize(ECPrivateKey ecKey) {
        ECField field = ecKey.getParams().getCurve().getField();
        int keySize = (field.getFieldSize() + Bytes.SIZE - 1) / Bytes.SIZE;
        return keySize;
    }

    /**
     * Currently only ECDSA signatures are supported.
     *
     * TODO: add support and tests for Ed25519 and Ed448.
     */
    static boolean coseSign1CheckSignature(DataItem coseSign1,
            byte[] detachedContent, PublicKey publicKey) {
        if (coseSign1.getMajorType() != MajorType.ARRAY) {
            throw new IllegalArgumentException("Data item is not an array");
        }
        @SuppressWarnings("unchecked")
        List<DataItem> items = ((Array<DataItem>) coseSign1).getDataItems();
        if (items.size() < 4) {
            throw new IllegalArgumentException("Expected at least four items in COSE_Sign1 array");
        }
        if (items.get(0).getMajorType() != MajorType.BYTE_STRING) {
            throw new IllegalArgumentException("Item 0 (protected headers) is not a byte-string");
        }
        byte[] encodedProtectedHeaders = ((ByteString) items.get(
                0)).getBytes();
        byte[] payload = new byte[0];
        if (items.get(2).getMajorType() == MajorType.SPECIAL) {
            if (((co.nstant.in.cbor.model.Special) items.get(2)).getSpecialType() != SpecialType.SIMPLE_VALUE) {
                throw new IllegalArgumentException(
                        "Item 2 (payload) is a special but not a simple value");
            }
            SimpleValue simple = (SimpleValue) items.get(2);
            if (simple.getSimpleValueType() != SimpleValueType.NULL) {
                throw new IllegalArgumentException(
                        "Item 2 (payload) is a simple but not the value null");
            }
        } else if (items.get(2).getMajorType() == MajorType.BYTE_STRING) {
            payload = ((ByteString) items.get(2)).getBytes();
        } else {
            throw new IllegalArgumentException("Item 2 (payload) is not nil or byte-string");
        }
        System.out.println(Hex.toHexString(payload));

        if (items.get(3).getMajorType() != MajorType.BYTE_STRING) {
            throw new IllegalArgumentException("Item 3 (signature) is not a byte-string");
        }
        byte[] coseSignature = ((ByteString) items.get(3)).getBytes();

        byte[] derSignature = signatureCoseToDer(coseSignature);
        System.out.println(Hex.toHexString(derSignature));

        int dataLen = payload.length;
        int detachedContentLen = (detachedContent != null ? detachedContent.length : 0);
        if (dataLen > 0 && detachedContentLen > 0) {
            throw new IllegalArgumentException("data and detachedContent cannot both be non-empty");
        }

        DataItem protectedHeaders = cborDecode(encodedProtectedHeaders);
        @SuppressWarnings("rawtypes")
        long alg = cborMapExtractNumber((Map) protectedHeaders, COSE_LABEL_ALG);
        String signature;
        if (alg == COSE_ALG_ECDSA_256) {
            signature = "SHA256withECDSA";
        } else if (alg == COSE_ALG_ECDSA_384) {
            signature = "SHA384withECDSA";
        } else if (alg == COSE_ALG_ECDSA_512) {
            signature = "SHA512withECDSA";
        } else {
            throw new IllegalArgumentException("Unsupported COSE alg " + alg);
        }

        System.out.println(signature);

        byte[] toBeSigned = IdentityUtil.coseBuildToBeSigned(encodedProtectedHeaders, payload,
                detachedContent);

        System.out.println(Hex.toHexString(toBeSigned));

        try {
            // Use BouncyCastle provider for verification since it supports a lot more curves than
            // the default provider, including the brainpool curves
            //
            Signature verifier = Signature.getInstance(signature,
                    new org.bouncycastle.jce.provider.BouncyCastleProvider());
            verifier.initVerify(publicKey);
            verifier.update(toBeSigned);
            return verifier.verify(derSignature);
        } catch (SignatureException | NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException("Error verifying signature", e);
        }
    }

    private static byte[] coseBuildToBeMACed(byte[] encodedProtectedHeaders,
            byte[] payload,
            byte[] detachedContent) {
        CborBuilder macStructure = new CborBuilder();
        ArrayBuilder<CborBuilder> array = macStructure.addArray();

        array.add("MAC0");
        array.add(encodedProtectedHeaders);

        // We currently don't support Externally Supplied Data (RFC 8152 section 4.3)
        // so external_aad is the empty bstr
        byte[] emptyExternalAad = new byte[0];
        array.add(emptyExternalAad);

        // Next field is the payload, independently of how it's transported (RFC
        // 8152 section 4.4). Since our API specifies only one of |data| and
        // |detachedContent| can be non-empty, it's simply just the non-empty one.
        if (payload != null && payload.length > 0) {
            array.add(payload);
        } else {
            array.add(detachedContent);
        }

        return cborEncode(macStructure.build().get(0));
    }

    static DataItem coseMac0(SecretKey key,
            byte[] data,
            byte[] detachedContent) {

        int dataLen = (data != null ? data.length : 0);
        int detachedContentLen = (detachedContent != null ? detachedContent.length : 0);
        if (dataLen > 0 && detachedContentLen > 0) {
            throw new IllegalArgumentException("data and detachedContent cannot both be non-empty");
        }

        CborBuilder protectedHeaders = new CborBuilder();
        MapBuilder<CborBuilder> protectedHeadersMap = protectedHeaders.addMap();
        protectedHeadersMap.put(COSE_LABEL_ALG, COSE_ALG_HMAC_256_256);
        byte[] protectedHeadersBytes = cborEncode(protectedHeaders.build().get(0));

        byte[] toBeMACed = coseBuildToBeMACed(protectedHeadersBytes, data, detachedContent);

        byte[] mac;
        try {
            Mac m = Mac.getInstance("HmacSHA256");
            m.init(key);
            m.update(toBeMACed);
            mac = m.doFinal();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException("Unexpected error", e);
        }

        CborBuilder builder = new CborBuilder();
        ArrayBuilder<CborBuilder> array = builder.addArray();
        array.add(protectedHeadersBytes);
        /* MapBuilder<ArrayBuilder<CborBuilder>> unprotectedHeaders = */
        array.addMap();
        if (data == null || data.length == 0) {
            array.add(new SimpleValue(SimpleValueType.NULL));
        } else {
            array.add(data);
        }
        array.add(mac);

        return builder.build().get(0);
    }

    static byte[] coseMac0GetTag(DataItem coseMac0) {
        @SuppressWarnings("unchecked")
        List<DataItem> items = castTo(Array.class, coseMac0).getDataItems();
        if (items.size() < 4) {
            throw new IllegalArgumentException("coseMac0 have less than 4 elements");
        }
        DataItem tagItem = items.get(3);
        return castTo(ByteString.class, tagItem).getBytes();
    }

    static boolean hasSubByteArray(byte[] haystack, byte[] needle) {
        if (haystack.length < needle.length) {
            return false;
        }

        // brute-force but good enough since users will only pass relatively small amounts of data.
        for (int off = 0; off < haystack.length - needle.length; off++) {
            if (Arrays.compare(haystack, off, off + needle.length, needle, 0, needle.length) == 0) {
                return true;
            }
        }
        return false;
    }

    static byte[] stripLeadingZeroes(byte[] value) {
        for (int off = 0; off < value.length; off++) {
            if (value[off] != 0x00) {
                return Arrays.copyOfRange(value, off, value.length - off);
            }
        }
        return new byte[0];
    }

    /**
     * Returns #6.24(bstr) of the given already encoded CBOR
     */
    static DataItem cborBuildTaggedByteString(byte[] encodedCbor) {
        DataItem item = new ByteString(encodedCbor);
        item.setTag(CBOR_SEMANTIC_TAG_ENCODED_CBOR);
        return item;
    }

    /**
     * For a #6.24(bstr), extracts the bytes.
     */
    static byte[] cborExtractTaggedCbor(byte[] encodedTaggedBytestring) {
        DataItem item = cborDecode(encodedTaggedBytestring);
        ByteString itemByteString = castTo(ByteString.class, item);
        if (!item.hasTag() || item.getTag().getValue() != CBOR_SEMANTIC_TAG_ENCODED_CBOR) {
            throw new IllegalArgumentException("ByteString is not tagged with tag 24");
        }
        return itemByteString.getBytes();
    }

    /**
     * For a #6.24(bstr), extracts the bytes and decodes it and returns
     * the decoded CBOR as a DataItem.
     */
    static DataItem cborExtractTaggedAndEncodedCbor(DataItem item) {
        ByteString itemByteString = castTo(ByteString.class, item);
        if (!item.hasTag() || item.getTag().getValue() != CBOR_SEMANTIC_TAG_ENCODED_CBOR) {
            throw new IllegalArgumentException("ByteString is not tagged with tag 24");
        }
        byte[] encodedCbor = itemByteString.getBytes();
        DataItem embeddedItem = cborDecode(encodedCbor);
        return embeddedItem;
    }

    /**
     * Returns the empty byte-array if no data is included in the structure.
     */
    static byte[] coseSign1GetData(DataItem coseSign1) {
        if (coseSign1.getMajorType() != MajorType.ARRAY) {
            throw new IllegalArgumentException("Data item is not an array");
        }
        @SuppressWarnings("unchecked")
        List<DataItem> items = castTo(Array.class, coseSign1).getDataItems();
        if (items.size() < 4) {
            throw new IllegalArgumentException("Expected at least four items in COSE_Sign1 array");
        }
        byte[] payload = new byte[0];
        if (items.get(2).getMajorType() == MajorType.SPECIAL) {
            if (((co.nstant.in.cbor.model.Special) items.get(2)).getSpecialType() != SpecialType.SIMPLE_VALUE) {
                throw new IllegalArgumentException(
                        "Item 2 (payload) is a special but not a simple value");
            }
            SimpleValue simple = castTo(SimpleValue.class, items.get(2));
            if (simple.getSimpleValueType() != SimpleValueType.NULL) {
                throw new IllegalArgumentException(
                        "Item 2 (payload) is a simple but not the value null");
            }
        } else if (items.get(2).getMajorType() == MajorType.BYTE_STRING) {
            payload = castTo(ByteString.class, items.get(2)).getBytes();
        } else {
            throw new IllegalArgumentException("Item 2 (payload) is not nil or byte-string");
        }
        return payload;
    }

    /**
     * Retrieves the X509 certificate chain (x5chain) from the COSE_Sign1 signature.
     * 
     * @return the empty collection if no x5chain is included in the structure
     * @throws a runtime exception if the given bytes aren't valid COSE_Sign1
     */
    static List<X509Certificate> coseSign1GetX5Chain(
            DataItem coseSign1) throws IllegalArgumentException {
        ArrayList<X509Certificate> ret = new ArrayList<>();
        if (coseSign1.getMajorType() != MajorType.ARRAY) {
            throw new IllegalArgumentException("Data item is not an array");
        }
        @SuppressWarnings("unchecked")
        List<DataItem> items = castTo(Array.class, coseSign1).getDataItems();
        if (items.size() < 4) {
            throw new IllegalArgumentException("Expected at least four items in COSE_Sign1 array");
        }
        if (items.get(1).getMajorType() != MajorType.MAP) {
            throw new IllegalArgumentException("Item 1 (unprotected headers) is not a map");
        }
        @SuppressWarnings("rawtypes")
        Map map = (Map) items.get(1);
        @SuppressWarnings("unchecked")
        DataItem x5chainItem = map.get(new UnsignedInteger(COSE_LABEL_X5CHAIN));
        if (x5chainItem != null) {
            try {
                CertificateFactory factory = CertificateFactory.getInstance("X.509");
                if (x5chainItem instanceof ByteString) {
                    ByteArrayInputStream certBais = new ByteArrayInputStream(
                            castTo(ByteString.class, x5chainItem).getBytes());
                    ret.add((X509Certificate) factory.generateCertificate(certBais));
                } else if (x5chainItem instanceof Array) {
                    @SuppressWarnings("unchecked")
                    Array<DataItem> x5chainItemArray = (Array<DataItem>) x5chainItem;
                    // NOTE was: for (DataItem certItem : castTo(Array.class, x5chainItem).getDataItems()) {
                    for (DataItem certItem : x5chainItemArray.getDataItems()) {
                        ByteArrayInputStream certBais = new ByteArrayInputStream(
                                castTo(ByteString.class, certItem).getBytes());
                        ret.add((X509Certificate) factory.generateCertificate(certBais));
                    }
                } else {
                    throw new IllegalArgumentException("Unexpected type for x5chain value");
                }
            } catch (CertificateException e) {
                throw new IllegalArgumentException("Unexpected error", e);
            }
        }
        return ret;
    }

    static DataItem cborBuildCoseKey(PublicKey key) {
        ECPublicKey ecKey = (ECPublicKey) key;
        ECPoint w = ecKey.getW();
        // X and Y are always positive so for interop we remove any leading zeroes
        // inserted by the BigInteger encoder.
        byte[] x = stripLeadingZeroes(w.getAffineX().toByteArray());
        byte[] y = stripLeadingZeroes(w.getAffineY().toByteArray());
        DataItem item = new CborBuilder()
                .addMap()
                .put(COSE_KEY_KTY, COSE_KEY_TYPE_EC2)
                .put(COSE_KEY_EC2_CRV, COSE_KEY_EC2_CRV_P256)
                .put(COSE_KEY_EC2_X, x)
                .put(COSE_KEY_EC2_Y, y)
                .end()
                .build().get(0);
        return item;
    }

    static boolean cborMapHasKey(DataItem map, String key) {
        @SuppressWarnings("unchecked")
        DataItem item = castTo(Map.class, map).get(new UnicodeString(key));
        return item != null;
    }

    static boolean cborMapHasKey(DataItem map, long key) {
        DataItem keyDataItem = key >= 0 ? new UnsignedInteger(key) : new NegativeInteger(key);
        @SuppressWarnings("unchecked")
        DataItem item = castTo(Map.class, map).get(keyDataItem);
        return item != null;
    }

    static long cborMapExtractNumber(DataItem map, long key) {
        DataItem keyDataItem = key >= 0 ? new UnsignedInteger(key) : new NegativeInteger(key);
        @SuppressWarnings("unchecked")
        DataItem item = castTo(Map.class, map).get(keyDataItem);
        return checkedLongValue(item);
    }
}
