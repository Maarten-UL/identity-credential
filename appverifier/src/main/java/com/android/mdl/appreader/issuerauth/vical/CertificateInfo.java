package com.android.mdl.appreader.issuerauth.vical;

import static com.android.mdl.appreader.issuerauth.vical.OptionalCertificateInfoKey.*;
import static com.android.mdl.appreader.issuerauth.vical.RequiredCertificateInfoKey.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.Set;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.UnicodeString;

/**
 * CertificateInfo represents the structure with the same name from From 18013-5 C.1.7.
 * This class contains a {@link Builder} to create a <code>CertificateInfo</code> instance.
 * <p>
 * In addition the class contains an {@link Encoder} and a {@link Decoder} to create a CBOR DataItem
 * out of the various fields in the class, which can then be translated to/from the binary representation.
 * </p>
 * <p>
 * <pre>
 * CertificateInfo = {
 *     "certificate" : bstr ; DER-encoded X.509 certificate
 *     "serialNumber" : biguint ; value of the serial number field of the certificate
 *     "ski" : bstr ; value of the Subject Key Identifier field of the certificate
 *     "docType" : [+ DocType] ; DocType for which the certificate may be used as a trust point
 *     ? "certificateProfile" : [+ CertificateProfile] ; Type of certificate
 *     ? "issuingAuthority" : tstr ; Name of the certificate issuing authority
 *     ? "issuingCountry" : tstr ; ISO3166-1 or ISO3166-2 depending on the issuing authority
 *     ? "stateOrProvinceName" : tstr ; State or province name of the certificate issuing authority
 *     ? "issuer" : bstr ; DER-encoded Issuer field of the certificate (i.e. the complete Name structure)
 *     ? "subject" : bstr ; DER-encoded Subject field of the certificate (i.e. the complete Name structure)
 *     ? "notBefore" : tdate ; value of the notBefore field of the certificate
 *     ? "notAfter" : tdate ; value of the notAfter field of the certificate
 *     ? "extensions" : Extensions ; Can be used for proprietary extensions
 *     * tstr => any ; To be used for future extensions, all values are RFU
 * }
 * </p>
 * </pre>
 * 
 * It is possible to add extensions as key /value pairs, where the key must be a CBOR UnicodeString.
 * Adding RFU is not supported, but any encoded RFU's will be made available and contained.
 * An extension or RFU that doesn't have a UnicodeString as key will result in a decoder exception.
 * 
 * @author UL Solutions
 */

// NOTE class currently not made Serializable due to the extensions (CBOR DataItem) not being serializable
// equals and hashCode have been implemented though
public class CertificateInfo {
    private static final int TAG_BIGUINT = 2;

    /**
     * The builder to create a CertificateInfo instance.
     * 
     * The resulting <code>CertificateInfo</code> instances can be used as input to {@link Builder}.
     */
    public static class Builder implements InstanceBuilder<CertificateInfo> {

        private final CertificateInfo certInfo;
        private final X509CertificateHolder certHolder;

        /**
         * Creates a CertificateInfo by copying the indicated fields from the certificate
         * as well as the certificate itself.
         * It is highly recommended to set the docTypes for which the certificate is valid.
         * If this is not indicated then the certificate is valid for any document type.
         * 
         * @param cert                      the certificate described by this <code>CertificateInfo</code> instance.
         * @param docTypes                  the docTypes that this certificate can be used for; at least one has to be provided
         * @param optionalCertificateFields any optional fields in a table, see {@link CertificateInfoKey}
         *                                  for more information
         */

        public Builder(X509Certificate cert, Set<String> docTypes,
                Set<OptionalCertificateInfoKey> optionalCertificateFields) {
            if (docTypes.isEmpty()) {
                throw new IllegalArgumentException("At least one docType has to be provided for each certificate");
            }
            
            this.certInfo = new CertificateInfo(cert, docTypes);
            try {
                this.certHolder = new X509CertificateHolder(cert.getEncoded());
            } catch (CertificateEncodingException | IOException e) {
                throw new RuntimeException(
                        "Error re-coding the certificate to X509CertificateHolder",
                        e);
            }

            for (OptionalCertificateInfoKey certificateInfoKey : optionalCertificateFields) {
                copyCertificateInformation(certificateInfoKey);
            }
        }

        private void copyCertificateInformation(OptionalCertificateInfoKey certificateInfoKey) {
            switch (certificateInfoKey) {
            case CERTIFICATE_PROFILE:
                copyCertificateProfile();
                break;
            case ISSUING_AUTHORITY:
                copyIssuingAuthority();
                break;
            case ISSUING_COUNTRY:
                copyIssuingCountry();
                break;
            case STATE_OR_PROVINCE_NAME:
                copyStateOrProvince();
                break;
            case ISSUER:
                copyIssuer();
                break;
            case SUBJECT:
                copySubject();
                break;
            case NOT_BEFORE:
                copyNotBefore();
                break;
            case NOT_AFTER:
                copyNotAfter();
                break;
            default:
                throw new RuntimeException(
                        "Don't know how to copy the field " + certificateInfoKey + " from the certificate");
            }
        }

        /**
         * Can be used to indicate the issuing authority of the certificate if it is different from the certificate.
         * 
         * @param issuingAuthority the issuing authority, not null
         */
        public void indicateIssuingAuthority(String issuingAuthority) {
            if (issuingAuthority == null) {
                throw new IllegalArgumentException("The indicated issuingAuthority should not be null");
            }
            certInfo.issuingAuthority = issuingAuthority;
        }

        /**
         * Can be used to indicate the issuing country of the certificate if it is different from the certificate.
         * 
         * @param issuingCountry the issuing country, not null
         */
        public void indicateIssuingCountry(String issuingCountry) {
            if (issuingCountry == null) {
                throw new IllegalArgumentException("The indicated issuingCountry should not be null");
            }
            certInfo.issuingCountry = issuingCountry;
        }

        /**
         * Can be used to indicate the state or province name of the issuing authority.
         * 
         * @param stateOrProvinceName the state or province name of the issuing authority, not null
         */
        public void indicateStateOrProvinceName(String stateOrProvinceName) {
            if (stateOrProvinceName == null) {
                throw new IllegalArgumentException("The indicated stateOrProvinceName should not be null");
            }
            certInfo.stateOrProvinceName = stateOrProvinceName;
        }
        
        /**
         * Adds an extension. If no extensions are indicated then the field will not be present.
         * @param key the key of the extension
         * @param value the value of the extension
         */
        public void addExtension(UnicodeString key, DataItem value) {
            if (certInfo.extensions == null) {
                certInfo.extensions = new Map();
            }
            
            certInfo.extensions.put(key, value);
        }
        
        /**
         * Adds a possibly unknown key / value to the CertificateInfo.
         * This method does not perform any verification and it allows overwriting of existing, known key / value pairs.
         * 
         * @param key the key
         * @param value the value
         */
        public void addRFU(UnicodeString key, DataItem value) {
            certInfo.rfu.put(key, value);
        }
        
        /*
         * Should probably not be used; the Extended Key Usage extension should not be present in IACA certificates.
         */
        private void copyCertificateProfile() {
            // WARNING: specification is unclear w.r.t. how certificateProfile is formatted,
            // or how to use this key / value pair
            
            List<String> keyUsages;
            try {
                keyUsages = certInfo.certificate.getExtendedKeyUsage();
            } catch (CertificateParsingException e) {
                // TODO provide better runtime exception
                throw new RuntimeException(
                        "Could not decode extended key usage for certificate profile",
                        e);
            }
            if (keyUsages != null) {
                certInfo.certificateProfile.addAll(keyUsages);
                for (String keyUsage : keyUsages) {
                    certInfo.certificateProfile.add("urn:oid:" + keyUsage);
                }
            }

            // certInfo.certificateProfile = certificateProfiles;
        }

        private void copyIssuingAuthority() {
            certInfo.issuingAuthority = certHolder.getIssuer().toString();
        }

        private void copyIssuingCountry() {
            X500Name issuer = certHolder.getIssuer();
            RDN[] rdns = certHolder.getIssuer().getRDNs(BCStyle.C);
            if (rdns.length != 1) {
                throw new RuntimeException(
                        "No country or multiple countries indicated for issuer: " + issuer.toString());
            }
            AttributeTypeAndValue[] countryTypesAndValues = rdns[0].getTypesAndValues();
            if (countryTypesAndValues.length != 1) {
                throw new RuntimeException(
                        "No country types or values or multiple country types and values indicated for issuer: "
                                + issuer.toString());
            }

            certInfo.issuingCountry = IETFUtils.valueToString(countryTypesAndValues[0].getValue());
        }

        private void copyStateOrProvince() {
            X500Name issuer = certHolder.getIssuer();
            RDN[] rdns = certHolder.getIssuer().getRDNs(BCStyle.ST);
            if (rdns.length != 1) {
                // TODO think of ways to make this "copy if present" in settings
                //                throw new RuntimeException(
                //                        "No state/province or multiple state/provinces indicated for issuer: " + issuer.toString());
                return;
            }

            AttributeTypeAndValue[] stateOrProvinceTypesAndValues = rdns[0].getTypesAndValues();
            if (stateOrProvinceTypesAndValues.length != 1) {
                throw new RuntimeException(
                        "No state/province types or values or multiple state/province types and values indicated for issuer: "
                                + issuer.toString());
            }

            certInfo.stateOrProvinceName = IETFUtils.valueToString(stateOrProvinceTypesAndValues[0].getValue());
        }

        // TODO check if this is indeed a "binary copy"
        private void copyIssuer() {
            try {
                certInfo.issuer = certHolder.getIssuer().getEncoded();
            } catch (IOException e) {
                throw new RuntimeException("Could not re-encode issuer", e);
            }
        }


        
        // TODO check if this is indeed a "binary copy"
        private void copySubject() {
            try {
                certInfo.subject = certHolder.getSubject().getEncoded();
            } catch (IOException e) {
                throw new RuntimeException("Could not re-encode subject", e);
            }
        }

        private void copyNotBefore() {
            certInfo.notBefore = certHolder.getNotBefore().toInstant();
        }

        private void copyNotAfter() {
            certInfo.notAfter = certHolder.getNotAfter().toInstant();
        }

        @Override
        public CertificateInfo build() {
            return certInfo;
        }
    }

    /**
     * An encoder to encode instances of the <code>CertificateInfo</code> class.
     * 
     * This class is usually called by {@link com.android.mdl.appreader.issuerauth.vical.Vical.Encoder} directly.
     */
    public static class Encoder implements DataItemEncoder<Map, CertificateInfo> {

        private static final int TAG_BIGUINT = 2;

        /**
         * Creates an Encoder instance specific to {@link CertificateInfo} instances.
         */
        public Encoder() {
            // not parameterized for now
        }

        /**
         * Encodes a CertificateInfo into a CBOR structure, which is part of the overall VICAL structure.
         * The CBOR structure can be encoded to binary using {@link CborEncoder#encode(DataItem)}.
         * Usually the VICAL structure is converted to binary as a whole instead. 
         * 
         * @param certificateInfo The <code>CertificateInfo</code> instance to encode
         * @return the encoded <code>CertificateInfo</code> instance as CBOR structure
         */
        @Override
        public Map encode(CertificateInfo certificateInfo) {
            final Map map = new Map(4);
            try {
                map.put(CERTIFICATE.getUnicodeString(), new ByteString(certificateInfo.certificate().getEncoded()));
            } catch (CertificateEncodingException e) {
                // TODO provide better runtime exception
                throw new RuntimeException("Uncaught exception, blame developer", e);
            }

            ByteString string = new ByteString(toUnsigned(certificateInfo.serialNumber()));
            string.setTag(TAG_BIGUINT);
            map.put(SERIAL_NUMBER.getUnicodeString(), string);

            map.put(SKI.getUnicodeString(), new ByteString(certificateInfo.ski()));

            Set<String> profiles = certificateInfo.certificateProfile();
            if (!profiles.isEmpty()) {
                Array profileArray = new Array();
                for (String profile : profiles) {
                    profileArray.add(new UnicodeString(profile));
                }
                map.put(CERTIFICATE_PROFILE.getUnicodeString(), profileArray);
            }

            Optional<String> issuingAuthority = certificateInfo.issuingAuthority();
            if (issuingAuthority.isPresent()) {
                map.put(ISSUING_AUTHORITY.getUnicodeString(), new UnicodeString(issuingAuthority.get()));
            }

            Optional<String> issuingCountry = certificateInfo.issuingCountry();
            if (issuingCountry.isPresent()) {
                map.put(ISSUING_COUNTRY.getUnicodeString(), new UnicodeString(issuingCountry.get()));
            }

            Optional<String> stateOrProvinceName = certificateInfo.stateOrProvinceName();
            if (stateOrProvinceName.isPresent()) {
                map.put(STATE_OR_PROVINCE_NAME.getUnicodeString(), new UnicodeString(stateOrProvinceName.get()));
            }

            Optional<byte[]> issuer = certificateInfo.issuer();
            if (issuer.isPresent()) {
                map.put(ISSUER.getUnicodeString(), new ByteString(issuer.get()));
            }

            Optional<byte[]> subject = certificateInfo.subject();
            if (subject.isPresent()) {
                map.put(SUBJECT.getUnicodeString(), new ByteString(subject.get()));
            }

            Optional<Instant> notBefore = certificateInfo.notBefore();
            if (notBefore.isPresent()) {
                map.put(NOT_BEFORE.getUnicodeString(), Util.createTDate(notBefore.get()));
            }

            Optional<Instant> notAfter = certificateInfo.notAfter();
            if (notAfter.isPresent()) {
                map.put(NOT_AFTER.getUnicodeString(), Util.createTDate(notAfter.get()));
            }

            Set<String> docTypes = certificateInfo.docTypes();
            Array docTypeArray = new Array(docTypes.size());
            for (String docType : docTypes) {
                docTypeArray.add(new UnicodeString(docType));
            }
            map.put(DOC_TYPE.getUnicodeString(), docTypeArray);

            // extensions is directly put in; it should contain a map in all probability, but it is defined as any
            Optional<Map> extensions = certificateInfo.extensions();
            if (extensions.isPresent()) {
                map.put(EXTENSIONS.getUnicodeString(), extensions.get());
            }

            Map rfu = certificateInfo.rfu();

            Set<Entry<UnicodeString, DataItem>> entrySet = Util.getEntrySet(rfu);
            for (Entry<UnicodeString, DataItem> entry : entrySet) {
                map.put(entry.getKey(), entry.getValue());
            }

            return map;
        }

        private static byte[] toUnsigned(BigInteger i) {
            byte[] signed = i.toByteArray();
            if (signed[0] != 0x00) {
                return signed;
            }
            return Arrays.copyOfRange(signed, 1, signed.length);
        }
    }


    /**
     *
     * An decoder to decode instances of the <code>CertificateInfo</code> class.
     *
     * This class is usually called by {@link com.android.mdl.appreader.issuerauth.vical.Vical.Decoder} directly
     * after which the <code>CertificateInfo</code> instances can be retrieved using {@link Vical#certificateInfos()}.
     *
     * Currently the decoder does not support any undefined or RFU fields.
     */
    public static class Decoder implements DataItemDecoder<CertificateInfo, Map> {

        @Override
        public CertificateInfo decode(Map map) throws DataItemDecoderException {

            // === first get the required fields and create the instance
            CertificateInfo certInfo;
            try {
                X509Certificate cert = decodeCertificate(map);

                BigInteger serialNumber = decodeSerialNumber(map);

                byte[] ski = decodeSki(map);

                Set<String> docType = decodeDocType(map);

                certInfo = new CertificateInfo(cert, serialNumber, ski, docType);
            } catch (CertificateException e) {
                throw new DataItemDecoderException("Could not decode certificate");
            }


            // === now get the optional fields
            //     CERTIFICATE_PROFILE, ISSUING_AUTHORITY, ISSUING_COUNTRY, STATE_OR_PROVINCE_NAME, ISSUER, SUBJECT,
            // NOT_BEFORE, NOT_AFTER, EXTENSIONS;

            certInfo.certificateProfile = decodeCertificateProfile(map);

            certInfo.issuingAuthority = decodeIssuingAuthority(map);
            certInfo.issuingCountry = decodeIssuingCountry(map);
            certInfo.stateOrProvinceName = decodeStateOrProvinceName(map);
            certInfo.issuer = decodeIssuer(map);
            certInfo.subject = decodeSubject(map);
            certInfo.notBefore = decodeNotBefore(map);
            certInfo.notAfter = decodeNotAfter(map);
            certInfo.extensions = decodeExtensions(map);
            certInfo.rfu = decodeRFU(map);


            // TODO more things to decode

            //            Set<Entry<UnicodeString,DataItem>> entrySet = map.getEntrySet();
            //            for (Entry<UnicodeString, DataItem> entry : entrySet) {
            //                String keyName = entry.getKey().getString();
            //                Optional<CertificateInfoKey> knownKey = CertificateInfoKey.forKeyName(keyName);
            //                if (knownKey .isEmpty()) {
            //                    // ignore
            //                    // TODO add to rfu
            //                    continue;
            //                }
            //                CertificateInfoKey key = knownKey.get();
            //                if (key instanceof RequiredCertificateInfoKey) {
            //                    // ignore, already retrieved
            //                    continue;
            //                }
            //
            //                OptionalCertificateInfoKey optKey = (OptionalCertificateInfoKey) key;
            //                switch (optKey) {
            //                case CERTIFICATE_PROFILE:
            //
            //                }
            //            }
            return certInfo;
        }

        private X509Certificate decodeCertificate(Map map)
                throws DataItemDecoderException {
            DataItem certificateDI = map.get(RequiredCertificateInfoKey.CERTIFICATE.getUnicodeString());
            if (!(certificateDI instanceof ByteString)) {
                throw new DataItemDecoderException(certificateDI.getClass().getTypeName());
            }
            byte[] certData = ((ByteString) certificateDI).getBytes();
            CertificateFactory fact;
            try {
                fact = CertificateFactory.getInstance("X509");
            } catch (CertificateException e) {
                throw new RuntimeException("Required X.509 certificate factory not available", e);
            }
            X509Certificate signingCert;
            try {
                signingCert = (X509Certificate) fact
                        .generateCertificate(new ByteArrayInputStream(certData));
            } catch (CertificateException e) {
                throw new DataItemDecoderException("Uncaught exception, blame developer", e);
            }
            return signingCert;
        }

        private BigInteger decodeSerialNumber(Map map) {
            DataItem certificateDI = map.get(RequiredCertificateInfoKey.SERIAL_NUMBER.getUnicodeString());
            if (!(certificateDI instanceof ByteString)) {
                // TODO refactor ot better exception
                throw new RuntimeException();
            }
            if (!certificateDI.hasTag() || certificateDI.getTag().getValue() != TAG_BIGUINT) {
                // TODO refactor to better exception
                throw new RuntimeException();
            }

            return new BigInteger(1, ((ByteString) certificateDI).getBytes());
        }

        private byte[] decodeSki(Map map) {
            DataItem certificateDI = map.get(RequiredCertificateInfoKey.SKI.getUnicodeString());
            if (!(certificateDI instanceof ByteString)) {
                // TODO refactor or better exception
                throw new RuntimeException();
            }

            // TODO test tag?

            return ((ByteString) certificateDI).getBytes();
        }

        private Set<String> decodeDocType(Map map)
                throws CertificateException {
            DataItem docTypeDI = map.get(RequiredCertificateInfoKey.DOC_TYPE.getUnicodeString());
            if (!(docTypeDI instanceof Array)) {
                // TODO refactor to better exception
                throw new RuntimeException();
            }
            Set<String> docTypes = new HashSet<>();

            Array docTypeArray = (Array) docTypeDI;
            List<?> dataItems = docTypeArray.getDataItems();
            for (Object dataItem : dataItems) {
                if (!(dataItem instanceof UnicodeString)) {

                     // DEBUG don't skip, used to avoid AAMVA BREAK of indefinite length array
                    continue;
                    // TODO refactor to better exception
                    // throw new RuntimeException();
                }
                UnicodeString docType = (UnicodeString) dataItem;
                docTypes.add(docType.getString());
            }
            return docTypes;
        }

        private Set<String> decodeCertificateProfile(Map map) {

            Set<String> certificateProfiles = new HashSet<>();
            DataItem certificateProfileDI = map.get(OptionalCertificateInfoKey.CERTIFICATE_PROFILE.getUnicodeString());
            if (certificateProfileDI == null) {
                return certificateProfiles;
            }

            if (!(certificateProfileDI instanceof Array)) {
                // TODO refactor to better exception
                throw new RuntimeException(certificateProfileDI.getClass().getTypeName());
            }

            Array certificateProfileArray = (Array) certificateProfileDI;
            List<?> dataItems = certificateProfileArray.getDataItems();
            for (Object dataItem : dataItems) {
                if (!(dataItem instanceof UnicodeString)) {
                    // TODO refactor to better exception
                    throw new RuntimeException();
                }
                UnicodeString docType = (UnicodeString) dataItem;
                certificateProfiles.add(docType.getString());
            }
            return certificateProfiles;
        }

        private String decodeIssuingAuthority(Map map) {
            DataItem issuingAuthorityDI = map.get(OptionalCertificateInfoKey.ISSUING_AUTHORITY.getUnicodeString());
            if (issuingAuthorityDI == null) {
                return null;
            }
            if (!(issuingAuthorityDI instanceof UnicodeString)) {
                // TODO refactor ot better exception
                throw new RuntimeException();
            }
            UnicodeString issuingAuthority = (UnicodeString) issuingAuthorityDI;
            return issuingAuthority.getString();
        }

        private String decodeIssuingCountry(Map map) {
            DataItem issuingCountryDI = map.get(OptionalCertificateInfoKey.ISSUING_COUNTRY.getUnicodeString());
            if (issuingCountryDI == null) {
                return null;
            }
            if (!(issuingCountryDI instanceof UnicodeString)) {
                // TODO refactor ot better exception
                throw new RuntimeException();
            }
            UnicodeString issuingCountry = (UnicodeString) issuingCountryDI;
            String issuingCountryStr = issuingCountry.getString();
            if (issuingCountryStr.length() < 2 || issuingCountryStr.length() > 3) {
                // TODO refactor ot better exception
                throw new RuntimeException();
            }
            return issuingCountryStr;
        }

        private String decodeStateOrProvinceName(Map map) {
            DataItem issuingStateOrProvinceNameDI = map
                    .get(OptionalCertificateInfoKey.STATE_OR_PROVINCE_NAME.getUnicodeString());
            if (issuingStateOrProvinceNameDI == null) {
                return null;
            }
            if (!(issuingStateOrProvinceNameDI instanceof UnicodeString)) {
                // TODO refactor ot better exception
                throw new RuntimeException();
            }
            UnicodeString issuingStateOrProvinceName = (UnicodeString) issuingStateOrProvinceNameDI;
            return issuingStateOrProvinceName.getString();
        }

        private byte[] decodeIssuer(Map map) {
            DataItem issuerDI = map.get(OptionalCertificateInfoKey.ISSUER.getUnicodeString());
            if (issuerDI == null) {
                return null;
            }

            if (!(issuerDI instanceof ByteString)) {
                // TODO refactor ot better exception
                throw new RuntimeException();
            }
            return ((ByteString) issuerDI).getBytes();
        }

        private byte[] decodeSubject(Map map) {
            DataItem subjectDI = map.get(OptionalCertificateInfoKey.ISSUER.getUnicodeString());
            if (subjectDI == null) {
                return null;
            }

            if (!(subjectDI instanceof ByteString)) {
                // TODO refactor ot better exception
                throw new RuntimeException();
            }
            return ((ByteString) subjectDI).getBytes();
        }

        private Instant decodeNotBefore(Map map) {
            DataItem tdateDI = map.get(OptionalCertificateInfoKey.NOT_BEFORE.getUnicodeString());
            if (tdateDI == null) {
                return null;
            }
            return Util.parseTDate(tdateDI);
        }

        private Instant decodeNotAfter(Map map) {
            DataItem tdateDI = map.get(OptionalCertificateInfoKey.NOT_AFTER.getUnicodeString());
            if (tdateDI == null) {
                return null;
            }
            return Util.parseTDate(tdateDI);
        }

        private Map decodeExtensions(Map map) throws DataItemDecoderException {
            DataItem extensionsDI = map.get(OptionalCertificateInfoKey.EXTENSIONS.getUnicodeString());
            if (extensionsDI == null) {
                return null;
            }

            Map extensions = Util.toVicalCompatibleMap("extensions", extensionsDI);
            return extensions;
        }

        private Map decodeRFU(Map map) throws DataItemDecoderException {
            Map rfu = new Map();
            KEYS: for (DataItem key : map.getKeys()) {
                if (!(key instanceof UnicodeString)) {
                    throw new DataItemDecoderException("key in RFU is not of type UnicodeString");
                }

                // TODO this is a bit laborsome, maybe do something
                for (RequiredCertificateInfoKey requiredKey : EnumSet.allOf(RequiredCertificateInfoKey.class)) {
                    if (key.equals(requiredKey.getUnicodeString())) {
                        continue KEYS;
                    }
                }

                for (OptionalCertificateInfoKey optionalKey : EnumSet.allOf(OptionalCertificateInfoKey.class)) {
                    if (key.equals(optionalKey.getUnicodeString())) {
                        continue KEYS;
                    }
                }

                rfu.put(key, map.get(key));
            }
            return rfu;
        }

    }

    private String version;
    private X509Certificate certificate;
    private BigInteger serialNumber;
    private byte[] ski;
    private Set<String> docTypes;

    // optional (nullable) fields, copied from certificate
    private Set<String> certificateProfile = new HashSet<String>();
    private String issuingCountry;
    private String stateOrProvinceName;
    private byte[] issuer;
    private byte[] subject;
    private Instant notBefore;
    private Instant notAfter;

    // optional (nullable) field, provided separately
    private String issuingAuthority;

    // lazy instantiation, null means no extensions (as it is an optional keyed field)
    private Map extensions = null;

    // always instantiated, empty means no RFU
    private Map rfu;

    private CertificateInfo(X509Certificate cert, Set<String> docTypes) {
        this.version = "1.0";
        this.certificate = cert;
        this.serialNumber = cert.getSerialNumber();
        this.ski = getSubjectPublicKeyIdentifier(cert);
        this.docTypes = docTypes;
        this.rfu = new Map();
    }

    private CertificateInfo(X509Certificate cert, BigInteger serialNumber, byte[] ski, Set<String> docType) {
        this.certificate = cert;
        this.serialNumber = serialNumber;
        // clone not really necessary if non-public, but it won't hurt performance anyway
        this.ski = ski.clone();
        this.docTypes = docType;
        this.rfu = new Map();
    }

    // TODO do we need a copy constructor + build method?

    public String version() {
        return version;
    }

    public X509Certificate certificate() {
        return certificate;
    }

    public BigInteger serialNumber() {
        return serialNumber;
    }

    /**
     * Returns the subject public key field for the certificate;
     * this should be the same as the SPKI contained within the certificate.
     *
     * @return the SubjectPublicKeyInfo field
     */
    public byte[] ski() {
        return ski.clone();
    }

    public Set<String> docTypes() {
        return docTypes;
    }

    public Set<String> certificateProfile() {
        return certificateProfile;
    }

    public Optional<String> issuingAuthority() {
        return Optional.ofNullable(issuingAuthority);
    }

    public Optional<String> issuingCountry() {
        return Optional.ofNullable(issuingCountry);
    }

    public Optional<String> stateOrProvinceName() {
        return Optional.ofNullable(stateOrProvinceName);
    }

    public Optional<byte[]> issuer() {
        return Optional.ofNullable(issuer);
    }

    public Optional<byte[]> subject() {
        return Optional.ofNullable(subject);
    }

    public Optional<Instant> notBefore() {
        return Optional.ofNullable(notBefore);
    }

    public Optional<Instant> notAfter() {
        return Optional.ofNullable(notAfter);
    }

    /**
     * Returns empty or a map of extensions.
     * This map may still be empty if the CertificateInfo structure was encoded as such.
     * @return empty
     */
    public Optional<Map> extensions() {
        return Optional.ofNullable(extensions);
    }

    /**
     * Returns a possibly empty map of RFU values, i.e. any key that is not defined in the current version 1 of the standard.
     * @return a map of all the undefined key / value pairs in the CertificateInfo structure
     */
    public Map rfu() {
        return rfu;
    }

    private static byte[] getSubjectPublicKeyIdentifier(X509Certificate cert) {
        byte[] doubleWrappedSKI = cert.getExtensionValue(Extension.subjectKeyIdentifier.getId());
        try {
            return stripEncoding(stripEncoding(doubleWrappedSKI));
        } catch (Exception e) {
            throw new RuntimeException(
                    "Could not remove OCTETSTRING or BITSTRING encoding around SubjectPublicKeyIdentifier",
                    e);
        }
    }

    /**
     * Removes an
     * 
     * @param encodedValue
     * @return
     */
    private static byte[] stripEncoding(byte[] encodedValue) {
        final ASN1Primitive derObject;

        try (ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(encodedValue))) {
            derObject = asn1InputStream.readObject();
        } catch (IOException e) {
            throw new RuntimeException("I/O exception when reading from memory stream", e);
        }

        if (derObject instanceof DEROctetString) {
            final DEROctetString derOctetString = (DEROctetString) derObject;
            return derOctetString.getOctets();
        } else if (derObject instanceof DERBitString) {
            final DERBitString derBitString = (DERBitString) derObject;
            if (derBitString.getPadBits() != 0) {
                throw new RuntimeException("Number of bits in DERBitString is not alligned");
            }
            return derBitString.getBytes();
        } else {
            // TODO check if the ski is always wrapped this way
            throw new RuntimeException("Expected double wrapped octet string for subjectkeyidentifier");
        }
    }

    /**
     * Returns a multi-line description of this CertificateInfo instance.
     */
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        //        sb.append(String.format("Version: %s%n", this.version));
        sb.append(String.format("certificate: %s%n", Hex.toHexString(calculateID(this.certificate))));
        sb.append(String.format("serialNumber: %x%n", this.serialNumber));
        sb.append(String.format("ski: %s%n", Hex.toHexString(ski)));
        sb.append(String.format("docType (set): %s%n", this.docTypes));
        sb.append(String.format("certificateProfile: %s%n", this.certificateProfile));
        sb.append(String.format("issuingAuthority: %s%n", valueOrNone(this.issuingAuthority)));
        sb.append(String.format("issuingCountry: %s%n", valueOrNone(this.issuingCountry)));
        sb.append(String.format("stateOrProvinceName: %s%n", valueOrNone(this.stateOrProvinceName)));
        final String issuerString = this.issuer == null ? "<none>" : Hex.toHexString(issuer);
        sb.append(String.format("issuer: %s%n", issuerString));
        String subjectString = this.subject == null ? "<none>" : Hex.toHexString(subject);
        sb.append(String.format("subject: %s%n", subjectString));
        String notBeforeString = this.notBefore == null ? "<none>" : Util.visualTDate(notBefore);
        sb.append(String.format("notBefore: %s%n", notBeforeString));
        String notAfterString = this.notAfter == null ? "<none>" : Util.visualTDate(notAfter);
        sb.append(String.format("notAfter: %s%n", notAfterString));
        sb.append(String.format("extensions: %s%n", this.extensions));
        sb.append(String.format("any: %s%n", this.rfu()));
        return sb.toString();
    }

    private static String valueOrNone(String value) {
        return value == null ? "<none>" : value;
    }

    private static byte[] calculateID(X509Certificate cert) {
        try {
            byte[] certData = cert.getEncoded();
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            return sha1.digest(certData);
        } catch (CertificateEncodingException e) {
            throw new RuntimeException("Could not encode certificate while calculating ID", e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Required algorithm not available", e);
        }
    }
    
}
