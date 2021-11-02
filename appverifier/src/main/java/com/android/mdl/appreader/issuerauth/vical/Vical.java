package com.android.mdl.appreader.issuerauth.vical;

import static com.android.mdl.appreader.issuerauth.vical.OptionalCertificateInfoKey.EXTENSIONS;
import static com.android.mdl.appreader.issuerauth.vical.OptionalVicalKey.VICAL_ISSUE_ID;
import static com.android.mdl.appreader.issuerauth.vical.RequiredVicalKey.*;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.Date;
import java.util.EnumSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.UnicodeString;
import co.nstant.in.cbor.model.UnsignedInteger;

/**
 * Implements a VICAL data structure.
 * The data structure can be build using the internal {@link Builder} class.
 * It can be CBOR encoded / decoded using the {@link Encoder} and {@link Decoder} classes.
 * The VICAL data structure itself is stateless;
 * the builder can be used to add / change information and create a new instance.
 * See for instance the {@link Builder#Builder(Vical,Instant,Optional<Integer>)} copy constructor.
 * 
 * @author UL TS BV
 */
public class Vical {

    public static final String CURRENT_VERSION = "1.0";

    /**
     * The builder to create a Vical instance.
     * 
     * The most important method of this class is arguably the {@link #addCertificateInfo(CertificateInfo)} method
     * which can be used to include certificates and their descriptions. 
     */
    
    public static class Builder implements InstanceBuilder<Vical> {

        // private String vicalProvider;

        private Vical vical;
        
        /**
         * Creates an instance with the minimum of information, the provider and the date.
         * 
         * @param vicalProvider the name of the provider of the VICAL structure
         * @param date the date of issuance of this VICAL
         * @param vicalIssueID the ID of this VICAL
         */
        public Builder(String vicalProvider, Instant date, Optional<Integer> vicalIssueID) {
            vical = new Vical(vicalProvider);
            vical.version = CURRENT_VERSION;
            vical.date = date;
            vical.vicalIssueID = vicalIssueID.orElse(null);
            vical.certificateInfos = new LinkedList<>();
        }
        
        /**
         * Creates a builder from an existing VICAL structure to that CertificateInfo structures can be added or removed.
         * Note that the vicalIssueID and nextUpdate structures are not copied and a new date needs to be supplied.
         * 
         * @param previousVical the previous VICAL
         * @param date the date of issuance of this VICAL
         * @param vicalIssueID the ID of this VICAL
         */
        public Builder(Vical previousVical, Instant date, Optional<Integer> vicalIssueID) {
            vical = new Vical(previousVical.vicalProvider);
            vical.version = previousVical.version;
            vical.date = date;
            vical.vicalIssueID = vicalIssueID.orElse(null);
            vical.certificateInfos = new LinkedList<>(previousVical.certificateInfos);
        }

        /**
         * Can be used to indicate when the next signed VICAL structure can be expected.
         *  
         * @param nextUpdate indicates the date for the next VICAL to be released.
         * 
         * @return the builder itself
         */
        public Builder nextUpdate(Instant nextUpdate) {
            if (nextUpdate == null) {
                throw new NullPointerException("nextUpdate should not be null");
            }
            
          vical.nextUpdate = nextUpdate;
          return this;
      }
        
        /**
         * Adds a certificate and its description to the VICAL.
         * Note that it is possible to create {@link CertificateInfo} structures
         * using the {@link CertificateInfo.Builder} class. 
         * 
         * @param certInfo the certificate and (additional) information on the certificate
         * @return the builder itself
         */
        public Builder addCertificateInfo(CertificateInfo certInfo) {
            vical.certificateInfos.add(certInfo);
            return this;
        }
        
        /**
         * Returns CertificateInfo fields from this VICAL.
         * This is method is mainly useful to check which CertificateInfo structures are present in the VICAL.
         * @param matcher the matcher that selects the certificates
         * @return the list of certificates that match
         */
        public List<CertificateInfo> returnMatchingCertificateInfos(CertificateInfoMatcher matcher) {
            return vical.certificateInfos.parallelStream().filter(x -> matcher.matches(x)).collect(Collectors.toList());
        }

        /**
         * Checks if the CertificateInfo contains a CertificateInfo for a specific certificate and returns it.
         * 
         * @param certificate the certificate to look for
         * @return
         */
        public Optional<CertificateInfo> certificateInfoFor(X509Certificate certificate) {
            List<CertificateInfo> certificateInfos = returnMatchingCertificateInfos(x -> x.certificate().equals(certificate));
            if (certificateInfos.isEmpty()) {
                return Optional.empty();
            }
            
            return null;
        }
        
        /**
         * Tests CertificateInfo fields from this VICAL.
         * This is method is mainly useful to check if certificates are present in this VICAL.
         * @param matcher the matcher that selects the certificates meant for removal
         * @return the builder itself
         */
        public Builder removeMatchingCertificateInfos(CertificateInfoMatcher matcher) {
            vical.certificateInfos = vical.certificateInfos.parallelStream().filter(x -> !matcher.matches(x)).collect(Collectors.toList());
            return this;
        }
        
        /**
         * Adds an extension. If no extensions are indicated then the field will not be present.
         * @param key the key of the extension
         * @param value the value of the extension
         */
        public void addExtension(UnicodeString key, DataItem value) {
            if (vical.extensions == null) {
                vical.extensions = new Map();
            }
            
            vical.extensions.put(key, value);
        }
        
        /**
         * Adds a possibly unknown key / value to the CertificateInfo.
         * This method does not perform any verification and it allows overwriting of existing, known key / value pairs.
         * 
         * @param key the key
         * @param value the value
         */
        public void addRFU(UnicodeString key, DataItem value) {
            vical.rfu.put(key, value);
        }

        /**
         * Builds the VICAL and returns it. 
         */
        @Override
        public Vical build() {
            return vical;
        }
    }
    
    /**
     * An encoder to encode instances of the <code>Vical</code> class.
     */
    public static class Encoder implements DataItemEncoder<Map, Vical> {

        @Override
        public Map encode(Vical vical) {
            final Map map = new Map(4);
            map.put(VERSION.getUnicodeString(), new UnicodeString(vical.version()));
            map.put(VICAL_PROVIDER.getUnicodeString(), new UnicodeString(vical.vicalProvider()));
            map.put(DATE.getUnicodeString(), Util.createTDate(vical.date()));
            
            Optional<Integer> vicalIssueID = vical.vicalIssueID();
            if (vicalIssueID.isPresent()) {
                map.put(VICAL_ISSUE_ID.getUnicodeString(), new UnsignedInteger(vicalIssueID.get()));
            }
            
            List<CertificateInfo> certificateInfos = vical.certificateInfos();
            // TODO put in the correct structure
            CertificateInfo.Encoder certInfoEncoder = new CertificateInfo.Encoder();
            // TODO we are here
            Array certificateInfoArray = new Array();
            
            for (CertificateInfo certificateInfo : certificateInfos) {
                certificateInfoArray.add(certInfoEncoder.encode(certificateInfo));
            }
            map.put(CERTIFICATE_INFOS.getUnicodeString(), certificateInfoArray);
            
            // extensions is directly put in; it should contain a map in all probability, but it is defined as any
            Optional<Map> extensions = vical.extensions();
            if (extensions.isPresent()) {
                map.put(EXTENSIONS.getUnicodeString(), extensions.get());
            }

            Map rfu = vical.rfu();
            Set<Entry<UnicodeString, DataItem>> entrySet = Util.getEntrySet(rfu);
            for (Entry<UnicodeString, DataItem> entry : entrySet) {
                map.put(entry.getKey(), entry.getValue());
            }

            return map;
        }

        public void encodeToBytes() {
            // TODO implement (?)
        }
        

    }
    
    /**
     * A decoder to decode instances of the <code>Vical</code> class.
     */
    public static class Decoder implements DataItemDecoder <Vical, Map> {
        
        @Override
        public Vical decode(Map map) throws DataItemDecoderException {
            
            // === first get the required fields and create the instance
            String version = decodeVersion(map);
            
            // NOTE this needs to be changed in case additional versions are added to compare
            if (!version.equals(CURRENT_VERSION)) {
                // TODO introduce checked exception (in DataItemDecoder?)
                throw new RuntimeException("Unknown version");
            }
            
            String vicalProvider = decodeVicalProvider(map);
            Vical vical = new Vical(vicalProvider);
            
            vical.version = version;
            try {
                vical.date = decodeDate(map);
            } catch (ParseException e) {
                throw new DataItemDecoderException("Could not parse VICAL date", e);
            }
            vical.certificateInfos = decodeCertificateInfos(map);

            // === now get the optional fields
            Optional<Integer> vicalIssueID = decodeVicalIssueID(map);
            if (vicalIssueID.isPresent()) {
                vical.vicalIssueID = vicalIssueID.get();
            }
            
            vical.extensions = decodeExtensions(map);
            vical.rfu = decodeRFU(map);

            return vical;
        }

        private List<CertificateInfo> decodeCertificateInfos(Map map)
                throws DataItemDecoderException {
            DataItem certificateInfosDI = map.get(RequiredVicalKey.CERTIFICATE_INFOS.getUnicodeString());
            if (!(certificateInfosDI instanceof Array)) {
                throw new RuntimeException(certificateInfosDI.getClass().getTypeName()); 
            }
            Array certificateInfoArray = (Array) certificateInfosDI;
            
            CertificateInfo.Decoder certificateInfoDecoder = new CertificateInfo.Decoder();
            List<CertificateInfo> certificateInfos = new LinkedList<>();
            List<?> certificateInfoList = certificateInfoArray.getDataItems();
            for (Object certificateInfoObj : certificateInfoList) {
                Map certificateInfoMap = Util.toVicalCompatibleMap("CertificateInfo", certificateInfoObj);
                CertificateInfo certificateInfo = certificateInfoDecoder.decode(certificateInfoMap);
                certificateInfos.add(certificateInfo);
            }
            
            return certificateInfos;
        }


        private Optional<Integer> decodeVicalIssueID(Map map) {
            DataItem vicalIssueID_DI = map.get(OptionalVicalKey.VICAL_ISSUE_ID.getUnicodeString());
            if (vicalIssueID_DI == null) {
                return Optional.empty();
            }
            
            if (!(vicalIssueID_DI instanceof UnsignedInteger)) {
                throw new RuntimeException(); 
            }
            BigInteger vicalIssueID_BI = ((UnsignedInteger) vicalIssueID_DI).getValue();
            int vicalIssueID;
            try {
                // TODO  was intValueExact of higher API level, check if still OK
                vicalIssueID = vicalIssueID_BI.intValue();
            } catch (ArithmeticException e) {
                throw new RuntimeException(e);
            }
            
            return Optional.of(vicalIssueID);
        }


        private Instant decodeDate(Map map) throws ParseException {
            // TODO Auto-    static DataItem createTDate(Instant instant) {
            DataItem dateDI = map.get(RequiredVicalKey.DATE.getUnicodeString());
            
            if (!(dateDI instanceof UnicodeString)) {
                throw new RuntimeException(); 
            }
            String tdateString = ((UnicodeString)dateDI).getString();
            
            // WARNING fixing data's incorrect parsing of date string, scaling down to millisecond scale
            Pattern tdateWithFraction = Pattern.compile("(.*?[.])(\\d+)");
            Matcher tdateWithFractionMatcher = tdateWithFraction.matcher(tdateString);
            if (tdateWithFractionMatcher.matches()) {
                tdateString = tdateWithFractionMatcher.group(1) + tdateWithFractionMatcher.group(2).substring(0, 3); 
            }
            
//            Instant date = Instant.from(DateTimeFormatter.ISO_INSTANT.withZone(ZoneOffset.UTC).parse(tdateString));
            SimpleDateFormat inputFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS");
            Date parsedDate;
            try {
                parsedDate = inputFormat.parse(tdateString);
            } catch (ParseException e) {
                // TODO provide better runtime exception
                throw new RuntimeException("Uncaught exception, blame developer", e);
            }
            Instant date = parsedDate.toInstant();
            
            return date;
        }

        private String decodeVersion(Map map) {
            DataItem versionDI = map.get(RequiredVicalKey.VERSION.getUnicodeString());
            // TODO also check tag?
            if (!(versionDI instanceof UnicodeString)) {
                throw new RuntimeException(); 
            }
            return ((UnicodeString)versionDI).getString();
        }

        
        private String decodeVicalProvider(Map map) {
            DataItem vicalProviderDI = map.get(RequiredVicalKey.VICAL_PROVIDER.getUnicodeString());
            if (!(vicalProviderDI instanceof UnicodeString)) {
                throw new RuntimeException(); 
            }
            return ((UnicodeString)vicalProviderDI).getString();
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
                // TODO this is a bit laborsome, maybe do something
                if (!(key instanceof UnicodeString)) {
                    throw new DataItemDecoderException("Keys in RFU map should be of type UnicodeString");
                }

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
    private String vicalProvider;
    private Instant date;
    private Integer vicalIssueID;
    private Instant nextUpdate;
    private List<CertificateInfo> certificateInfos;

    private Map extensions = null;
    // lazy instantiation, null means no extensions (as it is an optional keyed field)

    // always instantiated, empty means no RFU
    private Map rfu = new Map();

    private Vical(String vicalProvider) {
        this.version = CURRENT_VERSION;
        this.vicalProvider = vicalProvider;
    }

    public String version() {
        return version;
    }
    
    public String vicalProvider() {
        return vicalProvider;
    }
    
    public Instant date() {
        return date;
    }
    
    public Optional<Integer> vicalIssueID() {
        return Optional.ofNullable(vicalIssueID);
    }
    
    public Optional<Instant> nextUpdate() {
        return Optional.ofNullable(nextUpdate);
    }
    
    List<CertificateInfo> certificateInfos() {
        return Collections.unmodifiableList(certificateInfos);
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

    
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("version: %s%n", this.version));
        sb.append(String.format("vicalProvider: %s%n", this.vicalProvider));
        // TODO fix format
        sb.append(String.format("date: %s%n", this.date.atZone(ZoneOffset.UTC).format(DateTimeFormatter.ISO_DATE)));
        final String vicalIssueIdString = this.vicalIssueID == null ? "<none>" : this.vicalIssueID.toString();
        sb.append(String.format("vicalIssueID: %s%n", vicalIssueIdString));
        final String nextUpdateString = this.nextUpdate == null ? "<unknown>" : String.format("%d", this.nextUpdate);
        sb.append(String.format("nextUpdate: %s%n", nextUpdateString));
        int count = 0;
        for (CertificateInfo certInfo : this.certificateInfos) {
            count++;
            sb.append(String.format(" --- CertificateInfo #%d --- %n", count));
            sb.append(certInfo);
        }
        sb.append((String.format("%n", this.extensions)));
        sb.append(String.format("extensions: %s%n", this.extensions));
        sb.append(String.format("any: %s%n", this.rfu()));
        return sb.toString();
    }
}
