package com.android.mdl.appreader.issuerauth.vical;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.MajorType;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.UnicodeString;

public final class Util {
    private static final int TAG_TDATE = 0;

    public static DataItem createTDate(Instant instant) {
        String tdateString = DateTimeFormatter.ISO_INSTANT.withZone(ZoneOffset.UTC).format(instant);
        UnicodeString tdate = new UnicodeString(tdateString);
        tdate.setTag(TAG_TDATE);
        return tdate;
    }

    public static Instant parseTDate(DataItem tdateDI) {
        if (!(tdateDI instanceof UnicodeString)) {
            // TODO think of better exception
            throw new RuntimeException();
        }
        UnicodeString tdate = (UnicodeString) tdateDI;
        if (!(tdate.hasTag() || tdate.getTag().equals(TAG_TDATE))) {
            // TODO think of better exception
            throw new RuntimeException();
        }
        Instant instant;
        try {
            instant = DateTimeFormatter.ISO_INSTANT.withZone(ZoneOffset.UTC).parse(tdate.getString(), Instant::from);
        } catch (DateTimeParseException e) {
            // TODO think of better exception
            throw new RuntimeException(e);
        }
        return instant;
    }

    public static String visualTDate(Instant instant) {
        return DateTimeFormatter.ISO_INSTANT.withZone(ZoneOffset.UTC).format(instant);
    }

    /**
     * Returns a Map of UnicodeString to DataItem after testing if the object given is such a thing.
     * 
     * @param expectedField the field we're trying to cast to a Map
     * @param obj           the object to cast to <code>Map<UnicodeString, DataItem></code>
     * @return the object as <code>Map<UnicodeString, DataItem></code>
     * @throws DataItemDecoderException if object is not a DataItem, a Map or particularly a Map with Unicode strings as
     *                                  keys
     */
    public static Map toVicalCompatibleMap(String expectedField, Object obj)
            throws DataItemDecoderException {
        // this method presumes that the object can be cast to the right type if the CBOR majortype is correct
        if (!(obj instanceof DataItem)) {
            throw new DataItemDecoderException(expectedField + " structure is not a DataItem");
        }

        DataItem di = (DataItem) obj;

        if (!(di.getMajorType() == MajorType.MAP && di instanceof Map)) {
            throw new DataItemDecoderException(expectedField + " structure is not a Map");
        }

        @SuppressWarnings("unchecked")
        Map map = (Map) di;

        Collection<DataItem> keys = map.getKeys();
        for (DataItem key : keys) {
            if (!(key.getMajorType() == MajorType.UNICODE_STRING && key instanceof UnicodeString)) {
                throw new DataItemDecoderException(expectedField + " contains a key that is not a Unicode string");
            }
        }

        @SuppressWarnings("unchecked")
        Map vicalMap = (Map) di;
        return vicalMap;
    }

    
    public static String oidStringToURN(String dotNotationOid) {
        if (!dotNotationOid.matches("[1-9]\\d*(?:[.][1-9]\\d*)*")) {
            throw new RuntimeException("Input is not a short / dot notation OID");
        }
        
        return "urn:oid:" + dotNotationOid;
    }
    
    public static String urnStringToOid(String oidUrn) {
        Matcher matcher = Pattern.compile("urn:oid:([1-9]\\d*(?:[.][1-9]\\d*)*)",
                Pattern.CASE_INSENSITIVE).matcher(oidUrn);
        if (!matcher.matches()) {
            throw new RuntimeException("Input is not a OID URN");
        }
        
        return matcher.group(1);
    }

    public static Set<java.util.Map.Entry<UnicodeString, DataItem>> getEntrySet(Map cborMap) {
        Set<java.util.Map.Entry<UnicodeString, DataItem>> ret = new HashSet<>();

        for (final DataItem keyDI : cborMap.getKeys()) {
            // TODO test type
            UnicodeString key = (UnicodeString) keyDI;
            final DataItem value = cborMap.get(key);
            java.util.Map.Entry<UnicodeString, DataItem> entry = new java.util.Map.Entry<UnicodeString, DataItem>() {
                @Override
                public UnicodeString getKey() {
                    return key;
                }

                @Override
                public DataItem getValue() {
                    return value;
                }

                @Override
                public DataItem setValue(DataItem dataItem) {
                    throw new RuntimeException("The set of Entry represented by the CBOR map is read only");
                }
            };
            ret.add(entry);
        }
        return ret;
    }

}
