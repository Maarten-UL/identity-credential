package com.android.mdl.appreader.issuerauth.vical

import co.nstant.`in`.cbor.model.Array
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import java.lang.ArithmeticException
import java.lang.RuntimeException
import java.lang.StringBuilder
import java.security.cert.X509Certificate
import java.text.ParseException
import java.text.SimpleDateFormat
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.*
import java.util.regex.Pattern
import java.util.stream.Collectors

/**
 * Implements a VICAL data structure.
 * The data structure can be build using the internal [Builder] class.
 * It can be CBOR encoded / decoded using the [Encoder] and [Decoder] classes.
 * The VICAL data structure itself is stateless;
 * the builder can be used to add / change information and create a new instance.
 * See for instance the [&lt;][Builder.Builder] copy constructor.
 *
 * @author UL TS BV
 */
class Vical private constructor(vicalProvider: String) {
    /**
     * The builder to create a Vical instance.
     *
     * The most important method of this class is arguably the [.addCertificateInfo] method
     * which can be used to include certificates and their descriptions.
     */
    class Builder : InstanceBuilder<Vical?> {
        // private String vicalProvider;
        private var vical: Vical

        /**
         * Creates an instance with the minimum of information, the provider and the date.
         *
         * @param vicalProvider the name of the provider of the VICAL structure
         * @param date the date of issuance of this VICAL
         * @param vicalIssueID the ID of this VICAL
         */
        constructor(vicalProvider: String, date: Instant?, vicalIssueID: Int?) {
            vical = Vical(vicalProvider)
            vical.version = CURRENT_VERSION
            vical.date = date
            vical.vicalIssueID = vicalIssueID
            vical.certificateInfos = LinkedList()
        }

        /**
         * Creates a builder from an existing VICAL structure to that CertificateInfo structures can be added or removed.
         * Note that the vicalIssueID and nextUpdate structures are not copied and a new date needs to be supplied.
         *
         * @param previousVical the previous VICAL
         * @param date the date of issuance of this VICAL
         * @param vicalIssueID the ID of this VICAL
         */
        constructor(previousVical: Vical, date: Instant?, vicalIssueID: Int?) {
            vical = Vical(previousVical.vicalProvider)
            vical.version = previousVical.version
            vical.date = date
            vical.vicalIssueID = vicalIssueID
            vical.certificateInfos = LinkedList(previousVical.certificateInfos)
        }

        /**
         * Can be used to indicate when the next signed VICAL structure can be expected.
         *
         * @param nextUpdate indicates the date for the next VICAL to be released.
         *
         * @return the builder itself
         */
        fun nextUpdate(nextUpdate: Instant): Builder {
            vical.nextUpdate = nextUpdate
            return this
        }

        /**
         * Adds a certificate and its description to the VICAL.
         * Note that it is possible to create [CertificateInfo] structures
         * using the [CertificateInfo.Builder] class.
         *
         * @param certInfo the certificate and (additional) information on the certificate
         * @return the builder itself
         */
        fun addCertificateInfo(certInfo: CertificateInfo): Builder {
            vical.certificateInfos.add(certInfo)
            return this
        }

        /**
         * Returns CertificateInfo fields from this VICAL.
         * This is method is mainly useful to check which CertificateInfo structures are present in the VICAL.
         * @param matcher the matcher that selects the certificates
         * @return the list of certificates that match
         */
        fun returnMatchingCertificateInfos(matcher: (CertificateInfo) -> Boolean): List<CertificateInfo> {
            return vical.certificateInfos.parallelStream()
                .filter(matcher)
                .collect(Collectors.toList())
        }

        /**
         * Checks if the CertificateInfo contains a CertificateInfo for a specific certificate and returns it.
         *
         * @param certificate the certificate to look for
         * @return the certificate info
         */
        fun certificateInfoFor(certificate: X509Certificate): CertificateInfo? {
            val certificateInfos =
                returnMatchingCertificateInfos { x: CertificateInfo -> x.certificate() == certificate }
            return if (certificateInfos.isEmpty()) null else certificateInfos[0]
        }

        /**
         * Tests CertificateInfo fields from this VICAL.
         * This is method is mainly useful to check if certificates are present in this VICAL.
         * @param matcher the matcher that selects the certificates meant for removal
         * @return the builder itself
         */
        fun removeMatchingCertificateInfos(matcher: (CertificateInfo) -> Boolean): Builder {
            vical.certificateInfos = vical.certificateInfos.parallelStream()
                .filter(matcher)
                .collect(Collectors.toList())
            return this
        }

        /**
         * Adds an extension. If no extensions are indicated then the field will not be present.
         * @param key the key of the extension
         * @param value the value of the extension
         */
        fun addExtension(key: UnicodeString?, value: DataItem?) {
            if (vical.extensions == null) {
                vical.extensions = co.nstant.`in`.cbor.model.Map()
            }
            vical.extensions!!.put(key, value)
        }

        /**
         * Adds a possibly unknown key / value to the CertificateInfo.
         * This method does not perform any verification and it allows overwriting of existing, known key / value pairs.
         *
         * @param key the key
         * @param value the value
         */
        fun addRFU(key: UnicodeString?, value: DataItem?) {
            vical.rfu.put(key, value)
        }

        /**
         * Builds the VICAL and returns it.
         */
        override fun build(): Vical {
            return vical
        }
    }

    /**
     * An encoder to encode instances of the `Vical` class.
     */
    class Encoder : DataItemEncoder<co.nstant.`in`.cbor.model.Map, Vical> {
        override fun encode(vical: Vical): co.nstant.`in`.cbor.model.Map {
            val map = co.nstant.`in`.cbor.model.Map(4)
            map.put(RequiredVicalKey.VERSION.getUnicodeString(), UnicodeString(vical.version()))
            map.put(
                RequiredVicalKey.VICAL_PROVIDER.getUnicodeString(),
                UnicodeString(vical.vicalProvider())
            )
            map.put(RequiredVicalKey.DATE.getUnicodeString(), Util.createTDate(vical.date()))
            val vicalIssueID = vical.vicalIssueID()
            if (vicalIssueID != null) {
                map.put(
                    OptionalVicalKey.VICAL_ISSUE_ID.getUnicodeString(),
                    // TODO lookup
                    UnsignedInteger(vicalIssueID.toBigInteger())
                )
            }
            val certificateInfos = vical.certificateInfos()
            // TODO put in the correct structure
            val certInfoEncoder = CertificateInfo.Encoder()
            // TODO we are here
            val certificateInfoArray = Array()
            for (certificateInfo in certificateInfos) {
                certificateInfoArray.add(certInfoEncoder.encode(certificateInfo))
            }
            map.put(RequiredVicalKey.CERTIFICATE_INFOS.getUnicodeString(), certificateInfoArray)

            // extensions is directly put in; it should contain a map in all probability, but it is defined as any
            val extensions = vical.extensions()
            if (extensions != null) {
                map.put(OptionalCertificateInfoKey.EXTENSIONS.getUnicodeString(), extensions)
            }
            val rfu = vical.rfu()
            val entrySet: Set<Map.Entry<UnicodeString?, DataItem>> = Util.getEntrySet(rfu)
            for ((key, value) in entrySet) {
                map.put(key, value)
            }
            return map
        }

        fun encodeToBytes() {
            // TODO implement (?)
        }
    }

    /**
     * A decoder to decode instances of the `Vical` class.
     */
    class Decoder : DataItemDecoder<Vical, co.nstant.`in`.cbor.model.Map> {
        @Throws(DataItemDecoderException::class)
        override fun decode(map: co.nstant.`in`.cbor.model.Map): Vical {

            // === first get the required fields and create the instance
            val version = decodeVersion(map)

            // NOTE this needs to be changed in case additional versions are added to compare
            if (version != CURRENT_VERSION) {
                // TODO introduce checked exception (in DataItemDecoder?)
                throw RuntimeException("Unknown version")
            }
            val vicalProvider = decodeVicalProvider(map)
            val vical = Vical(vicalProvider)
            vical.version = version
            try {
                vical.date = decodeDate(map)
            } catch (e: ParseException) {
                throw DataItemDecoderException("Could not parse VICAL date", e)
            }
            vical.certificateInfos = decodeCertificateInfos(map)

            // === now get the optional fields
            val vicalIssueID = decodeVicalIssueID(map)

            vical.vicalIssueID = vicalIssueID
            vical.extensions = decodeExtensions(map)
            vical.rfu = decodeRFU(map)
            return vical
        }

        @Throws(DataItemDecoderException::class)
        private fun decodeCertificateInfos(map: co.nstant.`in`.cbor.model.Map): MutableList<CertificateInfo> {
            val certificateInfosDI = map[RequiredVicalKey.CERTIFICATE_INFOS.getUnicodeString()]
            if (certificateInfosDI !is Array) {
                throw RuntimeException(certificateInfosDI.javaClass.typeName)
            }
            val certificateInfoDecoder = CertificateInfo.Decoder()
            val certificateInfos: MutableList<CertificateInfo> = LinkedList()
            val certificateInfoList: List<*> = certificateInfosDI.dataItems
            for (certificateInfoObj in certificateInfoList) {
                val certificateInfoMap =
                    Util.toVicalCompatibleMap("CertificateInfo", certificateInfoObj!!)
                val certificateInfo = certificateInfoDecoder.decode(certificateInfoMap)
                certificateInfos.add(certificateInfo)
            }
            return certificateInfos
        }

        private fun decodeVicalIssueID(map: co.nstant.`in`.cbor.model.Map): Int? {
            val vicalIssueID_DI = (map[OptionalVicalKey.VICAL_ISSUE_ID.getUnicodeString()]
                ?: return null) as? UnsignedInteger ?: throw RuntimeException()
            val vicalIssueID_BI = vicalIssueID_DI.value
            val vicalIssueID: Int
            vicalIssueID = try {
                // TODO  was intValueExact of higher API level, check if still OK
                vicalIssueID_BI.toInt()
            } catch (e: ArithmeticException) {
                throw RuntimeException(e)
            }
            return vicalIssueID
        }

        @Throws(ParseException::class)
        private fun decodeDate(map: co.nstant.`in`.cbor.model.Map): Instant {
            // TODO Auto-    static DataItem createTDate(Instant instant) {
            val dateDI = map[RequiredVicalKey.DATE.getUnicodeString()] as? UnicodeString
                ?: throw RuntimeException()
            var tdateString: String = (dateDI as UnicodeString).getString()

            // WARNING fixing data's incorrect parsing of date string, scaling down to millisecond scale
            val tdateWithFraction =
                Pattern.compile("(.*?[.])(\\d+)")
            val tdateWithFractionMatcher =
                tdateWithFraction.matcher(tdateString)
            if (tdateWithFractionMatcher.matches()) {
                tdateString = tdateWithFractionMatcher.group(1) + tdateWithFractionMatcher.group(2)
                    .substring(0, 3)
            }

//            Instant date = Instant.from(DateTimeFormatter.ISO_INSTANT.withZone(ZoneOffset.UTC).parse(tdateString));
            val inputFormat =
                SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS")
            val parsedDate: Date
            parsedDate = try {
                inputFormat.parse(tdateString)
            } catch (e: ParseException) {
                // TODO provide better runtime exception
                throw RuntimeException("Uncaught exception, blame developer", e)
            }
            return parsedDate.toInstant()
        }

        private fun decodeVersion(map: co.nstant.`in`.cbor.model.Map): String {
            val versionDI = map[RequiredVicalKey.VERSION.getUnicodeString()] as? UnicodeString
                ?: throw RuntimeException()
            // TODO also check tag?
            return (versionDI as UnicodeString).getString()
        }

        private fun decodeVicalProvider(map: co.nstant.`in`.cbor.model.Map): String {
            val vicalProviderDI =
                map[RequiredVicalKey.VICAL_PROVIDER.getUnicodeString()] as? UnicodeString
                    ?: throw RuntimeException()
            return (vicalProviderDI as UnicodeString).getString()
        }

        @Throws(DataItemDecoderException::class)
        private fun decodeExtensions(map: co.nstant.`in`.cbor.model.Map): co.nstant.`in`.cbor.model.Map? {
            val extensionsDI =
                map[OptionalCertificateInfoKey.EXTENSIONS.getUnicodeString()] ?: return null
            return Util.toVicalCompatibleMap("extensions", extensionsDI)
        }

        @Throws(DataItemDecoderException::class)
        private fun decodeRFU(map: co.nstant.`in`.cbor.model.Map): co.nstant.`in`.cbor.model.Map {
            val rfu = co.nstant.`in`.cbor.model.Map()
            KEYS@ for (key in map.keys) {
                // TODO this is a bit laborsome, maybe do something
                if (key !is UnicodeString) {
                    throw DataItemDecoderException("Keys in RFU map should be of type UnicodeString")
                }
                for (requiredKey in EnumSet.allOf(
                    RequiredCertificateInfoKey::class.java
                )) {
                    if (key == requiredKey.getUnicodeString()) {
                        continue@KEYS
                    }
                }
                for (optionalKey in EnumSet.allOf(
                    OptionalCertificateInfoKey::class.java
                )) {
                    if (key == optionalKey.getUnicodeString()) {
                        continue@KEYS
                    }
                }
                rfu.put(key, map[key])
            }
            return rfu
        }
    }

    private var version: String
    private val vicalProvider: String
    private var date: Instant? = null
    private var vicalIssueID: Int? = null
    private var nextUpdate: Instant? = null
    private lateinit var certificateInfos: MutableList<CertificateInfo>
    private var extensions: co.nstant.`in`.cbor.model.Map? = null

    // lazy instantiation, null means no extensions (as it is an optional keyed field)
    // always instantiated, empty means no RFU
    private var rfu = co.nstant.`in`.cbor.model.Map()
    fun version(): String {
        return version
    }

    fun vicalProvider(): String {
        return vicalProvider
    }

    fun date(): Instant? {
        return date
    }

    fun vicalIssueID(): Int? {
        return vicalIssueID
    }

    fun nextUpdate(): Instant? {
        return nextUpdate
    }

    fun certificateInfos(): List<CertificateInfo?> {
        return Collections.unmodifiableList(certificateInfos)
    }

    /**
     * Returns empty or a map of extensions.
     * This map may still be empty if the CertificateInfo structure was encoded as such.
     * @return empty
     */
    fun extensions(): co.nstant.`in`.cbor.model.Map? {
        return extensions
    }

    /**
     * Returns a possibly empty map of RFU values, i.e. any key that is not defined in the current version 1 of the standard.
     * @return a map of all the undefined key / value pairs in the CertificateInfo structure
     */
    fun rfu(): co.nstant.`in`.cbor.model.Map {
        return rfu
    }

    override fun toString(): String {
        val sb = StringBuilder()
        sb.append(String.format("version: %s%n", version))
        sb.append(String.format("vicalProvider: %s%n", vicalProvider))
        // TODO fix format
        sb.append(
            String.format(
                "date: %s%n",
                date!!.atZone(ZoneOffset.UTC).format(DateTimeFormatter.ISO_DATE)
            )
        )
        val vicalIssueIdString = if (vicalIssueID == null) "<none>" else vicalIssueID.toString()
        sb.append(String.format("vicalIssueID: %s%n", vicalIssueIdString))
        val nextUpdateString =
            if (nextUpdate == null) "<unknown>" else String.format("%d", nextUpdate)
        sb.append(String.format("nextUpdate: %s%n", nextUpdateString))
        var count = 0
        for (certInfo in certificateInfos!!) {
            count++
            sb.append(String.format(" --- CertificateInfo #%d --- %n", count))
            sb.append(certInfo)
        }
        sb.append(String.format("%n", extensions))
        sb.append(String.format("extensions: %s%n", extensions))
        sb.append(String.format("any: %s%n", rfu()))
        return sb.toString()
    }

    companion object {
        const val CURRENT_VERSION = "1.0"
    }

    init {
        version = CURRENT_VERSION
        this.vicalProvider = vicalProvider
    }
}