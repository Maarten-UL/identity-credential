package com.android.mdl.appreader.issuerauth

import android.content.Context
import com.android.mdl.appreader.issuerauth.vical.Vical
import java.time.format.DateTimeFormatter


/**
 * Class for the parsing, validation and storage of vicals
 * Because of it's dependency of Context, this class should be used from VerifierApp.vicalStoreInstance
 */
class VicalStore(context: Context) : Store<Vical>(context) {
    override val folderName: String
        get() = "Vical"
    override val extension: String
        get() = ".vical"

    override fun parse(content: ByteArray): Vical {
        TODO("Add vical parsing logic")
    }

    override fun determineFileName(item: Vical): String {
        val nameBuilder = StringBuilder()
        if (item.date() != null){
            nameBuilder.append(DateTimeFormatter.ofPattern("yyyyMMdd").format(item.date()) + " ")
        }
        nameBuilder.append(item.vicalProvider())
        if (item.version() != null){
            nameBuilder.append(" ${item.version()}")
        }
        return nameBuilder.toString()
    }

    override fun validate(item: Vical) {
        // intentionally left empty, validation will be done while parsing
    }
}