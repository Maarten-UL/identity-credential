package com.android.mdl.appreader.issuerauth

import android.content.Context
import java.io.File

/**
 * [Store] Base class for the validation, parsing and persistence of certificates or vicals
 */
abstract class Store<T> {

    abstract val folderName: String
    abstract val extension: String

    /**
     * Parse, validate and persist an item
     */
    fun save(context: Context, name: String, content: ByteArray) {
        var item = parse(content)
        validate(item)
        var fileName = sanitizeFilename("${determineFileName(item)}.$extension")
        val file = File(context.getDir(folderName, Context.MODE_PRIVATE), fileName)
        if (file.exists()) {
            // TODO: throw exception???
        } else {
            file.writeBytes(content);
        }
    }

    /**
     * Retrieve and parse all the items in the folder
     */
    fun getAll(context: Context): List<T> {
        val result = ArrayList<T>()
        context.getDir(folderName, Context.MODE_PRIVATE).walkTopDown().forEach {
            result.add(parse(it.readBytes()))
        }
        return result;
    }

    /**
     * Parse the content to an instance of <T>
     */
    protected abstract fun parse(content: ByteArray): T

    /**
     * Validate the parsed item
     */
    protected abstract fun validate(item: T)

    /**
     * Determine the filename (without extension)
     */
    protected abstract fun determineFileName(item: T):String

    /**
     * Replace reserved characters in the file name with underscores
     */
    private fun sanitizeFilename(filename: String): String {
        return filename.replace("[^a-zA-Z0-9.-=]".toRegex(), "_")
    }
}