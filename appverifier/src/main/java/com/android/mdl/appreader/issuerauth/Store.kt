package com.android.mdl.appreader.issuerauth

import android.content.Context
import java.io.File
import java.nio.file.Files

/**
 * [Store] Base class for the validation, parsing and persistence of certificates or vicals
 */
abstract class Store<T> {

    abstract val folderName: String
    abstract val extension: String

    /**
     * Parse, validate and persist an item
     */
    fun save(context: Context, content: ByteArray) {
        val item = parse(content)
        validate(item)
        val fileName = sanitizeFilename("${determineFileName(item)}$extension")
        val file = File(context.getDir(folderName, Context.MODE_PRIVATE), fileName)
        if (file.exists()) {
            // TODO: throw exception???
        } else {
            file.writeBytes(content)
        }
    }

    /**
     * Retrieve and parse all the items in the folder
     */
    fun getAll(context: Context): List<T> {
        val result = ArrayList<T>()
        val directory = context.getDir(folderName, Context.MODE_PRIVATE)
        if (directory.exists()) {
            directory.walk()
                .filter { file -> Files.isRegularFile(file.toPath()) }
                .filter { file -> file.toString().endsWith(extension) }
                .forEach { result.add(parse(it.readBytes())) }
        }
        return result
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
    protected abstract fun determineFileName(item: T): String

    /**
     * Replace reserved characters in the file name with underscores
     */
    private fun sanitizeFilename(filename: String): String {
        return filename.replace("[^a-zA-Z0-9.-=]".toRegex(), "_")
    }
}