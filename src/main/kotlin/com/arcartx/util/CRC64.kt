/**
 * ArcartXResourceSystem
 * Copyright (C) 2025 17Artist
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package com.arcartx.util

import java.io.File
import java.io.FileInputStream
import java.io.InputStream

object CRC64 {
     private const val POLY = -0x3693a86a2878f0beL
    
    private fun createLookupTable(): LongArray {
        val table = LongArray(256)
        for (i in 0 until 256) {
            var crc = i.toLong()
            for (j in 0 until 8) {
                if ((crc and 1L) == 1L) {
                    crc = (crc ushr 1) xor POLY
                } else {
                    crc = (crc ushr 1)
                }
            }
            table[i] = crc
        }
        return table
    }
    
    private val LOOKUP_TABLE = createLookupTable()


    private fun compute(inputStream: InputStream): Long {
        var crc = -1L
        val buffer = ByteArray(8192)

        inputStream.use { stream ->
            var bytesRead: Int
            while (stream.read(buffer).also { bytesRead = it } != -1) {
                for (i in 0 until bytesRead) {
                    crc = LOOKUP_TABLE[((crc.toInt() xor buffer[i].toInt()) and 0xFF)] xor (crc ushr 8)
                }
            }
        }

        return crc.inv()
    }

    fun compute(file: File): Long {
        return compute(FileInputStream(file))
    }
    

    fun toHexString(crc64: Long): String {
        return String.format("%016x", crc64)
    }
    

}
