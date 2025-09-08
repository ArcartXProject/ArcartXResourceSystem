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
package com.arcartx.service

import com.arcartx.data.FileInfo
import com.arcartx.util.CRC64
import kotlinx.datetime.toKotlinInstant
import org.slf4j.LoggerFactory
import java.io.File
import java.io.InputStream
import java.nio.file.Files
import java.nio.file.Paths
import java.nio.file.StandardCopyOption
import java.time.Instant
import java.time.ZoneOffset

class FileService(private val databaseService: DatabaseService) {
    private val logger = LoggerFactory.getLogger(FileService::class.java)
    private val uploadsDirectory = "uploads"
    private val allowedExtensions = setOf("zip")
    
    init {
        initializeUploadsDirectory()
    }
    
    private fun initializeUploadsDirectory() {
        val uploadsDir = File(uploadsDirectory)
        if (!uploadsDir.exists()) {
            uploadsDir.mkdirs()
            logger.info("创建上传目录: $uploadsDirectory")
        }
    }
    
    fun saveFile(fileName: String, inputStream: InputStream): Result<FileInfo> {
        return try {
            // 验证文件扩展名
            val extension = fileName.substringAfterLast('.', "").lowercase()
            if (!allowedExtensions.contains(extension)) {
                return Result.failure(IllegalArgumentException("不支持的文件类型: $extension"))
            }
            
            // 清理文件名，防止路径遍历攻击
            val cleanFileName = sanitizeFileName(fileName)
            val filePath = Paths.get(uploadsDirectory, cleanFileName)
            
            // 检查文件是否已存在
            if (Files.exists(filePath)) {
                return Result.failure(IllegalArgumentException("文件已存在: $cleanFileName"))
            }
            
            // 保存文件
            Files.copy(inputStream, filePath, StandardCopyOption.REPLACE_EXISTING)
            
            // 计算CRC64
            val file = filePath.toFile()
            val crc64Value = CRC64.compute(file)
            val crc64Hex = CRC64.toHexString(crc64Value)
            
            // 保存到数据库
            try {
                databaseService.addFileRecord(cleanFileName, file.length(), crc64Hex)
                logger.info("文件记录已保存到数据库: $cleanFileName, CRC64: $crc64Hex")
            } catch (e: Exception) {
                // 如果文件记录已存在，尝试更新
                try {
                    databaseService.updateFileRecord(cleanFileName, file.length(), crc64Hex)
                    logger.info("文件记录已更新: $cleanFileName, CRC64: $crc64Hex")
                } catch (updateError: Exception) {
                    logger.warn("保存文件记录失败: $cleanFileName", updateError)
                }
            }
            
            val fileInfo = getFileInfo(cleanFileName)
            logger.info("文件上传成功: $cleanFileName, 大小: ${fileInfo.size} bytes, CRC64: $crc64Hex")
            
            Result.success(fileInfo)
        } catch (e: Exception) {
            logger.error("文件上传失败: $fileName", e)
            Result.failure(e)
        }
    }
    
    fun deleteFile(fileName: String): Result<Boolean> {
        return try {
            val cleanFileName = sanitizeFileName(fileName)
            val filePath = Paths.get(uploadsDirectory, cleanFileName)
            
            if (!Files.exists(filePath)) {
                return Result.failure(IllegalArgumentException("文件不存在: $cleanFileName"))
            }
            
            val deleted = Files.deleteIfExists(filePath)
            if (deleted) {
                // 删除数据库记录
                try {
                    databaseService.removeFileRecord(cleanFileName)
                    logger.info("文件和数据库记录删除成功: $cleanFileName")
                } catch (e: Exception) {
                    logger.warn("删除文件数据库记录失败: $cleanFileName", e)
                }
            }
            
            Result.success(deleted)
        } catch (e: Exception) {
            logger.error("文件删除失败: $fileName", e)
            Result.failure(e)
        }
    }
    
    fun listFiles(): List<FileInfo> {
        return try {
            val uploadsDir = File(uploadsDirectory)
            if (!uploadsDir.exists()) {
                return emptyList()
            }
            
            uploadsDir.listFiles()
                ?.filter { it.isFile && allowedExtensions.contains(it.extension.lowercase()) }
                ?.map { file ->
                    FileInfo(
                        name = file.name,
                        size = file.length(),
                        lastModified = Instant.ofEpochMilli(file.lastModified()).atOffset(ZoneOffset.UTC).toInstant().toKotlinInstant()
                    )
                }
                ?.sortedBy { it.name }
                ?: emptyList()
        } catch (e: Exception) {
            logger.error("获取文件列表失败", e)
            emptyList()
        }
    }
    
    fun getFile(fileName: String): Result<File> {
        return try {
            val cleanFileName = sanitizeFileName(fileName)
            val file = File(uploadsDirectory, cleanFileName)
            
            if (!file.exists() || !file.isFile) {
                return Result.failure(IllegalArgumentException("文件不存在: $cleanFileName"))
            }
            
            // 验证文件扩展名
            val extension = file.extension.lowercase()
            if (!allowedExtensions.contains(extension)) {
                return Result.failure(IllegalArgumentException("不支持的文件类型: $extension"))
            }
            
            Result.success(file)
        } catch (e: Exception) {
            logger.error("获取文件失败: $fileName", e)
            Result.failure(e)
        }
    }
    
    fun getFileInfo(fileName: String): FileInfo {
        val cleanFileName = sanitizeFileName(fileName)
        val file = File(uploadsDirectory, cleanFileName)
        
        return FileInfo(
            name = file.name,
            size = file.length(),
            lastModified = Instant.ofEpochMilli(file.lastModified()).atOffset(ZoneOffset.UTC).toInstant().toKotlinInstant()
        )
    }
    
    fun fileExists(fileName: String): Boolean {
        val cleanFileName = sanitizeFileName(fileName)
        val file = File(uploadsDirectory, cleanFileName)
        return file.exists() && file.isFile
    }
    
    private fun sanitizeFileName(fileName: String): String {
        // 移除路径分隔符和危险字符
        return fileName
            .replace(Regex("[/\\\\:*?\"<>|]"), "_")
            .replace("..", "_")
            .trim()
            .takeIf { it.isNotEmpty() }
            ?: "unnamed_file"
    }
    
    fun getTotalSize(): Long {
        return try {
            val uploadsDir = File(uploadsDirectory)
            if (!uploadsDir.exists()) {
                return 0L
            }
            
            uploadsDir.listFiles()
                ?.filter { it.isFile && allowedExtensions.contains(it.extension.lowercase()) }
                ?.sumOf { it.length() }
                ?: 0L
        } catch (e: Exception) {
            logger.error("计算总大小失败", e)
            0L
        }
    }
}
