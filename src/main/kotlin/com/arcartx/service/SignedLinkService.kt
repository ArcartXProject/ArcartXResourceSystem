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

import com.arcartx.data.SignedLinkRecord
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import org.slf4j.LoggerFactory
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class SignedLinkService(private val databaseService: DatabaseService) {
    private val logger = LoggerFactory.getLogger(SignedLinkService::class.java)
    private val signedLinks = ConcurrentHashMap<String, SignedLinkRecord>()
    private val cleanupExecutor = Executors.newSingleThreadScheduledExecutor()
    
    companion object {
        private const val TOKEN_LENGTH = 32
    }
    
    private fun getMaxExpirationMinutes(): Int {
        return databaseService.getSignedLinkMaxMinutes()
    }
    
    private fun getMaxDownloadLimit(): Int {
        return databaseService.getSignedLinkMaxDownloads()
    }
    
    init {
        // 每5分钟清理一次过期的签名链接
        cleanupExecutor.scheduleWithFixedDelay(
            { cleanupExpiredLinks() },
            5, 5, TimeUnit.MINUTES
        )
        logger.info("签名链接服务初始化完成")
    }
    
    fun generateSignedLink(
        fileName: String,
        expirationMinutes: Int,
        downloadLimit: Int,
        createdBy: String
    ): Result<SignedLinkRecord> {
        return try {
            // 获取动态配置
            val maxExpirationMinutes = getMaxExpirationMinutes()
            val maxDownloadLimit = getMaxDownloadLimit()
            
            // 验证参数
            if (expirationMinutes <= 0 || expirationMinutes > maxExpirationMinutes) {
                return Result.failure(IllegalArgumentException("过期时间必须在1-${maxExpirationMinutes}分钟之间"))
            }
            
            if (downloadLimit <= 0 || downloadLimit > maxDownloadLimit) {
                return Result.failure(IllegalArgumentException("下载次数必须在1-${maxDownloadLimit}次之间"))
            }
            
            // 生成唯一token
            val token = generateToken()
            val now = Clock.System.now()
            val expiresAt = Instant.fromEpochMilliseconds(
                now.toEpochMilliseconds() + (expirationMinutes * 60 * 1000L)
            )
            
            val record = SignedLinkRecord(
                token = token,
                fileName = fileName,
                expiresAt = expiresAt,
                remainingDownloads = downloadLimit,
                createdBy = createdBy,
                createdAt = now
            )
            
            signedLinks[token] = record
            logger.info("生成签名链接: 文件=$fileName, 创建者=$createdBy, 过期时间=$expiresAt")
            
            Result.success(record)
        } catch (e: Exception) {
            logger.error("生成签名链接失败: fileName=$fileName", e)
            Result.failure(e)
        }
    }
    
    fun validateAndConsumeToken(token: String): Result<SignedLinkRecord> {
        val record = signedLinks[token]
            ?: return Result.failure(IllegalArgumentException("无效的下载令牌"))
        
        val now = Clock.System.now()
        
        // 检查是否过期
        if (now > record.expiresAt) {
            signedLinks.remove(token)
            logger.warn("令牌已过期: token=${token.substring(0, 8)}...")
            return Result.failure(IllegalArgumentException("下载链接已过期"))
        }
        
        // 检查下载次数
        if (record.remainingDownloads <= 0) {
            signedLinks.remove(token)
            logger.warn("令牌下载次数已用完: token=${token.substring(0, 8)}...")
            return Result.failure(IllegalArgumentException("下载次数已用完"))
        }
        
        // 消费一次下载次数
        val updatedRecord = record.copy(remainingDownloads = record.remainingDownloads - 1)
        
        if (updatedRecord.remainingDownloads <= 0) {
            signedLinks.remove(token)
            logger.info("令牌已用完并移除: 文件=${record.fileName}, token=${token.substring(0, 8)}...")
        } else {
            signedLinks[token] = updatedRecord
        }
        
        logger.info("令牌验证成功: 文件=${record.fileName}, 剩余次数=${updatedRecord.remainingDownloads}")
        return Result.success(updatedRecord)
    }

    
    fun getActiveTokensCount(): Int {
        return signedLinks.size
    }
    

    
    private fun generateToken(): String {
        val random = SecureRandom()
        val bytes = ByteArray(TOKEN_LENGTH)
        random.nextBytes(bytes)
        return bytes.joinToString("") { "%02x".format(it) }
    }
    
    private fun cleanupExpiredLinks() {
        try {
            val now = Clock.System.now()
            val expiredTokens = mutableListOf<String>()
            
            signedLinks.forEach { (token, record) ->
                if (now > record.expiresAt || record.remainingDownloads <= 0) {
                    expiredTokens.add(token)
                }
            }
            
            expiredTokens.forEach { token ->
                signedLinks.remove(token)
            }
            
            if (expiredTokens.isNotEmpty()) {
                logger.info("清理过期签名链接: ${expiredTokens.size} 个")
            }
        } catch (e: Exception) {
            logger.error("清理过期链接失败", e)
        }
    }
    
    fun shutdown() {
        try {
            cleanupExecutor.shutdown()
            if (!cleanupExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                cleanupExecutor.shutdownNow()
            }
            logger.info("签名链接服务已关闭")
        } catch (e: Exception) {
            logger.error("关闭签名链接服务失败", e)
            cleanupExecutor.shutdownNow()
        }
    }
}
