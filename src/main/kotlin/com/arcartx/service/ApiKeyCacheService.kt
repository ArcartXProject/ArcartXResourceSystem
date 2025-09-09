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

import com.arcartx.data.ApiKeyInfo
import com.arcartx.data.ApiKeys
import org.jetbrains.exposed.sql.transactions.transaction
import org.slf4j.LoggerFactory
import java.security.MessageDigest
import java.time.ZoneOffset
import java.util.concurrent.ConcurrentHashMap
import kotlinx.datetime.toKotlinInstant
import org.jetbrains.exposed.sql.selectAll

class ApiKeyCacheService {
    private val logger = LoggerFactory.getLogger(ApiKeyCacheService::class.java)

    private val keyCache = ConcurrentHashMap<String, ApiKeyInfo>()

    private val ipWhitelistCache = ConcurrentHashMap<String, List<String>>()
    
    /**
     * 初始化缓存，从数据库加载所有API密钥
     */
    fun initializeCache() {
        logger.info("正在初始化API密钥缓存...")
        try {
            val cacheCount = reloadCache()
            logger.info("API密钥缓存初始化完成，缓存了 $cacheCount 个密钥")
        } catch (e: Exception) {
            logger.error("API密钥缓存初始化失败", e)
        }
    }

    private fun reloadCache(): Int {
        return transaction {
            keyCache.clear()
            ipWhitelistCache.clear()
            
            var count = 0
            ApiKeys.selectAll().forEach { row ->
                val keyInfo = ApiKeyInfo(
                    id = row[ApiKeys.id].value,
                    keyName = row[ApiKeys.keyName],
                    createdAt = row[ApiKeys.createdAt].toInstant(ZoneOffset.UTC).toKotlinInstant()
                )
                
                val keyHash = row[ApiKeys.keyHash]
                keyCache[keyHash] = keyInfo
                
                // 缓存IP白名单
                val ipWhitelist = row[ApiKeys.ipWhitelist]
                if (!ipWhitelist.isNullOrEmpty()) {
                    ipWhitelistCache[keyHash] = ipWhitelist.split(",").map { it.trim() }
                } else {
                    ipWhitelistCache[keyHash] = emptyList()
                }
                
                count++
            }
            count
        }
    }

    fun validateApiKey(apiKey: String): ApiKeyInfo? {
        val keyHash = hashApiKey(apiKey)
        return keyCache[keyHash]
    }

    fun validateApiKeyWithIp(apiKey: String, clientIp: String): Boolean {
        val keyHash = hashApiKey(apiKey)
        val keyInfo = keyCache[keyHash] ?: return false
        
        // 检查IP白名单
        val allowedIps = ipWhitelistCache[keyHash] ?: emptyList()
        if (allowedIps.isNotEmpty() && !allowedIps.contains(clientIp)) {
            logger.warn("API密钥使用被拒绝，IP不在白名单: $clientIp，密钥：${keyInfo.keyName}")
            return false
        }
        
        logger.debug("API密钥验证成功: ${keyInfo.keyName}, IP: $clientIp")
        return true
    }
    

    fun getIpWhitelist(keyName: String): List<String> {
        val keyHash = keyCache.entries.find { it.value.keyName == keyName }?.key
        return if (keyHash != null) {
            ipWhitelistCache[keyHash] ?: emptyList()
        } else {
            emptyList()
        }
    }

    fun updateIpWhitelistCache(keyName: String, ipList: List<String>) {
        val keyHash = keyCache.entries.find { it.value.keyName == keyName }?.key
        if (keyHash != null) {
            ipWhitelistCache[keyHash] = ipList
            logger.info("已更新密钥 $keyName 的IP白名单缓存")
        }
    }

    fun refreshCache() {
        logger.info("正在刷新API密钥缓存...")
        try {
            val cacheCount = reloadCache()
            logger.info("API密钥缓存刷新完成，缓存了 $cacheCount 个密钥")
        } catch (e: Exception) {
            logger.error("API密钥缓存刷新失败", e)
        }
    }

    fun addToCache(keyHash: String, keyInfo: ApiKeyInfo, ipWhitelist: List<String> = emptyList()) {
        keyCache[keyHash] = keyInfo
        ipWhitelistCache[keyHash] = ipWhitelist
        logger.info("已将密钥 ${keyInfo.keyName} 添加到缓存")
    }


    fun removeFromCache(keyName: String) {
        val keyHashToRemove = keyCache.entries.find { it.value.keyName == keyName }?.key
        if (keyHashToRemove != null) {
            keyCache.remove(keyHashToRemove)
            ipWhitelistCache.remove(keyHashToRemove)
            logger.info("已从缓存中移除密钥 $keyName")
        }
    }
    

    fun getCacheStats(): Map<String, Any> {
        return mapOf(
            "cached_keys_count" to keyCache.size,
            "whitelist_entries" to ipWhitelistCache.size,
            "cache_memory_usage" to "约${(keyCache.size + ipWhitelistCache.size) * 100}字节"
        )
    }

    private fun hashApiKey(apiKey: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hashBytes = digest.digest(apiKey.toByteArray(Charsets.UTF_8))
        return hashBytes.joinToString("") { "%02x".format(it) }
    }
}
