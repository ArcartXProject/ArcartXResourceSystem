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

import com.arcartx.data.*
import kotlinx.datetime.Instant
import kotlinx.datetime.toKotlinInstant
import org.jetbrains.exposed.dao.id.EntityID
import org.jetbrains.exposed.sql.*
import org.jetbrains.exposed.sql.SqlExpressionBuilder.eq
import org.jetbrains.exposed.sql.SqlExpressionBuilder.less
import org.jetbrains.exposed.sql.transactions.transaction
import org.mindrot.jbcrypt.BCrypt
import org.slf4j.LoggerFactory
import java.io.File
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.LocalDateTime
import java.time.ZoneOffset

class DatabaseService {
    private val logger = LoggerFactory.getLogger(DatabaseService::class.java)
    private val configCache = mutableMapOf<String, String>()
    private val apiKeyCacheService = ApiKeyCacheService()
    
    init {
        initDatabase()
        apiKeyCacheService.initializeCache()
    }
    
    private fun initDatabase() {
        val dbFile = File("data")
        if (!dbFile.exists()) {
            dbFile.mkdirs()
        }
        
        Database.connect(
            url = "jdbc:sqlite:data/database.db",
            driver = "org.sqlite.JDBC"
        )
        
        transaction {
            SchemaUtils.create(AdminUsers, ApiKeys, SecurityLogs, FileRecords, TrafficUsage, SystemSettings, RateLimitRecords)
            
            // 创建默认管理员账户如果不存在
            createDefaultAdminIfNotExists()
            
            // 初始化系统配置
            initSystemSettings()
        }
        
        logger.info("数据库初始化完成")
    }
    
    private fun createDefaultAdminIfNotExists() {
        val adminExists = AdminUsers.select { AdminUsers.username eq "admin" }
            .singleOrNull() != null
            
        if (!adminExists) {
            val passwordHash1 = BCrypt.hashpw("admin123", BCrypt.gensalt())
            AdminUsers.insert {
                it[username] = "admin"
                it[passwordHash] = passwordHash1
                it[isActive] = true
                it[createdAt] = LocalDateTime.now()
            }
            logger.info("创建默认管理员账户: admin/admin123")
            
            // 同时创建默认API密钥
            createDefaultApiKeyIfNotExists()
        }
    }
    
    private fun createDefaultApiKeyIfNotExists() {
        val apiKeyExists = ApiKeys.select { ApiKeys.keyName eq "default-api-key" }
            .singleOrNull() != null
            
        if (!apiKeyExists) {
            val apiKey = generateApiKey()
            val keyHashIn = hashApiKey(apiKey)
            
            ApiKeys.insert {
                it[keyName] = "default-api-key"
                it[keyHash] = keyHashIn
                it[createdAt] = LocalDateTime.now()
            }
            
            logger.info("创建默认API密钥: $apiKey")
            logger.info("请妥善保存此API密钥，它只会在日志中显示一次！")
        }
    }
    
    private fun initSystemSettings() {
        val defaultSettings = listOf(
            "daily_traffic_limit" to "214748364800",
            "download_rate_limit" to "30",
            "login_rate_limit" to "10",
            "max_file_size" to "536870912",
            "signed_link_max_minutes" to "60",
            "signed_link_max_downloads" to "10"
        )
        
        defaultSettings.forEach { (key, value) ->
            val exists = SystemSettings.select { SystemSettings.configKey eq key }.singleOrNull()
            if (exists == null) {
                SystemSettings.insert {
                    it[configKey] = key
                    it[configValue] = value
                    it[description] = getConfigDescription(key)
                    it[createdAt] = LocalDateTime.now()
                    it[updatedAt] = LocalDateTime.now()
                }
            }
        }
        
        logger.info("系统配置初始化完成")
        
        // 加载配置到内存缓存
        loadConfigCache()
    }
    
    private fun loadConfigCache() {
        configCache.clear()
        transaction {
            SystemSettings.selectAll().forEach { row ->
                configCache[row[SystemSettings.configKey]] = row[SystemSettings.configValue]
            }
        }
        logger.info("配置缓存已加载: ${configCache.size} 个配置项")
    }
    
    private fun getConfigDescription(key: String): String {
        return when (key) {
            "daily_traffic_limit" -> "全局每日流量限制：所有用户累计下载的最大字节数，达到后当日无法继续下载"
            "download_rate_limit" -> "单IP下载频率限制：每个IP地址每分钟最多允许的下载次数，防止单点过度请求"
            "login_rate_limit" -> "单IP登录频率限制：每个IP地址每小时最多允许的登录尝试次数，防暴力破解"
            "max_file_size" -> "单文件大小上限：允许上传的单个文件最大字节数，超过将被拒绝"
            "signed_link_max_minutes" -> "签名链接时效上限：创建签名下载链接时可设置的最大有效期分钟数"
            "signed_link_max_downloads" -> "签名链接次数上限：创建签名下载链接时可设置的最大下载次数"
            else -> "系统配置项"
        }
    }
    
    fun authenticateAdmin(username: String, password: String): Boolean {
        return transaction {
            val admin = AdminUsers.select { 
                (AdminUsers.username eq username) and (AdminUsers.isActive eq true) 
            }.singleOrNull()
            
            if (admin != null) {
                val passwordHash = admin[AdminUsers.passwordHash]
                val isValid = BCrypt.checkpw(password, passwordHash)
                
                if (isValid) {
                    AdminUsers.update({ AdminUsers.username eq username }) {
                        it[lastLoginAt] = LocalDateTime.now()
                    }
                }
                
                isValid
            } else {
                false
            }
        }
    }
    
    
    fun resetDefaultApiKey(): String {
        return transaction {
            val newApiKey = generateApiKey()
            val keyHashIn = hashApiKey(newApiKey)
            
            // 更新默认API密钥
            val updated = ApiKeys.update({ ApiKeys.keyName eq "default-api-key" }) {
                it[this.keyHash] = keyHashIn
                it[createdAt] = LocalDateTime.now()
            }
            
            if (updated > 0) {
                logger.info("默认API密钥已重置: $newApiKey")
                // 刷新缓存
                apiKeyCacheService.refreshCache()
                newApiKey
            } else {
                // 如果没有找到默认密钥，创建一个新的
                ApiKeys.insert {
                    it[keyName] = "default-api-key"
                    it[keyHash] = keyHashIn
                    it[createdAt] = LocalDateTime.now()
                }
                logger.info("创建新的默认API密钥: $newApiKey")
                // 刷新缓存
                apiKeyCacheService.refreshCache()
                newApiKey
            }
        }
    }
    
    
    fun getApiKeyInfo(): ApiKeyStatusInfo? {
        return transaction {
            val result = ApiKeys.select { 
                ApiKeys.keyName eq "default-api-key" 
            }.singleOrNull()
            
            result?.let { row ->
                ApiKeyStatusInfo(
                    maskedKey = "${row[ApiKeys.keyHash].take(8)}...${row[ApiKeys.keyHash].takeLast(8)}",
                    createdAt = row[ApiKeys.createdAt].toInstant(ZoneOffset.UTC).toKotlinInstant()
                )
            }
        }
    }
    
    fun validateApiKeyBasic(apiKey: String): ApiKeyInfo? {
        // 使用缓存验证API密钥
        return apiKeyCacheService.validateApiKey(apiKey)
    }
    
    fun validateApiKeyWithIp(apiKey: String, clientIp: String): Boolean {
        // 使用缓存验证API密钥和IP白名单
        return apiKeyCacheService.validateApiKeyWithIp(apiKey, clientIp)
    }
    
    fun logSecurityEvent(
        eventType: String,
        ipAddress: String,
        userAgent: String? = null,
        userId: Int? = null,
        apiKeyId: Int? = null,
        details: String? = null
    ) {
        transaction {
            SecurityLogs.insert {
                it[this.eventType] = eventType
                it[this.ipAddress] = ipAddress
                it[this.userAgent] = userAgent
                it[this.userId] = userId?.let { id -> EntityID(id, AdminUsers) }
                it[this.apiKeyId] = apiKeyId?.let { id -> EntityID(id, ApiKeys) }
                it[this.details] = details
                it[createdAt] = LocalDateTime.now()
            }
        }
    }
    
    
    private fun generateApiKey(): String {
        val random = SecureRandom()
        val bytes = ByteArray(32)
        random.nextBytes(bytes)
        return bytes.joinToString("") { "%02x".format(it) }
    }
    
    private fun hashApiKey(apiKey: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(apiKey.toByteArray()).joinToString("") { "%02x".format(it) }
    }

    fun addFileRecord(fileName: String, fileSize: Long, crc64: String) {
        transaction {
            FileRecords.insert {
                it[this.fileName] = fileName
                it[this.fileSize] = fileSize
                it[this.crc64] = crc64
                it[uploadedAt] = LocalDateTime.now()
                it[lastModified] = LocalDateTime.now()
            }
        }
    }
    
    fun updateFileRecord(fileName: String, fileSize: Long, crc64: String) {
        transaction {
            FileRecords.update({ FileRecords.fileName eq fileName }) {
                it[this.fileSize] = fileSize
                it[this.crc64] = crc64
                it[lastModified] = LocalDateTime.now()
            }
        }
    }
    
    fun removeFileRecord(fileName: String) {
        transaction {
            FileRecords.deleteWhere { FileRecords.fileName eq fileName }
        }
    }
    
    fun getFileCrc64List(): List<FileCrc64Info> {
        return transaction {
            FileRecords.selectAll()
                .map { row ->
                    FileCrc64Info(
                        fileName = row[FileRecords.fileName],
                        crc64 = row[FileRecords.crc64]
                    )
                }
                .sortedBy { it.fileName }
        }
    }

    
    // 更改密码方法
    fun changeAdminPassword(username: String, currentPassword: String, newPassword: String): Boolean {
        return transaction {
            val admin = AdminUsers.select { 
                (AdminUsers.username eq username) and (AdminUsers.isActive eq true) 
            }.singleOrNull()
            
            if (admin != null) {
                val currentPasswordHash = admin[AdminUsers.passwordHash]
                val isCurrentPasswordValid = BCrypt.checkpw(currentPassword, currentPasswordHash)
                
                if (isCurrentPasswordValid) {
                    val newPasswordHash = BCrypt.hashpw(newPassword, BCrypt.gensalt())
                    AdminUsers.update({ AdminUsers.username eq username }) {
                        it[passwordHash] = newPasswordHash
                    }
                    logger.info("管理员密码已更改: $username")
                    true
                } else {
                    logger.warn("更改密码失败，当前密码错误: $username")
                    false
                }
            } else {
                logger.warn("更改密码失败，用户不存在: $username")
                false
            }
        }
    }
    
    // IP白名单管理
    fun updateApiKeyIpWhitelist(ipList: List<String>): Boolean {
        return transaction {
            val whitelist = if (ipList.isEmpty()) null else ipList.joinToString(",")
            val updated = ApiKeys.update({ ApiKeys.keyName eq "default-api-key" }) {
                it[ipWhitelist] = whitelist
            }
            
            if (updated > 0) {
                logger.info("API密钥IP白名单已更新: ${ipList.joinToString(", ")}")
                // 更新缓存
                apiKeyCacheService.updateIpWhitelistCache("default-api-key", ipList)
                true
            } else {
                false
            }
        }
    }
    
    fun getApiKeyIpWhitelist(): List<String> {
        // 使用缓存获取IP白名单
        return apiKeyCacheService.getIpWhitelist("default-api-key")
    }
    
    // 系统配置管理（内存缓存）
    fun getSystemConfig(key: String, defaultValue: String): String {
        return configCache[key] ?: defaultValue
    }

    private fun getDailyTrafficLimit(): Long {
        return getSystemConfig("daily_traffic_limit", "214748364800").toLongOrNull() ?: 214748364800L
    }
    
    fun getDownloadRateLimit(): Int {
        return getSystemConfig("download_rate_limit", "30").toIntOrNull() ?: 30
    }
    
    fun getLoginRateLimit(): Int {
        return getSystemConfig("login_rate_limit", "10").toIntOrNull() ?: 10
    }
    
    fun getMaxFileSize(): Long {
        return getSystemConfig("max_file_size", "536870912").toLongOrNull() ?: 536870912L
    }
    
    fun getSignedLinkMaxMinutes(): Int {
        return getSystemConfig("signed_link_max_minutes", "60").toIntOrNull() ?: 60
    }
    
    fun getSignedLinkMaxDownloads(): Int {
        return getSystemConfig("signed_link_max_downloads", "10").toIntOrNull() ?: 10
    }
    
    fun getAllSystemConfigs(): List<SystemConfig> {
        return transaction {
            SystemSettings.selectAll()
                .map { row ->
                    SystemConfig(
                        key = row[SystemSettings.configKey],
                        value = row[SystemSettings.configValue],
                        description = row[SystemSettings.description] ?: ""
                    )
                }
                .sortedBy { it.key }
        }
    }
    
    fun updateSystemConfigs(configs: Map<String, String>): Int {
        return transaction {
            var updatedCount = 0
            
            configs.forEach { (key, value) ->
                val existing = SystemSettings.select { SystemSettings.configKey eq key }.singleOrNull()
                
                if (existing != null) {
                    SystemSettings.update({ SystemSettings.configKey eq key }) {
                        it[configValue] = value
                        it[updatedAt] = LocalDateTime.now()
                    }
                    updatedCount++
                    logger.info("系统配置已更新: $key = $value")
                } else {
                    // 如果配置项不存在，创建新的
                    SystemSettings.insert {
                        it[configKey] = key
                        it[configValue] = value
                        it[description] = getConfigDescription(key)
                        it[createdAt] = LocalDateTime.now()
                        it[updatedAt] = LocalDateTime.now()
                    }
                    updatedCount++
                    logger.info("系统配置已创建: $key = $value")
                }
            }

            updatedCount
        }.also {
            // 更新配置后刷新缓存
            if (it > 0) {
                loadConfigCache()
                logger.info("配置缓存已刷新")
            }
        }
    }
    
    // 速率限制（数据库版本，带防护）
    fun checkRateLimit(identifier: String, requestType: String, maxRequests: Int, windowMinutes: Int): Boolean {
        return transaction {
            val now = LocalDateTime.now()
            val windowStart = now.minusMinutes(windowMinutes.toLong())
            
            // 先删除过期记录
            RateLimitRecords.deleteWhere {
                (RateLimitRecords.identifier eq identifier) and 
                (RateLimitRecords.requestType eq requestType) and
                (lastRequestAt less windowStart)
            }
            
            // 查找现有记录
            val existing = RateLimitRecords.select { 
                (RateLimitRecords.identifier eq identifier) and 
                (RateLimitRecords.requestType eq requestType)
            }.singleOrNull()
            
            val currentCount = existing?.get(RateLimitRecords.requestCount) ?: 0
            
            if (currentCount >= maxRequests) {
                false
            } else {
                // 更新或创建记录
                if (existing != null) {
                    RateLimitRecords.update({ 
                        (RateLimitRecords.identifier eq identifier) and 
                        (RateLimitRecords.requestType eq requestType) 
                    }) {
                        it[requestCount] = currentCount + 1
                        it[lastRequestAt] = now
                    }
                } else {
                    RateLimitRecords.insert {
                        it[this.identifier] = identifier
                        it[this.requestType] = requestType
                        it[this.requestCount] = 1
                        it[this.windowStart] = now
                        it[this.lastRequestAt] = now
                    }
                }
                true
            }
        }
    }

    // 流量监控和限制
    fun recordTrafficUsage(apiKeyId: Int?, downloadedBytes: Long) {
        transaction {
            val today = LocalDateTime.now().toLocalDate().toString()
            
            // 查找今日记录
            val existingRecord = TrafficUsage.select {
                (TrafficUsage.date eq today) and (TrafficUsage.apiKeyId eq apiKeyId?.let { EntityID(it, ApiKeys) })
            }.singleOrNull()
            
            if (existingRecord != null) {
                // 更新现有记录
                TrafficUsage.update({ TrafficUsage.id eq existingRecord[TrafficUsage.id] }) {
                    it[downloadCount] = existingRecord[downloadCount] + 1
                    it[totalBytes] = existingRecord[totalBytes] + downloadedBytes
                    it[updatedAt] = LocalDateTime.now()
                }
            } else {
                // 创建新记录
                TrafficUsage.insert {
                    it[date] = today
                    it[this.apiKeyId] = apiKeyId?.let { id -> EntityID(id, ApiKeys) }
                    it[downloadCount] = 1
                    it[totalBytes] = downloadedBytes
                    it[createdAt] = LocalDateTime.now()
                    it[updatedAt] = LocalDateTime.now()
                }
            }
        }
    }
    
    fun getTodayTrafficUsage(): TrafficUsageInfo? {
        return transaction {
            val today = LocalDateTime.now().toLocalDate().toString()
            
            val result = TrafficUsage.select { TrafficUsage.date eq today }
                .map { row ->
                    TrafficUsageInfo(
                        date = row[TrafficUsage.date],
                        downloadCount = row[TrafficUsage.downloadCount],
                        totalBytes = row[TrafficUsage.totalBytes],
                        totalMB = row[TrafficUsage.totalBytes] / (1024.0 * 1024.0),
                        totalGB = row[TrafficUsage.totalBytes] / (1024.0 * 1024.0 * 1024.0)
                    )
                }
                .reduceOrNull { acc, curr ->
                    TrafficUsageInfo(
                        date = today,
                        downloadCount = acc.downloadCount + curr.downloadCount,
                        totalBytes = acc.totalBytes + curr.totalBytes,
                        totalMB = (acc.totalBytes + curr.totalBytes) / (1024.0 * 1024.0),
                        totalGB = (acc.totalBytes + curr.totalBytes) / (1024.0 * 1024.0 * 1024.0)
                    )
                }
            
            result
        }
    }
    
    fun checkDailyTrafficLimit(additionalBytes: Long = 0): Boolean {
        val todayUsage = getTodayTrafficUsage()
        val currentBytes = todayUsage?.totalBytes ?: 0L
        val totalBytes = currentBytes + additionalBytes
        val dailyLimit = getDailyTrafficLimit()
        
        return totalBytes <= dailyLimit
    }
    
    fun getDailyTrafficStats(): TrafficStatsResponse {
        val todayUsage = getTodayTrafficUsage()
        val usedBytes = todayUsage?.totalBytes ?: 0L
        val dailyLimit = getDailyTrafficLimit()
        val remainingBytes = maxOf(0L, dailyLimit - usedBytes)
        
        return TrafficStatsResponse(
            success = true,
            todayUsage = todayUsage,
            dailyLimit = dailyLimit,
            dailyLimitGB = dailyLimit / (1024.0 * 1024.0 * 1024.0),
            remainingBytes = remainingBytes,
            remainingGB = remainingBytes / (1024.0 * 1024.0 * 1024.0),
            isLimitExceeded = usedBytes >= dailyLimit,
            message = "每日流量统计获取成功"
        )
    }
}
