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
package com.arcartx.data

import org.jetbrains.exposed.dao.id.IntIdTable
import org.jetbrains.exposed.sql.javatime.datetime
import java.time.LocalDateTime

object AdminUsers : IntIdTable() {
    val username = varchar("username", 50).uniqueIndex()
    val passwordHash = varchar("password_hash", 60)
    val isActive = bool("is_active").default(true)
    val createdAt = datetime("created_at").default(LocalDateTime.now())
    val lastLoginAt = datetime("last_login_at").nullable()
}

object ApiKeys : IntIdTable() {
    val keyName = varchar("key_name", 100)
    val keyHash = varchar("key_hash", 64)
    val isActive = bool("is_active").default(true)
    val ipWhitelist = varchar("ip_whitelist", 1000).nullable()
    val createdAt = datetime("created_at").default(LocalDateTime.now())
    val expiresAt = datetime("expires_at").nullable()
    val lastUsedAt = datetime("last_used_at").nullable()
}

object SecurityLogs : IntIdTable() {
    val eventType = varchar("event_type", 50)
    val ipAddress = varchar("ip_address", 45)
    val userAgent = varchar("user_agent", 500).nullable()
    val userId = reference("user_id", AdminUsers).nullable()
    val apiKeyId = reference("api_key_id", ApiKeys).nullable()
    val details = varchar("details", 1000).nullable()
    val createdAt = datetime("created_at").default(LocalDateTime.now())
}


object FileRecords : IntIdTable() {
    val fileName = varchar("file_name", 255).uniqueIndex()
    val fileSize = long("file_size")
    val crc64 = varchar("crc64", 16)
    val uploadedAt = datetime("uploaded_at").default(LocalDateTime.now())
    val lastModified = datetime("last_modified").default(LocalDateTime.now())
}


object TrafficUsage : IntIdTable() {
    val date = varchar("date", 10)
    val apiKeyId = reference("api_key_id", ApiKeys).nullable()
    val downloadCount = integer("download_count").default(0)
    val totalBytes = long("total_bytes").default(0L)
    val createdAt = datetime("created_at").default(LocalDateTime.now())
    val updatedAt = datetime("updated_at").default(LocalDateTime.now())
    
    init {
        uniqueIndex("unique_date_apikey", date, apiKeyId)
    }
}

object SystemSettings : IntIdTable() {
    val configKey = varchar("config_key", 100).uniqueIndex()
    val configValue = varchar("config_value", 1000)
    val description = varchar("description", 500).nullable()
    val createdAt = datetime("created_at").default(LocalDateTime.now())
    val updatedAt = datetime("updated_at").default(LocalDateTime.now())
}

object RateLimitRecords : IntIdTable() {
    val identifier = varchar("identifier", 100)
    val requestType = varchar("request_type", 50)
    val requestCount = integer("request_count").default(1)
    val windowStart = datetime("window_start").default(LocalDateTime.now())
    val lastRequestAt = datetime("last_request_at").default(LocalDateTime.now())
    
    init {
        uniqueIndex("unique_identifier_type", identifier, requestType)
    }
}
