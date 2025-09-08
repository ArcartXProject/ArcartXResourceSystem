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

import kotlinx.serialization.Serializable
import kotlinx.datetime.Instant

@Serializable
data class LoginRequest(
    val username: String,
    val password: String,
    val captcha: String,
    val captchaId: String
)

@Serializable
data class CaptchaResponse(
    val success: Boolean,
    val captchaId: String,
    val captchaImage: String,
    val message: String? = null
)

@Serializable
data class LoginResponse(
    val success: Boolean,
    val token: String? = null,
    val message: String,
    val expiresAt: Instant? = null
)

@Serializable
data class FileInfo(
    val name: String,
    val size: Long,
    val lastModified: Instant,
    val downloadUrl: String? = null
)

@Serializable
data class FileListResponse(
    val files: List<FileInfo>,
    val totalCount: Int,
    val totalSize: Long
)

@Serializable
data class SignedLinkRequest(
    val fileName: String,
    val expirationMinutes: Int = 30,
    val downloadLimit: Int = 3
)

@Serializable
data class SignedLinkResponse(
    val success: Boolean,
    val downloadUrl: String? = null,
    val expiresAt: Instant? = null,
    val downloadLimit: Int? = null,
    val message: String? = null
)

@Serializable
data class ApiResponse<T>(
    val success: Boolean,
    val data: T? = null,
    val message: String? = null,
    val error: String? = null
)

@Serializable
data class UploadResponse(
    val success: Boolean,
    val fileName: String? = null,
    val fileSize: Long? = null,
    val message: String? = null
)

data class SignedLinkRecord(
    val token: String,
    val fileName: String,
    val expiresAt: Instant,
    val remainingDownloads: Int,
    val createdBy: String,
    val createdAt: Instant
)

@Serializable
data class ApiKeyInfo(
    val id: Int,
    val keyName: String,
    val isActive: Boolean,
    val createdAt: Instant,
    val expiresAt: Instant?,
    val lastUsedAt: Instant?
)

data class ApiKeyStatusInfo(
    val maskedKey: String,
    val isActive: Boolean,
    val createdAt: Instant,
    val lastUsedAt: Instant?
)

@Serializable
data class ApiKeyResetResponse(
    val success: Boolean,
    val apiKey: String? = null,
    val message: String? = null
)

@Serializable
data class ApiKeyStatusResponse(
    val success: Boolean,
    val maskedKey: String? = null,
    val isActive: Boolean = false,
    val createdAt: Instant? = null,
    val lastUsedAt: Instant? = null,
    val message: String? = null
)

@Serializable
data class ChangePasswordRequest(
    val currentPassword: String,
    val newPassword: String
)

@Serializable
data class ChangePasswordResponse(
    val success: Boolean,
    val message: String
)

@Serializable
data class FileCrc64Info(
    val fileName: String,
    val crc64: String
)

@Serializable
data class FileCrc64ListResponse(
    val success: Boolean,
    val files: List<FileCrc64Info>,
    val totalCount: Int,
    val message: String? = null
)

@Serializable
data class ApiKeyConfigRequest(
    val ipWhitelist: List<String>? = null,
    val dailyTrafficLimit: Long? = null
)

@Serializable
data class ApiKeyConfigResponse(
    val success: Boolean,
    val message: String
)

@Serializable
data class TrafficUsageInfo(
    val date: String,
    val downloadCount: Int,
    val totalBytes: Long,
    val totalMB: Double,
    val totalGB: Double
)

@Serializable
data class TrafficStatsResponse(
    val success: Boolean,
    val todayUsage: TrafficUsageInfo? = null,
    val dailyLimit: Long,
    val dailyLimitGB: Double,
    val remainingBytes: Long,
    val remainingGB: Double,
    val isLimitExceeded: Boolean,
    val message: String? = null
)

@Serializable
data class IPWhitelistResponse(
    val ipWhitelist: List<String>,
    val count: Int
)

@Serializable
data class SystemConfig(
    val key: String,
    val value: String,
    val description: String
)

@Serializable
data class SystemConfigListResponse(
    val success: Boolean,
    val configs: List<SystemConfig>,
    val message: String? = null
)

@Serializable
data class UpdateConfigRequest(
    val configs: Map<String, String>
)

@Serializable
data class UpdateConfigResponse(
    val success: Boolean,
    val message: String,
    val updatedCount: Int
)
