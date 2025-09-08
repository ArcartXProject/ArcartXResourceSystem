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
package com.arcartx.routes

import com.arcartx.data.*
import com.arcartx.service.DatabaseService
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import org.slf4j.LoggerFactory

fun Route.apiKeyRoutes(databaseService: DatabaseService) {
    val logger = LoggerFactory.getLogger("ApiKeyRoutes")
    
    route("/api/admin/keys") {
        
        // 需要管理员认证
        authenticate("auth-jwt") {
            
            get("/status") {
                try {
                    val apiKeyInfo = databaseService.getApiKeyInfo()
                    
                    if (apiKeyInfo != null) {
                        call.respond(
                            HttpStatusCode.OK,
                            ApiResponse(
                                success = true,
                                data = ApiKeyStatusResponse(
                                    success = true,
                                    maskedKey = apiKeyInfo.maskedKey,
                                    isActive = apiKeyInfo.isActive,
                                    createdAt = apiKeyInfo.createdAt,
                                    lastUsedAt = apiKeyInfo.lastUsedAt,
                                    message = "API密钥状态获取成功"
                                )
                            )
                        )
                    } else {
                        call.respond(
                            HttpStatusCode.NotFound,
                            ApiResponse<Nothing>(
                                success = false,
                                error = "未找到API密钥"
                            )
                        )
                    }
                } catch (e: Exception) {
                    logger.error("获取API密钥状态异常", e)
                    call.respond(
                        HttpStatusCode.InternalServerError,
                        ApiResponse<Nothing>(
                            success = false,
                            error = "获取API密钥状态失败"
                        )
                    )
                }
            }
            
            post("/reset") {
                try {
                    val newApiKey = databaseService.resetDefaultApiKey()
                    
                    logger.info("管理员重置了API密钥")
                    
                    call.respond(
                        HttpStatusCode.OK,
                        ApiResponse(
                            success = true,
                            data = ApiKeyResetResponse(
                                success = true,
                                apiKey = newApiKey,
                                message = "API密钥重置成功"
                            )
                        )
                    )
                } catch (e: Exception) {
                    logger.error("重置API密钥异常", e)
                    call.respond(
                        HttpStatusCode.InternalServerError,
                        ApiResponse<Nothing>(
                            success = false,
                            error = "重置API密钥失败"
                        )
                    )
                }
            }
            
            // IP白名单管理
            post("/whitelist") {
                try {
                    val request = call.receive<ApiKeyConfigRequest>()
                    
                    if (request.ipWhitelist != null) {
                        // 验证IP地址格式
                        val invalidIps = request.ipWhitelist.filter { ip ->
                            !isValidIp(ip)
                        }
                        
                        if (invalidIps.isNotEmpty()) {
                            call.respond(
                                HttpStatusCode.BadRequest,
                                ApiResponse<Nothing>(
                                    success = false,
                                    error = "无效的IP地址: ${invalidIps.joinToString(", ")}"
                                )
                            )
                            return@post
                        }
                        
                        val success = databaseService.updateApiKeyIpWhitelist(request.ipWhitelist)
                        
                        if (success) {
                            logger.info("API密钥IP白名单已更新")
                            call.respond(
                                HttpStatusCode.OK,
                                ApiResponse(
                                    success = true,
                                    data = ApiKeyConfigResponse(
                                        success = true,
                                        message = "IP白名单更新成功"
                                    )
                                )
                            )
                        } else {
                            call.respond(
                                HttpStatusCode.InternalServerError,
                                ApiResponse<Nothing>(
                                    success = false,
                                    error = "IP白名单更新失败"
                                )
                            )
                        }
                    } else {
                        call.respond(
                            HttpStatusCode.BadRequest,
                            ApiResponse<Nothing>(
                                success = false,
                                error = "请提供IP白名单"
                            )
                        )
                    }
                } catch (e: Exception) {
                    logger.error("更新IP白名单异常", e)
                    call.respond(
                        HttpStatusCode.BadRequest,
                        ApiResponse<Nothing>(
                            success = false,
                            error = "请求格式错误"
                        )
                    )
                }
            }
            
            // 获取IP白名单
            get("/whitelist") {
                try {
                    val ipWhitelist = databaseService.getApiKeyIpWhitelist()
                    
                    call.respond(
                        HttpStatusCode.OK,
                        ApiResponse(
                            success = true,
                            data = IPWhitelistResponse(ipWhitelist, ipWhitelist.size),
                            message = "IP白名单获取成功"
                        )
                    )
                } catch (e: Exception) {
                    logger.error("获取IP白名单异常", e)
                    call.respond(
                        HttpStatusCode.InternalServerError,
                        ApiResponse<Nothing>(
                            success = false,
                            error = "获取IP白名单失败"
                        )
                    )
                }
            }
            
            // 获取流量统计
            get("/traffic-stats") {
                try {
                    val stats = databaseService.getDailyTrafficStats()
                    
                    call.respond(
                        HttpStatusCode.OK,
                        ApiResponse(
                            success = true,
                            data = stats
                        )
                    )
                } catch (e: Exception) {
                    logger.error("获取流量统计异常", e)
                    call.respond(
                        HttpStatusCode.InternalServerError,
                        ApiResponse<Nothing>(
                            success = false,
                            error = "获取流量统计失败"
                        )
                    )
                }
            }
        }
    }
    
    // 系统配置管理路由
    route("/api/admin/config") {
        authenticate("auth-jwt") {
            
            // 获取所有系统配置
            get("/list") {
                try {
                    val configs = databaseService.getAllSystemConfigs()
                    
                    call.respond(
                        HttpStatusCode.OK,
                        ApiResponse(
                            success = true,
                            data = SystemConfigListResponse(
                                success = true,
                                configs = configs,
                                message = "系统配置获取成功"
                            )
                        )
                    )
                } catch (e: Exception) {
                    logger.error("获取系统配置异常", e)
                    call.respond(
                        HttpStatusCode.InternalServerError,
                        ApiResponse<Nothing>(
                            success = false,
                            error = "获取系统配置失败"
                        )
                    )
                }
            }
            
            // 更新系统配置
            post("/update") {
                try {
                    val request = call.receive<UpdateConfigRequest>()
                    
                    // 验证配置值的有效性
                    val validationErrors = validateConfigValues(request.configs)
                    if (validationErrors.isNotEmpty()) {
                        call.respond(
                            HttpStatusCode.BadRequest,
                            ApiResponse<Nothing>(
                                success = false,
                                error = "配置值无效: ${validationErrors.joinToString(", ")}"
                            )
                        )
                        return@post
                    }
                    
                    val updatedCount = databaseService.updateSystemConfigs(request.configs)
                    
                    call.respond(
                        HttpStatusCode.OK,
                        ApiResponse(
                            success = true,
                            data = UpdateConfigResponse(
                                success = true,
                                message = "系统配置更新成功",
                                updatedCount = updatedCount
                            )
                        )
                    )
                } catch (e: Exception) {
                    logger.error("更新系统配置异常", e)
                    call.respond(
                        HttpStatusCode.BadRequest,
                        ApiResponse<Nothing>(
                            success = false,
                            error = "请求格式错误"
                        )
                    )
                }
            }
        }
    }
}


private fun isValidIp(ip: String): Boolean {
    return try {
        val parts = ip.split(".")
        if (parts.size != 4) return false
        
        parts.all { part ->
            val num = part.toIntOrNull()
            num != null && num in 0..255
        }
    } catch (e: Exception) {
        false
    }
}


private fun validateConfigValues(configs: Map<String, String>): List<String> {
    val errors = mutableListOf<String>()
    
    configs.forEach { (key, value) ->
        when (key) {
            "daily_traffic_limit" -> {
                val bytes = value.toLongOrNull()
                if (bytes == null || bytes < 1073741824L) { // 最小1GB
                    errors.add("每日流量限制最小1GB")
                }
                if (bytes != null && bytes > 1099511627776L) { // 最大1TB
                    errors.add("每日流量限制最大1TB")
                }
            }
            "download_rate_limit" -> {
                val rate = value.toIntOrNull()
                if (rate == null || rate < 1 || rate > 1000) {
                    errors.add("下载速率限制必须在1-1000之间")
                }
            }
            "login_rate_limit" -> {
                val rate = value.toIntOrNull()
                if (rate == null || rate < 1 || rate > 100) {
                    errors.add("登录限制必须在1-100之间")
                }
            }
            "max_file_size" -> {
                val size = value.toLongOrNull()
                if (size == null || size < 1048576L) {
                    errors.add("文件大小限制最小1MB")
                }
                if (size != null && size > 2147483648L) {
                    errors.add("文件大小限制最大2GB")
                }
            }
            "signed_link_max_minutes" -> {
                val minutes = value.toIntOrNull()
                if (minutes == null || minutes < 1 || minutes > 1440) {
                    errors.add("链接有效期必须在1-1440分钟之间")
                }
            }
            "signed_link_max_downloads" -> {
                val downloads = value.toIntOrNull()
                if (downloads == null || downloads < 1 || downloads > 100) {
                    errors.add("下载次数限制必须在1-100之间")
                }
            }
        }
    }
    
    return errors
}
