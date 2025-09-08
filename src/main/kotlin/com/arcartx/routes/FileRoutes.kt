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
import com.arcartx.plugins.ApiKeyPrincipal
import com.arcartx.service.DatabaseService
import com.arcartx.service.FileService
import com.arcartx.service.SignedLinkService
import io.ktor.http.*
import io.ktor.http.content.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import org.slf4j.LoggerFactory
import java.io.File

fun Route.fileRoutes(
    fileService: FileService,
    signedLinkService: SignedLinkService,
    databaseService: DatabaseService
) {
    val logger = LoggerFactory.getLogger("FileRoutes")
    
    route("/api/files") {
        
        // 需要管理员认证的路由
        authenticate("auth-jwt") {
            
            get("/list") {
                try {
                    val files = fileService.listFiles()
                    val totalSize = fileService.getTotalSize()
                    
                    call.respond(
                        HttpStatusCode.OK,
                        ApiResponse(
                            success = true,
                            data = FileListResponse(
                                files = files,
                                totalCount = files.size,
                                totalSize = totalSize
                            )
                        )
                    )
                } catch (e: Exception) {
                    logger.error("获取文件列表失败", e)
                    call.respond(
                        HttpStatusCode.InternalServerError,
                        ApiResponse<Nothing>(
                            success = false,
                            error = "获取文件列表失败"
                        )
                    )
                }
            }
            
            post("/upload") {
                try {
                    val multipartData = call.receiveMultipart()
                    var fileName = ""
                    var fileUploaded = false
                    var uploadResult: Result<FileInfo>? = null
                    
                    multipartData.forEachPart { part ->
                        when (part) {
                            is PartData.FileItem -> {
                                fileName = part.originalFileName ?: "unknown"
                                val fileBytes = part.streamProvider().use { it.readBytes() }
                                
                                val maxFileSize = databaseService.getMaxFileSize()
                                if (fileBytes.size > maxFileSize) {
                                    val maxSizeMB = maxFileSize / (1024 * 1024)
                                    uploadResult = Result.failure(IllegalArgumentException("文件过大，最大支持${maxSizeMB}MB"))
                                    return@forEachPart
                                }
                                
                                uploadResult = fileService.saveFile(fileName, fileBytes.inputStream())
                                fileUploaded = true
                            }
                            else -> {}
                        }
                        part.dispose()
                    }
                    
                    if (!fileUploaded) {
                        call.respond(
                            HttpStatusCode.BadRequest,
                            ApiResponse<Nothing>(
                                success = false,
                                error = "未找到上传文件"
                            )
                        )
                        return@post
                    }
                    
                    uploadResult?.let { result ->
                        if (result.isSuccess) {
                            val fileInfo = result.getOrThrow()
                            logger.info("文件上传成功: $fileName")
                            
                            call.respond(
                                HttpStatusCode.OK,
                                ApiResponse(
                                    success = true,
                                    data = UploadResponse(
                                        success = true,
                                        fileName = fileInfo.name,
                                        fileSize = fileInfo.size,
                                        message = "文件上传成功"
                                    )
                                )
                            )
                        } else {
                            logger.warn("文件上传失败: $fileName - ${result.exceptionOrNull()?.message}")
                            call.respond(
                                HttpStatusCode.BadRequest,
                                ApiResponse<Nothing>(
                                    success = false,
                                    error = result.exceptionOrNull()?.message ?: "文件上传失败"
                                )
                            )
                        }
                    }
                } catch (e: Exception) {
                    logger.error("文件上传异常", e)
                    call.respond(
                        HttpStatusCode.InternalServerError,
                        ApiResponse<Nothing>(
                            success = false,
                            error = "文件上传失败"
                        )
                    )
                }
            }
            
            delete("/{fileName}") {
                try {
                    val fileName = call.parameters["fileName"]
                        ?: return@delete call.respond(
                            HttpStatusCode.BadRequest,
                            ApiResponse<Nothing>(
                                success = false,
                                error = "缺少文件名参数"
                            )
                        )
                    
                    val result = fileService.deleteFile(fileName)
                    
                    if (result.isSuccess && result.getOrThrow()) {
                        logger.info("文件删除成功: $fileName")
                        call.respond(
                            HttpStatusCode.OK,
                            ApiResponse<Unit>(
                                success = true,
                                message = "文件删除成功"
                            )
                        )
                    } else {
                        logger.warn("文件删除失败: $fileName - ${result.exceptionOrNull()?.message}")
                        call.respond(
                            HttpStatusCode.BadRequest,
                            ApiResponse<Nothing>(
                                success = false,
                                error = result.exceptionOrNull()?.message ?: "文件删除失败"
                            )
                        )
                    }
                } catch (e: Exception) {
                    logger.error("文件删除异常", e)
                    call.respond(
                        HttpStatusCode.InternalServerError,
                        ApiResponse<Nothing>(
                            success = false,
                            error = "文件删除失败"
                        )
                    )
                }
            }
        }
        
        // 需要管理员或API密钥认证的路由
        authenticate("auth-jwt", "auth-api") {
            get("/crc64-list") {
                try {
                    // 如果是API密钥请求，检查IP白名单
                    val apiPrincipal = call.principal<ApiKeyPrincipal>()
                    if (apiPrincipal != null) {
                        val clientIp = call.request.header("X-Forwarded-For") 
                            ?: call.request.header("X-Real-IP") 
                            ?: call.request.local.remoteAddress
                        
                        if (!databaseService.validateApiKeyWithIp(apiPrincipal.originalToken, clientIp)) {
                            logger.warn("API密钥IP验证失败: IP=$clientIp 不在白名单中")
                            call.respond(
                                HttpStatusCode.Forbidden,
                                ApiResponse<Nothing>(
                                    success = false,
                                    error = "IP地址不在白名单中"
                                )
                            )
                            return@get
                        }
                    }
                    
                    val fileCrc64List = databaseService.getFileCrc64List()
                    
                    call.respond(
                        HttpStatusCode.OK,
                        ApiResponse(
                            success = true,
                            data = FileCrc64ListResponse(
                                success = true,
                                files = fileCrc64List,
                                totalCount = fileCrc64List.size,
                                message = "文件CRC64列表获取成功"
                            )
                        )
                    )
                } catch (e: Exception) {
                    logger.error("获取文件CRC64列表失败", e)
                    call.respond(
                        HttpStatusCode.InternalServerError,
                        ApiResponse<Nothing>(
                            success = false,
                            error = "获取文件CRC64列表失败"
                        )
                    )
                }
            }
            
            post("/generate-signed-link") {
                try {
                    val request = call.receive<SignedLinkRequest>()
                    
                    // 获取创建者信息
                    val jwtPrincipal = call.principal<JWTPrincipal>()
                    val apiPrincipal = call.principal<ApiKeyPrincipal>()
                    val createdBy = jwtPrincipal?.subject ?: apiPrincipal?.keyName ?: "unknown"
                    
                    // 如果是API密钥请求，进行额外检查
                    if (apiPrincipal != null) {
                        // 获取客户端IP进行白名单验证
                        val clientIp = call.request.header("X-Forwarded-For") 
                            ?: call.request.header("X-Real-IP") 
                            ?: call.request.local.remoteAddress
                        
                        // 验证IP白名单
                        if (!databaseService.validateApiKeyWithIp(apiPrincipal.originalToken, clientIp)) {
                            logger.warn("API密钥IP验证失败: IP=$clientIp 不在白名单中")
                            call.respond(
                                HttpStatusCode.Forbidden,
                                ApiResponse<Nothing>(
                                    success = false,
                                    error = "IP地址不在白名单中"
                                )
                            )
                            return@post
                        }
                        
                        // 获取文件大小用于流量预检查
                        val fileInfo = fileService.getFileInfo(request.fileName)
                        val estimatedTraffic = fileInfo.size * request.downloadLimit
                        
                        if (!databaseService.checkDailyTrafficLimit(estimatedTraffic)) {
                            logger.warn("API密钥流量限制，拒绝生成链接: 文件=${request.fileName}, 预估流量=${estimatedTraffic}")
                            call.respond(
                                HttpStatusCode.TooManyRequests,
                                ApiResponse<Nothing>(
                                    success = false,
                                    error = "今日流量限制已达上限，无法生成更多下载链接"
                                )
                            )
                            return@post
                        }
                    }
                    
                    // 验证文件是否存在
                    if (!fileService.fileExists(request.fileName)) {
                        call.respond(
                            HttpStatusCode.NotFound,
                            ApiResponse<Nothing>(
                                success = false,
                                error = "文件不存在: ${request.fileName}"
                            )
                        )
                        return@post
                    }
                    
                    val result = signedLinkService.generateSignedLink(
                        fileName = request.fileName,
                        expirationMinutes = request.expirationMinutes,
                        downloadLimit = request.downloadLimit,
                        createdBy = createdBy
                    )
                    
                    if (result.isSuccess) {
                        val record = result.getOrThrow()
                        val downloadUrl = "/api/download/signed/${record.token}"
                        
                        logger.info("生成签名链接成功: 文件=${request.fileName}, 创建者=$createdBy")
                        
                        call.respond(
                            HttpStatusCode.OK,
                            ApiResponse(
                                success = true,
                                data = SignedLinkResponse(
                                    success = true,
                                    downloadUrl = downloadUrl,
                                    expiresAt = record.expiresAt,
                                    downloadLimit = record.remainingDownloads
                                )
                            )
                        )
                    } else {
                        logger.warn("生成签名链接失败: ${result.exceptionOrNull()?.message}")
                        call.respond(
                            HttpStatusCode.BadRequest,
                            ApiResponse<Nothing>(
                                success = false,
                                error = result.exceptionOrNull()?.message ?: "生成签名链接失败"
                            )
                        )
                    }
                } catch (e: Exception) {
                    logger.error("生成签名链接异常", e)
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
    

    route("/api/download") {
        get("/signed/{token}") {
            try {
                val token = call.parameters["token"]
                    ?: return@get call.respond(HttpStatusCode.BadRequest, "缺少下载令牌")
                
                val clientIp = call.request.header("X-Forwarded-For") 
                    ?: call.request.header("X-Real-IP") 
                    ?: call.request.local.remoteAddress
                
                // 验证速率限制
                val downloadRateLimit = databaseService.getDownloadRateLimit()
                if (!databaseService.checkRateLimit(clientIp, "DOWNLOAD", downloadRateLimit, 10)) {
                    call.respond(HttpStatusCode.TooManyRequests, "下载请求过于频繁，请稍后再试")
                    return@get
                }
                
                val result = signedLinkService.validateAndConsumeToken(token)
                
                if (result.isSuccess) {
                    val record = result.getOrThrow()
                    val fileResult = fileService.getFile(record.fileName)
                    
                    if (fileResult.isSuccess) {
                        val file = fileResult.getOrThrow()
                        
                        // 检查每日流量限制
                        if (!databaseService.checkDailyTrafficLimit(file.length())) {
                            logger.warn("每日流量限制已达上限，拒绝下载: 文件=${record.fileName}, IP=$clientIp")
                            call.respond(
                                HttpStatusCode.TooManyRequests, 
                                "今日流量已达上限，请明日再试"
                            )
                            return@get
                        }
                        
                        // 记录流量使用（这里使用null因为不是API密钥下载）
                        databaseService.recordTrafficUsage(null, file.length())
                        
                        logger.info("签名下载: 文件=${record.fileName}, 大小=${file.length()}, IP=$clientIp")
                        
                        call.response.header(
                            HttpHeaders.ContentDisposition,
                            ContentDisposition.Attachment.withParameter(
                                ContentDisposition.Parameters.FileName, 
                                file.name
                            ).toString()
                        )
                        
                        call.respondFile(file)
                    } else {
                        logger.error("签名下载失败，文件不存在: ${record.fileName}")
                        call.respond(HttpStatusCode.NotFound, "文件不存在")
                    }
                } else {
                    logger.warn("无效的下载令牌: token=${token.take(8)}..., IP=$clientIp")
                    call.respond(HttpStatusCode.Unauthorized, result.exceptionOrNull()?.message ?: "无效的下载令牌")
                }
            } catch (e: Exception) {
                logger.error("签名下载异常", e)
                call.respond(HttpStatusCode.InternalServerError, "下载失败")
            }
        }
    }
}
