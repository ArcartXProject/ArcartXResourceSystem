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
import com.arcartx.service.CaptchaService
import com.arcartx.service.DatabaseService
import com.arcartx.service.JwtService
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import org.slf4j.LoggerFactory

fun Route.authRoutes(
    databaseService: DatabaseService,
    jwtService: JwtService,
    captchaService: CaptchaService
) {
    val logger = LoggerFactory.getLogger("AuthRoutes")
    
    route("/api/auth") {
        
        get("/captcha") {
            try {
                val (captchaId, captchaImage) = captchaService.generateCaptcha()
                
                call.respond(
                    HttpStatusCode.OK,
                    CaptchaResponse(
                        success = true,
                        captchaId = captchaId,
                        captchaImage = "data:image/png;base64,$captchaImage",
                        message = "验证码生成成功"
                    )
                )
            } catch (e: Exception) {
                logger.error("生成验证码失败", e)
                call.respond(
                    HttpStatusCode.InternalServerError,
                    ApiResponse<Nothing>(
                        success = false,
                        error = "生成验证码失败"
                    )
                )
            }
        }
        
        post("/login") {
            try {
                val loginRequest = call.receive<LoginRequest>()
                val clientIp = call.request.header("X-Forwarded-For") 
                    ?: call.request.header("X-Real-IP") 
                    ?: call.request.local.remoteAddress
                val userAgent = call.request.header("User-Agent")
                
                // 检查登录尝试频率限制
                val loginRateLimit = databaseService.getLoginRateLimit()
                if (!databaseService.checkRateLimit(clientIp, "LOGIN", loginRateLimit, 60)) {
                    databaseService.logSecurityEvent(
                        eventType = "LOGIN_RATE_LIMITED",
                        ipAddress = clientIp,
                        userAgent = userAgent,
                        details = "登录尝试过于频繁: ${loginRequest.username}"
                    )
                    
                    call.respond(
                        HttpStatusCode.TooManyRequests,
                        ApiResponse<Nothing>(
                            success = false,
                            error = "登录尝试过于频繁，请稍后再试"
                        )
                    )
                    return@post
                }
                
                // 验证验证码
                if (!captchaService.validateCaptcha(loginRequest.captchaId, loginRequest.captcha)) {
                    databaseService.logSecurityEvent(
                        eventType = "LOGIN_CAPTCHA_FAILED",
                        ipAddress = clientIp,
                        userAgent = userAgent,
                        details = "验证码验证失败: ${loginRequest.username}"
                    )
                    
                    call.respond(
                        HttpStatusCode.BadRequest,
                        LoginResponse(
                            success = false,
                            message = "验证码错误"
                        )
                    )
                    return@post
                }
                
                // 验证用户名和密码
                val isValid = databaseService.authenticateAdmin(loginRequest.username, loginRequest.password)
                
                if (isValid) {
                    val token = jwtService.generateToken(loginRequest.username)
                    val expiresAt = Instant.fromEpochMilliseconds(
                        Clock.System.now().toEpochMilliseconds() + 3600000 // 1小时
                    )
                    
                    databaseService.logSecurityEvent(
                        eventType = "LOGIN_SUCCESS",
                        ipAddress = clientIp,
                        userAgent = userAgent,
                        details = "管理员登录成功: ${loginRequest.username}"
                    )
                    
                    logger.info("管理员登录成功: ${loginRequest.username}, IP: $clientIp")
                    
                    call.respond(
                        HttpStatusCode.OK,
                        LoginResponse(
                            success = true,
                            token = token,
                            message = "登录成功",
                            expiresAt = expiresAt
                        )
                    )
                } else {
                    databaseService.logSecurityEvent(
                        eventType = "LOGIN_FAILED",
                        ipAddress = clientIp,
                        userAgent = userAgent,
                        details = "登录失败: ${loginRequest.username}"
                    )
                    
                    logger.warn("登录失败: ${loginRequest.username}, IP: $clientIp")
                    
                    call.respond(
                        HttpStatusCode.Unauthorized,
                        LoginResponse(
                            success = false,
                            message = "用户名或密码错误"
                        )
                    )
                }
            } catch (e: Exception) {
                logger.error("登录处理异常", e)
                call.respond(
                    HttpStatusCode.BadRequest,
                    ApiResponse<Nothing>(
                        success = false,
                        error = "请求格式错误"
                    )
                )
            }
        }
        
        post("/validate") {
            val authHeader = call.request.header("Authorization")
            if (authHeader?.startsWith("Bearer ") == true) {
                val token = authHeader.substring(7)
                val result = jwtService.validateToken(token)
                
                if (result.isSuccess) {
                    val tokenInfo = result.getOrThrow()
                    call.respond(
                        HttpStatusCode.OK,
                        ApiResponse(
                            success = true,
                            data = mapOf(
                                "subject" to tokenInfo.subject,
                                "type" to tokenInfo.type.name,
                                "expiresAt" to tokenInfo.expiresAt.toString()
                            ),
                            message = "令牌有效"
                        )
                    )
                } else {
                    call.respond(
                        HttpStatusCode.Unauthorized,
                        ApiResponse<Nothing>(
                            success = false,
                            error = "令牌无效或已过期"
                        )
                    )
                }
            } else {
                call.respond(
                    HttpStatusCode.BadRequest,
                    ApiResponse<Nothing>(
                        success = false,
                        error = "缺少Authorization头部"
                    )
                )
            }
        }
        
        // 更改密码路由
        authenticate("auth-jwt") {
            post("/change-password") {
                try {
                    val request = call.receive<ChangePasswordRequest>()
                    val principal = call.principal<JWTPrincipal>()
                    val username = principal?.subject
                    
                    if (username == null) {
                        call.respond(
                            HttpStatusCode.Unauthorized,
                            ChangePasswordResponse(
                                success = false,
                                message = "无效的用户身份"
                            )
                        )
                        return@post
                    }
                    
                    // 检查新密码强度
                    if (request.newPassword.length < 6) {
                        call.respond(
                            HttpStatusCode.BadRequest,
                            ChangePasswordResponse(
                                success = false,
                                message = "新密码长度不能少于6位"
                            )
                        )
                        return@post
                    }
                    
                    val success = databaseService.changeAdminPassword(
                        username = username,
                        currentPassword = request.currentPassword,
                        newPassword = request.newPassword
                    )
                    
                    if (success) {
                        val clientIp = call.request.header("X-Forwarded-For") 
                            ?: call.request.header("X-Real-IP") 
                            ?: call.request.local.remoteAddress
                        val userAgent = call.request.header("User-Agent")
                        
                        databaseService.logSecurityEvent(
                            eventType = "PASSWORD_CHANGED",
                            ipAddress = clientIp,
                            userAgent = userAgent,
                            details = "管理员密码更改成功: $username"
                        )
                        
                        logger.info("管理员密码更改成功: $username")
                        
                        call.respond(
                            HttpStatusCode.OK,
                            ChangePasswordResponse(
                                success = true,
                                message = "密码更改成功"
                            )
                        )
                    } else {
                        call.respond(
                            HttpStatusCode.BadRequest,
                            ChangePasswordResponse(
                                success = false,
                                message = "当前密码错误"
                            )
                        )
                    }
                    
                } catch (e: Exception) {
                    logger.error("更改密码异常", e)
                    call.respond(
                        HttpStatusCode.BadRequest,
                        ChangePasswordResponse(
                            success = false,
                            message = "请求格式错误"
                        )
                    )
                }
            }
        }
    }
}
