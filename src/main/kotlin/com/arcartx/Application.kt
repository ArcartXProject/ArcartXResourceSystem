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
package com.arcartx

import com.arcartx.plugins.*
import com.arcartx.service.*
import io.ktor.server.application.*
import io.ktor.server.netty.*
import org.slf4j.LoggerFactory

fun main(args: Array<String>) {
    EngineMain.main(args)
}

fun Application.module() {
    val logger = LoggerFactory.getLogger(Application::class.java)
    
    try {
        // 初始化服务
        val databaseService = DatabaseService()
        val fileService = FileService(databaseService)
        val signedLinkService = SignedLinkService(databaseService)
        val cleanupService = CleanupService()
        val captchaService = CaptchaService()
        val jwtService = JwtService(
            secret = environment.config.propertyOrNull("app.auth.jwt.secret")?.getString() 
                ?: "your-secret-key-change-in-production"
        )

        configureSecurity(databaseService)
        configureSerialization()
        configureHTTP()
        configureRouting(databaseService, fileService, signedLinkService, jwtService, captchaService)
        configureMonitoring()
        configureRateLimit()

        environment.monitor.subscribe(ApplicationStopping) {
            logger.info("正在关闭...")
            signedLinkService.shutdown()
            cleanupService.shutdown()
            logger.info("关闭完成")
        }
        
        logger.info("ArcartX资源管理启动成功")
        
    } catch (e: Exception) {
        logger.error("启动失败", e)
        throw e
    }
}
