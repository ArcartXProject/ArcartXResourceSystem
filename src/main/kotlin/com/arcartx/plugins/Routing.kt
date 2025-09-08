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
package com.arcartx.plugins

import com.arcartx.data.ApiResponse
import com.arcartx.routes.*
import com.arcartx.service.*
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.http.content.*
import io.ktor.server.response.*
import io.ktor.server.routing.*

fun Application.configureRouting(
    databaseService: DatabaseService,
    fileService: FileService,
    signedLinkService: SignedLinkService,
    jwtService: JwtService,
    captchaService: CaptchaService
) {
    routing {
        // 健康检查端点
        get("/health") {
            call.respond(
                HttpStatusCode.OK,
                ApiResponse(
                    success = true,
                    data = mapOf(
                        "status" to "healthy",
                        "timestamp" to System.currentTimeMillis(),
                        "activeTokens" to signedLinkService.getActiveTokensCount()
                    ),
                    message = "运行正常"
                )
            )
        }

        staticResources("/static", "static")

        authRoutes(databaseService, jwtService, captchaService)
        fileRoutes(fileService, signedLinkService, databaseService)
        apiKeyRoutes(databaseService)
    }
}
