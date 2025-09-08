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

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.plugins.autohead.*
import io.ktor.server.plugins.cors.routing.*
import io.ktor.server.plugins.partialcontent.*
import io.ktor.server.plugins.statuspages.*
import io.ktor.server.response.*

fun Application.configureHTTP() {
    // 先获取配置值
    val allowedHosts = environment.config.propertyOrNull("app.security.cors.allowedHosts")?.getList()
        ?: listOf("*")
    
    install(CORS) {
        allowMethod(HttpMethod.Options)
        allowMethod(HttpMethod.Put)
        allowMethod(HttpMethod.Delete)
        allowMethod(HttpMethod.Patch)
        allowMethod(HttpMethod.Post)
        allowMethod(HttpMethod.Get)
        allowHeader(HttpHeaders.Authorization)
        allowHeader(HttpHeaders.ContentType)
        allowHeader("X-Requested-With")
        
        // 设置允许的主机
        allowedHosts.forEach { host ->
            if (host == "*") {
                anyHost()
            } else {
                allowHost(host, listOf("http", "https"))
            }
        }
        
        allowCredentials = true
        maxAgeInSeconds = 24 * 60 * 60
    }
    
    install(PartialContent) {
        // 支持断点续传
        maxRangeCount = 10
    }
    
    install(AutoHeadResponse)
    
    install(StatusPages) {
        exception<Throwable> { call, cause ->
            call.application.log.error("未处理的异常", cause)
            call.respond(HttpStatusCode.InternalServerError, "服务器内部错误")
        }
        
        status(HttpStatusCode.NotFound) { call, status ->
            call.respondText(
                contentType = ContentType.Application.Json,
                status = status
            ) {
                """{"success": false, "error": "请求的资源不存在", "status": ${status.value}}"""
            }
        }
        
        status(HttpStatusCode.Unauthorized) { call, status ->
            call.respondText(
                contentType = ContentType.Application.Json,
                status = status
            ) {
                """{"success": false, "error": "未授权访问", "status": ${status.value}}"""
            }
        }
        
        status(HttpStatusCode.Forbidden) { call, status ->
            call.respondText(
                contentType = ContentType.Application.Json,
                status = status
            ) {
                """{"success": false, "error": "禁止访问", "status": ${status.value}}"""
            }
        }
    }
}
