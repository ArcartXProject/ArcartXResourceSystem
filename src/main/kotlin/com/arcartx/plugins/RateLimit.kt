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

import io.ktor.server.application.*
import io.ktor.server.plugins.ratelimit.*
import kotlin.time.Duration.Companion.minutes

fun Application.configureRateLimit() {
    install(RateLimit) {
        register(RateLimitName("api")) {
            rateLimiter(limit = 100, refillPeriod = 1.minutes)
            requestKey { applicationCall ->
                applicationCall.request.headers["X-Forwarded-For"]
                    ?: applicationCall.request.headers["X-Real-IP"]
                    ?: applicationCall.request.local.remoteAddress
            }
        }
        
        register(RateLimitName("download")) {
            rateLimiter(limit = 30, refillPeriod = 1.minutes)
            requestKey { applicationCall ->
                applicationCall.request.headers["X-Forwarded-For"]
                    ?: applicationCall.request.headers["X-Real-IP"]
                    ?: applicationCall.request.local.remoteAddress
            }
        }
    }
}

