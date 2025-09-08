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

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.exceptions.JWTVerificationException
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import org.slf4j.LoggerFactory
import java.util.*

class JwtService(
    secret: String = "your-secret-key-change-in-production",
    private val issuer: String = "arcartx-resource-system",
    private val audience: String = "arcartx-users",
    private val expirationTime: Long = 3600000
) {
    private val logger = LoggerFactory.getLogger(JwtService::class.java)
    private val algorithm = Algorithm.HMAC256(secret)
    
    fun generateToken(username: String): String {
        return try {
            val now = Date()
            val expiresAt = Date(now.time + expirationTime)
            
            JWT.create()
                .withIssuer(issuer)
                .withAudience(audience)
                .withSubject(username)
                .withIssuedAt(now)
                .withExpiresAt(expiresAt)
                .withClaim("type", "admin")
                .sign(algorithm)
        } catch (e: Exception) {
            logger.error("生成JWT令牌失败: username=$username", e)
            throw e
        }
    }

    
    fun validateToken(token: String): Result<TokenInfo> {
        return try {
            val verifier = JWT.require(algorithm)
                .withIssuer(issuer)
                .withAudience(audience)
                .build()
            
            val decodedJWT = verifier.verify(token)
            val subject = decodedJWT.subject
            val type = decodedJWT.getClaim("type").asString()
            val tokenInfo = TokenInfo(
                subject = subject,
                type = TokenType.valueOf(type.uppercase()),
                issuedAt = Instant.fromEpochMilliseconds(decodedJWT.issuedAt.time),
                expiresAt = Instant.fromEpochMilliseconds(decodedJWT.expiresAt.time)
            )
            
            Result.success(tokenInfo)
        } catch (e: JWTVerificationException) {
            logger.warn("JWT令牌验证失败: ${e.message}")
            Result.failure(e)
        } catch (e: Exception) {
            logger.error("JWT令牌验证异常", e)
            Result.failure(e)
        }
    }

    
    data class TokenInfo(
        val subject: String,
        val type: TokenType,
        val issuedAt: Instant,
        val expiresAt: Instant
    )
    
    enum class TokenType {
        ADMIN, API
    }
}
