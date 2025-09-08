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

import com.arcartx.service.DatabaseService
import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.response.*

fun Application.configureSecurity(databaseService: DatabaseService) {
    val jwtRealm = environment.config.propertyOrNull("app.auth.jwt.realm")?.getString() 
        ?: "ArcartX Resource System"
    val jwtSecret = environment.config.propertyOrNull("app.auth.jwt.secret")?.getString() 
        ?: "your-secret-key-change-in-production"
    val jwtAudience = environment.config.propertyOrNull("app.auth.jwt.audience")?.getString() 
        ?: "arcartx-users"
    val jwtIssuer = environment.config.propertyOrNull("app.auth.jwt.issuer")?.getString() 
        ?: "arcartx-resource-system"
    
    install(Authentication) {
        jwt("auth-jwt") {
            realm = jwtRealm
            
            verifier(
                JWT
                    .require(Algorithm.HMAC256(jwtSecret))
                    .withAudience(jwtAudience)
                    .withIssuer(jwtIssuer)
                    .build()
            )
            
            validate { credential ->
                try {
                    val subject = credential.payload.subject
                    val tokenType = credential.payload.getClaim("type")?.asString()
                    
                    if (subject != null && tokenType == "admin") {
                        JWTPrincipal(credential.payload)
                    } else {
                        null
                    }
                } catch (e: Exception) {
                    null
                }
            }
            
            challenge { defaultScheme, realm ->
                call.respond(HttpStatusCode.Unauthorized, "无效的认证令牌")
            }
        }

        bearer("auth-api") {
            authenticate { tokenCredential ->
                try {
                    val apiKeyInfo = databaseService.validateApiKeyBasic(tokenCredential.token)
                    if (apiKeyInfo != null) {
                        ApiKeyPrincipal(
                            keyName = apiKeyInfo.keyName,
                            keyId = apiKeyInfo.id,
                            originalToken = tokenCredential.token
                        )
                    } else {
                        null
                    }
                } catch (e: Exception) {
                    null
                }
            }
        }
    }
}

data class ApiKeyPrincipal(
    val keyName: String,
    val keyId: Int,
    val originalToken: String
)
