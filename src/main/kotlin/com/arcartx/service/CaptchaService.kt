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

import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import org.slf4j.LoggerFactory
import java.awt.Color
import java.awt.Font
import java.awt.Graphics2D
import java.awt.RenderingHints
import java.awt.image.BufferedImage
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import javax.imageio.ImageIO
import kotlin.random.Random
import kotlin.time.Duration.Companion.minutes

class CaptchaService {
    private val logger = LoggerFactory.getLogger(CaptchaService::class.java)
    private val captchaCache = ConcurrentHashMap<String, CaptchaRecord>()
    private val random = SecureRandom()
    
    companion object {
        private const val CAPTCHA_WIDTH = 120
        private const val CAPTCHA_HEIGHT = 40
        private const val EXPIRATION_MINUTES = 5
    }
    
    data class CaptchaRecord(
        val answer: String,
        val expiresAt: Instant
    )
    
    fun generateCaptcha(): Pair<String, String> {
        val captchaId = generateId()

        val num1 = Random.nextInt(1, 10)
        val num2 = Random.nextInt(1, 10)
        val operator = if (Random.nextBoolean()) "+" else "-"
        
        val question = "$num1 $operator $num2 = ?"
        val answer = if (operator == "+") (num1 + num2).toString() else (num1 - num2).toString()

        val imageBase64 = generateCaptchaImage(question)

        val expiresAt = Clock.System.now().plus(EXPIRATION_MINUTES.minutes)
        captchaCache[captchaId] = CaptchaRecord(answer, expiresAt)
        
        logger.debug("生成验证码: ID=$captchaId, 问题=$question, 答案=$answer")
        
        return Pair(captchaId, imageBase64)
    }
    
    fun validateCaptcha(captchaId: String, userAnswer: String): Boolean {
        val record = captchaCache[captchaId]
        
        if (record == null) {
            logger.warn("验证码不存在: $captchaId")
            return false
        }

        if (Clock.System.now() > record.expiresAt) {
            captchaCache.remove(captchaId)
            logger.warn("验证码已过期: $captchaId")
            return false
        }

        captchaCache.remove(captchaId)
        
        val isCorrect = record.answer.equals(userAnswer.trim(), ignoreCase = true)
        logger.debug("验证码验证: ID=$captchaId, 用户答案=$userAnswer, 正确答案=${record.answer}, 结果=$isCorrect")
        
        return isCorrect
    }
    
    private fun generateCaptchaImage(text: String): String {
        val image = BufferedImage(CAPTCHA_WIDTH, CAPTCHA_HEIGHT, BufferedImage.TYPE_INT_RGB)
        val g2d: Graphics2D = image.createGraphics()
        
        try {
            g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
            g2d.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON)

            g2d.color = Color.WHITE
            g2d.fillRect(0, 0, CAPTCHA_WIDTH, CAPTCHA_HEIGHT)

            g2d.color = Color.LIGHT_GRAY
            for (i in 0..5) {
                val x1 = random.nextInt(CAPTCHA_WIDTH)
                val y1 = random.nextInt(CAPTCHA_HEIGHT)
                val x2 = random.nextInt(CAPTCHA_WIDTH)
                val y2 = random.nextInt(CAPTCHA_HEIGHT)
                g2d.drawLine(x1, y1, x2, y2)
            }

            g2d.font = Font("Arial", Font.BOLD, 16)
            g2d.color = Color.DARK_GRAY

            val fontMetrics = g2d.fontMetrics
            val textWidth = fontMetrics.stringWidth(text)
            val x = (CAPTCHA_WIDTH - textWidth) / 2
            val y = (CAPTCHA_HEIGHT + fontMetrics.ascent) / 2
            g2d.drawString(text, x, y)

            g2d.color = Color.GRAY
            for (i in 0..30) {
                val x = random.nextInt(CAPTCHA_WIDTH)
                val y = random.nextInt(CAPTCHA_HEIGHT)
                g2d.fillOval(x, y, 1, 1)
            }
            
        } finally {
            g2d.dispose()
        }

        val baos = ByteArrayOutputStream()
        ImageIO.write(image, "png", baos)
        val imageBytes = baos.toByteArray()
        return Base64.getEncoder().encodeToString(imageBytes)
    }
    
    private fun generateId(): String {
        val bytes = ByteArray(16)
        random.nextBytes(bytes)
        return bytes.joinToString("") { "%02x".format(it) }
    }
    

}

