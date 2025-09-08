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

import com.arcartx.data.SecurityLogs
import com.arcartx.data.TrafficUsage
import com.arcartx.data.RateLimitRecords
import org.jetbrains.exposed.sql.SqlExpressionBuilder.less
import org.jetbrains.exposed.sql.deleteWhere
import org.jetbrains.exposed.sql.transactions.transaction
import org.slf4j.LoggerFactory
import java.time.LocalDateTime
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class CleanupService {
    private val logger = LoggerFactory.getLogger(CleanupService::class.java)
    private val executor = Executors.newSingleThreadScheduledExecutor()
    
    init {
        executor.scheduleWithFixedDelay(
            { performCleanup() },
            1, 1, TimeUnit.HOURS
        )
        logger.info("清理服务已启动，将每小时执行一次清理任务")
    }
    
    private fun performCleanup() {
        try {
            val now = LocalDateTime.now()

            // 清理过期的速率限制记录（保留1小时内的记录）
            val rateLimitCutoff = now.minusHours(1)
            val rateLimitDeleted = transaction {
                RateLimitRecords.deleteWhere {
                    lastRequestAt less rateLimitCutoff
                }
            }

            // 清理旧的安全日志（保留30天内的记录）
            val securityLogCutoff = now.minusDays(30)
            val securityLogsDeleted = transaction {
                SecurityLogs.deleteWhere {
                    SecurityLogs.createdAt less securityLogCutoff
                }
            }
            
            // 清理旧的流量统计记录（保留90天内的记录）
            val trafficCutoff = now.minusDays(90)
            val trafficDeleted = transaction {
                TrafficUsage.deleteWhere {
                    TrafficUsage.createdAt less trafficCutoff
                }
            }
            
            if (rateLimitDeleted > 0 || securityLogsDeleted > 0 || trafficDeleted > 0) {
                logger.info("清理完成: 速率限制 $rateLimitDeleted 条, 安全日志 $securityLogsDeleted 条, 流量记录 $trafficDeleted 条")
            }
            
        } catch (e: Exception) {
            logger.error("清理任务执行失败", e)
        }
    }
    
    fun shutdown() {
        try {
            executor.shutdown()
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                executor.shutdownNow()
            }
            logger.info("清理服务已关闭")
        } catch (e: Exception) {
            logger.error("关闭清理服务失败", e)
            executor.shutdownNow()
        }
    }
}
