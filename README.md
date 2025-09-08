# ArcartX 资源管理

使用 Ktor 开发，用于管理ArcartX云同步资源的上传和分发。

## 快速开始

### 环境要求
- JDK 17或更高版本


默认在端口8080启动，可通过 http://localhost:8080/static/admin.html 访问管理界面。

### 默认账户
- 用户名：admin
- 密码：admin123
- 请初次启动完成后前往后台更改密码

### API密钥相关操作
首次启动时会自动生成API密钥，可在控制台日志中查看。

#### 获取文件CRC64列表
```http
GET /api/files/crc64-list
Authorization: Bearer <api-key>

响应：
{
    "success": true,
    "data": {
        "files": [
            {
                "fileName": "example.zip",
                "crc64": "a1b2c3d4e5f6g7h8"
            }
        ],
        "totalCount": 1
    }
}
```

#### 生成签名下载链接
```http
POST /api/files/generate-signed-link
Authorization: Bearer <api-key>
Content-Type: application/json

{
    "fileName": "example.zip",
    "expirationMinutes": 30,
    "downloadLimit": 3
}

响应：
{
    "success": true,
    "data": {
        "downloadUrl": "/api/download/signed/token",
        "expiresAt": "2024-01-01T11:30:00Z",
        "downloadLimit": 3
    }
}
```


