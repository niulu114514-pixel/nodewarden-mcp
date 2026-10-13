# NodeWarden MCP — 密码管理 MCP 服务器

部署在 Cloudflare Workers 上的 MCP（Model Context Protocol）服务器，连接 NodeWarden / Vaultwarden 密码库，提供 23 个工具供 AI 客户端安全管理密码。

## 核心特性

- **纯 MCP 服务**：无网页 UI，所有非 MCP 路径返回 404
- **Token 认证**：`/mcp` 端点需 Bearer Token，未认证返回 404（不暴露端点存在）
- **常量时间比较**：Token 和 MAC 校验使用 `constantTimeEqual` 防时序攻击
- **速率限制**：每 IP 每分钟 30 次请求（KV 计数器），防止 Token 暴力破解
- **CORS 限制**：可通过 `ALLOWED_ORIGINS` 配置允许的来源
- **三层缓存**：内存解密缓存（30s）+ KV 加密同步缓存（2min）+ 客户端复用（50min）
- **Bitwarden 兼容加密**：PBKDF2 / HKDF / AES-CBC / HMAC-SHA256
- **写入失效**：所有写操作自动清除缓存，保证数据一致性

## 技术栈

| 组件 | 技术 |
|------|------|
| 运行时 | Cloudflare Workers |
| 语言 | TypeScript (strict) |
| MCP SDK | @modelcontextprotocol/sdk |
| 加密 | Web Crypto API |
| 存储 | Cloudflare KV |
| 构建 | Wrangler 4.x |
| 校验 | zod |

## 项目结构

```
nodewarden-mcp/
├── src/
│   ├── index.ts              # 入口：路由分发、CORS、速率限制、MCP 传输
│   ├── tools.ts              # 23 个 MCP 工具定义
│   ├── nodewarden-client.ts  # NodeWarden 客户端：认证、同步、加解密、缓存
│   ├── crypto.ts             # 加密层：Bitwarden 兼容加解密、TOTP、密码生成
│   ├── sync-cache.ts         # KV 同步缓存工具
│   └── types.ts              # 类型定义：Env、Cipher、Session 等
├── wrangler.toml             # Wrangler 配置
├── package.json
├── tsconfig.json
└── README.md
```

## 快速开始

### 前置条件

- Cloudflare 账号
- NodeWarden / Vaultwarden 实例
- Node.js 20+

### 安装

```bash
npm install --legacy-peer-deps
```

### 本地开发

```bash
npx wrangler dev
```

提交或部署前可运行 `npm run build`（`npm test` 同样执行严格类型检查）。

### 部署

```bash
npx wrangler deploy
```

## 环境变量与密钥

`wrangler.toml` 中配置普通变量，敏感信息通过 `wrangler secret put` 设置：

| 变量名 | 类型 | 说明 |
|--------|------|------|
| `NODEWARDEN_URL` | 明文 | NodeWarden/Vaultwarden 服务地址 |
| `USER_EMAIL` | 明文 | NodeWarden 账号邮箱 |
| `SOFT_DELETE` | 明文 | 删除时是否进回收站（`"true"` / `"false"`，默认 `"true"`） |
| `ALLOWED_ORIGINS` | 明文 | 允许的 CORS 来源，逗号分隔（如 `"https://app.example.com"`）。不设则允许所有来源 |
| `MASTER_PASSWORD` | Secret | NodeWarden 主密码 |
| `MCP_AUTH_TOKEN` | Secret | MCP 端点认证 Token |

设置密钥：

```bash
npx wrangler secret put MASTER_PASSWORD
npx wrangler secret put MCP_AUTH_TOKEN
```

### KV 命名空间

绑定名 `KV`，用于存储：

| Key 前缀 | 用途 | TTL |
|-----------|------|-----|
| `sync_cache:*` | 加密的同步响应缓存 | 2 分钟 |
| `rl:*` | 速率限制计数器 | 1 分钟 |

## 路由说明

| 路径 | 认证 | 响应 |
|------|------|------|
| `/mcp` | 无 Token / Token 错误 | 404 Not Found |
| `/mcp` | 超过速率限制 | 429 Too Many Requests |
| `/mcp` | 正确 Bearer Token | MCP 协议响应 |
| 其他所有路径 | — | 404 Not Found |

### MCP 客户端配置示例

```json
{
  "mcpServers": {
    "nodewarden": {
      "url": "https://your-worker.workers.dev/mcp",
      "headers": {
        "Authorization": "Bearer your-mcp-auth-token"
      }
    }
  }
}
```

## MCP 工具列表（23 个）

### 浏览与搜索

| 工具 | 说明 |
|------|------|
| `get_vault_summary` | 密码库摘要：总数、分类、文件夹、最近修改 |
| `list_items` | 列出所有项目（名称、用户名、URL） |
| `search_items` | 按名称/用户名/URL/笔记搜索 |
| `quick_find` | 搜索并返回完整详情（一步到位） |
| `get_password` | 快速获取用户名+密码（按名称匹配） |
| `get_item` | 按 ID 或名称获取完整详情 |
| `list_favorites` | 列出收藏项目 |
| `help` | 完整工具使用指南 |

### 创建项目

| 工具 | 说明 |
|------|------|
| `create_item` | 创建登录项目 |
| `create_secure_note` | 创建安全笔记 |
| `create_card` | 创建银行卡项目 |
| `create_folder` | 创建文件夹 |
| `generate_password` | 生成随机安全密码（拒绝采样消除模偏差） |

### 修改项目

| 工具 | 说明 |
|------|------|
| `update_item` | 更新项目字段（支持 Login/Card/Identity） |
| `toggle_favorite` | 切换收藏状态 |
| `move_to_folder` | 移动到文件夹（不存在则自动创建） |

### 删除与回收站

| 工具 | 说明 |
|------|------|
| `delete_item` | 删除项目（需 `confirm="YES"`，默认回收站，可永久删除） |
| `list_trash` | 列出回收站 |
| `restore_item` | 从回收站恢复 |
| `purge_recycle_bin` | 清空回收站（需 `confirm="YES"`） |

### 实用工具

| 工具 | 说明 |
|------|------|
| `get_totp` | 获取 TOTP 验证码 |
| `list_folders` | 列出文件夹（含解密名称） |
| `check_duplicate` | 检查重复密码/用户名（安全审计） |

## 安全设计

- **Token 认证**：MCP 端点需 Bearer Token，未认证返回 404（不暴露端点存在）
- **常量时间比较**：Token 和 MAC 校验使用 `constantTimeEqual` 防时序攻击
- **速率限制**：每 IP 每分钟 30 次请求，超过返回 429
- **CORS 限制**：可通过 `ALLOWED_ORIGINS` 限制允许的来源
- **错误脱敏**：内部错误细节只记录到服务端日志，客户端只收到通用错误消息
- **密钥不持久化**：Vault 密钥仅存于内存，不写入 KV
- **缓存安全**：KV 中只缓存加密数据（同步响应），解密后的数据仅在内存
- **密码生成**：使用拒绝采样消除模偏差，确保字符均匀分布
- **输入校验**：zod schema 验证所有工具参数
- **写入确认**：删除和清空回收站需要 `confirm="YES"` 确认

## 缓存架构

| 层级 | 内容 | 位置 | TTL | 失效条件 |
|------|------|------|-----|----------|
| 客户端复用 | 认证会话 + Vault 密钥 | 全局内存 | 50 分钟 | 过期自动重建 |
| 解密缓存 | 解密后的 Cipher / Folder 名 | 实例内存 | 实例生命周期 | 写操作清除 |
| 同步缓存（内存） | 加密的 SyncResponse | 实例内存 | 30 秒 | 写操作清除 |
| 同步缓存（KV） | 加密的 SyncResponse | Cloudflare KV | 2 分钟 | 写操作清除 |

## 许可证

MIT
