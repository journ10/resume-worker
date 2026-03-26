# 简历访问控制服务

> **Resume Access Control Worker** — Password-gated resume backend powered by Cloudflare Workers & KV

将简历 JSON 数据存储在 Cloudflare KV 中（而非公开代码库），通过临时密码向指定查看者授权访问。任何人都可以 Fork 此仓库，配置自己的 Cloudflare 账号和 GitHub Secrets，即可搭建独立的简历服务。

## 架构

```
用户浏览器
    │
    │  输入密码
    ▼
GitHub Pages（前端）
    │  POST /api/verify
    ▼
Cloudflare Worker（本仓库）
    │  读写
    ▼
Cloudflare KV（数据存储）
    ├── resume_data          → 简历 JSON 数据
    ├── pwd_hash_{sha256}    → 密码条目（哈希索引）
    └── rl_*                 → 限流计数器
```

## 功能

- 🔐 **密码访问控制** — 简历内容不公开，只有持有有效密码的人才能查看
- 👥 **多密码支持** — 可为不同招聘方创建独立密码，互不干扰
- ⏰ **过期与吊销** — 每个密码可设置有效期，面试结束后一键吊销
- 🛡️ **管理后台** — 内置管理页面，支持上传简历数据、管理密码
- 🚦 **请求限流** — 基于 IP 的频率限制，防止暴力破解（5 次失败锁定 15 分钟）
- 🌐 **CORS 保护** — 仅允许配置的前端域名跨域访问

## 环境要求

- Node.js 20+
- Cloudflare 账号（免费套餐即可）
- GitHub 账号

## 快速上手（Fork & 部署）

### 第一步：Fork 本仓库

点击右上角 **Fork**，将仓库复制到你的 GitHub 账号下。

### 第二步：创建 Cloudflare KV 命名空间

```bash
# 登录 Cloudflare
npx wrangler login

# 创建 KV 命名空间，记下输出中的 id
npx wrangler kv namespace create "RESUME_KV"
```

输出示例：
```
{ binding = "RESUME_KV", id = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" }
```

### 第三步：配置 GitHub Secrets

进入你 Fork 后的仓库 → **Settings** → **Secrets and variables** → **Actions** → **New repository secret**，依次添加以下 Secrets：

| Secret 名称 | 说明 |
|---|---|
| `CLOUDFLARE_API_TOKEN` | Cloudflare API Token（需要 Workers 编辑权限） |
| `CLOUDFLARE_ACCOUNT_ID` | 你的 Cloudflare Account ID |
| `KV_NAMESPACE_ID` | 第二步创建的 KV 命名空间 ID |
| `ADMIN_KEY` | 管理密钥，自行设置一个强密码，例如 `sk_myKey2026!` |
| `ALLOWED_ORIGIN` | 你的前端域名，例如 `https://yourusername.github.io` |

> 获取 Cloudflare API Token：[Cloudflare Dashboard](https://dash.cloudflare.com/profile/api-tokens) → Create Token → 选择 "Edit Cloudflare Workers" 模板
>
> 获取 Account ID：Cloudflare Dashboard 右侧边栏即可看到

### 第四步：触发部署

推送任意提交到 `main` 分支，或在 **Actions** 页面手动触发 **Deploy to Cloudflare Workers** 工作流。

### 第五步：记下 Worker URL

部署成功后，在 Actions 日志中可以看到你的 Worker 地址：

```
https://resume-worker.<your-subdomain>.workers.dev
```

## 搭配前端使用

本 Worker 设计与 [journ10/journ10.github.io](https://github.com/journ10/journ10.github.io) 前端配合使用。

Fork 前端仓库后，需要在前端仓库的 GitHub Secrets 中添加：

| Secret 名称 | 说明 |
|---|---|
| `WORKER_URL` | 你的 Worker 地址，例如 `https://resume-worker.xxx.workers.dev` |

---

## API 文档

以下示例中 `WORKER_URL` 替换为你的 Worker 地址，`YOUR_ADMIN_KEY` 替换为你设置的 `ADMIN_KEY`。

### 上传 / 更新简历数据

```bash
curl -X PUT https://WORKER_URL/api/data \
  -H "Authorization: Bearer YOUR_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d @resume-data.json
```

### 查看当前简历数据

```bash
curl https://WORKER_URL/api/data \
  -H "Authorization: Bearer YOUR_ADMIN_KEY"
```

### 创建密码

```bash
curl -X POST https://WORKER_URL/api/passwords \
  -H "Authorization: Bearer YOUR_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"label": "给字节HR", "expiresIn": 604800}'
```

参数说明：
- `label`（可选）：备注，如 "给字节HR"
- `expiresIn`（可选）：过期秒数，默认 `604800`（7 天）

返回示例：

```json
{
  "id": "Ab3Kx9mNpQ2r",
  "password": "A7xNmP3q",
  "label": "给字节HR",
  "expires": 1745678400000
}
```

### 列出所有密码

```bash
curl https://WORKER_URL/api/passwords \
  -H "Authorization: Bearer YOUR_ADMIN_KEY"
```

### 吊销密码

```bash
curl -X DELETE https://WORKER_URL/api/passwords/Ab3Kx9mNpQ2r \
  -H "Authorization: Bearer YOUR_ADMIN_KEY"
```

### 清理过期/吊销的密码

```bash
curl -X DELETE https://WORKER_URL/api/passwords \
  -H "Authorization: Bearer YOUR_ADMIN_KEY"
```

### 验证密码（公开接口，供前端调用）

```bash
curl -X POST https://WORKER_URL/api/verify \
  -H "Content-Type: application/json" \
  -d '{"password": "A7xNmP3q"}'
```

- 密码有效：HTTP 200，返回完整简历 JSON
- 密码无效 / 已过期 / 已吊销：HTTP 403
- 请求过于频繁：HTTP 429

---

## 本地开发

```bash
# 安装依赖
npm install

# 启动本地开发服务器（Wrangler 会模拟 KV 存储）
npm run dev
```

如需在本地测试 secrets，使用：

```bash
npx wrangler secret put ADMIN_KEY
npx wrangler secret put ALLOWED_ORIGIN
```

---

## 安全说明

- **限流保护**：`/api/verify` 和管理接口均有基于 IP 的限流（5 次失败锁定 15 分钟）
- **CORS 保护**：通过 `ALLOWED_ORIGIN` 环境变量控制允许的跨域来源，`localhost` 在开发模式下自动放行
- **无硬编码凭证**：所有密钥通过 Cloudflare Secrets 或 GitHub Secrets 注入，不出现在代码库中
- **密码哈希索引**：密码以 SHA-256 哈希为 KV key，O(1) 查找，避免全量扫描
- **管理后台隐藏**：管理入口路径经过混淆，不直接暴露在 `/admin`

---

## License

[MIT](./LICENSE) © 2026 journ10
