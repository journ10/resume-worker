# resume-worker

Cloudflare Worker + KV 简历数据管理服务。

将简历 JSON 数据存储在 Cloudflare KV 中（而非公开代码库），通过临时密码向指定查看者授权访问。支持创建多个独立密码、设置过期时间以及随时主动吊销。

## 架构

```
Cloudflare Worker + KV (免费)
│
│  KV 存储:
│    resume_data        → JSON 简历数据
│    pwd_<id>           → { password, expires, active, label, createdAt }
│
│  管理接口 (需要 Header: Authorization: Bearer <ADMIN_KEY>):
│    PUT    /api/data           → 上传/更新简历数据
│    GET    /api/data           → 查看当前简历数据
│    POST   /api/passwords      → 创建密码
│    GET    /api/passwords      → 列出所有密码及其状态
│    DELETE /api/passwords/:id  → 吊销某个密码
│
│  公开接口:
│    POST   /api/verify         → 验证密码，有效则返回简历数据
```

## 部署步骤

### 1. 安装 Wrangler CLI

```bash
npm install -g wrangler
wrangler login
```

### 2. 创建 KV 命名空间

在 [Cloudflare Dashboard](https://dash.cloudflare.com/) → **Workers & Pages** → **KV** 中创建一个命名空间（例如 `RESUME_KV`），记下生成的 **Namespace ID**。

### 3. 填写 KV Namespace ID

编辑 `wrangler.toml`，将 `YOUR_KV_NAMESPACE_ID` 替换为真实的 ID：

```toml
[[kv_namespaces]]
binding = "RESUME_KV"
id = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

### 4. 安装依赖

```bash
npm install
```

### 5. 部署 Worker

```bash
npm run deploy
```

部署成功后会显示 Worker 的访问地址，格式类似 `https://resume-worker.<your-subdomain>.workers.dev`。

### 6. 设置 ADMIN_KEY 密钥

```bash
wrangler secret put ADMIN_KEY
# 输入一个足够复杂的密钥，例如: sk_mySecretKey2026!
# 这个密钥只有你知道，所有管理接口都需要它
```

---

## API 文档

以下示例中 `WORKER_URL` 替换为你的 Worker 地址，`YOUR_ADMIN_KEY` 替换为你设置的 ADMIN_KEY。

### 上传 / 更新简历数据

```bash
curl -X PUT https://WORKER_URL/api/data \
  -H "Authorization: Bearer YOUR_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "张三",
    "email": "zhangsan@example.com",
    "phone": "138-0000-0000",
    "skills": ["TypeScript", "React", "Node.js"]
  }'
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

将 `password` 字段的值（如 `A7xNmP3q`）发送给查看者即可。

### 列出所有密码

```bash
curl https://WORKER_URL/api/passwords \
  -H "Authorization: Bearer YOUR_ADMIN_KEY"
```

返回示例：

```json
[
  {
    "id": "Ab3Kx9mNpQ2r",
    "label": "给字节HR",
    "password": "A7xNmP3q",
    "expires": 1745678400000,
    "active": true,
    "createdAt": 1745072400000,
    "isExpired": false
  }
]
```

### 吊销密码

```bash
curl -X DELETE https://WORKER_URL/api/passwords/Ab3Kx9mNpQ2r \
  -H "Authorization: Bearer YOUR_ADMIN_KEY"
```

吊销后该密码立即失效，即使尚未过期。

### 验证密码（公开接口，供前端调用）

```bash
curl -X POST https://WORKER_URL/api/verify \
  -H "Content-Type: application/json" \
  -d '{"password": "A7xNmP3q"}'
```

- 密码有效：HTTP 200，返回完整简历 JSON
- 密码无效 / 已过期 / 已吊销：HTTP 403，返回 `{"error": "密码无效或已过期"}`

---

## 使用流程

1. **上传简历数据** — 通过 `PUT /api/data` 将简历 JSON 存入 KV
2. **创建密码** — 通过 `POST /api/passwords` 为每位查看者生成独立密码（可附备注）
3. **发送密码** — 将密码告知查看者，查看者通过前端输入密码后即可查看简历
4. **按需吊销** — 面试结束后通过 `DELETE /api/passwords/:id` 立即撤销访问权限

## 安全说明

- **ADMIN_KEY** 通过 `wrangler secret put` 设置，存储在 Cloudflare Secrets 中，不会出现在代码库里
- **CORS** 只允许 `https://journ10.github.io` 和 `localhost`（开发调试用）
- **密码明文存储**在 KV 中（需要比对），但 KV 是私有的，只有 Worker 能访问
- 所有响应均为 JSON 格式
- Worker 不使用任何 npm 运行时依赖，仅使用 Web 标准 API 和 Cloudflare Workers API

## 本地开发

```bash
npm run dev
```

Wrangler 会启动一个本地开发服务器，绑定到本地 KV 模拟存储。