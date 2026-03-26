export interface Env {
  RESUME_KV: KVNamespace;
  ADMIN_KEY: string;
}

interface PasswordEntry {
  password: string;
  expires: number;
  active: boolean;
  label: string;
  createdAt: number;
}

const ALLOWED_ORIGINS = [
  "https://journ10.github.io",
];

function isAllowedOrigin(origin: string | null): boolean {
  if (!origin) return false;
  if (ALLOWED_ORIGINS.includes(origin)) return true;
  if (/^https?:\/\/localhost(:\d+)?$/.test(origin)) return true;
  return false;
}

function corsHeaders(origin: string | null): Record<string, string> {
  const allowed = isAllowedOrigin(origin) ? origin! : ALLOWED_ORIGINS[0];
  return {
    "Access-Control-Allow-Origin": allowed,
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
  };
}

function jsonResponse(
  body: unknown,
  status = 200,
  origin: string | null = null
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...corsHeaders(origin),
    },
  });
}

function isAuthorized(request: Request, env: Env): boolean {
  const authHeader = request.headers.get("Authorization");
  if (!authHeader) return false;
  const token = authHeader.replace(/^Bearer\s+/i, "");
  return token === env.ADMIN_KEY;
}

/** Generate a cryptographically random alphanumeric string of the given length */
function randomAlphanumeric(length: number): string {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789";
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => chars[b % chars.length]).join("");
}

// ---------------------------------------------------------------------------
// Security helpers
// ---------------------------------------------------------------------------

/** Compute a SHA-256 hex digest of the given string */
async function sha256hex(str: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");
}

interface RateLimitData {
  count: number;
  firstAttempt: number;
}

const RATE_LIMIT_MAX = 5;
const RATE_LIMIT_WINDOW = 900; // 15 minutes in seconds

/** Returns a 429 response if the IP is rate-limited, otherwise null */
async function enforceRateLimit(
  env: Env,
  key: string,
  origin: string | null
): Promise<Response | null> {
  const raw = await env.RESUME_KV.get(key);
  if (raw) {
    const data: RateLimitData = JSON.parse(raw);
    if (data.count >= RATE_LIMIT_MAX) {
      return jsonResponse({ error: "请求过于频繁，请稍后再试" }, 429, origin);
    }
  }
  return null;
}

/** Increment the failed-attempt counter for an IP */
async function recordFailedAttempt(env: Env, key: string): Promise<void> {
  const raw = await env.RESUME_KV.get(key);
  let data: RateLimitData;
  if (raw) {
    data = JSON.parse(raw);
    data.count++;
  } else {
    data = { count: 1, firstAttempt: Date.now() };
  }
  await env.RESUME_KV.put(key, JSON.stringify(data), { expirationTtl: RATE_LIMIT_WINDOW });
}

/** Reset the failed-attempt counter on successful auth */
async function resetFailedAttempts(env: Env, key: string): Promise<void> {
  await env.RESUME_KV.delete(key);
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

/** PUT /api/data — upload / replace resume data (admin only) */
async function handlePutData(
  request: Request,
  env: Env,
  origin: string | null
): Promise<Response> {
  const ip = request.headers.get("CF-Connecting-IP") ?? "unknown";
  const rlKey = `rl_admin_${ip}`;

  const limited = await enforceRateLimit(env, rlKey, origin);
  if (limited) return limited;

  if (!isAuthorized(request, env)) {
    await recordFailedAttempt(env, rlKey);
    return jsonResponse({ error: "Unauthorized" }, 401, origin);
  }
  await resetFailedAttempts(env, rlKey);

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: "Invalid JSON body" }, 400, origin);
  }
  await env.RESUME_KV.put("resume_data", JSON.stringify(body));
  return jsonResponse({ ok: true }, 200, origin);
}

/** GET /api/data — retrieve resume data (admin only) */
async function handleGetData(
  request: Request,
  env: Env,
  origin: string | null
): Promise<Response> {
  const ip = request.headers.get("CF-Connecting-IP") ?? "unknown";
  const rlKey = `rl_admin_${ip}`;

  const limited = await enforceRateLimit(env, rlKey, origin);
  if (limited) return limited;

  if (!isAuthorized(request, env)) {
    await recordFailedAttempt(env, rlKey);
    return jsonResponse({ error: "Unauthorized" }, 401, origin);
  }
  await resetFailedAttempts(env, rlKey);

  const raw = await env.RESUME_KV.get("resume_data");
  if (!raw) {
    return jsonResponse({ error: "No resume data found" }, 404, origin);
  }
  return jsonResponse(JSON.parse(raw), 200, origin);
}

/** POST /api/passwords — create a new password (admin only) */
async function handleCreatePassword(
  request: Request,
  env: Env,
  origin: string | null
): Promise<Response> {
  const ip = request.headers.get("CF-Connecting-IP") ?? "unknown";
  const rlKey = `rl_admin_${ip}`;

  const limited = await enforceRateLimit(env, rlKey, origin);
  if (limited) return limited;

  if (!isAuthorized(request, env)) {
    await recordFailedAttempt(env, rlKey);
    return jsonResponse({ error: "Unauthorized" }, 401, origin);
  }
  await resetFailedAttempts(env, rlKey);

  let body: { label?: string; expiresIn?: number } = {};
  try {
    body = (await request.json()) as { label?: string; expiresIn?: number };
  } catch {
    // body is optional; defaults apply
  }

  const label = body.label ?? "";
  const expiresIn = body.expiresIn ?? 604800; // default 7 days
  const id = randomAlphanumeric(12);
  const password = randomAlphanumeric(8);
  const now = Date.now();
  const entry: PasswordEntry = {
    password,
    expires: now + expiresIn * 1000,
    active: true,
    label,
    createdAt: now,
  };

  const hash = await sha256hex(password);
  await Promise.all([
    env.RESUME_KV.put(`pwd_${id}`, JSON.stringify(entry)),
    env.RESUME_KV.put(`idx_${hash}`, `pwd_${id}`),
  ]);
  return jsonResponse({ id, password, label, expires: entry.expires }, 201, origin);
}

/** GET /api/passwords — list all passwords (admin only) */
async function handleListPasswords(
  request: Request,
  env: Env,
  origin: string | null
): Promise<Response> {
  const ip = request.headers.get("CF-Connecting-IP") ?? "unknown";
  const rlKey = `rl_admin_${ip}`;

  const limited = await enforceRateLimit(env, rlKey, origin);
  if (limited) return limited;

  if (!isAuthorized(request, env)) {
    await recordFailedAttempt(env, rlKey);
    return jsonResponse({ error: "Unauthorized" }, 401, origin);
  }
  await resetFailedAttempts(env, rlKey);

  const list = await env.RESUME_KV.list({ prefix: "pwd_" });
  const now = Date.now();
  const results = await Promise.all(
    list.keys.map(async (key) => {
      const raw = await env.RESUME_KV.get(key.name);
      if (!raw) return null;
      const entry: PasswordEntry = JSON.parse(raw);
      const id = key.name.slice("pwd_".length);
      return {
        id,
        label: entry.label,
        password: entry.password,
        expires: entry.expires,
        active: entry.active,
        createdAt: entry.createdAt,
        isExpired: entry.expires < now,
      };
    })
  );
  return jsonResponse(results.filter(Boolean), 200, origin);
}

/** DELETE /api/passwords/:id — revoke a password (admin only) */
async function handleRevokePassword(
  id: string,
  request: Request,
  env: Env,
  origin: string | null
): Promise<Response> {
  const ip = request.headers.get("CF-Connecting-IP") ?? "unknown";
  const rlKey = `rl_admin_${ip}`;

  const limited = await enforceRateLimit(env, rlKey, origin);
  if (limited) return limited;

  if (!isAuthorized(request, env)) {
    await recordFailedAttempt(env, rlKey);
    return jsonResponse({ error: "Unauthorized" }, 401, origin);
  }
  await resetFailedAttempts(env, rlKey);

  const key = `pwd_${id}`;
  const raw = await env.RESUME_KV.get(key);
  if (!raw) {
    return jsonResponse({ error: "Password not found" }, 404, origin);
  }
  const entry: PasswordEntry = JSON.parse(raw);
  entry.active = false;
  const hash = await sha256hex(entry.password);
  await Promise.all([
    env.RESUME_KV.put(key, JSON.stringify(entry)),
    env.RESUME_KV.delete(`idx_${hash}`),
  ]);
  return jsonResponse({ ok: true, id }, 200, origin);
}

/** POST /api/verify — verify password and return resume data (public) */
async function handleVerify(
  request: Request,
  env: Env,
  origin: string | null
): Promise<Response> {
  const ip = request.headers.get("CF-Connecting-IP") ?? "unknown";
  const rlKey = `rl_verify_${ip}`;

  const limited = await enforceRateLimit(env, rlKey, origin);
  if (limited) return limited;

  let body: { password?: string };
  try {
    body = (await request.json()) as { password?: string };
  } catch {
    return jsonResponse({ error: "Invalid JSON body" }, 400, origin);
  }

  const { password } = body;
  if (!password) {
    return jsonResponse({ error: "Missing password" }, 400, origin);
  }

  const now = Date.now();

  // O(1) hash-indexed lookup
  const hash = await sha256hex(password);
  const pwdKey = await env.RESUME_KV.get(`idx_${hash}`);

  if (pwdKey) {
    const raw = await env.RESUME_KV.get(pwdKey);
    if (raw) {
      const entry: PasswordEntry = JSON.parse(raw);
      if (entry.active && entry.expires > now) {
        await resetFailedAttempts(env, rlKey);
        const resumeRaw = await env.RESUME_KV.get("resume_data");
        if (!resumeRaw) {
          return jsonResponse({ error: "Resume data not found" }, 404, origin);
        }
        return jsonResponse(JSON.parse(resumeRaw), 200, origin);
      }
    }
  } else {
    // Legacy fallback: no hash index found — scan all passwords in parallel
    const list = await env.RESUME_KV.list({ prefix: "pwd_" });
    const entries = await Promise.all(
      list.keys.map(async (k) => {
        const raw = await env.RESUME_KV.get(k.name);
        return raw ? (JSON.parse(raw) as PasswordEntry) : null;
      })
    );
    for (const entry of entries) {
      if (entry && entry.password === password && entry.active && entry.expires > now) {
        await resetFailedAttempts(env, rlKey);
        const resumeRaw = await env.RESUME_KV.get("resume_data");
        if (!resumeRaw) {
          return jsonResponse({ error: "Resume data not found" }, 404, origin);
        }
        return jsonResponse(JSON.parse(resumeRaw), 200, origin);
      }
    }
  }

  await recordFailedAttempt(env, rlKey);
  return jsonResponse({ error: "密码无效或已过期" }, 403, origin);
}

/** DELETE /api/passwords — cleanup expired/revoked passwords (admin only) */
async function handleCleanup(
  request: Request,
  env: Env,
  origin: string | null
): Promise<Response> {
  const ip = request.headers.get("CF-Connecting-IP") ?? "unknown";
  const rlKey = `rl_admin_${ip}`;

  const limited = await enforceRateLimit(env, rlKey, origin);
  if (limited) return limited;

  if (!isAuthorized(request, env)) {
    await recordFailedAttempt(env, rlKey);
    return jsonResponse({ error: "Unauthorized" }, 401, origin);
  }
  await resetFailedAttempts(env, rlKey);

  const list = await env.RESUME_KV.list({ prefix: "pwd_" });
  const now = Date.now();

  const results = await Promise.all(
    list.keys.map(async (key) => {
      const raw = await env.RESUME_KV.get(key.name);
      if (!raw) return 0;
      const entry: PasswordEntry = JSON.parse(raw);
      if (!entry.active || entry.expires < now) {
        const hash = await sha256hex(entry.password);
        await Promise.all([
          env.RESUME_KV.delete(key.name),
          env.RESUME_KV.delete(`idx_${hash}`),
        ]);
        return 1;
      }
      return 0;
    })
  );
  const deleted = results.reduce<number>((sum, n) => sum + n, 0);

  return jsonResponse({ ok: true, deleted }, 200, origin);
}

// ---------------------------------------------------------------------------
// Admin HTML page
// ---------------------------------------------------------------------------

function getAdminHTML(): string {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>管理后台</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg: #0f1117;
    --surface: #1a1d27;
    --border: #2a2d3a;
    --accent: #6c8bff;
    --accent-hover: #8aa3ff;
    --danger: #ff5555;
    --danger-hover: #ff7070;
    --success: #50fa7b;
    --text: #e2e4f0;
    --muted: #8b8fa8;
    --radius: 10px;
  }
  body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif; min-height: 100vh; }
  a { color: var(--accent); }

  /* ---- Login ---- */
  #login-screen { display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px; }
  .login-card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 32px 24px; width: 100%; max-width: 360px; }
  .login-card h1 { font-size: 1.4rem; margin-bottom: 8px; }
  .login-card p { color: var(--muted); font-size: .9rem; margin-bottom: 24px; }
  .form-group { margin-bottom: 16px; }
  label { display: block; font-size: .85rem; color: var(--muted); margin-bottom: 6px; }
  input[type="password"], input[type="text"], textarea, select {
    width: 100%; background: var(--bg); border: 1px solid var(--border); border-radius: 8px;
    color: var(--text); font-size: 1rem; padding: 12px 14px; outline: none; transition: border-color .2s;
  }
  input[type="password"]:focus, input[type="text"]:focus, textarea:focus, select:focus { border-color: var(--accent); }
  textarea { resize: vertical; font-family: "SFMono-Regular", Consolas, monospace; font-size: .85rem; line-height: 1.5; }
  select { appearance: none; }

  /* ---- Buttons ---- */
  .btn { display: inline-flex; align-items: center; justify-content: center; gap: 6px;
    min-height: 44px; padding: 0 20px; border: none; border-radius: 8px;
    font-size: .95rem; font-weight: 600; cursor: pointer; transition: background .15s, opacity .15s; }
  .btn:active { opacity: .8; }
  .btn-primary { background: var(--accent); color: #fff; }
  .btn-primary:hover { background: var(--accent-hover); }
  .btn-danger { background: var(--danger); color: #fff; }
  .btn-danger:hover { background: var(--danger-hover); }
  .btn-ghost { background: transparent; color: var(--muted); border: 1px solid var(--border); }
  .btn-ghost:hover { color: var(--text); border-color: var(--text); }
  .btn-sm { min-height: 36px; padding: 0 14px; font-size: .85rem; }
  .btn-full { width: 100%; }

  /* ---- App shell ---- */
  #app { display: none; flex-direction: column; min-height: 100vh; }
  header { background: var(--surface); border-bottom: 1px solid var(--border); padding: 12px 16px; display: flex; align-items: center; justify-content: space-between; }
  header h1 { font-size: 1.1rem; }

  /* ---- Tabs ---- */
  .tabs { display: flex; background: var(--surface); border-bottom: 1px solid var(--border); }
  .tab-btn { flex: 1; padding: 14px 8px; background: none; border: none; color: var(--muted);
    font-size: .9rem; font-weight: 500; cursor: pointer; border-bottom: 2px solid transparent; transition: color .15s, border-color .15s; }
  .tab-btn.active { color: var(--accent); border-bottom-color: var(--accent); }
  .tab-panel { display: none; padding: 20px 16px; flex: 1; }
  .tab-panel.active { display: block; }

  /* ---- Cards ---- */
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 16px; margin-bottom: 16px; }
  .card-title { font-size: .95rem; font-weight: 600; margin-bottom: 14px; color: var(--text); }

  /* ---- Password list ---- */
  .pwd-item { background: var(--bg); border: 1px solid var(--border); border-radius: 8px; padding: 14px; margin-bottom: 10px; }
  .pwd-item-header { display: flex; align-items: flex-start; justify-content: space-between; gap: 8px; margin-bottom: 8px; }
  .pwd-label { font-weight: 600; font-size: .95rem; word-break: break-all; }
  .badge { display: inline-block; padding: 2px 10px; border-radius: 20px; font-size: .78rem; font-weight: 600; white-space: nowrap; }
  .badge-active { background: rgba(80,250,123,.15); color: var(--success); }
  .badge-expired { background: rgba(139,143,168,.15); color: var(--muted); }
  .badge-revoked { background: rgba(255,85,85,.15); color: var(--danger); }
  .pwd-meta { font-size: .82rem; color: var(--muted); margin-bottom: 10px; line-height: 1.6; }
  .pwd-row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
  .pwd-value { font-family: "SFMono-Regular", Consolas, monospace; background: var(--bg); border: 1px solid var(--border);
    border-radius: 6px; padding: 6px 10px; font-size: .9rem; letter-spacing: .05em; flex: 1; min-width: 0; word-break: break-all; }

  /* ---- Toast ---- */
  #toast-container { position: fixed; bottom: 24px; left: 50%; transform: translateX(-50%); z-index: 9999; display: flex; flex-direction: column; align-items: center; gap: 8px; pointer-events: none; width: calc(100% - 32px); max-width: 400px; }
  .toast { background: #2a2d3a; color: var(--text); border-radius: 8px; padding: 12px 18px; font-size: .9rem; box-shadow: 0 4px 20px rgba(0,0,0,.4); animation: toast-in .2s ease; text-align: center; width: 100%; }
  @keyframes toast-in { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: none; } }

  /* ---- Misc ---- */
  .row { display: flex; gap: 10px; flex-wrap: wrap; }
  .row .btn { flex: 1; }
  .section-title { font-size: .8rem; font-weight: 600; letter-spacing: .08em; text-transform: uppercase; color: var(--muted); margin-bottom: 12px; }
  .empty { color: var(--muted); font-size: .9rem; text-align: center; padding: 32px 0; }
  .created-pwd-box { background: var(--bg); border: 2px solid var(--success); border-radius: 8px; padding: 16px; margin-top: 14px; display: none; }
  .created-pwd-box .pwd-row { margin-top: 8px; }
</style>
</head>
<body>

<!-- Login screen -->
<div id="login-screen">
  <div class="login-card">
    <h1>🔐 管理后台</h1>
    <p>输入 ADMIN_KEY 登录</p>
    <div class="form-group">
      <label for="key-input">Admin Key</label>
      <input type="password" id="key-input" placeholder="sk_..." autocomplete="current-password">
    </div>
    <button class="btn btn-primary btn-full" id="login-btn">登录</button>
  </div>
</div>

<!-- App -->
<div id="app">
  <header>
    <h1>📋 简历管理</h1>
    <button class="btn btn-ghost btn-sm" id="logout-btn">登出</button>
  </header>

  <div class="tabs">
    <button class="tab-btn active" data-tab="data">简历数据</button>
    <button class="tab-btn" data-tab="passwords">密码管理</button>
  </div>

  <!-- Tab: Resume Data -->
  <div class="tab-panel active" id="tab-data">
    <div class="card">
      <div class="card-title">简历 JSON 数据</div>
      <div class="row" style="margin-bottom:12px">
        <button class="btn btn-ghost" id="load-data-btn">⬇ 加载当前数据</button>
        <button class="btn btn-primary" id="save-data-btn">💾 保存数据</button>
      </div>
      <textarea id="data-editor" rows="20" placeholder='{"personalInfo": {...}, "skills": [...], ...}'></textarea>
    </div>
  </div>

  <!-- Tab: Passwords -->
  <div class="tab-panel" id="tab-passwords">
    <!-- Create password -->
    <div class="card">
      <div class="card-title">创建新密码</div>
      <div class="form-group">
        <label for="pwd-label">标签（如「给字节HR」）</label>
        <input type="text" id="pwd-label" placeholder="给某某HR">
      </div>
      <div class="form-group">
        <label for="pwd-expires">有效期</label>
        <select id="pwd-expires">
          <option value="86400">1 天</option>
          <option value="259200">3 天</option>
          <option value="604800" selected>7 天</option>
          <option value="2592000">30 天</option>
        </select>
      </div>
      <button class="btn btn-primary btn-full" id="create-pwd-btn">✨ 创建密码</button>
      <div class="created-pwd-box" id="created-pwd-box">
        <div class="section-title">✅ 创建成功！密码如下</div>
        <div class="pwd-row">
          <span class="pwd-value" id="created-pwd-value"></span>
          <button class="btn btn-ghost btn-sm" id="copy-created-btn">复制</button>
        </div>
      </div>
    </div>

    <!-- Password list -->
    <div class="card">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px">
        <div class="card-title" style="margin-bottom:0">密码列表</div>
        <div style="display:flex;gap:8px">
          <button class="btn btn-ghost btn-sm" id="cleanup-pwd-btn">🧹 清理过期密码</button>
          <button class="btn btn-ghost btn-sm" id="refresh-pwd-btn">🔄 刷新</button>
        </div>
      </div>
      <div id="pwd-list"><div class="empty">加载中…</div></div>
    </div>
  </div>
</div>

<!-- Toast container -->
<div id="toast-container"></div>

<script>
(function () {
  'use strict';
  const BASE = window.location.origin;
  const STORAGE_KEY = 'admin_key';

  // ---- Helpers ----
  function getKey() { return sessionStorage.getItem(STORAGE_KEY) || ''; }

  function authHeaders() {
    return { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + getKey() };
  }

  function showToast(msg, duration) {
    duration = duration || 2500;
    var el = document.createElement('div');
    el.className = 'toast';
    el.textContent = msg;
    document.getElementById('toast-container').appendChild(el);
    setTimeout(function () { el.remove(); }, duration);
  }

  function fmtDate(ts) {
    return new Date(ts).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' });
  }

  // ---- Login / Logout ----
  function showApp() {
    document.getElementById('login-screen').style.display = 'none';
    document.getElementById('app').style.display = 'flex';
    loadPasswordList();
  }

  function showLogin() {
    document.getElementById('app').style.display = 'none';
    document.getElementById('login-screen').style.display = 'flex';
  }

  function verifyKey(key, onSuccess, onFail) {
    fetch(BASE + '/api/passwords', {
      headers: { 'Authorization': 'Bearer ' + key }
    }).then(function (r) {
      if (r.ok) { onSuccess(); } else { onFail(r.status === 401 ? 'Admin Key 无效' : '服务器错误，请稍后重试'); }
    }).catch(function () { onFail('网络请求失败，请检查连接'); });
  }

  if (getKey()) {
    showToast('验证中…', 1500);
    verifyKey(getKey(), showApp, function (msg) {
      sessionStorage.removeItem(STORAGE_KEY);
      showLogin();
      showToast(msg || 'Admin Key 无效，请重新登录');
    });
  }

  document.getElementById('login-btn').addEventListener('click', function () {
    var val = document.getElementById('key-input').value.trim();
    if (!val) { showToast('请输入 Admin Key'); return; }
    var btn = this;
    btn.disabled = true;
    verifyKey(val, function () {
      sessionStorage.setItem(STORAGE_KEY, val);
      btn.disabled = false;
      showApp();
    }, function (msg) {
      btn.disabled = false;
      showToast(msg || 'Admin Key 无效');
    });
  });

  document.getElementById('key-input').addEventListener('keydown', function (e) {
    if (e.key === 'Enter') document.getElementById('login-btn').click();
  });

  document.getElementById('logout-btn').addEventListener('click', function () {
    sessionStorage.removeItem(STORAGE_KEY);
    showLogin();
  });

  // ---- Tabs ----
  document.querySelectorAll('.tab-btn').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var tab = btn.dataset.tab;
      document.querySelectorAll('.tab-btn').forEach(function (b) { b.classList.remove('active'); });
      document.querySelectorAll('.tab-panel').forEach(function (p) { p.classList.remove('active'); });
      btn.classList.add('active');
      document.getElementById('tab-' + tab).classList.add('active');
      if (tab === 'passwords') loadPasswordList();
    });
  });

  // ---- Resume Data Tab ----
  document.getElementById('load-data-btn').addEventListener('click', function () {
    fetch(BASE + '/api/data', { headers: authHeaders() })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        if (data.error) { showToast('❌ ' + data.error); return; }
        document.getElementById('data-editor').value = JSON.stringify(data, null, 2);
        showToast('✅ 数据已加载');
      })
      .catch(function () { showToast('❌ 请求失败'); });
  });

  document.getElementById('save-data-btn').addEventListener('click', function () {
    var raw = document.getElementById('data-editor').value.trim();
    if (!raw) { showToast('内容不能为空'); return; }
    var parsed;
    try { parsed = JSON.parse(raw); } catch (e) { showToast('❌ JSON 格式无效，请检查'); return; }
    fetch(BASE + '/api/data', {
      method: 'PUT',
      headers: authHeaders(),
      body: JSON.stringify(parsed)
    })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        if (data.error) { showToast('❌ ' + data.error); return; }
        showToast('✅ 保存成功！');
      })
      .catch(function () { showToast('❌ 请求失败'); });
  });

  // ---- Password Tab ----
  function loadPasswordList() {
    var el = document.getElementById('pwd-list');
    el.innerHTML = '<div class="empty">加载中…</div>';
    fetch(BASE + '/api/passwords', { headers: authHeaders() })
      .then(function (r) { return r.json(); })
      .then(function (list) {
        if (!Array.isArray(list)) { el.innerHTML = '<div class="empty">加载失败</div>'; return; }
        if (list.length === 0) { el.innerHTML = '<div class="empty">暂无密码</div>'; return; }
        var now = Date.now();
        list.sort(function (a, b) { return b.createdAt - a.createdAt; });
        el.innerHTML = list.map(function (p) {
          var expired = p.expires < now;
          var badgeCls = !p.active ? 'badge-revoked' : expired ? 'badge-expired' : 'badge-active';
          var badgeText = !p.active ? '已吊销' : expired ? '已过期' : '有效';
          var canRevoke = p.active && !expired;
          return '<div class="pwd-item">' +
            '<div class="pwd-item-header">' +
              '<span class="pwd-label">' + escHtml(p.label || '（无标签）') + '</span>' +
              '<span class="badge ' + badgeCls + '">' + badgeText + '</span>' +
            '</div>' +
            '<div class="pwd-meta">创建：' + fmtDate(p.createdAt) + '　到期：' + fmtDate(p.expires) + '</div>' +
            '<div class="pwd-row">' +
              '<span class="pwd-value">' + escHtml(p.password) + '</span>' +
              '<button class="btn btn-ghost btn-sm copy-btn" data-pwd="' + escHtml(p.password) + '">复制</button>' +
              (canRevoke ? '<button class="btn btn-danger btn-sm revoke-btn" data-id="' + escHtml(p.id) + '">吊销</button>' : '') +
            '</div>' +
          '</div>';
        }).join('');
      })
      .catch(function () { el.innerHTML = '<div class="empty">加载失败</div>'; });
  }

  // Event delegation for copy/revoke — set up once on the stable container
  document.getElementById('pwd-list').addEventListener('click', function (e) {
    var target = e.target;
    if (target.classList.contains('copy-btn')) {
      copyText(target.dataset.pwd || '');
    } else if (target.classList.contains('revoke-btn')) {
      revokePassword(target.dataset.id || '');
    }
  });

  document.getElementById('refresh-pwd-btn').addEventListener('click', loadPasswordList);

  document.getElementById('cleanup-pwd-btn').addEventListener('click', function () {
    if (!confirm('清理所有已过期或已吊销的密码？')) return;
    fetch(BASE + '/api/passwords', { method: 'DELETE', headers: authHeaders() })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        if (data.error) { showToast('❌ ' + data.error); return; }
        showToast('✅ 已清理 ' + data.deleted + ' 条记录');
        loadPasswordList();
      })
      .catch(function () { showToast('❌ 请求失败'); });
  });

  document.getElementById('create-pwd-btn').addEventListener('click', function () {
    var label = document.getElementById('pwd-label').value.trim();
    var expiresIn = parseInt(document.getElementById('pwd-expires').value, 10);
    fetch(BASE + '/api/passwords', {
      method: 'POST',
      headers: authHeaders(),
      body: JSON.stringify({ label: label, expiresIn: expiresIn })
    })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        if (data.error) { showToast('❌ ' + data.error); return; }
        document.getElementById('created-pwd-value').textContent = data.password;
        document.getElementById('created-pwd-box').style.display = 'block';
        loadPasswordList();
      })
      .catch(function () { showToast('❌ 请求失败'); });
  });

  document.getElementById('copy-created-btn').addEventListener('click', function () {
    copyText(document.getElementById('created-pwd-value').textContent);
  });

  // ---- Helpers ----
  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { showToast('✅ 已复制！'); }).catch(function () { fallbackCopy(text); });
    } else { fallbackCopy(text); }
  }

  function fallbackCopy(text) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); showToast('✅ 已复制！'); } catch (e) { showToast('复制失败，请手动复制'); }
    document.body.removeChild(ta);
  }

  function revokePassword(id) {
    if (!confirm('确定吊销这个密码吗？')) return;
    fetch(BASE + '/api/passwords/' + encodeURIComponent(id), { method: 'DELETE', headers: authHeaders() })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        if (data.error) { showToast('❌ ' + data.error); return; }
        showToast('✅ 已吊销');
        loadPasswordList();
      })
      .catch(function () { showToast('❌ 请求失败'); });
  }

  function escHtml(str) {
    return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
  }
})();
</script>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// Main fetch handler
// ---------------------------------------------------------------------------

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const origin = request.headers.get("Origin");
    const { pathname } = new URL(request.url);

    // Handle CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders(origin),
      });
    }

    // Admin HTML page
    if (pathname === "/admin-panel-x7k9" && request.method === "GET") {
      return new Response(getAdminHTML(), {
        status: 200,
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }

    // Route dispatch
    if (pathname === "/api/data") {
      if (request.method === "PUT") return handlePutData(request, env, origin);
      if (request.method === "GET") return handleGetData(request, env, origin);
    }

    if (pathname === "/api/passwords") {
      if (request.method === "POST") return handleCreatePassword(request, env, origin);
      if (request.method === "GET") return handleListPasswords(request, env, origin);
      if (request.method === "DELETE") return handleCleanup(request, env, origin);
    }

    const revokeMatch = pathname.match(/^\/api\/passwords\/([^/]+)$/);
    if (revokeMatch && request.method === "DELETE") {
      return handleRevokePassword(revokeMatch[1], request, env, origin);
    }

    if (pathname === "/api/verify" && request.method === "POST") {
      return handleVerify(request, env, origin);
    }

    return jsonResponse({ error: "Not found" }, 404, origin);
  },
} satisfies ExportedHandler<Env>;
