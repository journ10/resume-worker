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
// Route handlers
// ---------------------------------------------------------------------------

/** PUT /api/data — upload / replace resume data (admin only) */
async function handlePutData(
  request: Request,
  env: Env,
  origin: string | null
): Promise<Response> {
  if (!isAuthorized(request, env)) {
    return jsonResponse({ error: "Unauthorized" }, 401, origin);
  }
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
  if (!isAuthorized(request, env)) {
    return jsonResponse({ error: "Unauthorized" }, 401, origin);
  }
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
  if (!isAuthorized(request, env)) {
    return jsonResponse({ error: "Unauthorized" }, 401, origin);
  }
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

  await env.RESUME_KV.put(`pwd_${id}`, JSON.stringify(entry));
  return jsonResponse({ id, password, label, expires: entry.expires }, 201, origin);
}

/** GET /api/passwords — list all passwords (admin only) */
async function handleListPasswords(
  request: Request,
  env: Env,
  origin: string | null
): Promise<Response> {
  if (!isAuthorized(request, env)) {
    return jsonResponse({ error: "Unauthorized" }, 401, origin);
  }
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
  if (!isAuthorized(request, env)) {
    return jsonResponse({ error: "Unauthorized" }, 401, origin);
  }
  const key = `pwd_${id}`;
  const raw = await env.RESUME_KV.get(key);
  if (!raw) {
    return jsonResponse({ error: "Password not found" }, 404, origin);
  }
  const entry: PasswordEntry = JSON.parse(raw);
  entry.active = false;
  await env.RESUME_KV.put(key, JSON.stringify(entry));
  return jsonResponse({ ok: true, id }, 200, origin);
}

/** POST /api/verify — verify password and return resume data (public) */
async function handleVerify(
  request: Request,
  env: Env,
  origin: string | null
): Promise<Response> {
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
  const list = await env.RESUME_KV.list({ prefix: "pwd_" });

  for (const key of list.keys) {
    const raw = await env.RESUME_KV.get(key.name);
    if (!raw) continue;
    const entry: PasswordEntry = JSON.parse(raw);
    if (entry.password === password && entry.active && entry.expires > now) {
      // Valid password — return resume data
      const resumeRaw = await env.RESUME_KV.get("resume_data");
      if (!resumeRaw) {
        return jsonResponse({ error: "Resume data not found" }, 404, origin);
      }
      return jsonResponse(JSON.parse(resumeRaw), 200, origin);
    }
  }

  return jsonResponse({ error: "密码无效或已过期" }, 403, origin);
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

    // Route dispatch
    if (pathname === "/api/data") {
      if (request.method === "PUT") return handlePutData(request, env, origin);
      if (request.method === "GET") return handleGetData(request, env, origin);
    }

    if (pathname === "/api/passwords") {
      if (request.method === "POST") return handleCreatePassword(request, env, origin);
      if (request.method === "GET") return handleListPasswords(request, env, origin);
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
