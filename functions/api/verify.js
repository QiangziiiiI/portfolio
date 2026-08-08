/**
 * POST /api/verify  — verify password, set HMAC-signed cookie on success.
 *
 * Required env vars:
 *   PASSWORD_HASH  — sha-256 hex of the access password
 *   COOKIE_SECRET  — random ≥32-char string used for cookie HMAC
 *
 * If either is unset, the endpoint returns 503 so it is obvious in deploy logs.
 */

const COOKIE_MAX_AGE = 60 * 60; // 1 hour

async function sha256Hex(text) {
  const buf = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(text),
  );
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

async function hmacHex(secret, data) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const sig = await crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(data),
  );
  return Array.from(new Uint8Array(sig))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function json(body, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      ...extraHeaders,
    },
  });
}

// Naive in-memory rate limit. Resets when the Worker isolates recycle.
// Good enough to slow down scripts; not a substitute for Cloudflare WAF rules.
const buckets = new Map();
function rateLimited(ip) {
  const now = Date.now();
  const win = 60_000;
  const max = 10; // 10 attempts / minute / IP
  const arr = (buckets.get(ip) || []).filter(t => now - t < win);
  arr.push(now);
  buckets.set(ip, arr);
  return arr.length > max;
}

export async function onRequestPost(context) {
  const env = context.env || {};
  const ip =
    context.request.headers.get('CF-Connecting-IP') ||
    context.request.headers.get('X-Forwarded-For') ||
    'unknown';

  if (rateLimited(ip)) {
    return json({ ok: false, error: '请求过快，稍后再试' }, 429);
  }

  let body;
  try {
    body = await context.request.json();
  } catch {
    return json({ ok: false, error: '请求格式错误' }, 400);
  }

  const password = String(body.password || '');
  if (!password || password.length > 256) {
    return json({ ok: false, error: '请输入密码' }, 400);
  }

  if (!env.PASSWORD_HASH || !env.COOKIE_SECRET) {
    return json(
      {
        ok: false,
        error: '服务未完成配置（缺少 PASSWORD_HASH 或 COOKIE_SECRET）',
      },
      503,
    );
  }

  const inputHash = await sha256Hex(password);
  const stored = env.PASSWORD_HASH.toLowerCase();
  const got = inputHash.toLowerCase();

  // Constant-time compare
  let diff = stored.length ^ got.length;
  for (let i = 0; i < Math.max(stored.length, got.length); i++) {
    diff |= (stored.charCodeAt(i) || 0) ^ (got.charCodeAt(i) || 0);
  }

  if (diff !== 0) {
    return json({ ok: false, error: '密码错误' }, 401);
  }

  const exp = Math.floor(Date.now() / 1000) + COOKIE_MAX_AGE;
  const sig = await hmacHex(env.COOKIE_SECRET, String(exp));
  const cookieVal = `${exp}.${sig}`;

  return json(
    { ok: true },
    200,
    {
      'Set-Cookie': `qz_auth=${cookieVal}; Max-Age=${COOKIE_MAX_AGE}; Path=/; HttpOnly; Secure; SameSite=Strict`,
    },
  );
}

export async function onRequestGet() {
  return json({ ok: false, error: 'POST only' }, 405);
}