/**
 * Global middleware for Cloudflare Pages.
 *
 * - Adds standard security headers to every response.
 * - Protects everything under /secret/* except the password-entry page itself.
 */

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

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    if (k) out[k] = decodeURIComponent(v);
  }
  return out;
}

async function isAuthed(request, env) {
  const cookies = parseCookies(request.headers.get('Cookie'));
  const val = cookies['qz_auth'];
  if (!val) return false;

  const dot = val.indexOf('.');
  if (dot < 0) return false;
  const exp = val.slice(0, dot);
  const sig = val.slice(dot + 1);
  if (!/^\d+$/.test(exp)) return false;

  const expNum = Number(exp);
  if (!Number.isFinite(expNum) || expNum < Math.floor(Date.now() / 1000)) {
    return false;
  }

  const secret = env.COOKIE_SECRET || 'dev-only-change-me';
  const expected = await hmacHex(secret, exp);
  if (expected.length !== sig.length) return false;

  // constant-time compare
  let diff = 0;
  for (let i = 0; i < expected.length; i++) {
    diff |= expected.charCodeAt(i) ^ sig.charCodeAt(i);
  }
  return diff === 0;
}

function addSecurityHeaders(headers, url) {
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('X-Frame-Options', 'DENY');
  headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');

  // CSP: strict default-src; allow inline styles + same-origin scripts (site uses small inline JS)
  // Allow images from same-origin and data: URIs (favicon uses inline SVG; portrait uses local)
  headers.set(
    'Content-Security-Policy',
    [
      "default-src 'self'",
      "img-src 'self' data:",
      "style-src 'self' 'unsafe-inline'",
      "script-src 'self' 'unsafe-inline'",
      "font-src 'self' data:",
      "connect-src 'self'",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'",
    ].join('; '),
  );

  // Strict Transport Security — only meaningful over HTTPS, harmless over HTTP
  headers.set(
    'Strict-Transport-Security',
    'max-age=31536000; includeSubDomains',
  );
}

export async function onRequest(context) {
  const url = new URL(context.request.url);

  // ── Auth gate for protected secret pages ──────────────────────────────
  const isProtectedSecret =
    url.pathname.startsWith('/secret/') &&
    !url.pathname.endsWith('/secret/') &&
    !url.pathname.endsWith('/secret/index.html') &&
    !url.pathname.startsWith('/api/');

  if (isProtectedSecret) {
    const ok = await isAuthed(context.request, context.env);
    if (!ok) {
      return Response.redirect(new URL('/secret/', url), 302);
    }
  }

  // ── Pass through to static asset handler ───────────────────────────────
  const response = await context.next();

  // ── Add security headers ───────────────────────────────────────────────
  const headers = new Headers(response.headers);
  addSecurityHeaders(headers, url);
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}