/**
 * POST /api/logout — clear the auth cookie.
 */

export async function onRequestPost() {
  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'Set-Cookie': 'qz_auth=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Strict',
    },
  });
}

export async function onRequestGet() {
  return new Response(JSON.stringify({ ok: false, error: 'POST only' }), {
    status: 405,
    headers: { 'Content-Type': 'application/json' },
  });
}