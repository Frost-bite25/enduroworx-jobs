// EnduroWorx media Worker
//  POST /upload?job=<jobId>&ext=<jpg|mp4|mov|...>   (staff only: Firebase ID token in Authorization: Bearer ...)
//        body = the file. Returns {key, url}.
//  GET  /m/<key>   serves the file to anyone with the link (keys are long and random). Supports Range for video.
const JWKS_URL = 'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com';
const TYPES = {jpg:'image/jpeg', jpeg:'image/jpeg', png:'image/png', webp:'image/webp', heic:'image/heic',
               mp4:'video/mp4', mov:'video/quicktime', m4v:'video/x-m4v', webm:'video/webm'};
let jwksCache = null;

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const cors = corsHeaders(req, env);
    if (req.method === 'OPTIONS') return new Response(null, {status: 204, headers: cors});
    try {
      if (req.method === 'POST' && url.pathname === '/upload') return await upload(req, env, url, cors);
      if ((req.method === 'GET' || req.method === 'HEAD') && url.pathname.startsWith('/m/')) return await serve(req, env, url);
      if (url.pathname === '/') return new Response('EnduroWorx media', {headers: cors});
      return json({error: 'Not found'}, 404, cors);
    } catch (e) {
      return json({error: e.message || 'Error'}, e.status || 500, cors);
    }
  }
};

function corsHeaders(req, env) {
  const origin = req.headers.get('Origin') || '';
  const ok = (env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
  const h = {'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 'Access-Control-Allow-Headers': 'Authorization, Content-Type',
             'Access-Control-Max-Age': '86400', 'Vary': 'Origin'};
  if (ok.includes(origin) || /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) h['Access-Control-Allow-Origin'] = origin;
  return h;
}
const json = (o, status, headers) => new Response(JSON.stringify(o), {status, headers: {...headers, 'Content-Type': 'application/json'}});
const fail = (msg, status) => Object.assign(new Error(msg), {status});

async function upload(req, env, url, cors) {
  const who = await verifyStaff(req, env);
  const job = url.searchParams.get('job') || '';
  const ext = (url.searchParams.get('ext') || '').toLowerCase();
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(job)) throw fail('Bad job id', 400);
  if (!TYPES[ext]) throw fail('That file type is not allowed', 415);
  const max = Number(env.MAX_MB || 95) * 1024 * 1024;
  const len = Number(req.headers.get('Content-Length') || 0);
  if (len > max) throw fail(`File too big (max ${env.MAX_MB || 95} MB)`, 413);
  const key = `jobs/${job}/${Date.now().toString(36)}-${rand(16)}.${ext}`;
  const obj = await env.MEDIA.put(key, req.body, {
    httpMetadata: {contentType: TYPES[ext], cacheControl: 'public, max-age=31536000, immutable'},
    customMetadata: {by: who, job}
  });
  if (obj.size > max) { await env.MEDIA.delete(key); throw fail('File too big', 413); }
  return json({key, url: `${url.origin}/m/${key}`, size: obj.size}, 200, cors);
}

async function serve(req, env, url) {
  const key = decodeURIComponent(url.pathname.slice(3));
  if (!/^jobs\/[A-Za-z0-9_-]+\/[a-z0-9]+-[a-z0-9]+\.[a-z0-9]+$/.test(key)) return new Response('Not found', {status: 404});
  const range = req.headers.get('Range');
  const obj = await env.MEDIA.get(key, range ? {range: req.headers} : {});
  if (!obj) return new Response('Not found', {status: 404});
  const h = new Headers();
  obj.writeHttpMetadata(h);
  h.set('ETag', obj.httpEtag);
  h.set('Accept-Ranges', 'bytes');
  h.set('Access-Control-Allow-Origin', '*');
  if (range && obj.range) {
    const start = obj.range.offset ?? 0, end = start + (obj.range.length ?? obj.size - start) - 1;
    h.set('Content-Range', `bytes ${start}-${end}/${obj.size}`);
    h.set('Content-Length', String(end - start + 1));
    return new Response(req.method === 'HEAD' ? null : obj.body, {status: 206, headers: h});
  }
  h.set('Content-Length', String(obj.size));
  return new Response(req.method === 'HEAD' ? null : obj.body, {headers: h});
}

function rand(n) {
  const a = crypto.getRandomValues(new Uint8Array(n));
  return [...a].map(b => (b % 36).toString(36)).join('');
}

// ---- Firebase ID token check (same rules as firestore.rules isStaff) ----
async function verifyStaff(req, env) {
  const tok = (req.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
  if (!tok) throw fail('Sign in first', 401);
  const [h64, p64, s64] = tok.split('.');
  if (!s64) throw fail('Bad sign-in token', 401);
  const head = JSON.parse(b64text(h64)), p = JSON.parse(b64text(p64));
  const pid = env.FIREBASE_PROJECT_ID, now = Date.now() / 1000;
  if (head.alg !== 'RS256') throw fail('Bad sign-in token', 401);
  if (p.aud !== pid || p.iss !== `https://securetoken.google.com/${pid}`) throw fail('Bad sign-in token', 401);
  if (!(p.exp > now - 60) || !(p.iat < now + 300)) throw fail('Sign-in expired, refresh the page', 401);
  const key = await publicKey(head.kid, env);
  const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, b64bytes(s64), new TextEncoder().encode(`${h64}.${p64}`));
  if (!ok) throw fail('Bad sign-in token', 401);
  const staff = (env.STAFF || '').split(',').map(s => s.trim());
  const email = p.email_verified === true ? String(p.email || '').toLowerCase() : '';
  const phone = p.phone_number || '';
  if (!(email && staff.includes(email)) && !(phone && staff.includes(phone))) throw fail('Only staff can add photos', 403);
  return email || phone;
}
async function publicKey(kid, env) {
  if (!jwksCache || jwksCache.until < Date.now() || !jwksCache.keys[kid]) {
    const r = env.JWKS_OVERRIDE ? {ok: true, json: async () => JSON.parse(env.JWKS_OVERRIDE)} : await fetch(JWKS_URL);
    if (!r.ok) throw fail('Could not check sign-in', 503);
    const {keys} = await r.json(), out = {};
    for (const k of keys) out[k.kid] = await crypto.subtle.importKey('jwk', k, {name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256'}, false, ['verify']);
    jwksCache = {keys: out, until: Date.now() + 3600e3};
  }
  const k = jwksCache.keys[kid];
  if (!k) throw fail('Bad sign-in token', 401);
  return k;
}
function b64bytes(s) { s = s.replace(/-/g, '+').replace(/_/g, '/'); const b = atob(s + '='.repeat((4 - s.length % 4) % 4)); return Uint8Array.from(b, c => c.charCodeAt(0)); }
function b64text(s) { return new TextDecoder().decode(b64bytes(s)); }
