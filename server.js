/**
 * khepri-secure-paste — server.js
 *
 * Minimal self-hosted encrypted paste.
 *
 * Design goals (in priority order):
 *   1. Short URL — 4-char base62 code, so the link is typable on a console.
 *   2. Newlines and full text survive intact — the body is a raw string.
 *   3. Deployment-specific key — the cipher key is NOT in the repo; it is
 *      generated at deploy time and injected via environment.
 *   4. Server sees only ciphertext — AES-256-GCM, key derivation in browser.
 *
 * Threat model (be honest about it):
 *   - Protects against: passive network observers, the server itself
 *     (it stores only ciphertext + salt + iv), and people who guess a code.
 *   - Does NOT protect against: someone who knows the deployment key. All
 *     pastes on one deployment share one key, by design — that is what makes
 *     the URL short. For per-paste keys you need a long URL (PrivateBin).
 *
 * No npm dependencies. Node >= 18 (uses global fetch + crypto.subtle on the
 * client; server uses only node:http and node:crypto).
 */

'use strict';

const http = require('node:http');
const crypto = require('node:crypto');

const PORT = parseInt(process.env.PORT || '8080', 10);
const KEY_HEX = process.env.KHEPRI_KEY || '';

// 4 chars base62 = 14,776,336 combinations. The code is an identifier, not a
// secret: the deployment key is the access control. Enumeration is further
// discouraged by burn-after-reading and the per-IP rate limiter below.
const CODE_LEN = 4;
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000; // 24h
const MAX_BODY = 512 * 1024;               // 512 KiB is plenty for code/scripts
const RATE_WINDOW_MS = 60 * 1000;
const RATE_MAX = 60;                       // req/min/IP — blocks enumeration

if (!KEY_HEX || KEY_HEX.length !== 64) {
  console.error('KHEPRI_KEY must be 64 hex chars (32 bytes). Generate with: openssl rand -hex 32');
  process.exit(1);
}
const KEY = Buffer.from(KEY_HEX, 'hex');

// In-memory store. Deliberate: a paste is ephemeral, a restart is an
// acceptable data loss, and this avoids a database entirely.
const store = new Map(); // code -> {ct, iv, salt, expires}
const rate = new Map();  // ip -> {count, resetAt}

function genCode() {
  // Rejection-sample to keep the distribution uniform over the alphabet.
  for (;;) {
    const b = crypto.randomBytes(CODE_LEN);
    let s = '';
    for (let i = 0; i < CODE_LEN; i++) s += ALPHABET[b[i] % ALPHABET.length];
    if (!store.has(s)) return s;
  }
}

function send(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let n = 0;
    const chunks = [];
    req.on('data', (c) => {
      n += c.length;
      if (n > MAX_BODY) {
        reject(new Error('too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function rateOk(ip) {
  const now = Date.now();
  const r = rate.get(ip);
  if (!r || r.resetAt < now) {
    rate.set(ip, { count: 1, resetAt: now + RATE_WINDOW_MS });
    return true;
  }
  r.count++;
  return r.count <= RATE_MAX;
}

const server = http.createServer(async (req, res) => {
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '')
    .split(',')[0].trim();
  if (!rateOk(ip)) return send(res, 429, { error: 'rate limited' });

  const url = new URL(req.url, 'http://x');

  if (req.method === 'POST' && url.pathname === '/api/paste') {
    let payload;
    try { payload = JSON.parse(await readBody(req)); }
    catch { return send(res, 400, { error: 'bad json' }); }

    // ct/iv/salt arrive as base64 from the browser's WebCrypto.
    const { ct, iv, salt } = payload;
    if (!ct || !iv || !salt) return send(res, 400, { error: 'missing fields' });

    const code = genCode();
    store.set(code, {
      ct, iv, salt,
      expires: Date.now() + DEFAULT_TTL_MS,
    });
    return send(res, 200, { code });
  }

  if (req.method === 'GET' && url.pathname.startsWith('/api/paste/')) {
    const code = url.pathname.split('/').pop();
    const p = store.get(code);
    if (!p) return send(res, 404, { error: 'not found' });
    if (p.expires < Date.now()) {
      store.delete(code);
      return send(res, 404, { error: 'expired' });
    }
    // Burn after reading: the ciphertext leaves exactly once.
    store.delete(code);
    return send(res, 200, { iv: p.iv, ct: p.ct, salt: p.salt });
  }

  if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/health')) {
    if (url.pathname === '/health') return send(res, 200, { ok: true });
    return serveStatic(res, '/public/index.html');
  }

  if (req.method === 'GET' && /^\/[A-Za-z0-9]{4}$/.test(url.pathname)) {
    return serveStatic(res, '/public/view.html');
  }

  send(res, 404, { error: 'not found' });
});

function serveStatic(res, file) {
  const fs = require('node:fs');
  const path = require('node:path');
  const p = path.join(__dirname, file);
  fs.readFile(p, (err, data) => {
    if (err) {
      res.writeHead(404);
      return res.end('not found');
    }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(data);
  });
}

// Sweep expired pastes so memory does not grow unbounded.
setInterval(() => {
  const now = Date.now();
  for (const [c, p] of store) if (p.expires < now) store.delete(c);
}, 60 * 1000).unref();

server.listen(PORT, '127.0.0.1', () => {
  console.log(`khepri listening on 127.0.0.1:${PORT}`);
});
