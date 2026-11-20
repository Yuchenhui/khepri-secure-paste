/**
 * khepri-short — shortener.js
 *
 * The second half of the architecture: it maps a short code to the long
 * PrivateBin-style URL and redirects.
 *
 * This service necessarily holds the complete long URL, and the long URL
 * contains the cipher key in its fragment. That is the explicit trade the
 * user accepted: short links at the cost of this service being able to
 * reconstruct keys.
 *
 * What still protects the content:
 *   - the password, if the sender set one, which this service never sees
 *   - burn-after-reading
 *
 * If no password was set, this service can reconstruct the key and decrypt
 * the paste once the ciphertext is fetched. Do not use short links without a
 * password for anything you would not send in plaintext.
 *
 * CORS: the paste core calls this cross-origin from the browser, so the
 * shorten endpoint answers preflight and sends Access-Control-Allow-Origin.
 */

'use strict';

const http = require('node:http');

const PORT = parseInt(process.env.PORT || '8080', 10);
const CODE_LEN = parseInt(process.env.CODE_LEN || '4', 10);
const TTL_HOURS = parseInt(process.env.TTL_HOURS || '24', 10);
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '';

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const MAX_URL = 8192;
const RATE_WINDOW_MS = 60 * 1000;
const RATE_MAX = 120;

const map = new Map();  // code -> {url, expires}
const rate = new Map(); // ip -> {n, resetAt}

function send(res, status, body, headers = {}) {
  res.writeHead(status, { 'Content-Length': Buffer.byteLength(body), 'Cache-Control': 'no-store', ...headers });
  res.end(body);
}

function rateOk(ip) {
  const now = Date.now();
  const r = rate.get(ip);
  if (!r || r.resetAt < now) { rate.set(ip, { n: 1, resetAt: now + RATE_WINDOW_MS }); return true; }
  r.n++;
  return r.n <= RATE_MAX;
}

function genCode(crypto) {
  for (;;) {
    const b = crypto.randomBytes(CODE_LEN);
    let s = '';
    for (let i = 0; i < CODE_LEN; i++) s += ALPHABET[b[i] % ALPHABET.length];
    if (!map.has(s)) return s;
  }
}

const server = http.createServer(async (req, res) => {
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  if (!rateOk(ip)) return send(res, 429, 'rate limited');

  const url = new URL(req.url, 'http://internal');

  // CORS preflight, issued by the paste core's browser-side fetch.
  if (req.method === 'OPTIONS') {
    if (!ALLOWED_ORIGIN) return send(res, 403, 'origin not configured');
    return send(res, 204, '', {
      'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Max-Age': '86400',
    });
  }

  // Shorten: GET /shorten?url=<encoded long url>, returns the short URL as text.
  if (req.method === 'GET' && url.pathname === '/shorten') {
    const longUrl = url.searchParams.get('url');
    if (!longUrl || longUrl.length > MAX_URL) return send(res, 400, 'bad url');
    if (!/^https?:\/\//.test(longUrl)) return send(res, 400, 'bad scheme');

    const code = genCode(require('node:crypto'));
    map.set(code, { url: longUrl, expires: Date.now() + TTL_HOURS * 3600 * 1000 });
    const short = (process.env.PUBLIC_URL || '') + '/' + code;

    const headers = {};
    if (ALLOWED_ORIGIN) {
      headers['Access-Control-Allow-Origin'] = ALLOWED_ORIGIN;
    }
    return send(res, 200, short, headers);
  }

  // Resolve: GET /<code> redirects to the long URL.
  if (req.method === 'GET' && /^\/[A-Za-z0-9]+$/.test(url.pathname)) {
    const code = url.pathname.slice(1);
    const entry = map.get(code);
    if (!entry) return send(res, 404, 'unknown code');
    if (entry.expires < Date.now()) {
      map.delete(code);
      return send(res, 404, 'expired');
    }
    // One-shot: the mapping is consumed on first use, mirroring the core's
    // burn-after-reading. A stale link cannot be replayed later.
    map.delete(code);
    return send(res, 302, '', { Location: entry.url });
  }

  if (req.method === 'GET' && url.pathname === '/health') return send(res, 200, 'ok');

  send(res, 404, 'not found');
});

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of map) if (v.expires < now) map.delete(k);
}, 60 * 1000).unref();

server.listen(PORT, '127.0.0.1', () => {
  console.log(`khepri short listening on 127.0.0.1:${PORT}`);
});
