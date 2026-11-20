'use strict';

const http = require('node:http');
const { createHash, timingSafeEqual } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { HTTP_OPTIONS, configuredHttpBase, clientIp, createRateLimit, send, readJson } = require('./http-util');

const PORT = Number(process.env.PORT || 8080);
const TTL_MS = Number(process.env.TTL_HOURS || 24) * 3600000;
const SHORTENER = process.env.SHORTENER_URL ? configuredHttpBase(process.env.SHORTENER_URL, true) : '';
const MAX_BODY = 1024 * 1024;
const MAX_PASTES = 1024;
const MAX_STORED_BYTES = 16 * MAX_BODY;
const PASTE_ID = /^[0-9a-f]{16}$/;
const TOKEN = /^[A-Za-z0-9_-]{43}$/;
const IV = /^[A-Za-z0-9_-]{16}$/;
const SALT = /^[A-Za-z0-9_-]{11}$/;
const CLAIM = /^[A-Za-z0-9_-]{64}$/;
const rateOk = createRateLimit(60);
if (!Number.isSafeInteger(TTL_MS) || TTL_MS <= 0) throw new Error('TTL_HOURS must be positive');
const store = new Map();
let storedBytes = 0;

function forget(id, entry) {
  store.delete(id);
  storedBytes -= entry.size;
}

function encoded(value, pattern) {
  return typeof value === 'string' && pattern.test(value);
}

function serveHtml(res, file) {
  fs.readFile(path.join(__dirname, 'public', file), 'utf8', (err, src) => {
    if (err) return send(res, 404, { error: 'not found' });
    const body = file === 'new.html' ? src.replace('__SHORTENER__', SHORTENER) : src;
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'Referrer-Policy': 'no-referrer',
      'X-Content-Type-Options': 'nosniff',
    });
    res.end(body);
  });
}

const server = http.createServer(HTTP_OPTIONS, async (req, res) => {
  let url;
  try { url = new URL(req.url, 'http://internal'); }
  catch { return send(res, 400, { error: 'bad URL' }); }
  const { pathname } = url;
  if (req.method === 'GET' && pathname === '/health') return send(res, 200, { ok: true });

  const ip = clientIp(req);
  if (!ip) return send(res, 400, { error: 'invalid client address' });
  if (!rateOk(ip)) return send(res, 429, { error: 'rate limited' });

  if (req.method === 'POST' && pathname === '/api/paste') {
    const data = await readJson(req, res, MAX_BODY);
    if (!data) return;
    const { id, ct, iv, salt, iterations, burn, pinIp, claim, claimIv, claimHash } = data;
    if (!encoded(id, PASTE_ID) || !encoded(iv, IV) || !encoded(salt, SALT) ||
        !encoded(claim, CLAIM) || !encoded(claimIv, IV) || claimIv === iv || !encoded(claimHash, TOKEN) ||
        typeof ct !== 'string' || ct.length < 23 || ct.length % 4 === 1 || !/^[A-Za-z0-9_-]+$/.test(ct) ||
        !Number.isInteger(iterations) || iterations < 100000 || iterations > 1000000 ||
        typeof burn !== 'boolean' || typeof pinIp !== 'boolean') {
      return send(res, 400, { error: 'invalid paste fields' });
    }
    if (store.has(id)) return send(res, 409, { error: 'id collision' });
    const size = ct.length + 256;
    if (store.size >= MAX_PASTES || storedBytes + size > MAX_STORED_BYTES) {
      return send(res, 503, { error: 'paste storage full' });
    }
    store.set(id, {
      ct, iv, salt, iterations, burn, pinIp, claim, claimIv,
      claimHash: Buffer.from(claimHash, 'base64url'), size, expires: Date.now() + TTL_MS,
    });
    storedBytes += size;
    return send(res, 200, { id });
  }

  if ((req.method === 'GET' || req.method === 'POST') && pathname.startsWith('/api/paste/')) {
    const id = pathname.slice('/api/paste/'.length);
    if (!PASTE_ID.test(id)) return send(res, 400, { error: 'bad id' });
    // No awaits between retrieving the entry, checking its address, and consuming it.
    const data = req.method === 'POST' ? await readJson(req, res, 256) : null;
    if (req.method === 'POST' && !data) return;
    const entry = store.get(id);
    if (!entry) return send(res, 404, { error: 'not found' });
    if (entry.expires <= Date.now()) {
      forget(id, entry);
      return send(res, 404, { error: 'not found' });
    }
    if (entry.pinnedTo && entry.pinnedTo !== ip) return send(res, 404, { error: 'not found' });
    if (req.method === 'GET') {
      const { salt, iterations, claim, claimIv } = entry;
      return send(res, 200, { salt, iterations, claim, claimIv });
    }
    if (!encoded(data.proof, TOKEN)) return send(res, 400, { error: 'invalid read proof' });
    const hash = createHash('sha256').update(Buffer.from(data.proof, 'base64url')).digest();
    if (!timingSafeEqual(hash, entry.claimHash)) return send(res, 404, { error: 'not found' });
    if (entry.pinIp) entry.pinnedTo = ip;
    if (entry.burn) forget(id, entry);
    return send(res, 200, { ct: entry.ct, iv: entry.iv });
  }

  if (req.method === 'GET' && pathname === '/') {
    return serveHtml(res, PASTE_ID.test(url.search.slice(1)) ? 'view.html' : 'new.html');
  }
  return send(res, 404, { error: 'not found' });
});

setInterval(() => {
  const now = Date.now();
  for (const [id, entry] of store) if (entry.expires <= now) forget(id, entry);
}, 60000).unref();

server.listen(PORT, '127.0.0.1', () => console.log(`Paste core listening on 127.0.0.1:${PORT}`));
