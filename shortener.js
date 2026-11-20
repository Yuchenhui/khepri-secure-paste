'use strict';

const http = require('node:http');
const { randomInt } = require('node:crypto');
const { HTTP_OPTIONS, configuredHttpBase, clientIp, createRateLimit, send, readJson } = require('./http-util');

const PORT = Number(process.env.PORT || 8080);
const DEFAULT_LENGTH = Number(process.env.CODE_LEN || 4);
const TTL_MS = Number(process.env.TTL_HOURS || 24) * 3600000;
const MAX_LINKS = 4096;
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const rateOk = createRateLimit(120);
const links = new Map();

const pasteOrigin = configuredHttpBase(process.env.ALLOWED_ORIGIN);
const publicBase = configuredHttpBase(process.env.PUBLIC_URL, true);

function validLength(length) {
  return Number.isInteger(length) && length >= 3 && length <= 12;
}
if (!Number.isSafeInteger(TTL_MS) || TTL_MS <= 0) throw new Error('TTL_HOURS must be positive');

if (!validLength(DEFAULT_LENGTH)) throw new Error('CODE_LEN must be an integer from 3 to 12');

function pasteTarget(value) {
  if (typeof value !== 'string') return null;
  let target;
  try { target = new URL(value); }
  catch { return null; }
  if (target.origin !== pasteOrigin || target.username || target.password || target.pathname !== '/' ||
      !/^\?[0-9a-f]{16}$/.test(target.search) || !/^#[A-Za-z0-9_-]{43}$/.test(target.hash)) return null;
  return target.href;
}

function newCode(length) {
  for (let attempt = 0; attempt < 16; attempt++) {
    let code = '';
    for (let i = 0; i < length; i++) code += ALPHABET[randomInt(ALPHABET.length)];
    if (!links.has(code)) return code;
  }
  return null;
}

const server = http.createServer(HTTP_OPTIONS, async (req, res) => {
  let url;
  try { url = new URL(req.url, 'http://internal'); }
  catch { return send(res, 400, 'bad URL'); }
  const { pathname } = url;
  if (req.method === 'GET' && pathname === '/health') return send(res, 200, 'ok');

  const ip = clientIp(req);
  if (!ip) return send(res, 400, 'invalid client address');
  if (pathname === '/shorten') {
    res.setHeader('Vary', 'Origin');
    if (req.headers.origin !== pasteOrigin) return send(res, 403, 'origin not allowed');
    res.setHeader('Access-Control-Allow-Origin', pasteOrigin);
    if (!rateOk(ip)) return send(res, 429, 'rate limited');
    if (req.method === 'OPTIONS') {
      res.writeHead(204, {
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Max-Age': '600',
      });
      return res.end();
    }
    if (req.method !== 'POST') return send(res, 405, 'method not allowed', { Allow: 'POST, OPTIONS' });
    if (url.search) return send(res, 400, 'query parameters not allowed');
    const data = await readJson(req, res, 1024);
    if (!data) return;
    const target = pasteTarget(data.url);
    const length = data.len === undefined ? DEFAULT_LENGTH : data.len;
    if (!target) return send(res, 400, 'invalid paste destination');
    if (!validLength(length)) return send(res, 400, 'len must be an integer from 3 to 12');
    if (links.size >= MAX_LINKS) return send(res, 503, 'short link storage full');
    const code = newCode(length);
    if (!code) return send(res, 503, 'could not allocate a short code');
    links.set(code, { target, expires: Date.now() + TTL_MS });
    return send(res, 200, publicBase + '/' + code);
  }

  if (!rateOk(ip)) return send(res, 429, 'rate limited');
  if (req.method === 'GET' && /^\/[A-Za-z0-9]{3,12}$/.test(pathname)) {
    const code = pathname.slice(1);
    const entry = links.get(code);
    if (!entry) return send(res, 404, 'unknown code');
    if (entry.expires <= Date.now()) {
      links.delete(code);
      return send(res, 404, 'unknown code');
    }
    // Following a redirect never consumes a paste or its short link.
    return send(res, 302, '', { Location: entry.target });
  }
  return send(res, 404, 'not found');
});

setInterval(() => {
  const now = Date.now();
  for (const [code, entry] of links) if (entry.expires <= now) links.delete(code);
}, 60000).unref();

server.listen(PORT, '127.0.0.1', () => console.log(`Shortener listening on 127.0.0.1:${PORT}`));
