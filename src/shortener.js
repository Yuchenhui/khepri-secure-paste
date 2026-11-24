'use strict';

const http = require('node:http');
const { randomInt } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');
const { HTTP_OPTIONS, configuredHttpBase, clientIp, createRateLimit, send, readJson } = require('./http-util');

const PORT = Number(process.env.PORT || 8080);
const DEFAULT_LENGTH = Number(process.env.CODE_LEN || 5);
const TTL_MS = Number(process.env.TTL_HOURS || 24) * 3600000;
const MAX_LINKS = Number(process.env.MAX_LINKS || 100000);
const MAX_IP_LINKS = Number(process.env.MAX_IP_LINKS || 200);
// Short links hold the paste key, so they live on disk like the pastes do: a
// restart must not turn every shared code into a dead link.
const DB_PATH = process.env.SHORTENER_DB_PATH || path.join(__dirname, 'shortener.db');
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const rateOk = createRateLimit(120);

const pasteOrigin = configuredHttpBase(process.env.ALLOWED_ORIGIN);
const publicBase = configuredHttpBase(process.env.PUBLIC_URL, true);

function validLength(length) {
  return Number.isInteger(length) && length >= 3 && length <= 12;
}
if (!Number.isSafeInteger(TTL_MS) || TTL_MS <= 0) throw new Error('TTL_HOURS must be positive');

if (!validLength(DEFAULT_LENGTH)) throw new Error('CODE_LEN must be an integer from 3 to 12');
if (!Number.isInteger(MAX_LINKS) || MAX_LINKS < 1) throw new Error('MAX_LINKS must be a positive integer');
if (!Number.isInteger(MAX_IP_LINKS) || MAX_IP_LINKS < 1) throw new Error('MAX_IP_LINKS must be a positive integer');

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
let db;
try {
  db = new DatabaseSync(DB_PATH);
} catch (err) {
  throw new Error('Could not open the short-link database at ' + DB_PATH + ': ' + err.message);
}
db.exec('PRAGMA journal_mode = WAL');
db.exec('PRAGMA synchronous = NORMAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS links (
    code TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    owner TEXT NOT NULL,
    expires INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS links_expires ON links(expires);
  CREATE INDEX IF NOT EXISTS links_owner ON links(owner);
`);
try { fs.chmodSync(DB_PATH, 0o600); } catch { /* best effort */ }

const qGet = db.prepare('SELECT target, expires FROM links WHERE code = ?');
const qHas = db.prepare('SELECT 1 AS hit FROM links WHERE code = ?');
const qInsert = db.prepare('INSERT INTO links (code, target, owner, expires) VALUES (?, ?, ?, ?)');
const qCount = db.prepare('SELECT count(*) AS c FROM links');
const qOwnerCount = db.prepare('SELECT count(*) AS c FROM links WHERE owner = ?');
const qDelete = db.prepare('DELETE FROM links WHERE code = ?');
const qDeleteExpired = db.prepare('DELETE FROM links WHERE expires <= ?');

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
    if (!qHas.get(code)) return code;
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
    // One client must not be able to fill the shared store on its own.
    if (qOwnerCount.get(ip).c >= MAX_IP_LINKS) return send(res, 429, 'short link quota exceeded');
    if (qCount.get().c >= MAX_LINKS) return send(res, 503, 'short link storage full');
    const code = newCode(length);
    if (!code) return send(res, 503, 'could not allocate a short code');
    qInsert.run(code, target, ip, Date.now() + TTL_MS);
    return send(res, 200, publicBase + '/' + code);
  }

  if (!rateOk(ip)) return send(res, 429, 'rate limited');
  if (req.method === 'GET' && /^\/[A-Za-z0-9]{3,12}$/.test(pathname)) {
    const code = pathname.slice(1);
    const entry = qGet.get(code);
    if (!entry) return send(res, 404, 'unknown code');
    if (entry.expires <= Date.now()) {
      qDelete.run(code);
      return send(res, 404, 'unknown code');
    }
    // Following a redirect never consumes a paste or its short link.
    return send(res, 302, '', { Location: entry.target });
  }
  return send(res, 404, 'not found');
});

setInterval(() => {
  try { qDeleteExpired.run(Date.now()); }
  catch (err) { console.error('sweep failed:', err.message); }
}, 60000).unref();

server.listen(PORT, '127.0.0.1', () => console.log(`Shortener listening on 127.0.0.1:${server.address().port} (db ${DB_PATH}, ${MAX_LINKS} links, ${MAX_IP_LINKS} per client)`));
