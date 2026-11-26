'use strict';

const http = require('node:http');
const { randomInt, randomBytes, createCipheriv, createDecipheriv, timingSafeEqual } = require('node:crypto');
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
// The core tells the shortener when a paste is gone. That call must not be
// something anyone on the internet can make: the secret is shared by the two
// services and never leaves the host.
const INTERNAL_KEY = process.env.SHORTENER_INTERNAL_KEY || '';
const PASTE_ID = /^[0-9a-f]{16}$/;

// Same treatment as the core: a browser that lands here gets a page, an API
// client gets the plain reason.
const ERROR_PAGES = {
  400: ['That made no sense', 'The request was malformed.'],
  403: ['Not allowed', 'This service only answers to its own paste site.'],
  404: ['Nothing here', 'This short code does not point to a paste.'],
  405: ['Wrong method', 'This address expects a different request.'],
  429: ['Too many requests', 'Give it a minute and try again.'],
  500: ['Something broke', 'Nothing was saved.'],
  503: ['No room left', 'No room for new short links. Try again later.'],
};

const ERROR_PAGE_CSS = `
  :root { color-scheme: light; --canvas:#f2f3f0; --paper:#fff; --ink:#182435; --muted:#546477; --line:#d8dfe5; --accent:#214fb8; --accent-hover:#183e97; }
  *, *::before, *::after { box-sizing: border-box; }
  body { margin:0; min-height:100svh; display:grid; place-items:center; padding:24px; background:var(--canvas); color:var(--ink); font:1rem/1.55 system-ui,-apple-system,"Segoe UI",sans-serif; }
  main { width:min(100%,30rem); padding:30px 32px 32px; border:1px solid var(--line); border-radius:16px; background:var(--paper); box-shadow:0 12px 32px -24px #18243566; }
  p.code { margin:0 0 8px; color:var(--muted); font:650 .75rem/1 ui-monospace,Menlo,Consolas,monospace; letter-spacing:.1em; text-transform:uppercase; }
  h1 { margin:0 0 10px; font-size:1.75rem; font-weight:650; letter-spacing:-.03em; line-height:1.15; }
  p.msg { margin:0 0 24px; color:var(--muted); }
  a.button { display:inline-flex; align-items:center; justify-content:center; min-height:44px; padding:8px 16px; border:1px solid transparent; border-radius:8px; background:var(--accent); color:var(--paper); font-size:.875rem; font-weight:650; text-decoration:none; }
  a.button:hover { background:var(--accent-hover); }
  a:focus-visible { outline:2px solid var(--accent); outline-offset:3px; }
`;

function errorPage(status) {
  const [title, body] = ERROR_PAGES[status] || ERROR_PAGES[500];
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title} — Khepri</title>
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<style>${ERROR_PAGE_CSS}</style>
</head>
<body>
<main>
  <p class="code">${status}</p>
  <h1>${title}</h1>
  <p class="msg">${body}</p>
  <a class="button" href="${pasteOrigin.href}">Create a paste</a>
</main>
</body>
</html>`;
}

function fail(req, res, status, message) {
  const accept = req.headers.accept;
  if (typeof accept === 'string' && accept.includes('text/html')) {
    return send(res, status, errorPage(status), { 'Content-Type': 'text/html; charset=utf-8' });
  }
  return send(res, status, message);
}

function validLength(length) {
  return Number.isInteger(length) && length >= 3 && length <= 8;
}
// The mapping holds the key of every live paste, so the file is encrypted with
// a key that never lands on disk: reading the database is not enough.
function parseKey(value) {
  if (typeof value !== 'string') return null;
  const raw = value.trim();
  if (!raw) return null;
  let buf;
  if (/^[0-9a-f]{64}$/i.test(raw)) buf = Buffer.from(raw, 'hex');
  else buf = Buffer.from(raw, 'base64');
  return buf.length === 32 ? buf : null;
}
const KEY = parseKey(process.env.SHORTENER_KEY);
if (!KEY) throw new Error('SHORTENER_KEY must be 32 bytes as base64 or 64 hex characters');

function sealTarget(target) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', KEY, iv);
  const body = Buffer.concat([cipher.update(target, 'utf8'), cipher.final()]);
  return { target: body.toString('base64'), iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64') };
}

function openTarget(row) {
  try {
    const decipher = createDecipheriv('aes-256-gcm', KEY, Buffer.from(row.iv, 'base64'));
    decipher.setAuthTag(Buffer.from(row.tag, 'base64'));
    return Buffer.concat([decipher.update(Buffer.from(row.target, 'base64')), decipher.final()]).toString('utf8');
  } catch {
    return null;
  }
}

if (!Number.isSafeInteger(TTL_MS) || TTL_MS <= 0) throw new Error('TTL_HOURS must be positive');

if (!validLength(DEFAULT_LENGTH)) throw new Error('CODE_LEN must be an integer from 3 to 8');
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
    expires INTEGER NOT NULL,
    iv TEXT NOT NULL DEFAULT '',
    tag TEXT NOT NULL DEFAULT '',
    paste_id TEXT NOT NULL DEFAULT ''
  );
  CREATE INDEX IF NOT EXISTS links_expires ON links(expires);
  CREATE INDEX IF NOT EXISTS links_owner ON links(owner);
`);
const columns = db.prepare('PRAGMA table_info(links)').all().map((c) => c.name);
if (!columns.includes('iv')) db.exec("ALTER TABLE links ADD COLUMN iv TEXT NOT NULL DEFAULT ''");
if (!columns.includes('tag')) db.exec("ALTER TABLE links ADD COLUMN tag TEXT NOT NULL DEFAULT ''");
// The paste id is not a secret: it is in the target URL, and the key that
// matters stays encrypted in the sealed target. Keeping it in its own column
// is what lets a link be dropped when its paste is gone.
if (!columns.includes('paste_id')) db.exec("ALTER TABLE links ADD COLUMN paste_id TEXT NOT NULL DEFAULT ''");
// The index comes after the column: on a database created before it existed,
// the column has to be added first.
db.exec('CREATE INDEX IF NOT EXISTS links_paste ON links(paste_id)');
// Rows written before the database was encrypted cannot be read back, so they
// are dropped rather than left to fail every lookup. Deleting a row does not
// erase its bytes: the file is rebuilt and the write-ahead log truncated, or
// the old plaintext would stay readable on disk.
const legacy = db.prepare("SELECT count(*) AS c FROM links WHERE iv = ''").get().c;
if (legacy > 0) {
  db.prepare("DELETE FROM links WHERE iv = ''").run();
  db.exec('VACUUM');
  console.log(`Dropped ${legacy} short link(s) stored before the database was encrypted`);
}
// The write-ahead log keeps the pages of rows that are already gone, so it is
// truncated at startup: a deleted link leaves nothing readable behind.
db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
try { fs.chmodSync(DB_PATH, 0o600); } catch { /* best effort */ }

const qGet = db.prepare('SELECT target, iv, tag, expires FROM links WHERE code = ?');
const qHas = db.prepare('SELECT 1 AS hit FROM links WHERE code = ?');
const qInsert = db.prepare('INSERT INTO links (code, target, owner, expires, iv, tag, paste_id) VALUES (?, ?, ?, ?, ?, ?, ?)');
const qCount = db.prepare('SELECT count(*) AS c FROM links WHERE expires > ?');
const qOwnerCount = db.prepare('SELECT count(*) AS c FROM links WHERE owner = ? AND expires > ?');
const qDelete = db.prepare('DELETE FROM links WHERE code = ?');
const qDeleteByPaste = db.prepare('DELETE FROM links WHERE paste_id = ?');
const qDeleteExpired = db.prepare('DELETE FROM links WHERE expires <= ?');

// The paste id and the key are both in the URL: the id says which paste this
// link points at, the key says how to open it. The id travels in its own
// column, in the clear, so the link can be dropped when that paste is gone.
function pasteTarget(value) {
  if (typeof value !== 'string') return null;
  let target;
  try { target = new URL(value); }
  catch { return null; }
  if (target.origin !== pasteOrigin || target.username || target.password || target.pathname !== '/' ||
      !/^\?[0-9a-f]{16}$/.test(target.search) || !/^#[A-Za-z0-9_-]{43}$/.test(target.hash)) return null;
  return { href: target.href, pasteId: target.search.slice(1) };
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
  catch { return fail(req, res, 400, 'bad URL'); }
  const { pathname } = url;
  if (req.method === 'GET' && pathname === '/health') return send(res, 200, 'ok');

  // The core drops a link when its paste is gone. The shared secret is the
  // gate: it exists only on this host, and nginx refuses this path from the
  // outside, so a request that arrives here with the right key is the core.
  // It sits before the address check: this call comes from the core over the
  // loopback and carries no client address of its own.
  if (pathname.startsWith('/internal/paste/')) {
    if (!INTERNAL_KEY) return fail(req, res, 404, 'not found');
    const key = req.headers['x-internal-key'];
    // timingSafeEqual throws on a length mismatch, so the lengths are compared
    // first: a caller that guesses a shorter key must not crash the service.
    if (typeof key !== 'string' || key.length !== INTERNAL_KEY.length ||
        !timingSafeEqual(Buffer.from(key), Buffer.from(INTERNAL_KEY))) {
      return fail(req, res, 403, 'forbidden');
    }
    // Belt and braces: even with the key, only this host may ask.
    if (req.socket.remoteAddress !== '127.0.0.1' && req.socket.remoteAddress !== '::1' && req.socket.remoteAddress !== '::ffff:127.0.0.1') {
      return fail(req, res, 403, 'forbidden');
    }
    if (req.method !== 'DELETE') return fail(req, res, 405, 'method not allowed');
    const pasteId = pathname.slice('/internal/paste/'.length);
    if (!PASTE_ID.test(pasteId)) return fail(req, res, 400, 'bad id');
    const removed = qDeleteByPaste.run(pasteId).changes;
    return send(res, 200, { removed });
  }

  const ip = clientIp(req);
  if (!ip) return fail(req, res, 400, 'invalid client address');
  // The read page probes a code before sending the reader there, so the
  // redirect route answers to the paste origin too. Only that origin may ask.
  if (pathname !== '/shorten') {
    res.setHeader('Vary', 'Origin');
    if (req.headers.origin === pasteOrigin) res.setHeader('Access-Control-Allow-Origin', pasteOrigin);
  }
  if (pathname === '/shorten') {
    res.setHeader('Vary', 'Origin');
    // A browser on the paste origin may ask, and so may a caller that sends no
    // Origin at all: a CLI agent has no origin to declare, and refusing it would
    // leave programmatic callers with no way to get a short code. A wrong Origin
    // is still refused, so another site cannot drive this endpoint from a
    // browser. Everything below is unchanged: the target must point at the paste
    // origin, and the rate limit and the per-client quota are per IP either way.
    const origin = req.headers.origin;
    if (origin !== undefined && origin !== pasteOrigin) return fail(req, res, 403, 'origin not allowed');
    if (origin === pasteOrigin) res.setHeader('Access-Control-Allow-Origin', pasteOrigin);
    if (!rateOk(ip)) return fail(req, res, 429, 'rate limited');
    if (req.method === 'OPTIONS') {
      res.writeHead(204, {
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Max-Age': '600',
      });
      return res.end();
    }
    if (req.method !== 'POST') return fail(req, res, 405, 'method not allowed');
    if (url.search) return fail(req, res, 400, 'query parameters not allowed');
    const data = await readJson(req, res, 1024);
    if (!data) return;
    const target = pasteTarget(data.url);
    const length = data.len === undefined ? DEFAULT_LENGTH : data.len;
    if (!target) return fail(req, res, 400, 'invalid paste destination');
    if (!validLength(length)) return fail(req, res, 400, 'len must be an integer from 3 to 8');
    // One client must not be able to fill the shared store on its own. The
    // quota counts the codes this client holds right now, not every code it
    // ever made: expired links free their slot.
    if (qOwnerCount.get(ip, Date.now()).c >= MAX_IP_LINKS) return fail(req, res, 429, 'short link quota exceeded');
    if (qCount.get(Date.now()).c >= MAX_LINKS) return fail(req, res, 503, 'short link storage full');
    const code = newCode(length);
    if (!code) return fail(req, res, 503, 'could not allocate a short code');
    const sealed = sealTarget(target.href);
    qInsert.run(code, sealed.target, ip, Date.now() + TTL_MS, sealed.iv, sealed.tag, target.pasteId);
    return send(res, 200, publicBase + '/' + code);
  }

  if (!rateOk(ip)) return fail(req, res, 429, 'rate limited');
  if (req.method === 'GET' && /^\/[A-Za-z0-9]{3,8}$/.test(pathname)) {
    const code = pathname.slice(1);
    const entry = qGet.get(code);
    if (!entry) return fail(req, res, 404, 'unknown code');
    if (entry.expires <= Date.now()) {
      qDelete.run(code);
      return fail(req, res, 404, 'unknown code');
    }
    const target = openTarget(entry);
    if (!target) {
      console.error('short link ' + code + ' could not be decrypted');
      return fail(req, res, 404, 'unknown code');
    }
    // The code travels on, so the reader can tell which short link brought
    // them here. It goes in the fragment, after the key, because the fragment
    // never reaches the server: the paste URL stays as secret as it was.
    // The key is base64url, which has no dot in it, so the split is clean.
    const landing = target.replace(/#([^#]*)$/, '#$1.' + code);
    // Following a redirect never consumes a paste or its short link.
    return send(res, 302, '', { Location: landing });
  }
  return fail(req, res, 404, 'not found');
});

setInterval(() => {
  try { qDeleteExpired.run(Date.now()); }
  catch (err) { console.error('sweep failed:', err.message); }
}, 60000).unref();

// Loopback by default; a container that publishes a port needs HOST=0.0.0.0.
const HOST = process.env.HOST || '127.0.0.1';
server.listen(PORT, HOST, () => console.log(`Shortener listening on ${HOST}:${server.address().port} (db ${DB_PATH}, ${MAX_LINKS} links, ${MAX_IP_LINKS} per client)`));
