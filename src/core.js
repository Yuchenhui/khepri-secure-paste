'use strict';

const http = require('node:http');
const { createHash, timingSafeEqual } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');
const { HTTP_OPTIONS, configuredHttpBase, clientIp, createRateLimit, send, readJson } = require('./http-util');

const PORT = Number(process.env.PORT || 8080);
const TTL_MS = Number(process.env.TTL_HOURS || 24) * 3600000;
const SHORTENER = process.env.SHORTENER_URL ? configuredHttpBase(process.env.SHORTENER_URL, true) : '';
const MAX_BODY = 1024 * 1024;
// 1024 was the in-memory era's guard on a Map. On disk the byte cap governs, so
// the row cap only matters for very small pastes and is set well above them.
const MAX_PASTES = Number(process.env.MAX_PASTES || 200000);
if (!Number.isInteger(MAX_PASTES) || MAX_PASTES < 1) throw new Error('MAX_PASTES must be a positive integer');
// Per client, so a single source cannot fill the store: two full-size pastes
// worth of ciphertext, or 32 small ones, whichever runs out first.
const MAX_IP_BYTES = 2 * MAX_BODY;
const MAX_IP_PASTES = 32;
// The env value is the ceiling: a client may ask for a shorter life, never a
// longer one. TTL_HOURS also bounds the choices the create form renders.
const MAX_TTL_S = Math.floor(TTL_MS / 1000);
const MAX_READS = 20;
// Ciphertext lives on disk, keyed by the same paste id; the SQLite page cache
// is the only memory tier, so capacity no longer costs resident memory.
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'paste.db');
const MAX_DISK_MB = Number(process.env.MAX_DISK_MB || 5120);
if (!Number.isInteger(MAX_DISK_MB) || MAX_DISK_MB < 1) throw new Error('MAX_DISK_MB must be a positive integer');
// Sources live in src/, the pages in public/ one level up; PUBLIC_DIR keeps
// the same layout inside the image (src/ and public/ under /app).
const PUBLIC_DIR = process.env.PUBLIC_DIR || path.join(__dirname, '..', 'public');
const PASTE_ID = /^[0-9a-f]{16}$/;
const TOKEN = /^[A-Za-z0-9_-]{43}$/;
const IV = /^[A-Za-z0-9_-]{16}$/;
const SALT = /^[A-Za-z0-9_-]{11}$/;
const CLAIM = /^[A-Za-z0-9_-]{64}$/;
const rateOk = createRateLimit(60);
if (!Number.isSafeInteger(TTL_MS) || TTL_MS <= 0) throw new Error('TTL_HOURS must be positive');
const stats = { creates: 0, reads: 0, rejected: 0, evicted: 0, expired: 0 };

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new DatabaseSync(DB_PATH);
db.exec('PRAGMA journal_mode = WAL');
db.exec('PRAGMA synchronous = NORMAL');
db.exec('PRAGMA auto_vacuum = INCREMENTAL');
db.exec('PRAGMA cache_size = -32768');
db.exec('PRAGMA journal_size_limit = 67108864');
db.exec(`
  CREATE TABLE IF NOT EXISTS pastes (
    id TEXT PRIMARY KEY,
    ct TEXT NOT NULL,
    iv TEXT NOT NULL,
    salt TEXT NOT NULL,
    iterations INTEGER NOT NULL,
    claim TEXT NOT NULL,
    claimIv TEXT NOT NULL,
    claimHash BLOB NOT NULL,
    pinIp INTEGER NOT NULL,
    pinnedTo TEXT,
    reads INTEGER NOT NULL,
    owner TEXT NOT NULL,
    size INTEGER NOT NULL,
    created INTEGER NOT NULL,
    expires INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS pastes_created ON pastes(created);
  CREATE INDEX IF NOT EXISTS pastes_expires ON pastes(expires);
  CREATE TABLE IF NOT EXISTS owners (
    owner TEXT PRIMARY KEY,
    bytes INTEGER NOT NULL,
    count INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS store (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    bytes INTEGER NOT NULL,
    rows INTEGER NOT NULL
  );
  INSERT OR IGNORE INTO store (id, bytes, rows) VALUES (1, 0, 0);
`);

// Hard ceiling on the file. SQLite refuses the write once the page count would
// pass it, which turns "disk full" into a 507 for one client, not a broken db.
{
  const pageSize = db.prepare('PRAGMA page_size').get().page_size;
  const maxPages = Math.max(16, Math.floor((MAX_DISK_MB * 1024 * 1024) / pageSize));
  db.exec(`PRAGMA max_page_count = ${maxPages}`);
}

const qGet = db.prepare('SELECT * FROM pastes WHERE id = ?');
const qHas = db.prepare('SELECT 1 AS hit FROM pastes WHERE id = ?');
const qInsert = db.prepare(`
  INSERT INTO pastes (id, ct, iv, salt, iterations, claim, claimIv, claimHash, pinIp, pinnedTo, reads, owner, size, created, expires)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?)
`);
const qDelete = db.prepare('DELETE FROM pastes WHERE id = ?');
const qSetReads = db.prepare('UPDATE pastes SET reads = ? WHERE id = ?');
const qSetPinned = db.prepare('UPDATE pastes SET pinnedTo = ? WHERE id = ?');
const qOwner = db.prepare('SELECT bytes, count FROM owners WHERE owner = ?');
const qOwnerAdd = db.prepare(`
  INSERT INTO owners (owner, bytes, count) VALUES (?, ?, 1)
  ON CONFLICT(owner) DO UPDATE SET bytes = bytes + excluded.bytes, count = count + 1
`);
const qOwnerSubtract = db.prepare('UPDATE owners SET bytes = bytes - ?, count = count - 1 WHERE owner = ?');
const qOwnerPrune = db.prepare('DELETE FROM owners WHERE owner = ? AND count <= 0');
// Totals live in one row: summing the table would read every ciphertext page on
// each create and make writes slower as the store grows.
const qTotals = db.prepare('SELECT bytes, rows FROM store WHERE id = 1');
const qAddTotals = db.prepare('UPDATE store SET bytes = bytes + ?, rows = rows + 1 WHERE id = 1');
const qSubTotals = db.prepare('UPDATE store SET bytes = bytes - ?, rows = rows - 1 WHERE id = 1');
const qOldest = db.prepare('SELECT id FROM pastes ORDER BY created LIMIT ?');
const qExpired = db.prepare('SELECT id FROM pastes WHERE expires <= ?');

// One cheap reconcile at boot so a database written by an older build (or a
// half-finished manual edit) cannot leave the cached totals wrong forever.
{
  const cached = qTotals.get().rows;
  const actual = db.prepare('SELECT count(*) AS c FROM pastes').get().c;
  if (cached !== actual) {
    db.exec('UPDATE store SET rows = (SELECT count(*) FROM pastes), bytes = (SELECT coalesce(sum(size), 0) FROM pastes) WHERE id = 1');
  }
}

function encoded(value, pattern) {
  return typeof value === 'string' && pattern.test(value);
}

function usageOf(owner) {
  const row = qOwner.get(owner);
  return row ? { bytes: row.bytes, count: row.count } : { bytes: 0, count: 0 };
}

// One delete path for reads, expiry and eviction: the row and the per-owner
// accounting always move together.
function dropPaste(id) {
  const row = qGet.get(id);
  if (!row) return false;
  qDelete.run(id);
  qSubTotals.run(row.size);
  qOwnerSubtract.run(row.size, row.owner);
  qOwnerPrune.run(row.owner);
  return true;
}

function evictOldest(limit) {
  let evicted = 0;
  for (const row of qOldest.all(limit)) if (dropPaste(row.id)) evicted += 1;
  return evicted;
}

function isDiskFull(err) {
  return typeof err?.message === 'string' && /database or disk is full/i.test(err.message);
}

// Page scripts are served from a hashed path under an immutable cache, so a
// repeat visit downloads only the no-store HTML. The hash is taken over the
// rendered bytes, which is also how a deployment invalidates the old copy.
function hashedName(file, body) {
  const digest = createHash('sha256').update(body).digest('hex').slice(0, 10);
  return file.replace(/\.js$/, '') + '.' + digest + '.js';
}

const ASSETS = new Map();
const SCRIPT_PATHS = {};

function loadScript(file, { render, cache }) {
  const source = fs.readFileSync(path.join(PUBLIC_DIR, file), 'utf8');
  const body = render ? render(source) : source;
  const assetPath = '/' + hashedName(file, body);
  ASSETS.set(assetPath, { body, cache });
  return assetPath;
}

function renderAppScript(src) {
  return src
    .replaceAll('__SHORTENER__', SHORTENER)
    .replaceAll('__MAX_TTL_S__', String(MAX_TTL_S))
    .replaceAll('__QR_PATH__', qrPath);
}

const QR_PATH = loadScript('vendor/qrcode.js', { cache: 'public, max-age=31536000, immutable' });
const qrPath = QR_PATH;
SCRIPT_PATHS['app.js'] = loadScript('app.js', { render: renderAppScript, cache: 'public, max-age=31536000, immutable' });
SCRIPT_PATHS['view.js'] = loadScript('view.js', {
  render: (src) => src.replace("'__READER_SHORTENER__'", () => JSON.stringify(SHORTENER)),
  cache: 'public, max-age=31536000, immutable',
});
ASSETS.set('/favicon.svg', {
  body: fs.readFileSync(path.join(PUBLIC_DIR, 'favicon.svg')),
  contentType: 'image/svg+xml',
  cache: 'public, max-age=3600',
});

// A browser that mistypes an address should land on a page that looks like
// the rest of the service, not on a line of JSON.
const ERROR_PAGES = {
  400: ['That made no sense', 'The request was malformed. Check the address and try again.'],
  404: ['Nothing here', 'This address does not point to a paste. It may have expired, already have been read, or never have existed.'],
  429: ['Too many requests', 'This address has been asking for too much. Give it a minute and try again.'],
  500: ['Something broke', 'The service hit an error it did not expect. Nothing was saved.'],
  503: ['No room left', 'The store is full at the moment. Try again a little later.'],
  507: ['No room left', 'The store is full at the moment. Try again a little later.'],
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
  <a class="button" href="/">Create a paste</a>
</main>
</body>
</html>`;
}

// Browsers get the page, API clients get JSON. A fetch() sends Accept: */*,
// so the browser pages are the only ones that turn into HTML.
function fail(req, res, status, message) {
  const accept = req.headers.accept;
  if (typeof accept === 'string' && accept.includes('text/html')) {
    return send(res, status, errorPage(status), { 'Content-Type': 'text/html; charset=utf-8' });
  }
  return send(res, status, { error: message });
}

function serveHtml(req, res, file) {
  fs.readFile(path.join(PUBLIC_DIR, file), 'utf8', (err, source) => {
    if (err) return fail(req, res, 404, 'not found');
    const body = source
      .replace('src="/app.js"', 'src="' + SCRIPT_PATHS['app.js'] + '"')
      .replace('src="/view.js"', 'src="' + SCRIPT_PATHS['view.js'] + '"');
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'Referrer-Policy': 'no-referrer',
      'X-Content-Type-Options': 'nosniff',
    });
    res.end(body);
  });
}

// Only the URLs registered in ASSETS can reach public files.
function serveAsset(res, asset) {
  res.writeHead(200, {
    'Content-Type': asset.contentType ?? 'application/javascript; charset=utf-8',
    'Content-Length': Buffer.byteLength(asset.body),
    'Cache-Control': asset.cache,
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(asset.body);
}

const server = http.createServer(HTTP_OPTIONS, async (req, res) => {
  let url;
  try { url = new URL(req.url, 'http://internal'); }
  catch { return fail(req, res, 400, 'bad URL'); }
  const { pathname } = url;
  if (req.method === 'GET' && pathname === '/health') return send(res, 200, { ok: true });

  const ip = clientIp(req);
  if (!ip) return fail(req, res, 400, 'invalid client address');
  if (!rateOk(ip)) return fail(req, res, 429, 'rate limited');

  if (req.method === 'GET' && ASSETS.has(pathname)) return serveAsset(res, ASSETS.get(pathname));

  if (req.method === 'POST' && pathname === '/api/paste') {
    const data = await readJson(req, res, MAX_BODY);
    if (!data) return;
    const { id, ct, iv, salt, iterations, burn, pinIp, claim, claimIv, claimHash, ttl, reads } = data;
    if (!encoded(id, PASTE_ID) || !encoded(iv, IV) || !encoded(salt, SALT) ||
        !encoded(claim, CLAIM) || !encoded(claimIv, IV) || claimIv === iv || !encoded(claimHash, TOKEN) ||
        typeof ct !== 'string' || ct.length < 23 || ct.length % 4 === 1 || !/^[A-Za-z0-9_-]+$/.test(ct) ||
        !Number.isInteger(iterations) || iterations < 100000 || iterations > 1000000 ||
        typeof burn !== 'boolean' || typeof pinIp !== 'boolean') {
      return fail(req, res, 400, 'invalid paste fields');
    }
    // Absent ttl/reads keeps the old behaviour: full env lifetime, and burn
    // meaning a single read.
    const ttlSeconds = ttl === undefined ? MAX_TTL_S : ttl;
    const readLimit = reads === undefined ? (burn ? 1 : 0) : reads;
    if (!Number.isInteger(ttlSeconds) || ttlSeconds < 60 || ttlSeconds > MAX_TTL_S) {
      return fail(req, res, 400, 'invalid expiry');
    }
    if (!Number.isInteger(readLimit) || readLimit < 0 || readLimit > MAX_READS) {
      return fail(req, res, 400, 'invalid read limit');
    }
    if (qHas.get(id)) return send(res, 409, { error: 'id collision' });

    const size = ct.length + 256;
    const usage = usageOf(ip);
    if (usage.count >= MAX_IP_PASTES || usage.bytes + size > MAX_IP_BYTES) {
      stats.rejected += 1;
      return fail(req, res, 429, 'paste quota exceeded');
    }

    // A full store drops the oldest pastes instead of refusing every write, so
    // one client's traffic cannot make the service read-only for everyone.
    let evicted = 0;
    for (;;) {
      const { rows: count, bytes } = qTotals.get();
      if (count < MAX_PASTES && bytes + size <= MAX_DISK_MB * 1024 * 1024) break;
      const removed = evictOldest(Math.max(1, Math.ceil(count / 8)));
      evicted += removed;
      if (!removed) break;
    }
    stats.evicted += evicted;

    const now = Date.now();
    try {
      db.exec('BEGIN IMMEDIATE');
      qInsert.run(id, ct, iv, salt, iterations, claim, claimIv, Buffer.from(claimHash, 'base64url'),
        pinIp ? 1 : 0, readLimit, ip, size, now, now + ttlSeconds * 1000);
      qOwnerAdd.run(ip, size);
      qAddTotals.run(size);
      db.exec('COMMIT');
    } catch (err) {
      try { db.exec('ROLLBACK'); } catch { /* already rolled back */ }
      if (isDiskFull(err)) {
        stats.rejected += 1;
        return fail(req, res, 507, 'paste storage full');
      }
      console.error('create failed:', err.message);
      return fail(req, res, 500, 'storage error');
    }
    stats.creates += 1;
    return send(res, 200, { id });
  }

  if ((req.method === 'GET' || req.method === 'POST') && pathname.startsWith('/api/paste/')) {
    const id = pathname.slice('/api/paste/'.length);
    if (!PASTE_ID.test(id)) return fail(req, res, 400, 'bad id');
    const data = req.method === 'POST' ? await readJson(req, res, 256) : null;
    if (req.method === 'POST' && !data) return;
    const now = Date.now();

    if (req.method === 'GET') {
      const row = qGet.get(id);
      if (!row) return fail(req, res, 404, 'not found');
      if (row.expires <= now) {
        dropPaste(id);
        return fail(req, res, 404, 'not found');
      }
      if (row.pinnedTo && row.pinnedTo !== ip) return fail(req, res, 404, 'not found');
      return send(res, 200, {
        salt: row.salt, iterations: row.iterations, claim: row.claim,
        claimIv: row.claimIv, reads: row.reads, expires: row.expires,
      });
    }

    if (!encoded(data.proof, TOKEN)) return send(res, 400, { error: 'invalid read proof' });
    const hash = createHash('sha256').update(Buffer.from(data.proof, 'base64url')).digest();

    // One transaction covers the lookup, the address check, the proof check and
    // the consume: a crash mid-way leaves the paste intact for a retry.
    let status = 404;
    let body = { error: 'not found' };
    db.exec('BEGIN IMMEDIATE');
    try {
      const row = qGet.get(id);
      if (row && row.expires <= now) {
        dropPaste(id);
      } else if (row && !(row.pinnedTo && row.pinnedTo !== ip) && timingSafeEqual(hash, Buffer.from(row.claimHash))) {
        if (row.pinIp) qSetPinned.run(ip, id);
        if (row.reads > 0) {
          if (row.reads === 1) dropPaste(id);
          else qSetReads.run(row.reads - 1, id);
        }
        status = 200;
        body = { ct: row.ct, iv: row.iv };
      }
      db.exec('COMMIT');
    } catch (err) {
      try { db.exec('ROLLBACK'); } catch { /* already rolled back */ }
      console.error('read failed:', err.message);
      return fail(req, res, 500, 'storage error');
    }
    if (status === 200) stats.reads += 1;
    return send(res, status, body);
  }

  if (req.method === 'GET' && pathname === '/') {
    // Any query string means someone followed a link: show the read page, which
    // reports a malformed ID itself, instead of silently offering a new paste.
    return serveHtml(req, res, url.search.length > 1 ? 'view.html' : 'new.html');
  }
  return fail(req, res, 404, 'not found');
});

function dbFootprint() {
  const sizeOf = (file) => { try { return fs.statSync(file).size; } catch { return 0; } };
  return sizeOf(DB_PATH) + sizeOf(DB_PATH + '-wal');
}

// One line per minute to the container log, and only when something happened:
// counters plus store gauges, never an address or a paste id.
setInterval(() => {
  const now = Date.now();
  let expired = 0;
  try {
    for (const row of qExpired.all(now)) if (dropPaste(row.id)) expired += 1;
    stats.expired += expired;
    if (expired) {
      // Bounded on purpose: an unbounded vacuum would walk every free page and
      // stall the single-threaded event loop. 256 pages is 1 MiB per minute.
      db.exec('PRAGMA incremental_vacuum(256)');
      db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
    }
  } catch (err) {
    console.error('sweep failed:', err.message);
  }
  if (stats.creates + stats.reads + stats.rejected + stats.evicted + stats.expired === 0) return;
  console.log(JSON.stringify({
    at: new Date(now).toISOString(),
    creates: stats.creates, reads: stats.reads, rejected: stats.rejected,
    evicted: stats.evicted, expired: stats.expired,
    pastes: qTotals.get().rows, bytes: qTotals.get().bytes, dbBytes: dbFootprint(),
  }));
  stats.creates = 0;
  stats.reads = 0;
  stats.rejected = 0;
  stats.evicted = 0;
  stats.expired = 0;
}, 60000).unref();

// Loopback by default; a container that publishes a port needs HOST=0.0.0.0.
const HOST = process.env.HOST || '127.0.0.1';
server.listen(PORT, HOST, () => {
  console.log(`Paste core listening on ${HOST}:${server.address().port} (db ${DB_PATH}, cap ${MAX_DISK_MB} MiB)`);
});
