'use strict';

// Covers the shortener's contract: who may create a link, what it will point
// at, the code length, and that resolving never consumes anything.

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { randomBytes } = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const ROOT = path.join(__dirname, '..');
const ORIGIN = 'https://paste.test';
const PUBLIC_BASE = 'https://paste.test/s';

function freePort() {
  return new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const { port } = probe.address();
      probe.close(() => resolve(port));
    });
  });
}

async function startShortener(env = {}) {
  const port = await freePort();
  // Each server gets its own database file; pass SHORTENER_DB_PATH in env to
  // share one between two starts (that is how the restart test works).
  const dir = env.SHORTENER_DB_PATH ? null : fs.mkdtempSync(path.join(os.tmpdir(), 'shortener-test-'));
  const dbPath = env.SHORTENER_DB_PATH || path.join(dir, 'shortener.db');
  const child = spawn(process.execPath, ['src/shortener.js'], {
    cwd: ROOT,
    env: {
      ...process.env,
      PORT: String(port),
      TTL_HOURS: '24',
      TRUST_PROXY: '1',
      ALLOWED_ORIGIN: ORIGIN,
      PUBLIC_URL: PUBLIC_BASE,
      SHORTENER_DB_PATH: dbPath,
      SHORTENER_KEY: randomBytes(32).toString('base64'),
      ...env,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let output = '';
  child.stdout.on('data', (chunk) => { output += chunk; });
  child.stderr.on('data', (chunk) => { output += chunk; });

  const base = `http://127.0.0.1:${port}`;
  const deadline = Date.now() + 10000;
  for (;;) {
    if (Date.now() > deadline) {
      child.kill();
      throw new Error(`shortener did not start: ${output}`);
    }
    try {
      if ((await fetch(`${base}/health`)).ok) break;
    } catch { /* not listening yet */ }
    await new Promise((r) => setTimeout(r, 50));
  }
  return {
    base,
    async stop() {
      if (child.exitCode === null) {
        await new Promise((resolve) => { child.once('exit', resolve); child.kill(); });
      }
      if (dir) fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    },
    logs() { return output; },
  };
}

const pasteUrl = () =>
  `${ORIGIN}/?${randomBytes(8).toString('hex')}#${randomBytes(32).toString('base64url')}`;

function shorten(server, body, headers = {}) {
  return fetch(server.base + '/shorten', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Origin: ORIGIN,
      'x-forwarded-for': '10.9.0.1',
      ...headers,
    },
    body: JSON.stringify(body),
  });
}

describe('shortener', () => {
  let server;
  before(async () => { server = await startShortener(); });
  after(() => server.stop());

  test('a paste URL becomes a five-character link by default', async () => {
    const target = pasteUrl();
    const r = await shorten(server, { url: target });
    assert.equal(r.status, 200);
    const link = (await r.text()).trim();
    assert.match(link, /^https:\/\/paste\.test\/s\/[A-Za-z0-9]{5}$/);

    const code = link.slice(link.lastIndexOf('/') + 1);
    const redirect = await fetch(`${server.base}/${code}`, { redirect: 'manual', headers: { 'x-forwarded-for': '10.9.0.2' } });
    assert.equal(redirect.status, 302);
    assert.equal(redirect.headers.get('location'), target);
  });

  test('the requested length is honoured across the whole range', async () => {
    for (const len of [3, 4, 6, 8]) {
      const r = await shorten(server, { url: pasteUrl(), len });
      assert.equal(r.status, 200);
      const link = (await r.text()).trim();
      assert.equal(link.slice(link.lastIndexOf('/') + 1).length, len);
    }
    assert.equal((await shorten(server, { url: pasteUrl(), len: 2 })).status, 400);
    assert.equal((await shorten(server, { url: pasteUrl(), len: 9 })).status, 400);
    assert.equal((await shorten(server, { url: pasteUrl(), len: '5' })).status, 400);
  });

  test('only this instance’s own paste URLs are accepted', async () => {
    const cases = [
      'https://evil.test/?' + 'a'.repeat(16) + '#' + 'A'.repeat(43),
      `${ORIGIN}/somewhere/?${'a'.repeat(16)}#${'A'.repeat(43)}`,
      `${ORIGIN}/?${'a'.repeat(15)}#${'A'.repeat(43)}`,
      `${ORIGIN}/?${'a'.repeat(16)}#short`,
      'javascript:alert(1)',
      'not a url',
      undefined,
    ];
    for (const url of cases) {
      assert.equal((await shorten(server, { url })).status, 400, String(url));
    }
  });

  test('the Origin header must match, and CORS preflight is answered', async () => {
    const wrong = await shorten(server, { url: pasteUrl() }, { Origin: 'https://evil.test' });
    assert.equal(wrong.status, 403);

    // A caller with no Origin at all is a CLI agent, not a browser: it has no
    // origin to declare and is let through. The wrong Origin above is still
    // refused, so another site cannot drive this endpoint from a browser.
    const headerless = await shorten(server, { url: pasteUrl() }, { 'x-forwarded-for': '10.9.0.7' });
    assert.equal(headerless.status, 200);

    const preflight = await fetch(server.base + '/shorten', {
      method: 'OPTIONS',
      headers: { Origin: ORIGIN, 'x-forwarded-for': '10.9.0.3' },
    });
    assert.equal(preflight.status, 204);
    assert.equal(preflight.headers.get('access-control-allow-origin'), ORIGIN);
  });

  test('unknown codes are 404 and resolving is repeatable', async () => {
    const link = (await (await shorten(server, { url: pasteUrl() })).text()).trim();
    const code = link.slice(link.lastIndexOf('/') + 1);
    for (let i = 0; i < 3; i += 1) {
      const r = await fetch(`${server.base}/${code}`, { redirect: 'manual', headers: { 'x-forwarded-for': '10.9.0.4' } });
      assert.equal(r.status, 302);
    }
    assert.equal((await fetch(`${server.base}/zzzzz`, { redirect: 'manual', headers: { 'x-forwarded-for': '10.9.0.4' } })).status, 404);
  });

  test('CODE_LEN moves the default', async () => {
    const other = await startShortener({ CODE_LEN: '7' });
    try {
      const link = (await (await shorten(other, { url: pasteUrl() })).text()).trim();
      assert.equal(link.slice(link.lastIndexOf('/') + 1).length, 7);
    } finally {
      await other.stop();
    }
  });

  test('a short link survives a restart', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shortener-restart-'));
    const dbPath = path.join(dir, 'shortener.db');
    const key = randomBytes(32).toString('base64');
    const first = await startShortener({ SHORTENER_DB_PATH: dbPath, SHORTENER_KEY: key });
    let link;
    try {
      const r = await shorten(first, { url: pasteUrl() });
      assert.equal(r.status, 200);
      link = (await r.text()).trim();
    } finally {
      await first.stop();
    }

    const second = await startShortener({ SHORTENER_DB_PATH: dbPath, SHORTENER_KEY: key });
    try {
      const code = new URL(link).pathname.split('/').pop();
      const redirect = await fetch(`${second.base}/${code}`, { redirect: 'manual', headers: { 'x-forwarded-for': '10.31.0.1' } });
      assert.equal(redirect.status, 302);
      assert.match(redirect.headers.get('location'), /^https:\/\/paste\.test\/\?[0-9a-f]{16}#/);
    } finally {
      await second.stop();
      fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });

  test('one client cannot fill the link store', async () => {
    const capped = await startShortener({ MAX_IP_LINKS: '2' });
    try {
      const headers = { Origin: ORIGIN, 'x-forwarded-for': '10.30.0.1' };
      assert.equal((await shorten(capped, { url: pasteUrl() }, headers)).status, 200);
      assert.equal((await shorten(capped, { url: pasteUrl() }, headers)).status, 200);
      const blocked = await shorten(capped, { url: pasteUrl() }, headers);
      assert.equal(blocked.status, 429);
      assert.equal(await blocked.text(), 'short link quota exceeded');
      const other = await shorten(capped, { url: pasteUrl() }, { Origin: ORIGIN, 'x-forwarded-for': '10.30.0.2' });
      assert.equal(other.status, 200);
    } finally {
      await capped.stop();
    }
  });

  test('the quota counts live links, not expired ones', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shortener-quota-'));
    const dbPath = path.join(dir, 'shortener.db');
    const capped = await startShortener({ SHORTENER_DB_PATH: dbPath, MAX_IP_LINKS: '1' });
    try {
      // A row that already expired still sits in the table until the sweep
      // runs; it must not take up the client's quota.
      const db = new DatabaseSync(dbPath);
      db.exec('PRAGMA busy_timeout = 2000');
      db.prepare('INSERT INTO links (code, target, owner, expires, iv, tag) VALUES (?, ?, ?, ?, ?, ?)')
        .run('OLDONE', 'ciphertext', '10.31.0.1', Date.now() - 60000, 'iv', 'tag');
      db.close();

      const headers = { Origin: ORIGIN, 'x-forwarded-for': '10.31.0.1' };
      assert.equal((await shorten(capped, { url: pasteUrl() }, headers)).status, 200);
      assert.equal((await shorten(capped, { url: pasteUrl() }, headers)).status, 429);
    } finally {
      await capped.stop();
      fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });

  test('the stored mapping is encrypted on disk', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shortener-crypt-'));
    const dbPath = path.join(dir, 'shortener.db');
    const server = await startShortener({ SHORTENER_DB_PATH: dbPath });
    try {
      const target = pasteUrl();
      const r = await shorten(server, { url: target });
      assert.equal(r.status, 200);
      const link = (await r.text()).trim();
      const code = link.slice(link.lastIndexOf('/') + 1);
      const raw = fs.readFileSync(dbPath).toString('latin1')
        + (fs.existsSync(dbPath + '-wal') ? fs.readFileSync(dbPath + '-wal').toString('latin1') : '');
      // The code is the lookup key and stays readable; the target it points at
      // must not be.
      assert.equal(raw.includes(target), false, 'the paste URL must not be readable on disk');
      assert.equal(raw.includes(code), true, 'the code is the lookup key');

      const redirect = await fetch(`${server.base}/${code}`, { redirect: 'manual', headers: { 'x-forwarded-for': '10.32.0.1' } });
      assert.equal(redirect.status, 302);
      assert.equal(redirect.headers.get('location'), target);
    } finally {
      await server.stop();
      fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });

  test('a link made under one key cannot be read under another', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shortener-key-'));
    const dbPath = path.join(dir, 'shortener.db');
    const keyA = randomBytes(32).toString('base64');
    const first = await startShortener({ SHORTENER_DB_PATH: dbPath, SHORTENER_KEY: keyA });
    let code;
    try {
      const r = await shorten(first, { url: pasteUrl() });
      assert.equal(r.status, 200);
      code = (await r.text()).trim().slice(-5);
    } finally {
      await first.stop();
    }

    const second = await startShortener({ SHORTENER_DB_PATH: dbPath, SHORTENER_KEY: randomBytes(32).toString('base64') });
    try {
      const redirect = await fetch(`${second.base}/${code}`, { redirect: 'manual', headers: { 'x-forwarded-for': '10.33.0.1' } });
      assert.equal(redirect.status, 404);
    } finally {
      await second.stop();
      fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });

  test('plaintext rows from before encryption are dropped and scrubbed', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shortener-legacy-'));
    const dbPath = path.join(dir, 'shortener.db');
    const target = pasteUrl();
    const old = new DatabaseSync(dbPath);
    old.exec(`CREATE TABLE links (code TEXT PRIMARY KEY, target TEXT NOT NULL, owner TEXT NOT NULL, expires INTEGER NOT NULL);`);
    old.prepare('INSERT INTO links (code, target, owner, expires) VALUES (?, ?, ?, ?)')
      .run('OLD', target, '10.34.0.1', Date.now() + 3600000);
    old.close();

    const server = await startShortener({ SHORTENER_DB_PATH: dbPath });
    try {
      const redirect = await fetch(`${server.base}/OLD`, { redirect: 'manual', headers: { 'x-forwarded-for': '10.34.0.1' } });
      assert.equal(redirect.status, 404);
      const raw = fs.readFileSync(dbPath).toString('latin1')
        + (fs.existsSync(dbPath + '-wal') ? fs.readFileSync(dbPath + '-wal').toString('latin1') : '');
      assert.equal(raw.includes(target), false, 'the dropped plaintext must not survive on disk');
    } finally {
      await server.stop();
      fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });
});
