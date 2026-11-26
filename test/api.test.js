'use strict';

// Runs against a real core.js process on a loopback port. `node --test` needs
// nothing else: no dependencies, no container, no browser.

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { createHash, randomBytes } = require('node:crypto');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const b64u = (buf) => Buffer.from(buf).toString('base64url');
const sha = (buf) => createHash('sha256').update(buf).digest();

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

async function startCore(env = {}) {
  const port = await freePort();
  // Each server gets its own database file; pass DB_PATH in env to share one
  // between two starts (that is how the restart tests work).
  const dir = env.DB_PATH ? null : fs.mkdtempSync(path.join(os.tmpdir(), 'paste-test-'));
  const dbPath = env.DB_PATH || path.join(dir, 'paste.db');
  const child = spawn(process.execPath, ['src/core.js'], {
    cwd: ROOT,
    env: { ...process.env, PORT: String(port), TTL_HOURS: '24', TRUST_PROXY: '1', DB_PATH: dbPath, ...env },
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
      throw new Error(`core did not start: ${output}`);
    }
    try {
      const r = await fetch(`${base}/health`);
      if (r.ok) break;
    } catch { /* not listening yet */ }
    await new Promise((r) => setTimeout(r, 50));
  }
  return {
    base,
    dbPath,
    async stop() {
      if (child.exitCode === null) {
        await new Promise((resolve) => { child.once('exit', resolve); child.kill(); });
      }
      if (dir) fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    },
    logs() { return output; },
  };
}

function paste(overrides = {}) {
  const proof = randomBytes(32);
  const id = randomBytes(8).toString('hex');
  const body = {
    id,
    ct: 'A'.repeat(120),
    iv: b64u(randomBytes(12)),
    salt: b64u(randomBytes(8)),
    claim: b64u(randomBytes(48)),
    claimIv: b64u(randomBytes(12)),
    claimHash: b64u(sha(proof)),
    iterations: 200000,
    burn: false,
    pinIp: false,
    ...overrides,
  };
  return { id, proof, proofToken: b64u(proof), body };
}

// A distinct X-Forwarded-For per test keeps the app's 60 req/min/IP limiter out
// of the way, and TRUST_PROXY is on so the server believes it.
function client(server, ip) {
  const headers = (extra) => ({ 'Content-Type': 'application/json', 'x-forwarded-for': ip, ...extra });
  return {
    post: (p, body) => fetch(server.base + p, {
      method: 'POST',
      headers: headers(),
      body: typeof body === 'string' ? body : JSON.stringify(body),
    }),
    get: (p) => fetch(server.base + p, { headers: { 'x-forwarded-for': ip } }),
  };
}

const read = (c, id, token) => c.post('/api/paste/' + id, { proof: token });
const status = async (p) => (await p).status;

describe('lifetime and read limit', () => {
  let server;
  before(async () => { server = await startCore(); });
  after(async () => { await server.stop(); });

  test('reads=3 allows three reads, then the paste is gone', async () => {
    const c = client(server, '10.1.0.1');
    const p = paste({ reads: 3, ttl: 3600 });
    assert.equal(await status(c.post('/api/paste', p.body)), 200);

    const meta = await (await c.get('/api/paste/' + p.id)).json();
    assert.equal(meta.reads, 3);
    assert.ok(Math.abs(meta.expires - Date.now() - 3600000) < 5000);

    assert.equal(await status(read(c, p.id, p.proofToken)), 200);
    assert.equal(await status(read(c, p.id, p.proofToken)), 200);
    assert.equal(await status(read(c, p.id, p.proofToken)), 200);
    assert.equal(await status(read(c, p.id, p.proofToken)), 404);
  });

  test('legacy burn flag still means one read', async () => {
    const c = client(server, '10.1.0.2');
    const p = paste({ burn: true });
    assert.equal(await status(c.post('/api/paste', p.body)), 200);
    const meta = await (await c.get('/api/paste/' + p.id)).json();
    assert.equal(meta.reads, 1);
    assert.equal(await status(read(c, p.id, p.proofToken)), 200);
    assert.equal(await status(read(c, p.id, p.proofToken)), 404);
  });

  test('reads=0 has no limit', async () => {
    const c = client(server, '10.1.0.3');
    const p = paste({ reads: 0, ttl: 60 });
    assert.equal(await status(c.post('/api/paste', p.body)), 200);
    for (let i = 0; i < 4; i += 1) {
      assert.equal(await status(read(c, p.id, p.proofToken)), 200);
    }
  });
});

describe('input validation', () => {
  let server;
  before(async () => { server = await startCore(); });
  after(async () => { await server.stop(); });

  const cases = [
    ['missing id', () => { const p = paste(); delete p.body.id; return p.body; }],
    ['id wrong length', () => paste({ id: 'abc' }).body],
    ['ct not base64url', () => paste({ ct: 'A'.repeat(60) + '+/=' }).body],
    ['ct length mod 4 is 1', () => paste({ ct: 'A'.repeat(65) }).body],
    ['ct too short', () => paste({ ct: 'AA' }).body],
    ['claimIv equals iv', () => { const p = paste(); p.body.claimIv = p.body.iv; return p.body; }],
    ['iterations too low', () => paste({ iterations: 99999 }).body],
    ['iterations too high', () => paste({ iterations: 1000001 }).body],
    ['iterations as string', () => paste({ iterations: '200000' }).body],
    ['burn not boolean', () => paste({ burn: 'true' }).body],
    ['pinIp not boolean', () => paste({ pinIp: 1 }).body],
    ['ttl below one minute', () => paste({ ttl: 59 }).body],
    ['ttl above the env ceiling', () => paste({ ttl: 86401 }).body],
    ['ttl not an integer', () => paste({ ttl: '3600' }).body],
    ['reads above the cap', () => paste({ reads: 21 }).body],
    ['reads negative', () => paste({ reads: -1 }).body],
    ['reads fractional', () => paste({ reads: 1.5 }).body],
  ];

  for (const [name, build] of cases) {
    test(name + ' is rejected', async () => {
      const c = client(server, '10.2.0.1');
      assert.equal(await status(c.post('/api/paste', build())), 400);
    });
  }

  test('wrong content type', async () => {
    const c = client(server, '10.2.0.2');
    const p = paste();
    const r = await fetch(server.base + '/api/paste', {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain', 'x-forwarded-for': '10.2.0.2' },
      body: JSON.stringify(p.body),
    });
    assert.equal(r.status, 415);
  });

  test('malformed JSON, arrays and null', async () => {
    const c = client(server, '10.2.0.3');
    for (const body of ['{oops', '[]', 'null', '']) {
      assert.equal(await status(c.post('/api/paste', body)), 400);
    }
  });

  test('unknown fields are ignored', async () => {
    const c = client(server, '10.2.0.4');
    const p = paste({ extra: 'kept out of the store' });
    assert.equal(await status(c.post('/api/paste', p.body)), 200);
  });
});

describe('read proof', () => {
  let server;
  before(async () => { server = await startCore(); });
  after(async () => { await server.stop(); });

  test('a malformed or wrong proof does not consume a read', async () => {
    const c = client(server, '10.3.0.1');
    const p = paste({ reads: 2, ttl: 3600 });
    assert.equal(await status(c.post('/api/paste', p.body)), 200);

    assert.equal(await status(c.post('/api/paste/' + p.id, { proof: 'short' })), 400);
    assert.equal(await status(c.post('/api/paste/' + p.id, { proof: '!'.repeat(43) })), 400);
    assert.equal(await status(c.post('/api/paste/' + p.id, {})), 400);
    assert.equal(await status(c.post('/api/paste/' + p.id, { proof: b64u(randomBytes(32)) })), 404);

    const meta = await (await c.get('/api/paste/' + p.id)).json();
    assert.equal(meta.reads, 2);
    assert.equal(await status(read(c, p.id, p.proofToken)), 200);
  });

  test('an unknown id is a 404, a bad id shape a 400', async () => {
    const c = client(server, '10.3.0.2');
    assert.equal(await status(c.get('/api/paste/' + '0'.repeat(16))), 404);
    assert.equal(await status(c.get('/api/paste/xyz')), 400);
  });
});

describe('request size', () => {
  let server;
  before(async () => { server = await startCore(); });
  after(async () => { await server.stop(); });

  test('exactly 2 MiB is accepted, one byte more is a 413', async () => {
    const c = client(server, '10.4.0.1');
    const target = 2 * 1024 * 1024;

    const build = (total) => {
      const p = paste();
      const withoutPad = JSON.stringify({ ...p.body, pad: '' }).length;
      return { p, body: JSON.stringify({ ...p.body, pad: 'A'.repeat(total - withoutPad) }) };
    };

    const exact = build(target);
    assert.equal(Buffer.byteLength(exact.body), target);
    assert.equal(await status(c.post('/api/paste', exact.body)), 200);

    const over = build(target + 1);
    assert.equal(await status(c.post('/api/paste', over.body)), 413);
  });

  test('a chunked body without Content-Length is counted too', async () => {
    const p = paste();
    const withoutPad = JSON.stringify({ ...p.body, pad: '' }).length;
    const body = JSON.stringify({ ...p.body, pad: 'A'.repeat(2 * 1024 * 1024 + 100 - withoutPad) });
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode(body));
        controller.close();
      },
    });
    const r = await fetch(server.base + '/api/paste', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-forwarded-for': '10.4.0.2' },
      body: stream,
      duplex: 'half',
    });
    assert.equal(r.status, 413);
  });
});

describe('quota and eviction', () => {
  test('one client cannot fill the store, and its usage is returned when pastes go', async () => {
    const server = await startCore();
    try {
      const hog = client(server, '10.5.0.1');
      const ids = [];
      for (let i = 0; i < 32; i += 1) {
        const p = paste({ reads: 1 });
        assert.equal(await status(hog.post('/api/paste', p.body)), 200, `paste ${i}`);
        ids.push(p);
      }
      const oneTooMany = paste();
      assert.equal(await status(hog.post('/api/paste', oneTooMany.body)), 429);

      // A different client is unaffected.
      const other = client(server, '10.5.0.2');
      assert.equal(await status(other.post('/api/paste', paste().body)), 200);

      // Consuming one paste frees its slot.
      assert.equal(await status(read(hog, ids[0].id, ids[0].proofToken)), 200);
      assert.equal(await status(hog.post('/api/paste', oneTooMany.body)), 200);
    } finally {
      await server.stop();
    }
  });

  test('a full store drops the oldest paste instead of refusing writes', async () => {
    const server = await startCore({ MAX_PASTES: '3' });
    try {
      const made = [];
      for (let i = 0; i < 4; i += 1) {
        const c = client(server, `10.6.0.${i + 1}`);
        const p = paste({ reads: 0, ttl: 3600 });
        assert.equal(await status(c.post('/api/paste', p.body)), 200);
        made.push(p);
      }
      const probe = client(server, '10.6.0.9');
      assert.equal(await status(probe.get('/api/paste/' + made[0].id)), 404, 'oldest was evicted');
      for (const p of made.slice(1)) {
        assert.equal(await status(probe.get('/api/paste/' + p.id)), 200);
      }
    } finally {
      await server.stop();
    }
  });
});

describe('pages and assets', () => {
  let server;
  before(async () => { server = await startCore(); });
  after(async () => { await server.stop(); });

  test('the create page is served at /, with the ceiling substituted', async () => {
    const c = client(server, '10.7.0.1');
    const html = await (await c.get('/')).text();
    assert.match(html, /id="sizeState"/);
    assert.ok(!html.includes('__MAX_TTL_S__'));
    assert.ok(!html.includes('__SHORTENER__'));
  });

  test('any query string gets the read page', async () => {
    const c = client(server, '10.7.0.2');
    assert.match(await (await c.get('/?abc')).text(), /Read paste/);
    assert.match(await (await c.get('/?0123456789abcdef')).text(), /Read paste/);
  });

  test('assets live under hashed paths and nothing else is reachable', async () => {
    const c = client(server, '10.7.0.3');
    const html = await (await c.get('/')).text();
    const appMatch = html.match(/<script src="(\/app\.[0-9a-f]{10}\.js)"><\/script>/);
    assert.ok(appMatch, 'hashed create script in the page');
    const appPath = appMatch[1];

    const app = await c.get(appPath);
    assert.equal(app.status, 200);
    assert.match(app.headers.get('content-type'), /javascript/);
    assert.match(app.headers.get('cache-control'), /immutable/);

    const appSource = await app.text();
    assert.ok(!appSource.includes('__MAX_TTL_S__'));
    assert.ok(!appSource.includes('__SHORTENER__'));
    assert.match(appSource, /const MAX_TTL_S = Number\('86400'\)/);
    assert.match(appSource, /el\.src = '\/vendor\/qrcode\.[0-9a-f]{10}\.js'/, 'QR path injected');

    const viewHtml = await (await c.get('/?abc')).text();
    const viewMatch = viewHtml.match(/<script src="(\/view\.[0-9a-f]{10}\.js)"><\/script>/);
    assert.ok(viewMatch, 'hashed read script in the page');
    assert.match(await (await c.get(viewMatch[1])).text(), /KHEPRI-FILE 1/);

    for (const stale of ['/app.js', '/view.js', '/vendor/qrcode.js', '/vendor/LICENSE', '/vendor/%2e%2e/core.js']) {
      assert.equal(await status(c.get(stale)), 404, stale);
    }
    assert.ok(!/<script>\s*'use strict'/.test(html), 'no inline script remains');
  });
});

describe('disk store', () => {
  test('a paste survives a restart', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'paste-restart-'));
    const dbPath = path.join(dir, 'paste.db');
    const first = await startCore({ DB_PATH: dbPath });
    let id;
    let token;
    try {
      const c = client(first, '10.8.0.1');
      const p = paste({ reads: 3, ttl: 3600 });
      assert.equal(await status(c.post('/api/paste', p.body)), 200);
      id = p.id;
      token = p.proofToken;
    } finally {
      await first.stop();
    }

    const second = await startCore({ DB_PATH: dbPath });
    try {
      const c = client(second, '10.8.0.2');
      assert.equal(await status(c.get('/api/paste/' + id)), 200, 'metadata after restart');
      assert.equal(await status(read(c, id, token)), 200, 'read after restart');
      assert.equal(await status(c.get('/api/paste/' + id)), 200, 'reads left after restart');
    } finally {
      await second.stop();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('an expired paste is deleted, not just hidden', async () => {
    const server = await startCore();
    try {
      const c = client(server, '10.8.1.1');
      const p = paste({ reads: 0, ttl: 60 });
      assert.equal(await status(c.post('/api/paste', p.body)), 200);

      const { DatabaseSync } = require('node:sqlite');
      const db = new DatabaseSync(server.dbPath);
      db.prepare('UPDATE pastes SET expires = ? WHERE id = ?').run(Date.now() - 1, p.id);
      assert.equal(db.prepare('SELECT count(*) AS c FROM pastes').get().c, 1);

      assert.equal(await status(c.get('/api/paste/' + p.id)), 404);
      assert.equal(db.prepare('SELECT count(*) AS c FROM pastes').get().c, 0, 'row removed on access');
      db.close();
    } finally {
      await server.stop();
    }
  });

  test('each reason a paste is missing gets its own code', async () => {
    const server = await startCore();
    try {
      const c = client(server, '10.9.1.1');
      const reasonFrom = async (client, id) => {
        const r = await client.get('/api/paste/' + id);
        if (!r.ok) return (await r.json()).error;
        return undefined; // served fine, so there is no reason to report
      };
      const reason = (id) => reasonFrom(c, id);

      // A paste that never existed, and one whose clock has run out.
      assert.equal(await reason('0123456789abcdef'), 'never existed');
      const gone = paste({ reads: 0, ttl: 60 });
      assert.equal(await status(c.post('/api/paste', gone.body)), 200);
      const { DatabaseSync } = require('node:sqlite');
      const db = new DatabaseSync(server.dbPath);
      db.prepare('UPDATE pastes SET expires = ? WHERE id = ?').run(Date.now() - 1, gone.id);
      db.close();
      assert.equal(await reason(gone.id), 'expired');

      // One locked to a first reader's address, asked for from another. The
      // helper already carries the proof token that matches its own claimHash.
      const pinned = paste({ reads: 3, pinIp: true });
      assert.equal(await status(c.post('/api/paste', pinned.body)), 200);
      assert.equal(await status(read(c, pinned.id, pinned.proofToken)), 200, 'first reader binds the address');
      // The binding address still reads it; a different one is told why not.
      const stranger = client(server, '10.9.1.2');
      assert.equal(await status(read(stranger, pinned.id, pinned.proofToken)), 404);
      assert.equal(await reasonFrom(stranger, pinned.id), 'pinned elsewhere');
      assert.equal(await reasonFrom(c, pinned.id), undefined, 'the binding address still gets the metadata');

      // One that exists but is asked for with the wrong key. The metadata GET
      // still succeeds — the paste is there — so the reason only shows up on
      // the read itself, which is where the password was checked.
      const other = paste({ reads: 3 });
      assert.equal(await status(c.post('/api/paste', other.body)), 200);
      const wrongKey = await read(c, other.id, b64u(randomBytes(32)));
      assert.equal(wrongKey.status, 404);
      assert.equal((await wrongKey.json()).error, 'wrong key');
      assert.equal(await reason(other.id), undefined, 'the metadata request still works');

      await new Promise((r) => setTimeout(r, 50));
    } finally {
      await server.stop();
    }
  });

  test('per-client usage is tracked on disk', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'paste-quota-'));
    const dbPath = path.join(dir, 'paste.db');
    const first = await startCore({ DB_PATH: dbPath });
    try {
      const hog = client(first, '10.8.2.1');
      for (let i = 0; i < 32; i += 1) {
        assert.equal(await status(hog.post('/api/paste', paste({ reads: 1 }).body)), 200, 'paste ' + i);
      }
      assert.equal(await status(hog.post('/api/paste', paste().body)), 429);
    } finally {
      await first.stop();
    }

    const second = await startCore({ DB_PATH: dbPath });
    try {
      const hog = client(second, '10.8.2.1');
      assert.equal(await status(hog.post('/api/paste', paste().body)), 429, 'quota survived the restart');
      const other = client(second, '10.8.2.2');
      assert.equal(await status(other.post('/api/paste', paste().body)), 200);
    } finally {
      await second.stop();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('a small disk cap evicts instead of failing', async () => {
    const server = await startCore({ MAX_DISK_MB: '1' });
    try {
      const c = client(server, '10.8.3.1');
      const a = paste({ ct: 'A'.repeat(600000), reads: 0, ttl: 3600 });
      const b = paste({ ct: 'A'.repeat(600000), reads: 0, ttl: 3600 });
      assert.equal(await status(c.post('/api/paste', a.body)), 200);
      assert.equal(await status(c.post('/api/paste', b.body)), 200);
      assert.equal(await status(c.get('/api/paste/' + a.id)), 404, 'oldest evicted');
      assert.equal(await status(c.get('/api/paste/' + b.id)), 200);
    } finally {
      await server.stop();
    }
  });
});
