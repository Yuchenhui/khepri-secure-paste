'use strict';

// The two services, together: a short link must stop working at the moment
// its paste stops existing. Runs a real core.js and a real shortener.js on
// loopback ports and lets them talk to each other, the way they do in the
// deployment.

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { createHash, randomBytes } = require('node:crypto');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const ORIGIN = 'https://paste.test';
const b64u = (buf) => Buffer.from(buf).toString('base64url');
const sha = (buf) => createHash('sha256').update(buf).digest();
const INTERNAL_KEY = 'internal-key-for-the-tests';

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

async function waitFor(url, child, what) {
  const deadline = Date.now() + 10000;
  for (;;) {
    if (Date.now() > deadline) {
      child.kill();
      throw new Error(what + ' did not start');
    }
    try {
      if ((await fetch(url)).ok) return;
    } catch { /* not listening yet */ }
    await new Promise((r) => setTimeout(r, 50));
  }
}

// Both services at once, wired together the way the deployment wires them:
// the core is told where the shortener is, and both share one secret.
async function startPair() {
  const corePort = await freePort();
  const shortPort = await freePort();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'khepri-pair-'));

  const shortener = spawn(process.execPath, ['src/shortener.js'], {
    cwd: ROOT,
    env: {
      ...process.env,
      PORT: String(shortPort),
      TTL_HOURS: '24',
      TRUST_PROXY: '1',
      ALLOWED_ORIGIN: ORIGIN,
      PUBLIC_URL: ORIGIN + '/s',
      SHORTENER_DB_PATH: path.join(dir, 'shortener.db'),
      SHORTENER_KEY: randomBytes(32).toString('base64'),
      SHORTENER_INTERNAL_KEY: INTERNAL_KEY,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let shortOut = '';
  shortener.stdout.on('data', (c) => { shortOut += c; });
  shortener.stderr.on('data', (c) => { shortOut += c; });
  await waitFor(`http://127.0.0.1:${shortPort}/health`, shortener, 'shortener');

  const core = spawn(process.execPath, ['src/core.js'], {
    cwd: ROOT,
    env: {
      ...process.env,
      PORT: String(corePort),
      TTL_HOURS: '24',
      TRUST_PROXY: '1',
      DB_PATH: path.join(dir, 'paste.db'),
      SHORTENER_INTERNAL_URL: `http://127.0.0.1:${shortPort}`,
      SHORTENER_INTERNAL_KEY: INTERNAL_KEY,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let coreOut = '';
  core.stdout.on('data', (c) => { coreOut += c; });
  core.stderr.on('data', (c) => { coreOut += c; });
  await waitFor(`http://127.0.0.1:${corePort}/health`, core, 'core');

  return {
    coreBase: `http://127.0.0.1:${corePort}`,
    shortBase: `http://127.0.0.1:${shortPort}`,
    async stop() {
      for (const child of [core, shortener]) {
        if (child.exitCode === null) {
          await new Promise((resolve) => { child.once('exit', resolve); child.kill(); });
        }
      }
      fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    },
    logs() { return coreOut + shortOut; },
  };
}

function paste(overrides = {}) {
  const proof = randomBytes(32);
  const id = randomBytes(8).toString('hex');
  return {
    id,
    proofToken: b64u(proof),
    body: {
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
    },
  };
}

async function createPaste(pair, p, ip = '10.20.0.1') {
  const r = await fetch(pair.coreBase + '/api/paste', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-forwarded-for': ip },
    body: JSON.stringify(p.body),
  });
  assert.equal(r.status, 200);
}

async function shorten(pair, p, ip = '10.20.0.1') {
  const r = await fetch(pair.shortBase + '/shorten', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: ORIGIN, 'x-forwarded-for': ip },
    body: JSON.stringify({ url: `${ORIGIN}/?${p.id}#${b64u(randomBytes(32))}` }),
  });
  assert.equal(r.status, 200);
  const link = (await r.text()).trim();
  return link.slice(link.lastIndexOf('/') + 1);
}

async function resolve(pair, code, ip = '10.20.0.2') {
  const r = await fetch(`${pair.shortBase}/${code}`, {
    redirect: 'manual',
    headers: { 'x-forwarded-for': ip },
  });
  const body = await r.text();
  if (r.status !== 302 && r.status !== 404) {
    throw new Error(`resolve ${code} -> ${r.status}: ${body.slice(0, 200)}`);
  }
  return r.status;
}

async function readPaste(pair, p, ip = '10.20.0.1') {
  const r = await fetch(`${pair.coreBase}/api/paste/${p.id}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-forwarded-for': ip },
    body: JSON.stringify({ proof: p.proofToken }),
  });
  return r.status;
}

// The shortener is told to drop a link over the network, which takes a moment.
async function settle() {
  for (let i = 0; i < 40; i++) {
    await new Promise((r) => setTimeout(r, 50));
  }
}

describe('a short link ends with its paste', () => {
  let pair;
  before(async () => { pair = await startPair(); });
  after(async () => {
    if (process.env.SHOW_LOGS) console.log('--- core+shortener logs ---\n' + pair.logs());
    await pair.stop();
  });

  test('a burned paste takes its short link with it', async () => {
    const p = paste({ burn: true });
    await createPaste(pair, p);
    const code = await shorten(pair, p);

    assert.equal(await resolve(pair, code), 302, 'the link works while the paste lives');

    assert.equal(await readPaste(pair, p), 200, 'the read burns the paste');
    const gone = await fetch(`${pair.coreBase}/api/paste/${p.id}`, { headers: { 'x-forwarded-for': '10.20.0.1' } });
    assert.equal(gone.status, 404, 'the paste is gone from the core');

    await settle();
    assert.equal(await resolve(pair, code), 404, 'the link is gone with the paste');
  });

  test('a paste that runs out of reads takes its link with it on the last read', async () => {
    const p = paste({ reads: 2 });
    await createPaste(pair, p);
    const code = await shorten(pair, p);

    assert.equal(await readPaste(pair, p), 200);
    await settle();
    assert.equal(await resolve(pair, code), 302, 'the link still works with a read left');

    assert.equal(await readPaste(pair, p), 200);
    await settle();
    assert.equal(await resolve(pair, code), 404, 'the link is gone with the last read');
  });

  test('a paste that lives keeps its link', async () => {
    const p = paste({ reads: 0 });
    await createPaste(pair, p);
    const code = await shorten(pair, p);

    assert.equal(await readPaste(pair, p), 200);
    await settle();
    assert.equal(await resolve(pair, code), 302, 'a link to a live paste still works');
  });

  test('one paste does not take another paste’s links with it', async () => {
    const a = paste({ burn: true });
    const b = paste({ reads: 0 });
    await createPaste(pair, a, '10.21.0.1');
    await createPaste(pair, b, '10.21.0.2');
    const codeA = await shorten(pair, a, '10.21.0.1');
    const codeB = await shorten(pair, b, '10.21.0.2');

    assert.equal(await readPaste(pair, a, '10.21.0.1'), 200);
    await settle();

    assert.equal(await resolve(pair, codeA), 404, 'the burned paste’s link is gone');
    assert.equal(await resolve(pair, codeB), 302, 'the other paste’s link is untouched');
  });

  test('the internal endpoint refuses a caller without the secret', async () => {
    const p = paste({ burn: true });
    await createPaste(pair, p);
    const code = await shorten(pair, p);

    const noKey = await fetch(`${pair.shortBase}/internal/paste/${p.id}`, {
      method: 'DELETE',
      headers: { 'x-forwarded-for': '10.22.0.1' },
    });
    assert.equal(noKey.status, 403);

    const wrongKey = await fetch(`${pair.shortBase}/internal/paste/${p.id}`, {
      method: 'DELETE',
      headers: { 'x-internal-key': 'not-the-key', 'x-forwarded-for': '10.22.0.1' },
    });
    assert.equal(wrongKey.status, 403);

    assert.equal(await resolve(pair, code), 302, 'the link survives a refused deletion');
  });
});
