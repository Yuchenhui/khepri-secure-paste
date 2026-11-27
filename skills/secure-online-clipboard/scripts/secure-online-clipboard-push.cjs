#!/usr/bin/env node
'use strict';
// secure-online-clipboard-push — upload to Secure online clipboard and print the link(s).
//
//   node secure-online-clipboard-push.cjs "content" [options]
//   node secure-online-clipboard-push.cjs --file report.pdf [options]
//
// Encryption happens here, in this process. The server only ever sees ciphertext.
// Zero dependencies: Node 18+.

const fs = require('node:fs');
const crypto = require('node:crypto');

const BASE = process.env.KHEPRI_BASE || 'https://paste.vantolab.com';
const ITERATIONS = 1000000;        // server accepts 100000..1000000
const MAX_REQUEST = 1024 * 1024;   // must match core.js MAX_BODY
const MAX_FILE = 512 * 1024;       // a file is base64'd twice: x1.778

const b64u = (buf) => Buffer.from(buf).toString('base64url');
const arg = (name, fallback) => {
  const i = process.argv.indexOf('--' + name);
  if (i === -1) return fallback;
  const v = process.argv[i + 1];
  return v === undefined || v.startsWith('--') ? fallback : v;
};
const flag = (name) => process.argv.includes('--' + name);

const USAGE = `secure-online-clipboard-push — upload an encrypted paste

  node secure-online-clipboard-push.cjs "content" [options]
  node secure-online-clipboard-push.cjs --file <path> [options]

Options:
  --file <path>     Attach a file instead of text (limit 512 KB)
  --short           Also ask the shortener for a short code
  --len <3-8>       Short code length (default 5)
  --ttl <seconds>   Lifetime, 60 to 604800 (default 21600 = 6 hours)
  --burn            Burn after one read
  --reads <0-20>    Read limit; 0 means unlimited (default: 1 with --burn, else 0)
  --pin-ip          Bind the paste to the first reader's address
  --password <pw>   Add a password — send it over a separate channel
  --base <url>      Deployment to talk to (default $KHEPRI_BASE or paste.vantolab.com)
  --quiet           Print only the link, no JSON
  -h, --help        This text

Environment:
  KHEPRI_BASE       Default deployment
  KHEPRI_IP         Client address to send as X-Forwarded-For, for a direct call
                    to a deployment behind a proxy

Output (JSON unless --quiet):
  {"long": "...", "short": "...", "shortError": "..."}   short only with --short
`;

async function main() {
  if (flag('help') || process.argv.includes('-h')) {
    process.stdout.write(USAGE);
    return;
  }

  const filePath = arg('file', null);
  const text = process.argv.slice(2).find((a, i) =>
    !a.startsWith('--') && process.argv[i - 1] !== '--file' && process.argv[i - 1] !== '--len' &&
    process.argv[i - 1] !== '--ttl' && process.argv[i - 1] !== '--reads' &&
    process.argv[i - 1] !== '--password' && process.argv[i - 1] !== '--base');

  let plaintext;
  if (filePath) {
    const bytes = fs.readFileSync(filePath);
    if (bytes.length > MAX_FILE) {
      throw new Error(`file is ${bytes.length} bytes; the limit is ${MAX_FILE} (${MAX_FILE / 1024} KB)`);
    }
    const meta = b64u(JSON.stringify({
      name: filePath.split(/[\\/]/).pop(), type: '', size: bytes.length,
    }));
    plaintext = 'KHEPRI-FILE 1\n' + meta + '\n' + b64u(bytes);
  } else {
    if (!text) throw new Error('nothing to send: pass text or --file <path>');
    plaintext = text;
  }

  // ---- generate the secrets locally -------------------------------------
  const id = crypto.randomBytes(8).toString('hex');
  const keyBytes = crypto.randomBytes(32);
  const salt = crypto.randomBytes(8);
  const iv = crypto.randomBytes(12);
  const password = arg('password', '') || '';

  const material = Buffer.concat([keyBytes, Buffer.from(password, 'utf8')]);
  const key = await new Promise((res, rej) => crypto.pbkdf2(
    material, salt, ITERATIONS, 32, 'sha256', (e, v) => (e ? rej(e) : res(v))));

  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(id, 'utf8'));            // the paste id is additional data
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final(), cipher.getAuthTag()]);

  // The reader proves itself with this before the server releases the body.
  const proof = crypto.randomBytes(32);
  const claimIv = crypto.randomBytes(12);
  const cc = crypto.createCipheriv('aes-256-gcm', key, claimIv);
  cc.setAAD(Buffer.from('claim:' + id, 'utf8'));
  const claim = Buffer.concat([cc.update(proof), cc.final(), cc.getAuthTag()]);
  const claimHash = crypto.createHash('sha256').update(proof).digest();

  // ---- the parameters the caller asked for -------------------------------
  const ttl = Number(arg('ttl', 21600));
  if (!Number.isInteger(ttl) || ttl < 60 || ttl > 604800) {
    throw new Error('--ttl must be an integer of seconds from 60 to 604800');
  }
  const burn = flag('burn');
  const readsArg = arg('reads', null);
  const readLimit = readsArg === null ? (burn ? 1 : 0) : Number(readsArg);
  if (!Number.isInteger(readLimit) || readLimit < 0 || readLimit > 20) {
    throw new Error('--reads must be an integer from 0 to 20');
  }
  const pinIp = flag('pin-ip');
  const len = Number(arg('len', 5));
  if (!Number.isInteger(len) || len < 3 || len > 8) {
    throw new Error('--len must be an integer from 3 to 8');
  }

  const payload = JSON.stringify({
    id, ct: b64u(ct), iv: b64u(iv), salt: b64u(salt),
    claim: b64u(claim), claimIv: b64u(claimIv), claimHash: b64u(claimHash),
    iterations: ITERATIONS, ttl, reads: readLimit, burn, pinIp,
  });
  if (payload.length > MAX_REQUEST) {
    throw new Error(`request would be ${payload.length} bytes; the limit is ${MAX_REQUEST} (1 MiB)`);
  }

  // ---- send ---------------------------------------------------------------
  const base = arg('base', BASE).replace(/\/+$/, '');
  const headers = { 'Content-Type': 'application/json' };
  if (process.env.KHEPRI_IP) headers['X-Forwarded-For'] = process.env.KHEPRI_IP;

  const r = await fetch(base + '/api/paste', { method: 'POST', headers, body: payload });
  const body = await r.text();
  if (r.status === 413) throw new Error('too large once encrypted (1 MiB)');
  if (!r.ok) throw new Error(`create failed ${r.status}: ${body}`);

  const longUrl = base + '/?' + id + '#' + b64u(keyBytes);
  const out = { long: longUrl };

  if (flag('short')) {
    const s = await fetch(base + '/s/shorten', {
      method: 'POST', headers,
      body: JSON.stringify({ url: longUrl, len }),
    });
    if (s.ok) out.short = (await s.text()).trim();
    else out.shortError = `shorten failed ${s.status}: ${await s.text()}`;
  }

  if (flag('quiet')) {
    process.stdout.write((out.short || out.long) + '\n');
  } else {
    process.stdout.write(JSON.stringify(out, null, 2) + '\n');
  }
}

main().catch((e) => { process.stderr.write('error: ' + e.message + '\n'); process.exit(1); });
