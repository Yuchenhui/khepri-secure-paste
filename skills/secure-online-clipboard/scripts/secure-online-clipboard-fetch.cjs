#!/usr/bin/env node
'use strict';
// secure-online-clipboard-fetch — read a paste back from Secure online clipboard.
//
//   node secure-online-clipboard-fetch.cjs "<long link>" [--out file.bin] [--password pw]
//   node secure-online-clipboard-fetch.cjs r7lld3                          # a short code works too
//
// The link alone is enough: the read proof is recoverable from the claim with
// the key, which is exactly what the browser does. Zero dependencies: Node 18+.

const fs = require('node:fs');
const crypto = require('node:crypto');

const BASE = process.env.KHEPRI_BASE || 'https://paste.vantolab.com';
const SHORT_PREFIX = process.env.KHEPRI_SHORT_PREFIX || '/s/';
const FILE_MARKER = 'KHEPRI-FILE 1';

const b64u = (buf) => Buffer.from(buf).toString('base64url');
const arg = (name, fallback) => {
  const i = process.argv.indexOf('--' + name);
  if (i === -1) return fallback;
  const v = process.argv[i + 1];
  return v === undefined || v.startsWith('--') ? fallback : v;
};
function b64uToBytes(s) {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(b64 + '='.repeat((4 - (b64.length % 4)) % 4), 'base64');
}

const USAGE = `secure-online-clipboard-fetch — read an encrypted paste back

  node secure-online-clipboard-fetch.cjs "<long link>" [--out file.bin] [--password pw]
  node secure-online-clipboard-fetch.cjs r7lld3

Arguments:
  <link|code>       A long link (?id#key), or a bare short code

Options:
  --out <path>      Write the file here; without it a file paste prints its
                    metadata as JSON. Text pastes always print.
  --password <pw>   The password the paste was created with, if any
  --base <url>      Deployment to talk to (default $KHEPRI_BASE)
  -h, --help        This text

Environment:
  KHEPRI_BASE       Default deployment
  KHEPRI_IP         Client address to send as X-Forwarded-For
`;

// A short link adds its code after the key in the fragment, so that the reader
// can see which code brought them here. The key is base64url and has no dot in
// it, so the two parts are told apart by the first dot.
function keyOf(fragment) {
  const raw = fragment.replace(/^#/, '');
  const dot = raw.indexOf('.');
  return dot === -1 ? raw : raw.slice(0, dot);
}

// Accept a long link or a bare short code, and return {base, id, keyBytes}.
async function resolve(target) {
  if (/^https?:\/\//i.test(target)) {
    const u = new URL(target);
    return { base: u.origin, id: u.search.slice(1), keyBytes: b64uToBytes(keyOf(u.hash)) };
  }
  // A bare code: ask the shortener where it points.
  const base = arg('base', BASE).replace(/\/+$/, '');
  const r = await fetch(base + SHORT_PREFIX + target, { redirect: 'manual' });
  const loc = r.headers.get('location');
  if (!loc) throw new Error(`no such short code (${r.status})`);
  const u = new URL(loc);
  return { base: u.origin, id: u.search.slice(1), keyBytes: b64uToBytes(keyOf(u.hash)) };
}

async function main() {
  if (flag_help()) { process.stdout.write(USAGE); return; }
  const target = process.argv[2];
  if (!target) throw new Error('pass a long link or a short code');

  const { base, id, keyBytes } = await resolve(target);
  const password = arg('password', '') || '';
  const headers = { 'Content-Type': 'application/json' };
  if (process.env.KHEPRI_IP) headers['X-Forwarded-For'] = process.env.KHEPRI_IP;

  // 1. opening call: salt, iterations, claim. No ciphertext yet.
  const meta = await (await fetch(`${base}/api/paste/${id}`, { headers })).json();
  if (meta.error) throw new Error(meta.error);

  // 2. derive the key exactly the way the creator did.
  const material = Buffer.concat([keyBytes, Buffer.from(password, 'utf8')]);
  const key = await new Promise((res, rej) => crypto.pbkdf2(
    material, b64uToBytes(meta.salt), meta.iterations, 32, 'sha256',
    (e, v) => (e ? rej(e) : res(v))));

  // 3. recover the proof from the claim, which is that proof encrypted under
  //    the same key. This is what the browser does on every read.
  const claimRaw = b64uToBytes(meta.claim);
  const dc = crypto.createDecipheriv('aes-256-gcm', key, b64uToBytes(meta.claimIv));
  dc.setAAD(Buffer.from('claim:' + id, 'utf8'));
  dc.setAuthTag(claimRaw.subarray(claimRaw.length - 16));   // tag before final
  const proof = Buffer.concat([
    dc.update(claimRaw.subarray(0, claimRaw.length - 16)),
    dc.final(),
  ]);

  // 4. trade the proof for the ciphertext.
  const r = await fetch(`${base}/api/paste/${id}`, {
    method: 'POST', headers, body: JSON.stringify({ proof: b64u(proof) }),
  });
  const data = await r.json();
  if (data.error) throw new Error(data.error);

  // 5. decrypt. The paste id is additional data, as on the write side.
  const raw = b64uToBytes(data.ct);
  const d = crypto.createDecipheriv('aes-256-gcm', key, b64uToBytes(data.iv));
  d.setAAD(Buffer.from(id, 'utf8'));
  d.setAuthTag(raw.subarray(raw.length - 16));
  const plaintext = Buffer.concat([
    d.update(raw.subarray(0, raw.length - 16)),
    d.final(),
  ]).toString('utf8');

  // 6. a file paste is marker + metadata + base64 payload; text is anything else.
  if (plaintext.startsWith(FILE_MARKER + '\n')) {
    const head = FILE_MARKER + '\n';
    const metaEnd = plaintext.indexOf('\n', head.length);
    const m = JSON.parse(b64uToBytes(plaintext.slice(head.length, metaEnd)).toString('utf8'));
    const bytes = b64uToBytes(plaintext.slice(metaEnd + 1).replace(/\s+/g, ''));
    const out = arg('out', null);
    if (out) {
      fs.writeFileSync(out, bytes);
      process.stdout.write(JSON.stringify({
        kind: 'file', name: m.name, type: m.type, size: bytes.length, saved: out,
      }, null, 2) + '\n');
    } else {
      process.stdout.write(JSON.stringify({
        kind: 'file', name: m.name, type: m.type, size: bytes.length,
        note: 'pass --out <path> to save it',
      }, null, 2) + '\n');
    }
    return;
  }
  process.stdout.write(plaintext + '\n');
}

function flag_help() { return process.argv.includes('-h') || process.argv.includes('--help'); }

main().catch((e) => { process.stderr.write('error: ' + e.message + '\n'); process.exit(1); });
