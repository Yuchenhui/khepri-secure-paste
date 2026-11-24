// Latency check for a running core, one request at a time unless stated.
//   node scripts/bench.mjs http://127.0.0.1:8080
// Each request uses its own X-Forwarded-For so the app's rate limiter and
// per-client quota do not shape the numbers; run the service with TRUST_PROXY=1.

import { createHash, randomBytes } from 'node:crypto';
const BASE = process.argv[2];
const b64u = (b) => Buffer.from(b).toString('base64url');
let ip = 0;
const nextIp = () => `10.${40 + Math.floor(ip / 62500) % 150}.${Math.floor(ip / 250) % 250}.${(ip++) % 250 + 1}`;
const paste = (bytes) => {
  const proof = randomBytes(32);
  return {
    proof: b64u(proof),
    body: {
      id: randomBytes(8).toString('hex'), ct: 'A'.repeat(bytes), iv: b64u(randomBytes(12)),
      salt: b64u(randomBytes(8)), claim: b64u(randomBytes(48)), claimIv: b64u(randomBytes(12)),
      claimHash: b64u(createHash('sha256').update(proof).digest()), iterations: 200000,
      burn: false, pinIp: false, ttl: 3600, reads: 3,
    },
  };
};
const pct = (a, p) => a.slice().sort((x, y) => x - y)[Math.min(a.length - 1, Math.floor(a.length * p))];
const line = (label, t) => {
  if (!t.length) return console.log(label.padEnd(30), 'no successes');
  const total = t.reduce((a, b) => a + b, 0);
  console.log(label.padEnd(30), `n=${String(t.length).padStart(3)}`,
    `p50=${pct(t, 0.5).toFixed(1)}ms`, `p95=${pct(t, 0.95).toFixed(1)}ms`,
    `max=${Math.max(...t).toFixed(1)}ms`, `rps=${(t.length / (total / 1000)).toFixed(0)}`);
};
async function write(bytes, n) {
  const times = []; const made = []; let fail = 0;
  for (let i = 0; i < n; i++) {
    const p = paste(bytes);
    const t = performance.now();
    const r = await fetch(BASE + '/api/paste', { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-forwarded-for': nextIp() }, body: JSON.stringify(p.body) });
    if (r.status === 200) { times.push(performance.now() - t); made.push(p); } else fail++;
  }
  return { times, made, fail };
}
line('write 1 KB', (await write(1000, 400)).times);
const mid = await write(256 * 1024, 30);
line('write 256 KB', mid.times);
const meta = [];
for (let i = 0; i < 300; i++) {
  const p = mid.made[i % mid.made.length];
  const t = performance.now();
  const r = await fetch(BASE + '/api/paste/' + p.body.id, { headers: { 'x-forwarded-for': nextIp() } });
  if (r.status === 200) meta.push(performance.now() - t);
}
line('metadata GET 256 KB paste', meta);
const claim = [];
for (const p of mid.made) {
  const t = performance.now();
  const r = await fetch(BASE + '/api/paste/' + p.body.id, { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-forwarded-for': nextIp() }, body: JSON.stringify({ proof: p.proof }) });
  if (r.status === 200) claim.push(performance.now() - t);
}
line('claim read 256 KB', claim);
const conc = [];
for (let round = 0; round < 5; round++) {
  const batch = await Promise.all(Array.from({ length: 8 }, async () => {
    const p = paste(64 * 1024);
    const t = performance.now();
    const r = await fetch(BASE + '/api/paste', { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-forwarded-for': nextIp() }, body: JSON.stringify(p.body) });
    return r.status === 200 ? performance.now() - t : null;
  }));
  for (const v of batch) if (v !== null) conc.push(v);
}
line('write 64 KB @8 concurrent', conc);
