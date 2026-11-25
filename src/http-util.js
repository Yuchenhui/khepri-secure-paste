'use strict';

const { isIP } = require('node:net');

const HTTP_OPTIONS = { headersTimeout: 10000, requestTimeout: 15000, connectionsCheckingInterval: 1000 };
const TRUST_PROXY = process.env.TRUST_PROXY === '1';

function configuredHttpBase(value, allowPrefix = false) {
  const url = new URL(value);
  const validPath = allowPrefix ? /^\/(?:[A-Za-z0-9_-]+\/?)?$/.test(url.pathname) : url.pathname === '/';
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash || !validPath) {
    throw new Error('Expected an HTTP(S) base URL without credentials, query, or fragment');
  }
  return url.origin + url.pathname.replace(/\/$/, '');
}

function clientIp(req) {
  const address = TRUST_PROXY ? req.headers['x-forwarded-for'] : req.socket.remoteAddress;
  return typeof address === 'string' && isIP(address) ? address : null;
}

function createRateLimit(limit) {
  const windowMs = 60000;
  const maxClients = 4096;
  const clients = new Map();
  let refused = 0;
  setInterval(() => {
    const now = Date.now();
    for (const [ip, bucket] of clients) if (bucket.expires <= now) clients.delete(ip);
    // A full map refuses new clients outright; without this the only symptom is
    // a 429 nobody can explain. One line a minute at most, and only then.
    if (refused) {
      console.log(JSON.stringify({ at: new Date().toISOString(), rateLimitRefused: refused, clients: clients.size }));
      refused = 0;
    }
  }, windowMs).unref();

  return (ip) => {
    const now = Date.now();
    const bucket = clients.get(ip);
    if (bucket && bucket.expires > now) return ++bucket.count <= limit;
    if (!bucket && clients.size >= maxClients) { refused += 1; return false; }
    clients.set(ip, { count: 1, expires: now + windowMs });
    return true;
  };
}

function send(res, status, value, headers = {}) {
  const text = typeof value === 'string';
  const body = text ? value : JSON.stringify(value);
  res.writeHead(status, {
    'Content-Type': text ? 'text/plain; charset=utf-8' : 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
    ...headers,
  });
  res.end(body);
}

async function readJson(req, res, maxBytes) {
  function reject(status, error) {
    if (!req.destroyed) req.resume();
    if (!res.destroyed) send(res, status, { error });
    return null;
  }
  if (req.headers['content-type']?.split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
    return reject(415, 'Expected application/json');
  }
  if (Number(req.headers['content-length']) > maxBytes) return reject(413, 'Request too large');

  try {
    let bytes = 0;
    const chunks = [];
    for await (const chunk of req.iterator({ destroyOnReturn: false })) {
      bytes += chunk.length;
      if (bytes > maxBytes) return reject(413, 'Request too large');
      chunks.push(chunk);
    }
    const data = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if (data === null || typeof data !== 'object' || Array.isArray(data)) {
      return reject(400, 'Expected a JSON object');
    }
    return data;
  } catch {
    return reject(400, 'Invalid JSON');
  }
}

module.exports = { HTTP_OPTIONS, configuredHttpBase, clientIp, createRateLimit, send, readJson };
