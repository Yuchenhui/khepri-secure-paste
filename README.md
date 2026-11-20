# khepri-secure-paste

Two services. The first stores ciphertext with zero knowledge. The second turns its long links into short ones.

```
┌──────────────────────────┐         ┌───────────────────────────┐
│  core.js  (paste core)   │         │  shortener.js  (redirect) │
│                          │         │                           │
│  stores {ct,iv,salt,     │         │  code -> long URL         │
│  iterations,adata}       │         │  302 on GET /<code>       │
│                          │         │                           │
│  no key, no password,    │         │  HOLDS THE CIPHER KEY     │
│  no plaintext            │         │  (it is in the URL)       │
└──────────────────────────┘         └───────────────────────────┘
        long link                             short link
   /?<16-hex-id>#<key>                     /a7k2
```

## Why two services

The long link carries a 256-bit random key in its fragment, which is what makes the core zero-knowledge. The shortener exists so you do not have to retype 84 characters.

The shortener is a separate process because it has different trust properties from the core: it necessarily holds keys, the core never does. Keeping them apart means a bug in one does not automatically become a bug in the other.

## Security model — read this before using short links

**The shortener holds the complete long URL, and the long URL contains the key.**

| Actor | Without password | With password |
|---|---|---|
| Network observer | cannot read | cannot read |
| The core server | cannot read | cannot read |
| **The shortener** | **can reconstruct the key and decrypt** | **cannot decrypt — never sees the password** |
| Someone with only the short link | cannot read | cannot read |

So: **short links without a password are protected only against passive observation.** With a password, the shortener is reduced to a redirect and the content stays zero-knowledge end to end.

Password is optional at creation time, as requested. Choose deliberately.

PrivateBin's maintainers advise against URL shorteners for the same reason. This is the trade this project makes to get short links; the password is what makes it survivable.

## Crypto

Matches PrivateBin's construction:

```
key material = 32 random bytes ++ password      (password appended, may be empty)
key          = PBKDF2-SHA256(material, salt, 200000)
ciphertext   = AES-256-GCM(plaintext, iv, adata = pasteId)
```

- `salt` 8 bytes, `iv` 16 bytes, both random per paste.
- `adata` binds the ciphertext to its paste id: swapping ciphertexts between ids fails authentication.
- AES-GCM authenticates, so a wrong password fails cleanly instead of producing garbage.
- The fragment (`#key`) is never sent to the server — browsers do not transmit fragments. That is the whole basis of the core's zero-knowledge claim.

## Run

```bash
# core — no secrets needed, nothing to configure
PORT=8080 TTL_HOURS=24 node core.js

# shortener
PORT=8081 PUBLIC_URL=https://s.example.com ALLOWED_ORIGIN=https://paste.example.com \
  node shortener.js
```

The core needs the shortener's public URL to render the Shorten button:

```bash
PORT=8080 SHORTENER_URL=https://s.example.com node core.js
```

Both bind `127.0.0.1`. Put each behind nginx with TLS and its own hostname. The shortener's `ALLOWED_ORIGIN` must be the core's public origin, since the browser calls it cross-origin.

## Storage

Both keep state in a `Map` in process memory. Restart drops everything. Intentional — a paste lives at most 24 hours and is destroyed on first read, so a database would be a component to back up and to leak for no benefit.

## Limits

- 1 MiB per paste. Larger transfers belong in `base64` or `scp`.
- Core validates `iterations` between 100000 and 1000000; the client always sends 200000.
- Shortener codes are 4 chars base62 and are consumed on first use.
- Rate limits: core 60 req/min/IP, shortener 120 req/min/IP.

## What is deliberately absent

- No account system. Anyone who can reach the core can create a paste.
- No file upload. See `base64` above.
- No formatting, syntax highlighting or markdown. The reading page is a `<pre>`, which preserves every byte.
- No language selector. Single-user tool.

## License

MIT
