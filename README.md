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
| Shortener or someone with the short link | Can resolve the URL and decrypt | Needs the password; weak passwords can be guessed offline |

Password protection is optional. For sensitive content use a strong password or share the long link directly. Short codes are not access controls. Short link creation sends the full URL in a POST body; disable request-body and redirect-URL logging for the shortener and its proxies.

## Optional IP pinning

A paste can be locked to the IP of the first successful read-proof submission. Any later read from a different IP returns `404`. Shared egress IPs do not distinguish users, and a network change can lock out the original recipient.

Good uses: a fixed-IP server, a specific office egress, a machine you control.
Bad uses: a phone, a home broadband connection, anything that changes network.

Opening a page or entering a wrong password does not bind the IP or burn the paste. If the creator successfully reads it first, the creator's IP counts. With burn enabled, the ciphertext is removed atomically when released; a response lost after that point cannot be retried.

### Proxy configuration

Set an authoritative client address on all proxied application routes:

```nginx
proxy_set_header X-Forwarded-For $remote_addr;
```

Run both services with `TRUST_PROXY=1` only behind that trusted proxy. Do not expose their upstream ports to untrusted clients. Without the flag, forwarded headers are ignored.

## Crypto

Matches PrivateBin's construction:

```
key material = 32 random bytes ++ password      (password appended, may be empty)
key          = PBKDF2-SHA256(material, salt, 200000)
ciphertext   = AES-256-GCM(plaintext, iv, adata = pasteId)
```

- Each paste uses an 8-byte random salt and separate 12-byte random IVs for the body and the read token.
- The browser authenticates both envelopes against the paste ID from the URL. It decrypts a random read token locally, sends only that token to the core, and gets the body ciphertext after the token matches its stored hash. Neither the password nor the URL fragment is sent to the core.

## Run

```bash
# core — no secrets needed, nothing to configure
PORT=8080 TTL_HOURS=24 node core.js

# shortener
PORT=8081 PUBLIC_URL=https://paste.example.com/s ALLOWED_ORIGIN=https://paste.example.com \
  node shortener.js
```

Set the core's `SHORTENER_URL` to enable automatic short link creation:

```bash
PORT=8080 SHORTENER_URL=https://paste.example.com/s node core.js
```

Both processes bind `127.0.0.1`. The Linux Docker deployment uses host networking so nginx can reach the loopback ports and route `/s/` to the shortener, stripping that prefix. The same public hostname and TLS certificate serve both paths. `ALLOWED_ORIGIN` is the core's public origin and the only permitted redirect origin. `PUBLIC_URL` is the shortener's public base URL, including `/s`. CORS is not authentication.

## Storage

Both services keep state in memory; restart drops all pastes and short links. A short link does not consume the paste and can redirect until its own TTL (24 hours by default), even if the paste is already gone.

## Small files

The create form can attach one file up to 256 KB. The browser reads the bytes, base64-encodes them, and puts them in the same encrypted text paste the service already stores:

```
KHEPRI-FILE 1
<base64url JSON {name, type, size}>
<base64 bytes>
```

The reading page recognises the marker, rebuilds the file in the browser and offers it as a download; a file that does not carry the marker still renders as text, and an older reader just shows the marker plus base64. The server is untouched: it stores ciphertext only, and a file costs roughly 1.78× its size in the create request (base64 of the payload, then base64url of the ciphertext). For anything above 256 KB, use an actual file transfer.

## Limits

- Core accepts up to 1 MiB of JSON per create request, including ciphertext encoding; it caps stored entries at 1024 and accounts for up to 16 MiB of payload and metadata.
- The create form caps an attached file at 256 KB, which encodes to roughly 466 KB of JSON — comfortably inside the 1 MiB request limit.
- Core validates `iterations` between 100000 and 1000000; the client always sends 200000.
- Base62 codes default to 4 characters. Creation API accepts lengths 3–12 and caps stored mappings at 4096.
- Rate limits: core 60 req/min/IP; shortener 120 req/min/IP. Rate-limit tables expire old entries and are bounded.

## What is deliberately absent

- No account system. Anyone who can reach the core can create a paste.
- No binary upload transport: no multipart endpoint, no streaming, no object storage. Small files ride inside the base64 text body described above.
- No formatting, syntax highlighting or markdown. The reading page is a `<pre>`, which preserves every byte.
- No language selector. Single-user tool.

## License

MIT
