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

## Layout

```
src/         core.js, shortener.js, http-util.js — the two services
public/      new.html, view.html, the scripts they load, vendor/ (QR encoder)
test/        node --test suites that drive a real process over HTTP
scripts/     bench.mjs, the latency check
deploy/      deploy.sh and the nginx vhost
design/      design tokens and registry for the UI; reference only, never served
```

Only the files named in the asset map in `src/core.js` are reachable over HTTP, and the page scripts are addressed by content-hashed names.

## Security model — read this before using short links

**The shortener holds the complete long URL, and the long URL contains the key.** On disk that mapping is encrypted under `SHORTENER_KEY`; in memory the shortener has the key it must redirect to.

| Actor | Without password | With password |
|---|---|---|
| Network observer | cannot read | cannot read |
| The core server | cannot read | cannot read |
| Shortener or someone with the short link | Can resolve the URL and decrypt | Needs the password; weak passwords can be guessed offline |

Password protection is optional. For sensitive content use a strong password or share the long link directly. Short codes are not access controls. Short link creation sends the full URL in a POST body; disable request-body and redirect-URL logging for the shortener and its proxies.

The create form generates a password for you: the refresh button inside the password field writes 20 random characters — upper case, lower case, digits and symbols, at least one of each — and the copy button next to it puts the value on the clipboard. The password never reaches the server; it is appended to the random key material before the key is derived.

## Optional IP pinning

A paste can be locked to the IP of the first successful read-proof submission. Any later read from a different IP returns `404`. Shared egress IPs do not distinguish users, and a network change can lock out the original recipient.

Good uses: a fixed-IP server, a specific office egress, a machine you control.
Bad uses: a phone, a home broadband connection, anything that changes network.

Opening a page or entering a wrong password does not bind the IP or consume a read. If the creator successfully reads it first, the creator's IP counts. With a single-read paste the ciphertext is removed atomically when released; a response lost after that point cannot be retried.

## Lifetime and read limit

Each paste carries its own lifetime and read limit, chosen in the create form:

- **Expiry** — 1 hour, 6 hours, 24 hours, 3 days or 7 days. The form renders only the choices the server accepts: `TTL_HOURS` is the ceiling (24 in code, 168 in the deployment, so seven days is the maximum), and the longest allowed choice stays selected.
- **Read limit** — one read (the paste is deleted when the body is released), 3, 5, or no limit. The default is a single read.

The create API takes `ttl` in seconds and `reads` as an integer (`0` means no limit, at most 20). Both are optional: without them the core uses the full `TTL_HOURS` lifetime and treats `burn: true` as a single read, which is what older clients send. The core rejects a `ttl` below 60 seconds or above the env ceiling with `400 invalid expiry`, and a `reads` outside `0..20` with `400 invalid read limit`.

`GET /api/paste/<id>` returns `reads` and `expires` alongside the read token, so the reading page can warn before consuming a single-read paste and show the remaining lifetime. Neither value is secret; both come from the ciphertext's metadata, not from its content.

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
key          = PBKDF2-SHA256(material, salt, 1000000)
ciphertext   = AES-256-GCM(plaintext, iv, adata = pasteId)
```

- Each paste uses an 8-byte random salt and separate 12-byte random IVs for the body and the read token.
- The browser authenticates both envelopes against the paste ID from the URL. It decrypts a random read token locally, sends only that token to the core, and gets the body ciphertext after the token matches its stored hash. Neither the password nor the URL fragment is sent to the core.
- New pastes use 1000000 iterations, the ceiling the core accepts, so a stolen paste plus a stolen key still costs an expensive offline guess. The count is stored with the paste, so a paste made earlier keeps the count it was made with.

## Run

```bash
# core — no secrets needed; the database file is the only writable path
PORT=8080 TTL_HOURS=24 DB_PATH=./paste.db MAX_DISK_MB=5120 node src/core.js

# shortener — SHORTENER_KEY is required: 32 bytes as base64 or 64 hex characters
PORT=8081 PUBLIC_URL=https://paste.example.com/s ALLOWED_ORIGIN=https://paste.example.com \
  SHORTENER_KEY="$(openssl rand -base64 32)" node src/shortener.js
```

Set the core's `SHORTENER_URL` to enable automatic short link creation:

```bash
PORT=8080 SHORTENER_URL=https://paste.example.com/s node src/core.js
```

Both processes bind `127.0.0.1`. The Linux Docker deployment uses host networking so nginx can reach the loopback ports and route `/s/` to the shortener, stripping that prefix. The same public hostname and TLS certificate serve both paths. `ALLOWED_ORIGIN` is the core's public origin and the only permitted redirect origin. `PUBLIC_URL` is the shortener's public base URL, including `/s`. CORS is not authentication.

## Storage

Pastes live in a SQLite database (`node:sqlite`, no dependency): WAL mode, a 32 MiB page cache, `synchronous = NORMAL`, and a hard page limit so the file cannot outgrow `MAX_DISK_MB` (5 GiB by default). It holds ciphertext and the same fields the memory store used to hold — never a key, never a password, never plaintext. A restart keeps every paste that has not expired, and the deployment keeps the file on the `paste-data` volume, so recreating a container no longer drops anything.

Expiry is enforced twice: on access, and by a sweep every minute that deletes expired rows and then runs `incremental_vacuum` plus a WAL checkpoint, so the file shrinks as pastes die. Nothing survives its TTL.

Short links live in their own SQLite database on the same `paste-data` volume, so recreating the shortener container no longer turns every shared code into a dead link. A short link redirects until its own TTL (168 hours by default, matching the paste lifetime) even if the paste behind it is gone. The mapping holds the paste key, so the target is encrypted with AES-256-GCM under `SHORTENER_KEY` — a key that never lands on the volume — and the file is written with owner-only permissions. The shortener refuses to start without that key, and rows written before it was encrypted are dropped rather than left to fail.

One client may hold at most 200 live codes (`MAX_IP_LINKS`) and the store holds 100000 (`MAX_LINKS`). Both count what is alive right now, not what a client ever created: an expired link frees its slot, whether it was swept or not.

Backups are deliberately not part of this service. If you add one, it would outlive the TTL and keep ciphertext the service itself has already deleted.

## Small files

The create form can attach one file per paste, up to 256 KB; a second file is refused rather than silently replacing the first. The browser reads the bytes, base64-encodes them, and puts them in the same encrypted text paste the service already stores:

```
KHEPRI-FILE 1
<base64url JSON {name, type, size}>
<base64 bytes>
```

The reading page recognises the marker, rebuilds the file in the browser and offers it as a download; a file that does not carry the marker still renders as text, and an older reader just shows the marker plus base64. The server is untouched: it stores ciphertext only, and a file costs roughly 1.78× its size in the create request (base64 of the payload, then base64url of the ciphertext). For anything above 256 KB, use an actual file transfer.

## QR code

The create page can render the link it currently shows as a QR code, for handing it to a phone. The encoder is a vendored MIT build of `qrcode-generator`, pinned in `public/vendor/README.md`; the core serves it at `/vendor/qrcode.js` with a one-day cache and the page fetches it only when the button is pressed, so a paste that never shows a QR loads exactly the bytes it did before.

The code encodes whichever link is displayed: with the shortener enabled that is the short link, which still contains the key. A displayed QR is as sensitive as the link itself.

## Edge limits (nginx)

`deploy/paste.vantolab.com.conf` is the only network-facing layer; the app's own limiter (60 req/min/IP) sits behind it. The vhost adds:

- `limit_req` 120 req/min per IP with a burst of 40 (20 on `/s/`) and `limit_conn` 16 concurrent connections (8 on `/s/`), both answering `429`. This caps bursts before Node sees them and stops a slow reader from parking many sockets.
- 10-second header, body and send timeouts. Nothing here streams or long-polls.
- `Strict-Transport-Security` (one year), `X-Frame-Options: DENY`, `frame-ancestors 'none'`, and a `Content-Security-Policy` of `default-src 'none'` with `script-src 'self'`, `style-src 'unsafe-inline'`, `connect-src 'self'`. Each page loads one same-origin script and one inline stylesheet, so no inline script is allowed at all. Styles stay inline because they are static and carry no data.
- `X-Robots-Tag: noindex, nofollow, noarchive` and `Cross-Origin-Resource-Policy: same-origin`: a paste URL stays out of search indexes and cannot be embedded by another site, so a link cannot be probed from a third-party page.
- TLS session tickets off and a shared session cache, so a captured session cannot be resumed after a key leak. HTTP/2 is on, so the page and its script share one connection.
- Caching and compression: page scripts are served from a content-hashed path (`/app.<hash>.js`, `/view.<hash>.js`, `/vendor/qrcode.<hash>.js`) with `Cache-Control: immutable`, so a repeat visit downloads only the no-store HTML. nginx gzips the HTML and scripts (12.6 KB page to 3.9 KB, 15.6 KB script to 5.5 KB) and has gzip off under `/api/`, where the body is base64 ciphertext and compressing it only burns CPU.
- `405` for anything other than `GET`, `HEAD`, `POST` or `OPTIONS`.

## Abuse model

The core never holds a key, so it cannot read, classify or block a payload: content filtering is impossible by construction, not a missing feature. What is bounded instead is the shape of the service:

- 200000 pastes and 5 GiB of ciphertext on disk, 1 MiB per request, 256 KB per attached file, 20 reads, 7 days at most. A flood cannot grow the store past the cap, and every paste dies at its TTL.
- 2 MiB and 32 pastes per client: a single source cannot fill the store. Creating past a full store drops the oldest paste instead of refusing every write, so one client's traffic cannot make the service read-only for others.
- The shortener keeps 100000 codes in total and 200 per client, so one source cannot fill the shared link store either.
- 60 create/read requests per minute per IP at the app, 120/min with a burst cap at nginx, 16 concurrent connections per IP.
- No accounts, no logs of requests, no disk writes, nothing to hand over beyond ciphertext that expires. The only thing written to the container log is one line per active minute with counters and store gauges: `creates`, `reads`, `rejected`, `evicted`, `expired`, `pastes`, `bytes`, `clients`. No address, no paste id, no content.
- The shortener only accepts URLs under its own host, so it cannot be used as a general-purpose shortener for third-party links.

On the reading side, a decrypted file is always delivered as `application/octet-stream` with a sanitised filename, regardless of the MIME type the sender declared, so a paste can never be executed as HTML or SVG in the site's origin.

The containers themselves already run `--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges`, with 256 MB of memory and 128 pids. Host-level items — firewall, SSH, keeping nginx patched — are outside this repository.

## Limits

- Core accepts up to 1 MiB of JSON per create request, including ciphertext encoding; it caps stored entries at 200000 (`MAX_PASTES`) and the database at `MAX_DISK_MB` (5120). The create form shows a live character count and the encrypted weight against that cap, measures the encoded request before sending, and refuses it locally with the size and the limit, so an oversized paste never reaches the server.
- The create form caps an attached file at 256 KB, which encodes to roughly 466 KB of JSON — comfortably inside the 1 MiB request limit. One file per paste: the payload format holds a single `KHEPRI-FILE` block.
- Core validates `iterations` between 100000 and 1000000; the client always sends 1000000.
- Base62 codes default to 5 characters (`CODE_LEN` overrides). Creation API accepts lengths 3–12 and caps stored mappings at 100000 (`MAX_LINKS`), with 200 per client (`MAX_IP_LINKS`).
- Rate limits: core 60 req/min/IP; shortener 120 req/min/IP. Rate-limit tables expire old entries and are bounded.

## Tests

`node --test` from the repository root runs `test/`: each suite spawns the real service on a loopback port and drives it over HTTP. No dependencies, no browser, about a second.

- `test/api.test.js` — lifetime and read limits, the validation table, read proofs, the 1 MiB body cap (with and without `Content-Length`), the per-client quota, eviction when the store or the disk cap is full, survival across a restart, physical deletion of expired rows, and the page and asset routes.
- `test/shortener.test.js` — which URLs may be shortened, the code length range and default, the `Origin` check and CORS preflight, that resolving a link is repeatable, that a link survives a restart, that the store is encrypted on disk, that another key cannot read it, and that the per-client quota counts live links only.

## What is deliberately absent

- No account system. Anyone who can reach the core can create a paste.
- No binary upload transport: no multipart endpoint, no streaming, no object storage. Small files ride inside the base64 text body described above.
- No formatting, syntax highlighting or markdown. The reading page is a `<pre>`, which preserves every byte.
- No language selector. Single-user tool.

## License

MIT
