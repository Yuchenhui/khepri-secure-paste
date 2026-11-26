# Secure online clipboard

A self-hosted encrypted pastebin. Paste text or a small file, get a link, and
the server never sees what you wrote.

The browser encrypts before anything is sent, so the key travels inside the
link. Whoever you send it to is the only one who can open it. A paste can
delete itself after a single read, and a short link (`/s/XXXXX`) keeps the URL
small enough to retype on a locked-down console.

Running at https://paste.vantolab.com/.

## Screenshots

<img src="assets/new.png" width="620" alt="The create form: demo text, a password, a six-hour lifetime, three reads">

<img src="assets/read.png" width="620" alt="A decrypted paste, two reads left">

## What it does

- Text, or one file of up to 512 KB.
- Encrypted in the browser. The server keeps the ciphertext, a paste id and the
  limits you set.
- An optional password, so the link on its own is not enough.
- Read limits: once, three, five, or unlimited. "Once" deletes the paste when
  it is read.
- An optional lock to the first reader's IP.
- Short links (`/s/XXXXX`), because the long link is nearly 90 characters.
- Every failure says what happened in words: a wrong password, a paste that
  expired, a code that resolves to nothing. No raw status codes, no JSON.

## How it works

The browser generates 32 random bytes, appends the password to them, and
derives the key with PBKDF2-SHA256 (1,000,000 rounds). The paste is encrypted
with AES-256-GCM, with the paste id as additional data. The key stays in the
link's fragment, which browsers do not send to servers.

Two processes: **core** keeps ciphertext in SQLite and hands it over once the
reader sends a token that only the key can produce; **shortener** maps short
codes to long links. The shortener has to see keys, so its table is encrypted
at rest under `SHORTENER_KEY`.

## Running it

From source, no build step:

```bash
# core
PORT=8080 TTL_HOURS=24 DB_PATH=./paste.db MAX_DISK_MB=5120 node src/core.js

# shortener — SHORTENER_KEY is required: 32 bytes as base64 or 64 hex characters
PORT=8081 PUBLIC_URL=https://paste.example.com/s ALLOWED_ORIGIN=https://paste.example.com \
  SHORTENER_KEY="$(openssl rand -base64 32)" node src/shortener.js
```

Point the core at the shortener with `SHORTENER_URL` to get short links.

Deployment stages the code under `/opt/paste/releases/<sha>/` and bind-mounts it
over `/app/src` and `/app/public`, so the image carries only the Node runtime:
an ordinary deploy never rebuilds it, and a rollback is pointing the mounts at
an older release. The script and nginx vhost are not published — they name the
host, the domain and the ports.

Or straight from Docker Hub — the paste service alone:

```bash
docker run -d --name khepri -p 8080:8080 \
  -e HOST=0.0.0.0 -e TTL_HOURS=168 -e DB_PATH=/data/paste.db \
  -v khepri-data:/data yuchenhui/khepri-secure-paste:latest
```

`HOST=0.0.0.0` is what makes the published port reachable: the service binds
to loopback by default. Put a TLS terminator in front of it before anyone else
can reach it.

Short links need a second container from the same image:

```bash
docker run -d --name khepri-short -p 8081:8080 \
  -e HOST=0.0.0.0 -e TTL_HOURS=168 -e SHORTENER_DB_PATH=/data/shortener.db \
  -e SHORTENER_KEY="$(openssl rand -base64 32)" \
  -e PUBLIC_URL=http://localhost:8081 -e ALLOWED_ORIGIN=http://localhost:8080 \
  -v khepri-data:/data yuchenhui/khepri-secure-paste:latest node src/shortener.js
```

Give the core `SHORTENER_URL=http://localhost:8081` and the two services will
hand out short links.

## Programmatic access

An agent can upload without a browser: it generates the key locally, encrypts
with AES-256-GCM, and POSTs the ciphertext to `/api/paste`. The key travels in
the URL fragment, so it never reaches the server — the agent has to do the
crypto itself, there is no "upload this text" endpoint.

### The `secure-online-clipboard` skill

The whole protocol is packaged as an agent skill, with four scripts that are
already tested against a running deployment. Point an agent at the skill and it
can upload, take a short code, and read back, without reimplementing any of the
crypto.

| Script | Does | Needs |
|---|---|---|
| `secure-online-clipboard-push.cjs` | upload | Node 18+, no packages |
| `secure-online-clipboard-fetch.cjs` | read back | Node 18+, no packages |
| `secure-online-clipboard-push.py` | upload | Python 3.8+ + `cryptography` |
| `secure-online-clipboard-fetch.py` | read back | Python 3.8+ + `cryptography` |

The skill covers every parameter, the field-by-field request contract, the error
table, and how to pick a parameter set for a given situation. PBKDF2 uses the
standard library on both sides; only AES-GCM needs a package in Python.

### Parameters

```bash
node secure-online-clipboard-push.cjs "the content" --short --len 6 --ttl 3600
```

| Flag | Meaning |
|---|---|
| `--file <path>` | Attach a file instead of text (limit 512 KB) |
| `--short` | Also ask for a short code |
| `--len <3-8>` | Short code length (default 5) |
| `--ttl <seconds>` | Lifetime, 60 to 604800 (default 21600) |
| `--burn` | Burn after one read |
| `--reads <0-20>` | Read limit; 0 means unlimited |
| `--pin-ip` | Bind to the first reader's address |
| `--password <pw>` | Add a password — send it over a separate channel |
| `--base <url>` | Deployment to talk to (default `$KHEPRI_BASE`) |
| `--quiet` | Print only the link |

Reading back takes a long link or a bare short code, and needs nothing beyond
the link itself — the read proof is recoverable from the claim with the key,
which is what the browser does:

```bash
node secure-online-clipboard-fetch.cjs "https://paste.vantolab.com/?<id>#<key>" --out ./file.bin
node secure-online-clipboard-fetch.cjs a0k --out ./file.bin
```

A file uploaded with `--file` comes back as the same name and the same bytes; a
text paste prints. A paste made with `--password` needs the same password, and a
wrong one fails the authentication instead of returning garbage.

`/s/shorten` answers a caller with no `Origin` header, so a CLI agent can get a
short code; a wrong `Origin` is still refused. The shortener sees the full URL
including the key, which is the same trade-off the web page makes.

Note that neither `curl` nor `openssl enc` can decrypt this protocol: curl has
no symmetric-cipher tooling, and `openssl enc` refuses AEAD ciphers outright. A
reader needs Node 18+ or Python 3.8+ with `cryptography`.

## Versions

A release is one tag: the base version, the minute it was built and the commit
it came from, for example `1.0.0-20261125-1546-2d9df2b`. Pull `latest` for the
newest one. The same string is used as the git tag, so an image and a commit
always name the same build. The current release is
`1.0.0-20261125-1546-2d9df2b`, running at paste.vantolab.com.

## Limits

1 MiB per request, 512 KB per file, 5 GiB and 200000 pastes on disk, 100000
short links. Per client: 2 MiB, 32 pastes, 200 live short codes. Rate limits
are 60 requests a minute on the core and 120 on the shortener. A paste lives
at most `TTL_HOURS` (24 by default, 168 in the deployment); the form starts at
six hours. Expired pastes are swept out every minute.

## Security notes

- A short link leads to the key. Anyone holding it can open the long link and
  read a paste that has no password; with a password they need that too, so
  make it strong — the key is derived from it, which is slow to guess.
- The core never sees a key, a password or plaintext. The shortener does see
  keys; its database is encrypted with `SHORTENER_KEY`, which stays on the host
  and never touches the data volume, so neither volume holds anything readable
  on its own.
- Browsers get an error page that explains what happened; API clients get a
  short reason code. The page never says more than "nothing here", so probing
  addresses learns nothing about what used to exist.
- No accounts, no request logs, no backups. Everything expires.

## Layout

`src/` holds the two services and their shared helpers, `public/` the two
pages, `assets/` the screenshots above, `design/` the token set the pages are
drawn from, `scripts/` a latency benchmark, `test/` the suite that runs with
`node --test`.

## Not included

Read receipts, secret requests, a CLI, backups, link previews. None of them
earn their keep here.

MIT licensed.
