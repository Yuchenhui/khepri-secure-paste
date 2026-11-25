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

- Text, or one file of up to 256 KB.
- Encrypted in the browser. The server keeps the ciphertext, a paste id and the
  limits you set.
- An optional password, so the link on its own is not enough.
- Read limits: once, three, five, or unlimited. "Once" deletes the paste when
  it is read.
- An optional lock to the first reader's IP.
- Short links (`/s/XXXXX`), because the long link is nearly 90 characters.

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

```bash
# core
PORT=8080 TTL_HOURS=24 DB_PATH=./paste.db MAX_DISK_MB=5120 node src/core.js

# shortener — SHORTENER_KEY is required: 32 bytes as base64 or 64 hex characters
PORT=8081 PUBLIC_URL=https://paste.example.com/s ALLOWED_ORIGIN=https://paste.example.com \
  SHORTENER_KEY="$(openssl rand -base64 32)" node src/shortener.js
```

Point the core at the shortener with `SHORTENER_URL` to get short links.
`deploy/deploy.sh` builds the image, runs both containers and installs the
nginx vhost.

Or straight from Docker Hub:

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

## Versions

A release carries three tags on the image: `latest`, the commit it was built
from (`936dea2`) and the day it went out (`v2026.11.25`). Pin the commit when
you want to stay put, pull `latest` when you want the newest. The same string
is used as the git tag.

## Limits

1 MiB per request, 256 KB per file, 5 GiB and 200000 pastes on disk, 100000
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
- No accounts, no request logs, no backups. Everything expires.

## Layout

`src/` holds the two services and their shared helpers, `public/` the two
pages, `deploy/` the deployment script and nginx vhost, `assets/` the
screenshots above, `test/` the suite that runs with `node --test`.

## Not included

Read receipts, secret requests, a CLI, backups, link previews. None of them
earn their keep here.

MIT licensed.
