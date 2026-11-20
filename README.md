# khepri-secure-paste

Minimal self-hosted encrypted paste. Four-character links, deployment-specific key, AES-256-GCM, burn-after-reading.

## What it is

A single Node process with no dependencies. You paste text or a script in the browser, it encrypts locally with AES-256-GCM, and posts only ciphertext. The server stores the ciphertext under a 4-character code and deletes it on first read.

```
https://paste.example.com/a7k2
```

## Why not PrivateBin

PrivateBin is the better tool if you want per-paste keys with zero server
trust. Its cost is a ~90 character URL, because the cipher key must travel in
the link itself.

This project optimises for a different constraint: a link you can retype on a
restricted console. That means the key cannot live in the URL, so it comes
from a password instead — and the 4-char code is an identifier, not a secret.

Both designs are sound. They are answering different questions.

## Two layers of encryption

| Layer | Where | Key | Protects against |
|---|---|---|---|
| 1. Client cipher | Browser, AES-256-GCM | PBKDF2(your password, random salt) | The server, network observers, anyone with the link |
| 2. Deployment seal | Server, AES-256-GCM | `KHEPRI_KEY` from the environment | Data at rest — stolen memory dumps, backups, disk images |

Layer 1 is the one that matters: the server never holds the password, so it
cannot decrypt your paste even while serving it.

Layer 2 seals the already-encrypted envelope with a key that exists only in
the process environment. **It does not stop a compromised running server**,
because that process holds the key and can strip this layer. What it buys is
that data leaving the process — a crash dump, a memory snapshot, a future
disk-based store — is worthless.

Every paste uses a fresh random salt, so two pastes made with the same
password do not share a cipher key.

## Deploy

```bash
# 1. Generate a deployment key — never commit this
export KHEPRI_KEY=$(openssl rand -hex 32)

# 2. Run
PORT=8080 KHEPRI_KEY=$KHEPRI_KEY node server.js
```

The server binds `127.0.0.1` only. Put it behind nginx with TLS and a hostname of your choosing.

With Docker:

```bash
export KHEPRI_KEY=$(openssl rand -hex 32)
docker build -t khepri .
docker run -d --name khepri -e KHEPRI_KEY -p 127.0.0.1:8080:8080 khepri
```

## Security notes

- The key is never in this repository. It exists only in the process environment.
- The 4-char code is an identifier, not a secret. Access control is the key plus a 60 req/min/IP rate limit.
- Burn-after-reading means a link works exactly once. If the recipient fails to copy the text, you must create a new paste.
- AES-GCM authenticates the ciphertext, so a wrong password fails cleanly rather than producing garbage.

## Limits

- 512 KiB per paste. For larger transfers use `base64` or `scp`.
- In-memory store: a restart drops all pastes. Intentional.

## License

MIT
