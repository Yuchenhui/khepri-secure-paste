# khepri-secure-paste

Minimal self-hosted encrypted paste. Four-character links, deployment-specific key, AES-256-GCM, burn-after-reading.

## What it is

A single Node process with no dependencies. You paste text or a script in the browser, it encrypts locally with AES-256-GCM, and posts only ciphertext. The server stores the ciphertext under a 4-character code and deletes it on first read.

```
https://paste.example.com/a7k2
```

## Why not PrivateBin

PrivateBin's URL must contain the cipher key, so links are ~90 characters. This project trades per-paste keys for short links: the key is derived from a password at read time, and the deployment key gates access. Suitable for a single trusted user passing commands to their own machines — not a public pastebin.

## Threat model

| Protects against | Does not protect against |
|---|---|
| Passive network observers | Someone who knows the deployment key |
| The server itself (stores only ciphertext) | A compromised browser |
| Guessing a 4-char code | Keyloggers on the reading device |

All pastes on one deployment share one derived key. That is the trade that makes the URL short.

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
