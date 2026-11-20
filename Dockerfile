# syntax=docker/dockerfile:1
#
# Build once, run twice — one container per service:
#
#   docker run -d --name paste-core \
#     -e PORT=8080 -e TRUST_PROXY=1 \
#     -e SHORTENER_URL=https://s.paste.example.com \
#     -p 127.0.0.1:18901:8080 \
#     --read-only --cap-drop ALL --security-opt no-new-privileges \
#     paste:latest node core.js
#
#   docker run -d --name paste-short \
#     -e PORT=8080 -e PUBLIC_URL=https://s.paste.example.com \
#     -e ALLOWED_ORIGIN=https://paste.example.com \
#     -p 127.0.0.1:18902:8080 \
#     --read-only --cap-drop ALL --security-opt no-new-privileges \
#     paste:latest node shortener.js
#
# --read-only is safe: both services keep state in process memory and write
# nothing to disk. It removes the whole class of on-disk compromise.

FROM node:20-alpine

# Non-root. Neither service writes, mounts, or binds a privileged port —
# nginx on the host owns the public sockets and proxies to 127.0.0.1.
RUN addgroup -S app && adduser -S app -G app

WORKDIR /app
COPY --chown=app:app core.js shortener.js ./
COPY --chown=app:app public/ ./public/

# No package.json and no npm install: the code uses only Node built-ins
# (node:http, node:fs, node:path, node:crypto). Nothing to resolve, no
# third-party packages, no supply-chain surface from dependencies.
USER app

# Both services listen on 8080 inside the container; only one runs per
# container, so there is no conflict. nginx maps the host ports.
EXPOSE 8080
