#!/usr/bin/env bash
# Deploy the paste service to a host running nginx + Docker.
#
# Builds the image, recreates both containers, and installs a single nginx
# vhost. Pastes and short links live in SQLite on the paste-data volume, so
# recreating the containers keeps both until their TTL runs out.
#
# Usage: sudo ./deploy.sh [--domain paste.example.com]

set -Eeuo pipefail

DOMAIN="paste.vantolab.com"
IMAGE="paste:latest"
CORE_PORT=18901
SHORT_PORT=18902
APP_DIR=/opt/paste

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain) DOMAIN="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ $(id -u) -eq 0 ]] || { echo "run as root" >&2; exit 1; }

echo "==> deploying to $DOMAIN (short links at /s/)"

# ---- 1. code -------------------------------------------------------------
mkdir -p "$APP_DIR"
mkdir -p "$APP_DIR/src"
cp src/core.js src/shortener.js src/http-util.js "$APP_DIR/src"/
cp -r public "$APP_DIR"/
chown -R root:root "$APP_DIR"
chmod -R go-w "$APP_DIR"

# ---- 2. image ------------------------------------------------------------
# Host networking for the build: buildkit's bridge path to the Alpine mirrors
# stalls on this host, which leaves apk hanging inside the build.
docker build --network host -q -t "$IMAGE" .

# ---- 3. containers -------------------------------------------------------
# --read-only: nothing is written outside the paste volume, which holds the
# SQLite database of ciphertext. --cap-drop ALL + no-new-privileges above all.
# The volume keeps pastes across container recreation; expiry deletes them.
run_svc() {
  local name="$1" port="$2" script="$3"; shift 3
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker run -d --name "$name" \
    --restart unless-stopped \
    --read-only --cap-drop ALL --security-opt no-new-privileges \
    --memory 256m --pids-limit 128 \
    --network host \
    -e "PORT=$port" \
    "$@" \
    "$IMAGE" node "src/$script" >/dev/null
}

echo "==> starting core on 127.0.0.1:$CORE_PORT"
run_svc paste-core "$CORE_PORT" core.js \
  -e TRUST_PROXY=1 \
  -e TTL_HOURS=168 \
  -e MAX_DISK_MB=5120 \
  -e DB_PATH=/data/paste.db \
  -v paste-data:/data \
  -e "SHORTENER_URL=https://$DOMAIN/s"

echo "==> starting shortener on 127.0.0.1:$SHORT_PORT"
run_svc paste-short "$SHORT_PORT" shortener.js \
  -e TRUST_PROXY=1 \
  -e "PUBLIC_URL=https://$DOMAIN/s" \
  -e "ALLOWED_ORIGIN=https://$DOMAIN" \
  -e SHORTENER_DB_PATH=/data/shortener.db \
  -e TTL_HOURS=168 \
  -v paste-data:/data

# ---- 4. nginx ------------------------------------------------------------
sed -e "s/__DOMAIN__/$DOMAIN/g" \
    deploy/paste.vantolab.com.conf  > /etc/nginx/sites-available/$DOMAIN.conf
ln -sfn /etc/nginx/sites-available/$DOMAIN.conf      /etc/nginx/sites-enabled/$DOMAIN.conf

# ---- 5. verify then reload ----------------------------------------------
if nginx -t; then
  systemctl reload nginx
  echo "==> nginx reloaded"
else
  echo "!!! nginx -t failed — not reloading. Fix the config and re-run." >&2
  exit 1
fi

# ---- 6. health -----------------------------------------------------------
sleep 2
for pair in "core:$CORE_PORT" "shortener:$SHORT_PORT"; do
  name="${pair%%:*}"; port="${pair##*:}"
  if curl -fsS --max-time 5 "http://127.0.0.1:$port/health" >/dev/null; then
    echo "    $name healthy"
  else
    echo "    $name UNHEALTHY — docker logs $name" >&2
  fi
done

cat <<EOF

deployed.
  paste:     https://$DOMAIN
  shortener: https://$DOMAIN/s/

The TLS certificate for $DOMAIN must already be installed before deployment.
EOF
