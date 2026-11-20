#!/usr/bin/env bash
# Deploy the paste service to a host running nginx + Docker.
#
# Idempotent: safe to re-run. It builds the image, recreates both
# containers, installs the nginx vhosts, and reloads nginx only after
# nginx -t passes.
#
# Usage:  sudo ./deploy.sh [--domain paste.example.com] [--short s.example.com]

set -Eeuo pipefail

DOMAIN="paste.vantolab.com"
SHORT_DOMAIN="s.paste.vantolab.com"
IMAGE="paste:latest"
CORE_PORT=18901
SHORT_PORT=18902
APP_DIR=/opt/paste

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain) DOMAIN="$2"; shift 2 ;;
    --short)  SHORT_DOMAIN="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ $(id -u) -eq 0 ]] || { echo "run as root" >&2; exit 1; }

echo "==> deploying to $DOMAIN / $SHORT_DOMAIN"

# ---- 1. code -------------------------------------------------------------
mkdir -p "$APP_DIR"
cp core.js shortener.js "$APP_DIR"/
cp -r public "$APP_DIR"/
chown -R root:root "$APP_DIR"
chmod -R go-w "$APP_DIR"

# ---- 2. image ------------------------------------------------------------
docker build -q -t "$IMAGE" .

# ---- 3. containers -------------------------------------------------------
# --read-only: neither service writes to disk, state lives in memory.
# --cap-drop ALL + no-new-privileges: nothing here needs any capability.
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
    "$IMAGE" node "$script" >/dev/null
}

echo "==> starting core on 127.0.0.1:$CORE_PORT"
run_svc paste-core "$CORE_PORT" core.js \
  -e TRUST_PROXY=1 \
  -e TTL_HOURS=24 \
  -e "SHORTENER_URL=https://$SHORT_DOMAIN"

echo "==> starting shortener on 127.0.0.1:$SHORT_PORT"
run_svc paste-short "$SHORT_PORT" shortener.js \
  -e TRUST_PROXY=1 \
  -e "PUBLIC_URL=https://$SHORT_DOMAIN" \
  -e "ALLOWED_ORIGIN=https://$DOMAIN" \
  -e TTL_HOURS=24

# ---- 4. nginx ------------------------------------------------------------
sed -e "s/__DOMAIN__/$DOMAIN/g" \
    deploy/paste.vantolab.com.conf  > /etc/nginx/sites-available/$DOMAIN.conf
sed -e "s/__SHORT__/$SHORT_DOMAIN/g" \
    deploy/s.paste.vantolab.com.conf > /etc/nginx/sites-available/$SHORT_DOMAIN.conf
ln -sfn /etc/nginx/sites-available/$DOMAIN.conf      /etc/nginx/sites-enabled/$DOMAIN.conf
ln -sfn /etc/nginx/sites-available/$SHORT_DOMAIN.conf /etc/nginx/sites-enabled/$SHORT_DOMAIN.conf

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
  shortener: https://$SHORT_DOMAIN

Certificates are NOT issued by this script. If these domains are new:
  acme.sh --issue -d $DOMAIN --keylength ec-256 --dns dns_cf \
          --nginx --reloadcmd "systemctl reload nginx"
EOF
